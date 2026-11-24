/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP_Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Logins
{

    /// <summary>
    /// Which charging stations may sign in to this local controller, with
    /// what, and under which group's rules.
    /// </summary>
    /// <remarks>
    /// <b>Its own file, with its own permissions.</b> These are credentials,
    /// and the configuration file beside this one is an ordinary file that
    /// anybody who can read the directory may read. So they live here, and the
    /// file is written for its owner alone. Passwords are written the way the
    /// web login is written - PBKDF2 over a random salt - and a password that
    /// has been set is not readable again, not by this controller and not by
    /// whoever set it. A TOTP shared secret is the one thing here that cannot
    /// be hashed, because verifying a token means computing it.
    ///
    /// <b>A list, not a door.</b> A charging station that is not in this file
    /// cannot sign in with a password or a token, whatever it calls itself.
    /// Adding one is a deliberate act, which is the only way the list means
    /// anything.
    ///
    /// <b>Groups decide, logins belong.</b> What a station may do is said by
    /// the group it is in, so that it is said once for a site rather than
    /// forty times. See <see cref="WebSocketLoginGroup"/>.
    /// </remarks>
    public sealed class WebSocketLogins
    {

        #region Data

        /// <summary>
        /// The file beside the process, when nobody says otherwise.
        /// </summary>
        public const String  DefaultFileName    = "websocket-logins.json";

        /// <summary>
        /// The file these logins were kept in before they were the logins of
        /// every WebSocket and not the charging stations' alone - see
        /// <see cref="TryLoad"/>.
        /// </summary>
        public const String  FormerFileName     = "ocpp-stations.json";

        /// <summary>
        /// The longest a charging station identification may be; what OCPP 2.1
        /// allows for one.
        /// </summary>
        public const Int32   MaxIdLength        = 48;

        /// <summary>
        /// The longest a description of a station may be, in each language.
        /// </summary>
        public const Int32   MaxDescriptionLength  = 200;

        /// <summary>
        /// The shortest password that may be set by hand. OCPP asks for at
        /// least 16 characters of entropy in the password of a charging
        /// station, and a controller that accepted "1234" would be the weakest
        /// part of a system built around that rule.
        /// </summary>
        public const Int32   MinPasswordLength  = 16;

        /// <summary>
        /// The longest one may be; what OCPP allows for the field.
        /// </summary>
        public const Int32   MaxPasswordLength  = 64;

        /// <summary>
        /// How many charging stations may be listed.
        /// </summary>
        public const Int32   MaxStations        = 1000;

        /// <summary>
        /// Something to hash when there is nothing to compare against; see
        /// <see cref="Verify"/>.
        /// </summary>
        private const String TimingEqualiser       = "no such charging station";

        /// <summary>
        /// Something to derive a token from when there is nothing to compare
        /// against; see <see cref="VerifyTOTP"/>.
        /// </summary>
        private const String TOTPTimingEqualiser   = "no-such-charging-station-at-all";

        /// <summary>
        /// The login of no charging station: what a name that can be no login
        /// is looked for as, so that it is answered as an unknown one is - in
        /// the same time, too.
        /// </summary>
        public static readonly User_Id NoLogin = User_Id.Parse(TOTPTimingEqualiser);

        private readonly Object                                   updateLock  = new ();
        private readonly Dictionary<User_Id, WebSocketLogin>      logins      = [];
        private readonly Dictionary<String, WebSocketLoginGroup>  groups      = [];
        private readonly Dictionary<String, ForwardingTarget>     targets     = [];

        /// <summary>
        /// Every key pin that was listed for a station at any time since this
        /// store was made - see <see cref="WasEverListed"/>.
        /// </summary>
        private readonly HashSet<KeyPin>                          pinsEverListed  = [];

        #endregion

        #region Properties

        /// <summary>
        /// The file the logins live in.
        /// </summary>
        public String   Path     { get; }

        /// <summary>
        /// Whether the file exists.
        /// </summary>
        public Boolean  Exists
            => File.Exists(Path);

        /// <summary>
        /// The clock this controller reads.
        /// </summary>
        public TimeProvider  TimeProvider  { get; }

        /// <summary>
        /// Every charging station in the file, by identification.
        /// </summary>
        public IReadOnlyList<WebSocketLogin> Logins
        {
            get
            {
                lock (updateLock)
                    return [.. logins.Values.OrderBy(login => login.Login)];
            }
        }

        /// <summary>
        /// Every group, the built-in one first and the rest by name.
        /// </summary>
        public IReadOnlyList<WebSocketLoginGroup> Groups
        {
            get
            {
                lock (updateLock)
                    return [.. groups.Values.OrderByDescending(group => group.IsBuiltIn).
                                             ThenBy          (group => group.Id, StringComparer.OrdinalIgnoreCase)];
            }
        }

        /// <summary>
        /// Every forwarding target, by identification.
        /// </summary>
        public IReadOnlyList<ForwardingTarget> Targets
        {
            get
            {
                lock (updateLock)
                    return [.. targets.Values.OrderBy(target => target.Id, StringComparer.Ordinal)];
            }
        }

        /// <summary>
        /// How many of them may sign in at the moment.
        /// </summary>
        /// <remarks>
        /// A station in a group that is switched off may not, however switched
        /// on the station itself is - so the group has its say here too, and
        /// the number on the page is the number that could actually come in.
        /// </remarks>
        public Int32 EnabledCount
        {
            get
            {
                lock (updateLock)
                    return logins.Values.Count(login => login.Enabled &&
                                                        groups.GetValueOrDefault(login.GroupId)?.Enabled == true);
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Something happened here that belongs in the log of the controller.
        /// </summary>
        public event Action<LogLevel, String>? OnNotice;

        /// <summary>
        /// The list changed, and whatever is serving charging stations has to
        /// be told - a station whose password was taken away must stop being
        /// able to use it now and not at the next start.
        /// </summary>
        public event Action? OnChanged;

        #endregion

        #region NodeNoun

        /// <summary>
        /// What the node calls itself in what this store says: "this station
        /// cannot ..." - the node's own word, or the process's where none was
        /// given.
        /// </summary>
        public String NodeNoun
            => nodeNoun ?? NodeWording.Noun;

        private readonly String? nodeNoun;

        #endregion

        #region LoginNoun

        /// <summary>
        /// Who a login is, in what this store and the SSH logins made of it
        /// say: "the charging station 'cs001' may now sign in" - or, at a
        /// grid operator, "the local controller 'lc-1'".
        /// </summary>
        public String LoginNoun { get; }

        /// <summary>
        /// Who a login is where nothing says otherwise.
        /// </summary>
        public const String DefaultLoginNoun = "charging station";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The logins in the given file; it need not exist yet.
        /// </summary>
        /// <param name="Path">The file; it need not exist yet.</param>
        /// <param name="TimeProvider">What says the time.</param>
        /// <param name="NodeNoun">What the node calls itself.</param>
        /// <param name="LoginNoun">Who a login is: "charging station", where nothing says otherwise.</param>
        public WebSocketLogins(String?        Path          = null,
                                     TimeProvider?  TimeProvider  = null,
                                     String?        NodeNoun      = null,
                                     String?        LoginNoun     = null)
        {

            this.Path          = System.IO.Path.GetFullPath(Path ?? DefaultFileName);
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;
            this.nodeNoun      = NodeNoun;
            this.LoginNoun     = String.IsNullOrWhiteSpace(LoginNoun) ? DefaultLoginNoun : LoginNoun.Trim();

            // Before anything is read, so that a controller with no file at all
            // still has the group every login falls back to.
            this.groups[WebSocketLoginGroup.DefaultId] = WebSocketLoginGroup.Default(this.TimeProvider.GetUtcNow());

        }

        #endregion


        #region TryLoad(out Error)

        /// <summary>
        /// Read the file. No file is not a failure - it is a local controller
        /// that has not been told about any charging station yet.
        /// </summary>
        /// <remarks>
        /// A file that is there but unreadable <em>is</em> a failure, and a loud
        /// one: carrying on with an empty list would turn every charging
        /// station on the site away while looking like nothing was wrong.
        ///
        /// A login pointing at a group that is not in the file is a failure of
        /// the same kind, and deliberately not repaired by moving it to the
        /// default group: that group is the permissive one, so the repair would
        /// quietly hand a station more than whoever wrote the file meant it to
        /// have.
        /// </remarks>
        public Boolean TryLoad([NotNullWhen(false)] out String? Error)
        {

            Error = null;

            lock (updateLock)
            {

                logins.Clear();
                groups.Clear();
                targets.Clear();
                groups[WebSocketLoginGroup.DefaultId] = WebSocketLoginGroup.Default(TimeProvider.GetUtcNow());

                // The file of before, where it is all there is, is not read: its
                // groups said OCPP's security profiles, and a node that started
                // without its logins would turn everybody away while looking as
                // if nobody had ever been let in. Said, and not started.
                if (!File.Exists(Path) &&
                    System.IO.Path.GetDirectoryName(Path) is String directory &&
                    File.Exists(System.IO.Path.Combine(directory, FormerFileName)))
                {
                    Error = $"'{System.IO.Path.Combine(directory, FormerFileName)}' is no more read: the WebSocket logins are kept in '{Path}'. " +
                            $"Rename it to '{DefaultFileName}', and say in each of its groups how the members may authenticate - " +
                            $"'clientAuthentication' of {String.Join(", ", WebSocketClientAuthentications.Names.Select(name => $"\"{name}\""))} " +
                             "instead of OCPP's 'securityProfiles' 1, 2 and 3.";
                    return false;
                }

                if (!File.Exists(Path))
                    return true;

                // Passwords: what an earlier version wrote readable by others
                // is closed at the next start.
                OwnerOnly.File(Path, problem => OnNotice?.Invoke(LogLevel.Warning, problem));

                JObject document;

                try
                {

                    var text = File.ReadAllText(Path);

                    if (String.IsNullOrWhiteSpace(text))
                        return true;

                    document = JObject.Parse(text);

                }
                catch (Exception e)
                {
                    Error = $"'{Path}' could not be read: {e.Message}";
                    return false;
                }

                #region The groups, when the file knows about any

                if (document["groups"] is JToken groupsToken && groupsToken.Type != JTokenType.Null)
                {

                    if (groupsToken is not JArray groupArray)
                    {
                        Error = $"'{Path}': 'groups' must be a JSON array.";
                        return false;
                    }

                    foreach (var token in groupArray)
                    {

                        if (token is not JObject json)
                        {
                            Error = $"'{Path}': every entry of 'groups' must be a JSON object.";
                            return false;
                        }

                        if (!WebSocketLoginGroup.TryParse(json, out var group, out var problem, NodeNoun))
                        {
                            Error = $"'{Path}': {problem}";
                            return false;
                        }

                        groups[group.Id] = group;

                    }

                }

                #endregion

                #region The forwarding targets, when the file knows about any

                if (document["targets"] is JToken targetsToken && targetsToken.Type != JTokenType.Null)
                {

                    if (targetsToken is not JArray targetArray)
                    {
                        Error = $"'{Path}': 'targets' must be a JSON array.";
                        return false;
                    }

                    foreach (var token in targetArray)
                    {

                        if (token is not JObject json)
                        {
                            Error = $"'{Path}': every entry of 'targets' must be a JSON object.";
                            return false;
                        }

                        if (!ForwardingTarget.TryParse(json, out var target, out var problem))
                        {
                            Error = $"'{Path}': {problem}";
                            return false;
                        }

                        targets[target.Id] = target;

                    }

                }

                #endregion

                #region The logins

                if (document["logins"] is not JArray stations)
                {
                    Error = $"'{Path}' must hold a 'logins' array.";
                    return false;
                }

                foreach (var token in stations)
                {

                    if (token is not JObject json)
                    {
                        Error = $"'{Path}': every entry of 'stations' must be a JSON object.";
                        return false;
                    }

                    if (!WebSocketLogin.TryParse(json, out var login, out var problem, NodeNoun))
                    {
                        Error = $"'{Path}': {problem}";
                        return false;
                    }

                    if (!groups.ContainsKey(login.GroupId))
                    {
                        Error = $"'{Path}': the {LoginNoun} '{login.Login}' belongs to the group '{login.GroupId}', which is not in this file.";
                        return false;
                    }

                    // Not sent to the back end in charge instead: that is a
                    // CSMS nobody chose for this station.
                    if (login.Target is String targetId && !targets.ContainsKey(targetId))
                    {
                        Error = $"'{Path}': the {LoginNoun} '{login.Login}' is forwarded to the target '{targetId}', which is not in this file.";
                        return false;
                    }

                    // One key is one charging station, written by hand or not:
                    // a key two stations share lets either sign in as the other.
                    foreach (var key in login.Keys)
                        if (logins.Values.FirstOrDefault(other => other.Keys.Any(known => known.Fingerprint == key.Fingerprint)) is WebSocketLogin holder)
                        {
                            Error = $"'{Path}': the SSH key {key.Fingerprint} is listed for the {LoginNoun}s '{holder.Login}' and '{login.Login}'; one key is one {LoginNoun}.";
                            return false;
                        }

                    // The same for a key pin, and for a sharper reason: the pin
                    // is the whole of who the station is, so a pin two stations
                    // share would let the one connect as the other on its path.
                    foreach (var keyPin in login.Pins)
                        if (logins.Values.FirstOrDefault(other => other.FindKeyPin(keyPin.Pin) is not null) is WebSocketLogin holder)
                        {
                            Error = $"'{Path}': the key pin {keyPin.Pin} is listed for the {LoginNoun}s '{holder.Login}' and '{login.Login}'; one key is one {LoginNoun}.";
                            return false;
                        }

                    logins[login.Login] = login;

                }

                #endregion

                foreach (var login in logins.Values)
                    foreach (var keyPin in login.Pins)
                        pinsEverListed.Add(keyPin.Pin);

            }

            return true;

        }

        #endregion


        #region TryAddOrUpdateGroup(Id, Name, Enabled, AuthMethods, ClientAuthentication, Description, out Error [, out NotSaved])

        /// <summary>
        /// Make a group, or change what one allows.
        /// </summary>
        public Boolean TryAddOrUpdateGroup(String?                           Id,
                                           String?                           Name,
                                           Boolean                           Enabled,
                                           IEnumerable<AuthMethod>?          AuthMethods,
                                           IEnumerable<WebSocketClientAuthentication>?  ClientAuthentication,
                                           I18NString?                       Description,
                                           [NotNullWhen(false)] out String?  Error)

            => TryAddOrUpdateGroup(Id, Name, Enabled, AuthMethods, ClientAuthentication, Description, out Error, out _);

        /// <summary>
        /// Make a group, or change what one allows - and say whether a refusal
        /// was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryAddOrUpdateGroup(String?                           Id,
                                           String?                           Name,
                                           Boolean                           Enabled,
                                           IEnumerable<AuthMethod>?          AuthMethods,
                                           IEnumerable<WebSocketClientAuthentication>?  ClientAuthentication,
                                           I18NString?                       Description,
                                           [NotNullWhen(false)] out String?  Error,
                                           out Boolean                       NotSaved)

            => TryAddOrUpdateGroup(Id, Name, Enabled, AuthMethods, ClientAuthentication, Description, null, out Error, out NotSaved);

        /// <summary>
        /// Make a group, or change what one allows - and what its members
        /// have over their SSH connection besides OCPP.
        /// </summary>
        /// <param name="SSHChannels">Of <see cref="WebSocketLoginGroup.KnownSSHChannels"/>; null to leave what the group gives as it is, which for a new group is nothing.</param>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryAddOrUpdateGroup(String?                           Id,
                                           String?                           Name,
                                           Boolean                           Enabled,
                                           IEnumerable<AuthMethod>?          AuthMethods,
                                           IEnumerable<WebSocketClientAuthentication>?  ClientAuthentication,
                                           I18NString?                       Description,
                                           IEnumerable<String>?              SSHChannels,
                                           [NotNullWhen(false)] out String?  Error,
                                           out Boolean                       NotSaved)
        {

            NotSaved = false;

            lock (updateLock)
            {

                // Normalised the same way TryCreate will normalise it, so that
                // "Field-Test" and "field-test" are the same group rather than
                // a second one that shadows the first.
                var existing = groups.GetValueOrDefault(Id?.Trim().ToLowerInvariant() ?? "");

                if (!WebSocketLoginGroup.TryCreate(Id,
                                          Name,
                                          Enabled,
                                          AuthMethods,
                                          ClientAuthentication,
                                          Description,
                                          existing?.AddedAt ?? TimeProvider.GetUtcNow(),
                                          out var group,
                                          out Error))
                {
                    return false;
                }

                if (SSHChannels is null)
                    group = group with { SSHChannels = existing?.SSHChannels };

                else
                {

                    if (!WebSocketLoginGroup.TryChannels(SSHChannels, out var channels, out Error))
                        return false;

                    group = group with { SSHChannels = channels };

                }

                if (existing is null && groups.Count >= WebSocketLoginGroup.MaxGroups)
                {
                    Error = $"At most {WebSocketLoginGroup.MaxGroups} login groups may be listed here.";
                    return false;
                }

                groups[group.Id] = group;

                if (!TrySave(out Error))
                {

                    NotSaved = true;

                    if (existing is not null)
                        groups[group.Id] = existing;
                    else
                        groups.Remove(group.Id);

                    return false;

                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    existing is null
                        ? $"The login group '{group.Id}' was added: {group}."
                        : $"The login group '{group.Id}' was changed: {group}."
                );

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TryRemoveGroup(Id, out Error [, out NotSaved])

        /// <summary>
        /// Forget a group nobody is in.
        /// </summary>
        /// <remarks>
        /// A group with members is not removed and its members are not moved
        /// to the default group behind somebody's back: that group allows more
        /// than most, so the tidying would be a quiet widening. Whoever wants
        /// the group gone moves its members first, and sees where they land.
        /// </remarks>
        public Boolean TryRemoveGroup(String                            Id,
                                      [NotNullWhen(false)] out String?  Error)

            => TryRemoveGroup(Id, out Error, out _);

        /// <summary>
        /// Forget a group nobody is in - and say whether a refusal was the
        /// file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryRemoveGroup(String                            Id,
                                      [NotNullWhen(false)] out String?  Error,
                                      out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            var id = Id?.Trim().ToLowerInvariant() ?? "";

            lock (updateLock)
            {

                if (!groups.TryGetValue(id, out var group))
                {
                    Error = $"This {NodeNoun} has never heard of a login group called '{Id}'.";
                    return false;
                }

                if (group.IsBuiltIn)
                {
                    Error = "The default login group cannot be removed; it is what a login without a group of its own belongs to.";
                    return false;
                }

                var members = logins.Values.Count(login => login.GroupId == id);

                if (members > 0)
                {
                    Error = $"The login group '{id}' still holds {members} {LoginNoun}(s). Move them to another group first.";
                    return false;
                }

                groups.Remove(id);

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    groups[id]  = group;
                    return false;
                }

                OnNotice?.Invoke(LogLevel.Notice, $"The login group '{id}' was removed.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TrySetGroup(Id, GroupId, out Error [, out NotSaved])

        /// <summary>
        /// Move a charging station into another group.
        /// </summary>
        public Boolean TrySetGroup(User_Id                        Login,
                                   String?                           GroupId,
                                   [NotNullWhen(false)] out String?  Error)

            => TrySetGroup(Login, GroupId, out Error, out _);

        /// <summary>
        /// Move a charging station into another group - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetGroup(User_Id                        Login,
                                   String?                           GroupId,
                                   [NotNullWhen(false)] out String?  Error,
                                   out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            var groupId = GroupId?.Trim().ToLowerInvariant() ?? "";

            if (groupId.Length == 0)
                groupId = WebSocketLoginGroup.DefaultId;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                if (!groups.ContainsKey(groupId))
                {
                    Error = $"This {NodeNoun} has never heard of a login group called '{GroupId}'.";
                    return false;
                }

                if (login.GroupId == groupId)
                    return true;

                logins[Login] = login with { GroupId = groupId };

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(LogLevel.Notice, $"The {LoginNoun} '{Login}' is now in the login group '{groupId}'.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion


        #region TrySetPassword(Login, Password, GroupId, Description, out Error [, out NotSaved])

        /// <summary>
        /// Add a charging station, or give one that is already here a new
        /// password.
        /// </summary>
        /// <remarks>
        /// The password is given, and none is made up here: it is kept nowhere
        /// but in its hash, and whoever sets it has to know it to type it into
        /// the charging station.
        /// </remarks>
        /// <param name="Login">What the charging station calls itself in OCPP.</param>
        /// <param name="Password">The password, at least <see cref="MinPasswordLength"/> characters long.</param>
        /// <param name="GroupId">The group it should belong to, or null for the one it is in already.</param>
        /// <param name="Description">What this station is, for whoever reads the list later - in as many languages as it is said in.</param>
        public Boolean TrySetPasswordAuthentication(User_Id                           Login,
                                                    String?                           Password,
                                                    String?                           GroupId,
                                                    I18NString?                       Description,
                                                    [NotNullWhen(false)] out String?  Error)

            => TrySetPasswordAuthentication(
                   Login,
                   Password,
                   GroupId,
                   Description,
                   out Error,
                   out _
               );


        /// <summary>
        /// Add a charging station, or give one that is already here a new
        /// password - and say whether a refusal was the file's rather than the
        /// change's.
        /// </summary>
        /// <param name="Login">What the charging station calls itself in OCPP.</param>
        /// <param name="Password">The password, at least <see cref="MinPasswordLength"/> characters long.</param>
        /// <param name="GroupId">The group it should belong to, or null for the one it is in already.</param>
        /// <param name="Description">What this station is, for whoever reads the list later - in as many languages as it is said in.</param>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetPasswordAuthentication(User_Id                           Login,
                                                    String?                           Password,
                                                    String?                           GroupId,
                                                    I18NString?                       Description,
                                                    [NotNullWhen(false)] out String?  Error,
                                                    out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            if (!TryCheckLoginAndDescription(Login, Description, out var login, out var description, out Error))
                return false;

            var password = Password?.Trim() ?? String.Empty;

            if (password.Length == 0)
            {
                Error = $"A {LoginNoun} password must be at least {MinPasswordLength} characters long!";
                return false;
            }

            if (password.Length < MinPasswordLength)
            {
                Error = $"A {LoginNoun} password must be at least {MinPasswordLength} characters long{(LoginNoun == DefaultLoginNoun ? "; OCPP asks for that much" : "")}.";
                return false;
            }

            if (password.Length > MaxPasswordLength)
            {
                Error = $"A {LoginNoun} password may be at most {MaxPasswordLength} characters long.";
                return false;
            }

            return TryChange(
                       login,
                       description,
                       GroupId,
                       login   => login with { Password = SecurePassword.Create(password) },
                       existed => existed
                                      ? $"The password of the {LoginNoun} '{login}' was changed."
                                      : $"The {LoginNoun} '{login}' may now sign in to this {NodeNoun}.",
                       out Error,
                       out NotSaved
                   );

        }

        #endregion

        #region TrySetTOTPAuthentication(Login, SharedSecret, ValidityTime, Length, Alphabet, HashAlgorithm, GroupId, Description, out Error [, out NotSaved])

        /// <summary>
        /// Add a charging station, or give one that is already here what it
        /// needs to be let in with a one-time token.
        /// </summary>
        /// <remarks>
        /// A shared secret of null means "make one up". Unlike a password it
        /// stays readable - the controller computes tokens from it - so the
        /// one made up is read from the login, by <see cref="TryGet"/>,
        /// whenever it is to be shown.
        /// </remarks>
        public Boolean TrySetTOTPAuthentication(User_Id                           Login,
                                                String?                           SharedSecret,
                                                TimeSpan?                         ValidityTime,
                                                UInt32?                           Length,
                                                String?                           Alphabet,
                                                TOTPHashAlgorithm?                HashAlgorithm,
                                                String?                           GroupId,
                                                I18NString?                       Description,
                                                [NotNullWhen(false)] out String?  Error)

            => TrySetTOTPAuthentication(
                   Login,
                   SharedSecret,
                   ValidityTime,
                   Length,
                   Alphabet,
                   HashAlgorithm,
                   GroupId,
                   Description,
                   out Error,
                   out _
               );


        /// <summary>
        /// Add a charging station, or give one that is already here what it
        /// needs to be let in with a one-time token - and say whether a refusal
        /// was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetTOTPAuthentication(User_Id                           Login,
                                                String?                           SharedSecret,
                                                TimeSpan?                         ValidityTime,
                                                UInt32?                           Length,
                                                String?                           Alphabet,
                                                TOTPHashAlgorithm?                HashAlgorithm,
                                                String?                           GroupId,
                                                I18NString?                       Description,
                                                [NotNullWhen(false)] out String?  Error,
                                                out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            if (!TryCheckLoginAndDescription(Login, Description, out var login, out var description, out Error))
                return false;

            if (!TOTPSettings.TryCreate(
                     SharedSecret,
                     ValidityTime,
                     Length,
                     Alphabet,
                     HashAlgorithm,
                     out var settings,
                     out _,
                     out Error
               ))
            {
                return false;
            }

            if (!TryChange(
                     login,
                     description,
                     GroupId,
                     // A new secret does not undo the binding that was
                     // asked for: that would be less than configured,
                     // quietly.
                     login => login with { TOTP = settings with { TLSChannelBinding = login.TOTP?.TLSChannelBinding ?? false } },
                     existed => existed
                                    ? $"The TOTP configuration of the {LoginNoun} '{login}' was changed: {settings}."
                                    : $"The {LoginNoun} '{login}' may now sign in to this {NodeNoun} with a one-time token.",
                     out Error,
                     out NotSaved
               ))
            {
                return false;
            }

            return true;

        }

        #endregion

        #region TrySetTOTPBinding(Id, Bound, out Error [, out NotSaved])

        /// <summary>
        /// Say whether the one-time token of a charging station has to be
        /// bound to the TLS session of its connection, leaving its secret and
        /// everything else about it alone.
        /// </summary>
        public Boolean TrySetTOTPBinding(User_Id                        Login,
                                         Boolean                           Bound,
                                         [NotNullWhen(false)] out String?  Error)

            => TrySetTOTPBinding(Login, Bound, out Error, out _);

        /// <summary>
        /// Say whether the one-time token of a charging station has to be
        /// bound to the TLS session of its connection - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetTOTPBinding(User_Id                        Login,
                                         Boolean                           Bound,
                                         [NotNullWhen(false)] out String?  Error,
                                         out Boolean                       NotSaved)

            => TryClear(Login,
                        login => login.HasTOTP,
                        login => login with { TOTP = login.TOTP! with { TLSChannelBinding = Bound } },
                        Bound
                            ? $"The one-time token of the {LoginNoun} '{Login}' has to be bound to the TLS session of its connection from now on: it signs in over HTTP/3 only."
                            : $"The one-time token of the {LoginNoun} '{Login}' need no longer be bound to the TLS session of its connection.",
                        $"The {LoginNoun} '{Login}' has no TOTP configuration to bind.",
                        out Error,
                        out NotSaved);

        #endregion

        #region TryClearPassword(Id, out Error [, out NotSaved]) / TryClearTOTP(Id, out Error [, out NotSaved])

        /// <summary>
        /// Take the password away from a charging station, leaving everything
        /// else about it alone.
        /// </summary>
        public Boolean TryClearPassword(User_Id                        Login,
                                        [NotNullWhen(false)] out String?  Error)

            => TryClearPassword(Login, out Error, out _);

        /// <summary>
        /// Take the password away from a charging station - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryClearPassword(User_Id                        Login,
                                        [NotNullWhen(false)] out String?  Error,
                                        out Boolean                       NotSaved)

            => TryClear(Login,
                        login => login.HasPassword,
                        login => login with { Password = null },
                        $"The {LoginNoun} '{Login}' can no longer sign in with a password.",
                        $"The {LoginNoun} '{Login}' has no password to take away.",
                        out Error,
                        out NotSaved);

        /// <summary>
        /// Take the one-time token away from a charging station, leaving
        /// everything else about it alone.
        /// </summary>
        public Boolean TryClearTOTP(User_Id                        Login,
                                    [NotNullWhen(false)] out String?  Error)

            => TryClearTOTP(Login, out Error, out _);

        /// <summary>
        /// Take the one-time token away from a charging station - and say
        /// whether a refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryClearTOTP(User_Id                        Login,
                                    [NotNullWhen(false)] out String?  Error,
                                    out Boolean                       NotSaved)

            => TryClear(Login,
                        login => login.HasTOTP,
                        login => login with { TOTP = null },
                        $"The {LoginNoun} '{Login}' can no longer sign in with a one-time token.",
                        $"The {LoginNoun} '{Login}' has no TOTP configuration to take away.",
                        out Error,
                        out NotSaved);

        #endregion

        #region (static) LoginOf(Text)

        /// <summary>
        /// The login the given text names - a user name a client signed in
        /// with, the path it asked for, the common name of its certificate -,
        /// or <see cref="NoLogin"/> where it names none.
        /// </summary>
        /// <param name="Text">A login as text.</param>
        public static User_Id LoginOf(String? Text)

            => User_Id.TryParse(Text) ?? NoLogin;

        #endregion

        #region TryAddSSHKey(Login, Line, Label, GroupId, Description, CreatedBy, out Key, out Error [, out NotSaved])

        /// <summary>
        /// Add a charging station, or give one that is already here an SSH key
        /// to sign in with for OCPP-over-SSH.
        /// </summary>
        /// <param name="Login">What the charging station calls itself in OCPP - and signs in to SSH as.</param>
        /// <param name="Line">Its public key, as one line of an authorized_keys file: "ssh-ed25519 AAAA... comment", options such as from= in front where wanted.</param>
        /// <param name="Label">What the key is called, if anything.</param>
        /// <param name="GroupId">The group it should belong to, or null for the one it is in already.</param>
        /// <param name="Description">What this station is, for whoever reads the list later - in as many languages as it is said in.</param>
        /// <param name="CreatedBy">Who added the key, if anybody said.</param>
        /// <param name="Key">The key, as it was added.</param>
        public Boolean TryAddSSHKey(User_Id                               Login,
                                    String?                               Line,
                                    String?                               Label,
                                    String?                               GroupId,
                                    I18NString?                           Description,
                                    String?                               CreatedBy,
                                    [NotNullWhen(true)]  out UserSSHKey?  Key,
                                    [NotNullWhen(false)] out String?      Error)

            => TryAddSSHKey(
                   Login,
                   Line,
                   Label,
                   GroupId,
                   Description,
                   CreatedBy,
                   out Key,
                   out Error,
                   out _
               );

        /// <summary>
        /// Add a charging station, or give one that is already here an SSH key
        /// - and say whether a refusal was the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// <b>One key is one charging station.</b> A key that already lets
        /// another station in is refused: the station signs in under its own
        /// name, and a key two stations share is a key either can use to be
        /// the other.
        ///
        /// <b>Its own key, not an authority.</b> A cert-authority line vouches
        /// for certificates rather than signing in itself; that is how a whole
        /// fleet of stations would be let in, and it is not what this is.
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryAddSSHKey(User_Id                               Login,
                                    String?                               Line,
                                    String?                               Label,
                                    String?                               GroupId,
                                    I18NString?                           Description,
                                    String?                               CreatedBy,
                                    [NotNullWhen(true)]  out UserSSHKey?  Key,
                                    [NotNullWhen(false)] out String?      Error,
                                    out Boolean                           NotSaved)
        {

            Key       = null;
            NotSaved  = false;

            if (!TryCheckLoginAndDescription(Login, Description, out _, out var description, out Error))
                return false;

            if (Line is null || Line.Trim().Length == 0)
            {
                Error = "An SSH public key is required, as one line of an authorized_keys file: \"ssh-ed25519 AAAA... comment\".";
                return false;
            }

            if (!UserSSHKey.TryCreate(Line, Label, TimeProvider.GetUtcNow(), CreatedBy, out var key, out var refused))
            {
                Error = refused;
                return false;
            }

            if (key.Key.IsCertAuthority)
            {
                Error = "That is a cert-authority line, which vouches for SSH certificates rather than signing in itself. " +
                        $"A {LoginNoun} signs in with a key of its own: give its public key.";
                return false;
            }

            lock (updateLock)
            {

                var existing = logins.GetValueOrDefault(Login);

                if (existing is null && logins.Count >= MaxStations)
                {
                    Error = $"At most {MaxStations} {LoginNoun}s may be listed here.";
                    return false;
                }

                var groupId = GroupId?.Trim().ToLowerInvariant() is { Length: > 0 } wanted
                                  ? wanted
                                  : existing?.GroupId ?? WebSocketLoginGroup.DefaultId;

                if (!groups.ContainsKey(groupId))
                {
                    Error = $"This {NodeNoun} has never heard of a login group called '{groupId}'.";
                    return false;
                }

                if (logins.Values.FirstOrDefault(login => login.Keys.Any(known => known.Fingerprint == key.Fingerprint)) is WebSocketLogin holder)
                {

                    Error = holder.Login == Login
                                ? $"The {LoginNoun} '{Login}' has the SSH key {key.Fingerprint} already."
                                : $"The SSH key {key.Fingerprint} already lets the {LoginNoun} '{holder.Login}' in. " +
                                   $"One key is one {LoginNoun}: give this one a key of its own.";

                    return false;

                }

                if (existing is not null && existing.Keys.Count >= WebSocketLogin.MaxSSHKeys)
                {
                    Error = $"A {LoginNoun} may have at most {WebSocketLogin.MaxSSHKeys} SSH keys; take an old one away first.";
                    return false;
                }

                logins[Login] = (existing ?? new WebSocketLogin(
                                                  Login,
                                                  groupId,
                                                  null,
                                                  null,
                                                  true,
                                                  TimeProvider.GetUtcNow(),
                                                  null
                                              )) with {
                                 GroupId      = groupId,
                                 Description  = description ?? existing?.Description,
                                 SSHKeys      = [ .. existing?.Keys ?? [], key ]
                             };

                if (!TrySave(out Error))
                {

                    NotSaved = true;

                    if (existing is not null)
                        logins[Login] = existing;
                    else
                        logins.Remove(Login);

                    return false;

                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    existing is not null
                        ? $"The {LoginNoun} '{Login}' may now sign in with the SSH key {key}."
                        : $"The {LoginNoun} '{Login}' may now sign in to this {NodeNoun}, with the SSH key {key}."
                );

            }

            OnChanged?.Invoke();

            Key = key;
            return true;

        }

        #endregion

        #region TryRemoveSSHKey(Id, Fingerprint, out Error [, out NotSaved])

        /// <summary>
        /// Take an SSH key away from a charging station, leaving everything
        /// else about it alone.
        /// </summary>
        /// <param name="Id">The charging station.</param>
        /// <param name="Fingerprint">The key's SHA-256 fingerprint, "SHA256:..." as OpenSSH writes it.</param>
        public Boolean TryRemoveSSHKey(User_Id                        Login,
                                       String                            Fingerprint,
                                       [NotNullWhen(false)] out String?  Error)

            => TryRemoveSSHKey(Login, Fingerprint, out Error, out _);

        /// <summary>
        /// Take an SSH key away from a charging station - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// A session the key opened ends: whoever serves OCPP-over-SSH is told
        /// through <see cref="OnChanged"/>, and asks every open session again.
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryRemoveSSHKey(User_Id                        Login,
                                       String                            Fingerprint,
                                       [NotNullWhen(false)] out String?  Error,
                                       out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                var key = login.Keys.FirstOrDefault(known => known.Fingerprint == Fingerprint);

                if (key is null)
                {
                    Error = $"The {LoginNoun} '{Login}' has no SSH key {Fingerprint}.";
                    return false;
                }

                var rest = login.Keys.Where(known => !ReferenceEquals(known, key)).ToArray();

                logins[Login] = login with { SSHKeys = rest.Length > 0 ? rest : null };

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(LogLevel.Notice, $"The {LoginNoun} '{Login}' can no longer sign in with the SSH key {key}.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TryAddKeyPin(Id, Pin, Label, GroupId, Description, AddedBy, out KeyPin, out Error [, out NotSaved])

        /// <summary>
        /// Add a charging station, or give one that is already here the key pin
        /// of a TLS client key to sign in with.
        /// </summary>
        /// <param name="Id">What the charging station calls itself in OCPP - the last segment of the URL it connects to.</param>
        /// <param name="Pin">The key pin: 64 hexadecimal digits, with or without colons, or "sha256//" and base64.</param>
        /// <param name="Label">What the key is called, if anything.</param>
        /// <param name="GroupId">The group it should belong to, or null for the one it is in already.</param>
        /// <param name="Description">What this station is, for whoever reads the list later - in as many languages as it is said in.</param>
        /// <param name="AddedBy">Who listed the pin, if anybody said.</param>
        /// <param name="KeyPin">The key pin, as it was listed.</param>
        public Boolean TryAddKeyPin(User_Id                               Login,
                                    String?                                  Pin,
                                    String?                                  Label,
                                    String?                                  GroupId,
                                    I18NString?                              Description,
                                    String?                                  AddedBy,
                                    [NotNullWhen(true)]  out LoginKeyPin?  KeyPin,
                                    [NotNullWhen(false)] out String?         Error)

            => TryAddKeyPin(Login, Pin, Label, GroupId, Description, AddedBy, out KeyPin, out Error, out _);

        /// <summary>
        /// Add a charging station, or give one that is already here a key pin -
        /// and say whether a refusal was the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// <b>One key is one charging station.</b> A key pin that already lets
        /// another station in is refused. With a key pin that is not a matter of
        /// tidiness: a certificate accepted by its key pin names nobody, and the
        /// station it is let in as is the one its pin is listed for - so a pin
        /// two stations shared would let either be the other.
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryAddKeyPin(User_Id                               Login,
                                    String?                                  Pin,
                                    String?                                  Label,
                                    String?                                  GroupId,
                                    I18NString?                              Description,
                                    String?                                  AddedBy,
                                    [NotNullWhen(true)]  out LoginKeyPin?  KeyPin,
                                    [NotNullWhen(false)] out String?         Error,
                                    out Boolean                              NotSaved)
        {

            KeyPin    = null;
            NotSaved  = false;

            if (!TryCheckLoginAndDescription(Login, Description, out _, out var description, out Error))
                return false;

            if (!LoginKeyPin.TryCreate(Pin, Label, TimeProvider.GetUtcNow(), AddedBy, out var keyPin, out Error))
                return false;

            lock (updateLock)
            {

                var existing = logins.GetValueOrDefault(Login);

                if (existing is null && logins.Count >= MaxStations)
                {
                    Error = $"At most {MaxStations} {LoginNoun}s may be listed here.";
                    return false;
                }

                var groupId = GroupId?.Trim().ToLowerInvariant() is { Length: > 0 } wanted
                                  ? wanted
                                  : existing?.GroupId ?? WebSocketLoginGroup.DefaultId;

                if (!groups.ContainsKey(groupId))
                {
                    Error = $"This {NodeNoun} has never heard of a login group called '{groupId}'.";
                    return false;
                }

                if (logins.Values.FirstOrDefault(login => login.FindKeyPin(keyPin.Pin) is not null) is WebSocketLogin holder)
                {
                    Error = holder.Login == Login
                                ? $"The {LoginNoun} '{Login}' has the key pin {keyPin.Pin} already."
                                : $"The key pin {keyPin.Pin} already lets the {LoginNoun} '{holder.Login}' in. " +
                                   $"One key is one {LoginNoun}: give this one a key of its own.";
                    return false;
                }

                if (existing is not null && existing.Pins.Count >= WebSocketLogin.MaxKeyPins)
                {
                    Error = $"A {LoginNoun} may have at most {WebSocketLogin.MaxKeyPins} key pins; take an old one away first.";
                    return false;
                }

                logins[Login] = (existing ?? new WebSocketLogin(
                                              Login,
                                              groupId,
                                              null,
                                              null,
                                              true,
                                              TimeProvider.GetUtcNow(),
                                              null
                                          )) with {
                                 GroupId  = groupId,
                                 Description  = description ?? existing?.Description,
                                 KeyPins  = [ .. existing?.Pins ?? [], keyPin ]
                             };

                if (!TrySave(out Error))
                {

                    NotSaved = true;

                    if (existing is not null)
                        logins[Login] = existing;
                    else
                        logins.Remove(Login);

                    return false;

                }

                pinsEverListed.Add(keyPin.Pin);

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    existing is not null
                        ? $"The {LoginNoun} '{Login}' may now sign in with the key pin {keyPin}."
                        : $"The {LoginNoun} '{Login}' may now sign in to this {NodeNoun}, with the key pin {keyPin}."
                );

            }

            OnChanged?.Invoke();

            KeyPin = keyPin;
            return true;

        }

        #endregion

        #region TryRemoveKeyPin(Id, Pin, out Error [, out NotSaved])

        /// <summary>
        /// Take a key pin away from a charging station, leaving everything else
        /// about it alone.
        /// </summary>
        /// <param name="Id">The charging station.</param>
        /// <param name="Pin">The key pin, in any of the notations <see cref="LoginKeyPin.TryCreate"/> reads.</param>
        public Boolean TryRemoveKeyPin(User_Id                        Login,
                                       String                            Pin,
                                       [NotNullWhen(false)] out String?  Error)

            => TryRemoveKeyPin(Login, Pin, out Error, out _);

        /// <summary>
        /// Take a key pin away from a charging station - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// A connection the pin let in stays open, as one a password let in
        /// does when the password is taken away: what is decided at the door is
        /// decided at the door. The next one is refused.
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryRemoveKeyPin(User_Id                        Login,
                                       String                            Pin,
                                       [NotNullWhen(false)] out String?  Error,
                                       out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            if (!org.GraphDefined.Vanaheimr.Hermod.KeyPin.TryParse(Pin, out var pin))
            {
                Error = $"'{Pin}' is not a key pin.";
                return false;
            }

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                var keyPin = login.FindKeyPin(pin);

                if (keyPin is null)
                {
                    Error = $"The {LoginNoun} '{Login}' has no key pin {pin}.";
                    return false;
                }

                var rest = login.Pins.Where(known => !ReferenceEquals(known, keyPin)).ToArray();

                logins[Login] = login with { KeyPins = rest.Length > 0 ? rest : null };

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(LogLevel.Notice, $"The {LoginNoun} '{Login}' can no longer sign in with the key pin {keyPin}.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TrySetEnabled(Id, Enabled, out Error [, out NotSaved])

        /// <summary>
        /// Let a charging station in, or stop letting it in, without throwing
        /// its credentials away.
        /// </summary>
        public Boolean TrySetEnabled(User_Id                        Login,
                                     Boolean                           Enabled,
                                     [NotNullWhen(false)] out String?  Error)

            => TrySetEnabled(Login, Enabled, out Error, out _);

        /// <summary>
        /// Let a charging station in, or stop letting it in - and say whether
        /// a refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetEnabled(User_Id                        Login,
                                     Boolean                           Enabled,
                                     [NotNullWhen(false)] out String?  Error,
                                     out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                if (login.Enabled == Enabled)
                    return true;

                logins[Login] = login with { Enabled = Enabled };

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    Enabled
                        ? $"The {LoginNoun} '{Login}' may sign in again."
                        : $"The {LoginNoun} '{Login}' may no longer sign in."
                );

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TrySetLocalController(Id, LocalController, out Error [, out NotSaved]) / IsLocalController(Id)

        /// <summary>
        /// Mark a login as a local controller's, which may send in the name of
        /// the charging stations behind it - or no longer.
        /// </summary>
        public Boolean TrySetLocalController(User_Id                        Login,
                                             Boolean                           LocalController,
                                             [NotNullWhen(false)] out String?  Error)

            => TrySetLocalController(Login, LocalController, out Error, out _);

        /// <summary>
        /// Mark a login as a local controller's, or no longer - and say whether
        /// a refusal was the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// In the overlay network a frame names whom it comes from itself: a
        /// login that is not marked sends in its own name alone, and a frame of
        /// it in another station's is dropped. A local controller's speaks for
        /// whatever station is behind it - which a station's must not, or any
        /// station could have the SSH key of another enrolled as its own.
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetLocalController(User_Id                        Login,
                                             Boolean                           LocalController,
                                             [NotNullWhen(false)] out String?  Error,
                                             out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                if (login.LocalController == LocalController)
                    return true;

                // A local controller's login is no gateway's: marked as the
                // one, it is no longer the other.
                logins[Login] = login with { LocalController = LocalController,
                                          Gateway         = login.Gateway && !LocalController };

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    LocalController
                        ? $"'{Login}' is a local controller now: in the overlay network it may send in the name of the charging stations behind it." +
                          (login.Gateway ? " It is no gateway any more." : "")
                        : $"'{Login}' is no local controller any more: it sends in its own name alone."
                );

            }

            OnChanged?.Invoke();

            return true;

        }

        /// <summary>
        /// Whether the given login is a local controller's.
        /// </summary>
        public Boolean IsLocalController(User_Id Login)
        {
            lock (updateLock)
            {
                return logins.TryGetValue(Login, out var login) && login.LocalController;
            }
        }

        #endregion

        #region TrySetGateway(Id, Gateway, out Error [, out NotSaved]) / IsGateway(Id) / SpeaksForOthers(Id)

        /// <summary>
        /// Mark a login as a gateway's, which may send in the name of the
        /// charging stations behind it - or no longer.
        /// </summary>
        public Boolean TrySetGateway(User_Id                        Login,
                                     Boolean                           Gateway,
                                     [NotNullWhen(false)] out String?  Error)

            => TrySetGateway(Login, Gateway, out Error, out _);

        /// <summary>
        /// Mark a login as a gateway's, or no longer - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// To this node a gateway is what a local controller is: a node in
        /// the overlay network with charging stations behind it, which sends
        /// in their names. It is marked as what it is all the same, so that
        /// the list, the log and a connection that connects to it say so. A login
        /// marked as a gateway's is no local controller's any more.
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetGateway(User_Id                        Login,
                                     Boolean                           Gateway,
                                     [NotNullWhen(false)] out String?  Error,
                                     out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                if (login.Gateway == Gateway)
                    return true;

                logins[Login] = login with { Gateway          = Gateway,
                                          LocalController  = login.LocalController && !Gateway };

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    Gateway
                        ? $"'{Login}' is a gateway now: in the overlay network it may send in the name of the charging stations behind it." +
                          (login.LocalController ? " It is no local controller any more." : "")
                        : $"'{Login}' is no gateway any more: it sends in its own name alone."
                );

            }

            OnChanged?.Invoke();

            return true;

        }

        /// <summary>
        /// Whether the given login is a gateway's.
        /// </summary>
        public Boolean IsGateway(User_Id Login)
        {
            lock (updateLock)
            {
                return logins.TryGetValue(Login, out var login) && login.Gateway;
            }
        }

        /// <summary>
        /// Whether the given login may send in the name of the charging
        /// stations behind it: a local controller's, or a gateway's.
        /// </summary>
        public Boolean SpeaksForOthers(User_Id Login)
        {
            lock (updateLock)
            {
                return logins.TryGetValue(Login, out var login) && login.SpeaksForOthers;
            }
        }

        #endregion

        #region KnownPeerIds

        /// <summary>
        /// The peers of the node these logins are the logins of, asked when a
        /// target is written: a target that names a peer nobody has heard of
        /// is refused rather than kept to fail on the first message. Null:
        /// every peer is taken as given.
        /// </summary>
        /// <remarks>
        /// Asked, not told once: peers come and go while the node runs. A peer
        /// removed later stays in the targets that named it, and is passed
        /// over as one that is not connected - see <see cref="ForwardingTarget"/>.
        /// </remarks>
        public Func<IEnumerable<String>>? KnownPeerIds { get; set; }

        #endregion

        #region TryAddOrUpdateTarget(Id, PeerIds, Description, out Error [, out NotSaved])

        /// <summary>
        /// Make a forwarding target, or change the peers it tries and their order.
        /// </summary>
        public Boolean TryAddOrUpdateTarget(String?                           Id,
                                            IEnumerable<String>?              PeerIds,
                                            I18NString?                       Description,
                                            [NotNullWhen(false)] out String?  Error)

            => TryAddOrUpdateTarget(Id, PeerIds, Description, out Error, out _);

        /// <summary>
        /// Make a forwarding target, or change it - and say whether a refusal
        /// was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryAddOrUpdateTarget(String?                           Id,
                                            IEnumerable<String>?              PeerIds,
                                            I18NString?                       Description,
                                            [NotNullWhen(false)] out String?  Error,
                                            out Boolean                       NotSaved)
        {

            NotSaved = false;

            if (!ForwardingTarget.TryCheckId(Id, out var id, out Error))
                return false;

            var peers = (PeerIds ?? []).Select(peer => peer?.Trim() ?? "").ToArray();

            if (peers.Length == 0 || peers.Length > ForwardingTarget.MaxPeers || peers.Any(String.IsNullOrEmpty))
            {
                Error = $"A target tries 1 to {ForwardingTarget.MaxPeers} peers.";
                return false;
            }

            if (peers.Distinct(StringComparer.Ordinal).Count() != peers.Length)
            {
                Error = "A target names each of its peers once.";
                return false;
            }

            if (KnownPeerIds?.Invoke().ToHashSet(StringComparer.Ordinal) is HashSet<String> known &&
                peers.FirstOrDefault(peer => !known.Contains(peer)) is String unknown)
            {
                Error = $"This {NodeNoun} has no peer called '{unknown}'.";
                return false;
            }

            I18NString? description = null;

            if (Description is not null &&
                !Descriptions.TryCheckRequired(Description, ForwardingTarget.MaxDescriptionLength, "", out description, out _))
            {
                Error = $"A target is described in 1 to {ForwardingTarget.MaxDescriptionLength} characters, in each language it is said in.";
                return false;
            }

            lock (updateLock)
            {

                targets.TryGetValue(id, out var existing);

                if (existing is null && targets.Count >= ForwardingTarget.MaxTargets)
                {
                    Error = $"This {NodeNoun} holds at most {ForwardingTarget.MaxTargets} targets.";
                    return false;
                }

                targets[id] = new ForwardingTarget(
                                  id,
                                  peers,
                                  existing?.AddedAt ?? TimeProvider.GetUtcNow(),
                                  description ?? existing?.Description
                              );

                if (!TrySave(out Error))
                {

                    NotSaved = true;

                    if (existing is not null)
                        targets[id] = existing;
                    else
                        targets.Remove(id);

                    return false;

                }

                OnNotice?.Invoke(LogLevel.Notice, $"The target '{id}' {(existing is null ? "was made" : "was changed")}: it forwards to {String.Join(", then ", peers.Select(peer => $"'{peer}'"))}.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TryRemoveTarget(Id, out Error [, out NotSaved])

        /// <summary>
        /// Forget a forwarding target no login names.
        /// </summary>
        /// <remarks>
        /// A target that logins name is not removed and its logins are not
        /// handed to the back end in charge behind somebody's back: that would
        /// send their stations to a CSMS nobody chose for them. Whoever wants
        /// the target gone gives its logins another one first.
        /// </remarks>
        public Boolean TryRemoveTarget(String                            Id,
                                       [NotNullWhen(false)] out String?  Error)

            => TryRemoveTarget(Id, out Error, out _);

        /// <summary>
        /// Forget a forwarding target no login names - and say whether a
        /// refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TryRemoveTarget(String                            Id,
                                       [NotNullWhen(false)] out String?  Error,
                                       out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            var id = Id?.Trim().ToLowerInvariant() ?? "";

            lock (updateLock)
            {

                if (!targets.TryGetValue(id, out var target))
                {
                    Error = $"This {NodeNoun} has never heard of a target called '{Id}'.";
                    return false;
                }

                var naming = logins.Values.Count(login => login.Target == id);

                if (naming > 0)
                {
                    Error = $"The target '{id}' is still named by {naming} login(s). Give them another target first.";
                    return false;
                }

                targets.Remove(id);

                if (!TrySave(out Error))
                {
                    NotSaved     = true;
                    targets[id]  = target;
                    return false;
                }

                OnNotice?.Invoke(LogLevel.Notice, $"The target '{id}' was removed.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region TrySetTarget(Login, TargetId, out Error [, out NotSaved]) / TargetOf(Login) / GetTarget(Id)

        /// <summary>
        /// Give a charging station the forwarding target what it sends up goes
        /// to - or none, for the back end in charge of this node.
        /// </summary>
        public Boolean TrySetTarget(User_Id                           Login,
                                    String?                           TargetId,
                                    [NotNullWhen(false)] out String?  Error)

            => TrySetTarget(Login, TargetId, out Error, out _);

        /// <summary>
        /// Give a charging station a forwarding target, or none - and say
        /// whether a refusal was the file's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the file could not be written: see <see cref="TryRemove(User_Id, out String?, out Boolean)"/>.</param>
        public Boolean TrySetTarget(User_Id                           Login,
                                    String?                           TargetId,
                                    [NotNullWhen(false)] out String?  Error,
                                    out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            var targetId = TargetId?.Trim().ToLowerInvariant() is { Length: > 0 } given ? given : null;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                if (targetId is not null && !targets.ContainsKey(targetId))
                {
                    Error = $"This {NodeNoun} has never heard of a target called '{TargetId}'.";
                    return false;
                }

                if (login.Target == targetId)
                    return true;

                logins[Login] = login with { Target = targetId };

                if (!TrySave(out Error))
                {
                    NotSaved       = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    targetId is not null
                        ? $"What the {LoginNoun} '{Login}' sends up goes to the target '{targetId}' now."
                        : $"What the {LoginNoun} '{Login}' sends up goes to the back end in charge of this {NodeNoun} now."
                );

            }

            OnChanged?.Invoke();

            return true;

        }

        /// <summary>
        /// The forwarding target of the given login, or null where it names
        /// none - or is no login at all.
        /// </summary>
        public ForwardingTarget? TargetOf(User_Id Login)
        {
            lock (updateLock)
            {
                return logins.TryGetValue(Login, out var login) &&
                       login.Target is String targetId &&
                       targets.TryGetValue(targetId, out var target)
                           ? target
                           : null;
            }
        }

        /// <summary>
        /// The target of the given identification, or null.
        /// </summary>
        public ForwardingTarget? GetTarget(String Id)
        {
            lock (updateLock)
            {
                return targets.GetValueOrDefault(Id?.Trim().ToLowerInvariant() ?? "");
            }
        }

        #endregion


        #region TryRemove(Id, out Error [, out NotSaved])

        /// <summary>
        /// Forget a charging station entirely.
        /// </summary>
        public Boolean TryRemove(User_Id                        Login,
                                 [NotNullWhen(false)] out String?  Error)

            => TryRemove(Login, out Error, out _);

        /// <summary>
        /// Forget a charging station entirely - and say whether a refusal was
        /// the file's rather than the change's.
        /// </summary>
        /// <remarks>
        /// Every change here says so, where it may be refused for two reasons
        /// that are answered differently: something about it was wrong - no
        /// such station, a password too short - or it was fine and the file
        /// could not be written, the change put back as it was. The web
        /// interface answered both with the 404 or 400 of the first, and a
        /// disk that was full was a station "not found".
        /// </remarks>
        /// <param name="NotSaved">True where the file could not be written, and the change was undone.</param>
        public Boolean TryRemove(User_Id                        Login,
                                 [NotNullWhen(false)] out String?  Error,
                                 out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                logins.Remove(Login);

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(LogLevel.Notice, $"The {LoginNoun} '{Login}' was removed; it can no longer sign in.");

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion


        #region Verify(Id, Password)

        /// <summary>
        /// Whether this pair may sign in.
        /// </summary>
        /// <remarks>
        /// A station that is switched off is refused as surely as one that was
        /// never here; the two are not told apart on the way out, because
        /// whoever is asking has no business learning which identifications
        /// exist. What the group allows is decided by the caller, which knows
        /// what the transport looked like.
        /// </remarks>
        public Boolean Verify(User_Id Login, String Password)
        {

            WebSocketLogin? login;

            lock (updateLock)
                login = logins.GetValueOrDefault(Login);

            // Still hashed when there is nothing to compare against, so that an
            // unknown identification does not answer faster than a known one.
            // A fixed word rather than the one that was sent: the work is the
            // same either way, and hashing what arrived would mean an empty
            // password throws here instead of being refused.
            if (login is null || !login.Enabled || login.Password is not SecurePassword password)
            {
                SecurePassword.Create(TimingEqualiser).Verify(TimingEqualiser);
                return false;
            }

            return password.Verify(Password);

        }

        #endregion

        #region VerifyTOTP(Id, Token)

        /// <summary>
        /// Whether this is the one-time token this charging station should be
        /// showing right now.
        /// </summary>
        /// <remarks>
        /// The same silence as <see cref="Verify"/>, and the same equalising:
        /// a token is derived for an identification that is not here either,
        /// so that the answer takes the same shape of time whether or not the
        /// station exists.
        /// </remarks>
        /// <param name="Bound">Whether the token was sent as one bound to the TLS session of its connection.</param>
        /// <param name="TLSExporterMaterial">The keying material of the connection it arrived on, or null where its TLS exports none.</param>
        public Boolean VerifyTOTP(User_Id Login,
                                  String   Token,
                                  Boolean  Bound                = false,
                                  Byte[]?  TLSExporterMaterial  = null)
        {

            WebSocketLogin? login;

            lock (updateLock)
                login = logins.GetValueOrDefault(Login);

            if (login is null || !login.Enabled || login.TOTP is not TOTPSettings settings)
            {

                TOTPGenerator.GenerateTOTPs(
                    TOTPTimingEqualiser,
                    TOTPSettings.DefaultValidityTime,
                    TOTPSettings.DefaultLength,
                    TOTPSettings.DefaultAlphabet,
                    TimeProvider.GetUtcNow(),
                    null,
                    TOTPHashAlgorithm.SHA256
                );

                return false;

            }

            return settings.Matches(Token, TimeProvider.GetUtcNow(), Bound, TLSExporterMaterial);

        }

        #endregion

        #region FindSSHKey(Id, PublicKeyBlob, At)

        /// <summary>
        /// The charging station of this identification and its key a client
        /// offers, where the two may sign in at the given time: the station
        /// switched on, and the key one of its own, switched on and valid.
        /// Null where they may not.
        /// </summary>
        /// <remarks>
        /// What the group allows is decided by the caller, as for
        /// <see cref="Verify"/>. No hashing to equalise here: a public key
        /// proves itself by a signature the SSH server checks, and nothing
        /// about this lookup takes longer for a station that exists.
        /// </remarks>
        /// <param name="Id">What the station signs in as.</param>
        /// <param name="PublicKeyBlob">The public key blob the client offers.</param>
        /// <param name="At">When the client signs in.</param>
        public (WebSocketLogin Login, UserSSHKey Key)? FindSSHKey(User_Id             Login,
                                                                         ReadOnlySpan<Byte>  PublicKeyBlob,
                                                                         DateTimeOffset      At)
        {

            WebSocketLogin? login;

            lock (updateLock)
                login = logins.GetValueOrDefault(Login);

            if (login is null || !login.Enabled)
                return null;

            return login.FindSSHKey(PublicKeyBlob, At) is UserSSHKey key
                       ? (login, key)
                       : null;

        }

        #endregion

        #region FindKeyPin(KeyPin) / WasEverListed(KeyPin)

        /// <summary>
        /// The charging station the given key pin is listed for, switched on or
        /// not - or null where it is nobody's.
        /// </summary>
        /// <remarks>
        /// Not narrowed to the stations that may sign in, unlike
        /// <see cref="FindSSHKey"/>: a pin of a station that is switched off is
        /// still that station's pin, and a certificate with its key is refused
        /// as that station - not taken for a stranger's whose common name then
        /// decides who it is. What the station and its group allow is the
        /// caller's to ask.
        /// </remarks>
        /// <param name="KeyPin">The key pin of the key a client presented.</param>
        public WebSocketLogin? FindKeyPin(KeyPin KeyPin)
        {
            lock (updateLock)
                return logins.Values.FirstOrDefault(login => login.FindKeyPin(KeyPin) is not null);
        }

        /// <summary>
        /// Whether the given key pin was listed for a charging station at any
        /// time since this store was made, whether or not it still is.
        /// </summary>
        /// <remarks>
        /// For the moment between a TLS handshake and the WebSocket upgrade that
        /// follows it, which the client decides the length of. A certificate let
        /// through the handshake by its key pin skipped the accepted chains; if
        /// the pin is taken away before the upgrade arrives, the certificate
        /// must not be read as one that went through them. Whoever asks this
        /// holds such a certificate against the chains once more.
        /// </remarks>
        /// <param name="KeyPin">A key pin.</param>
        public Boolean WasEverListed(KeyPin KeyPin)
        {
            lock (updateLock)
                return pinsEverListed.Contains(KeyPin);
        }

        #endregion

        #region TryGet(Login, out WebSocketLogin) / GroupOf(WebSocketLogin)

        /// <summary>
        /// One charging station, when it is listed here.
        /// </summary>
        /// <param name="Login">The login of the charging station.</param>
        /// <param name="WebSocketLogin">Its entry.</param>
        public Boolean TryGet(User_Id                                  Login,
                              [NotNullWhen(true)] out WebSocketLogin?  WebSocketLogin)
        {
            lock (updateLock)
            {
                WebSocketLogin = logins.GetValueOrDefault(Login);
                return WebSocketLogin is not null;
            }
        }

        /// <summary>
        /// The group a login belongs to.
        /// </summary>
        /// <remarks>
        /// Never null for a login that came from this store: a login whose
        /// group is missing is refused while the file is read. A login from
        /// anywhere else falls back to nothing, and the caller must treat that
        /// as "not allowed" rather than as "no restrictions".
        /// </remarks>
        public WebSocketLoginGroup? GroupOf(WebSocketLogin Login)
        {
            lock (updateLock)
                return groups.GetValueOrDefault(Login.GroupId);
        }

        /// <summary>
        /// One group by its identification.
        /// </summary>
        public WebSocketLoginGroup? GetGroup(String Id)
        {
            lock (updateLock)
                return groups.GetValueOrDefault(Id?.Trim().ToLowerInvariant() ?? "");
        }

        #endregion

        #region SecurePasswords()

        /// <summary>
        /// The stations that may sign in with a password, in the shape the
        /// WebSocket server keeps them in.
        /// </summary>
        /// <remarks>
        /// Only those whose group still allows a password at all - the server
        /// keeps this list to answer with, and a station whose group has had
        /// Basic Authentication taken away should not be in it.
        /// </remarks>
        public IReadOnlyDictionary<String, SecurePassword> SecurePasswords()
        {
            lock (updateLock)
                return logins.Values.Where(login => login.Enabled &&
                                                    login.Password.HasValue &&
                                                    groups.GetValueOrDefault(login.GroupId)?.Allows(AuthMethod.Basic) == true).
                                     ToDictionary(login => login.Login.ToString(), login => login.Password!.Value, StringComparer.OrdinalIgnoreCase);
        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The charging stations and their groups, as the web interface reads
        /// them.
        /// </summary>
        /// <remarks>
        /// Without the hashes and without the shared secrets. A page showing
        /// who may sign in is a page that whoever may read the configuration
        /// may open; a PBKDF2 hash on a screen is a hash somebody can take away
        /// and attack offline, and a shared secret on a screen is a charging
        /// station somebody can impersonate outright.
        /// </remarks>
        /// <param name="WithTargets">Whether the forwarding targets are said as well: where the logins are a node's charging stations, which are forwarded.</param>
        public JObject ToJSON(Boolean WithTargets = false)
        {

            lock (updateLock)
            {

                var json = new JObject(

                    new JProperty("file",               Path),
                    new JProperty("enabled",            logins.Values.Count(login => login.Enabled &&
                                                                                     groups.GetValueOrDefault(login.GroupId)?.Enabled == true)),
                    new JProperty("maxLogins",          MaxStations),
                    new JProperty("maxGroups",          WebSocketLoginGroup.MaxGroups),
                    new JProperty("minPasswordLength",  MinPasswordLength),
                    new JProperty("minSecretLength",    TOTPSettings.MinSecretLength),
                    new JProperty("defaultGroup",       WebSocketLoginGroup.DefaultId),

                    new JProperty("groups",             new JArray(
                        groups.Values.OrderByDescending(group => group.IsBuiltIn).
                                      ThenBy          (group => group.Id, StringComparer.OrdinalIgnoreCase).
                                      Select          (group => group.ToJSON(logins.Values.Count(login => login.GroupId == group.Id)))
                    )),

                    new JProperty("logins",             new JArray(
                        logins.Values.OrderBy(login => login.Login).
                                      Select (login => login.ToJSON())
                    ))

                );

                if (WithTargets)
                {

                    json.Add("maxTargets",      ForwardingTarget.MaxTargets);
                    json.Add("maxTargetPeers",  ForwardingTarget.MaxPeers);

                    json.Add("targets",         new JArray(
                        targets.Values.OrderBy(target => target.Id, StringComparer.Ordinal).
                                       Select (target => target.ToJSON(logins.Values.Count(login => login.Target == target.Id)))
                    ));

                }

                return json;

            }

        }

        #endregion


        #region (private) TryCheckLoginAndDescription(...) / TryChange(...) / TryClear(...)

        /// <summary>
        /// What every way of adding a charging station has to check first.
        /// </summary>
        private Boolean TryCheckLoginAndDescription(User_Id                           Login,
                                                    I18NString?                       Description,
                                                    out User_Id                       CheckedLogin,
                                                    out I18NString?                   CheckedDescription,
                                                    [NotNullWhen(false)] out String?  Error)
        {

            CheckedLogin        = Login;
            CheckedDescription  = null;
            Error               = null;

            if (CheckedLogin.Length == 0)
            {
                Error = $"A {LoginNoun} needs a login it signs in with.";
                return false;
            }

            if (CheckedLogin.Length > MaxIdLength)
            {
                Error = $"A {LoginNoun} login may be at most {MaxIdLength} characters long.";
                return false;
            }

            if (!Descriptions.TryCheck(Description, MaxDescriptionLength, out CheckedDescription, out Error))
                return false;

            return true;

        }

        /// <summary>
        /// Add a charging station or change one, write the file, and put
        /// everything back where it was when the file could not be written.
        /// </summary>
        private Boolean TryChange(User_Id                               Login,
                                  I18NString?                           Description,
                                  String?                               GroupId,
                                  Func<WebSocketLogin, WebSocketLogin>  Change,
                                  Func<Boolean, String>                 Notice,
                                  [NotNullWhen(false)] out String?      Error,
                                  out Boolean                           NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.ContainsKey(Login) && logins.Count >= MaxStations)
                {
                    Error = $"At most {MaxStations} {LoginNoun}s may be listed here.";
                    return false;
                }

                var existing  = logins.GetValueOrDefault(Login);

                var groupId   = GroupId?.Trim().ToLowerInvariant() is { Length: > 0 } wanted
                                    ? wanted
                                    : existing?.GroupId ?? WebSocketLoginGroup.DefaultId;

                if (!groups.ContainsKey(groupId))
                {
                    Error = $"This {NodeNoun} has never heard of a login group called '{groupId}'.";
                    return false;
                }

                logins[Login] = Change(
                                    existing ?? new WebSocketLogin(
                                                    Login,
                                                    groupId,
                                                    null,
                                                    null,
                                                    true,
                                                    TimeProvider.GetUtcNow(),
                                                    null
                                                )
                                ) with {
                                    GroupId  = groupId,
                                    Description  = Description ?? existing?.Description
                                };

                if (!TrySave(out Error))
                {

                    NotSaved = true;

                    if (existing is not null)
                        logins[Login] = existing;
                    else
                        logins.Remove(Login);

                    return false;

                }

                OnNotice?.Invoke(LogLevel.Notice, Notice(existing is not null));

            }

            OnChanged?.Invoke();

            return true;

        }

        /// <summary>
        /// Take one credential away from a charging station.
        /// </summary>
        private Boolean TryClear(User_Id                                Login,
                                 Func<WebSocketLogin, Boolean>         Has,
                                 Func<WebSocketLogin, WebSocketLogin>  Change,
                                 String                                Notice,
                                 String                                NothingThere,
                                 [NotNullWhen(false)] out String?      Error,
                                 out Boolean                           NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            lock (updateLock)
            {

                if (!logins.TryGetValue(Login, out var login))
                {
                    Error = $"This {NodeNoun} has never heard of a {LoginNoun} called '{Login}'.";
                    return false;
                }

                if (!Has(login))
                {
                    Error = NothingThere;
                    return false;
                }

                logins[Login] = Change(login);

                if (!TrySave(out Error))
                {
                    NotSaved    = true;
                    logins[Login]  = login;
                    return false;
                }

                OnNotice?.Invoke(
                    LogLevel.Notice,
                    Notice
                );

            }

            OnChanged?.Invoke();

            return true;

        }

        #endregion

        #region (private) TrySave(out Error)

        /// <summary>
        /// Write the file, readable by its owner alone.
        /// </summary>
        private Boolean TrySave([NotNullWhen(false)] out String? Error)
        {

            Error = null;

            try
            {

                var directory = System.IO.Path.GetDirectoryName(Path);

                if (!String.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);

                var temporary = Path + ".tmp";

                OwnerOnlyFile.Write(
                    temporary,
                    new JObject(

                        new JProperty("groups",   new JArray(
                            groups.Values.OrderByDescending(group => group.IsBuiltIn).
                                          ThenBy          (group => group.Id, StringComparer.OrdinalIgnoreCase).
                                          Select          (group => group.ToJSON())
                        )),

                        new JProperty("targets",  new JArray(
                            targets.Values.OrderBy(target => target.Id, StringComparer.Ordinal).
                                           Select (target => target.ToJSON())
                        )),

                        new JProperty("logins", new JArray(
                            logins.Values.OrderBy(login => login.Login).
                                          Select (login => login.ToJSON(WithSecrets: true))
                        ))

                    ).ToString(Formatting.Indented) + Environment.NewLine,

                    problem => OnNotice?.Invoke(LogLevel.Warning, problem)
                );

                File.Move(temporary, Path, overwrite: true);

                return true;

            }
            catch (Exception e)
            {
                Error = $"'{Path}' could not be written: {e.Message}";
                return false;
            }

        }

        #endregion

        #region (override) ToString()

        public override String ToString()
        {
            lock (updateLock)
                return $"{logins.Values.Count(login => login.Enabled)} of {logins.Count} {LoginNoun}(s) " +
                       $"in {groups.Count} group(s) may sign in";
        }

        #endregion

    }

}
