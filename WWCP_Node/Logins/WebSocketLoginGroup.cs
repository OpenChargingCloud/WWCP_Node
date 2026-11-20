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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Logins
{

    /// <summary>
    /// A way a WebSocket login can prove who it is.
    /// </summary>
    /// <remarks>
    /// Deliberately not the same thing as a way a client may authenticate at
    /// the server (<see cref="WebSocketClientAuthentication"/>), which says
    /// what the transport looks like: HTTP authentication without TLS or over
    /// it, or a TLS client certificate - OCPP's security profiles 1, 2 and 3.
    /// TOTP is not in OCPP at all; it is what this node accepts beside them.
    /// So a group says both: which of these it accepts, and over which
    /// transports.
    ///
    /// An SSH key is no such transport either: messages over SSH are a
    /// transport of their own, encrypted and authenticated by SSH, so a
    /// group's ways of client authentication are not asked of a login that
    /// signs in with one - only whether the group accepts SSH keys.
    ///
    /// A key pin is a TLS client key, so it comes in as a TLS client
    /// certificate - and is a way in of its own all the same, because it
    /// vouches for one key of one login rather than for whatever a
    /// certificate authority signed (EVQI Transport, key pins, 5.8).
    /// </remarks>
    public enum AuthMethod
    {

        /// <summary>
        /// HTTP Basic Authentication: the identification and a password.
        /// </summary>
        Basic,

        /// <summary>
        /// HTTP TOTP Authentication: the identification and a token derived
        /// from a shared secret and the time.
        /// </summary>
        TOTP,

        /// <summary>
        /// A TLS client certificate, held against the accepted chains.
        /// </summary>
        Certificate,

        /// <summary>
        /// An SSH public key of the charging station, for OCPP over SSH: the
        /// station signs in to this controller's SSH server under its
        /// identification.
        /// </summary>
        SSHKey,

        /// <summary>
        /// The key pin of the key of a TLS client certificate: SHA-256 over its
        /// SubjectPublicKeyInfo, listed for the station. Chain, name and dates
        /// of the certificate are not looked at, and its common name names
        /// nobody - the station is the one the pin is listed for.
        /// </summary>
        KeyPin

    }


    /// <summary>
    /// Extension methods for authentication methods.
    /// </summary>
    public static class AuthMethodExtensions
    {

        /// <summary>
        /// What this method is called in the configuration file and over HTTP.
        /// </summary>
        public static String AsText(this AuthMethod Method)

            => Method switch {
                   AuthMethod.Basic        => "basic",
                   AuthMethod.TOTP         => "totp",
                   AuthMethod.Certificate  => "certificate",
                   AuthMethod.SSHKey       => "sshkey",
                   AuthMethod.KeyPin       => "keypin",
                   _                       => Method.ToString().ToLowerInvariant()
               };

        /// <summary>
        /// Read one back, or null when it is not a method this controller knows.
        /// </summary>
        public static AuthMethod? TryParseAuthMethod(String? Text)

            => Text?.Trim().ToLowerInvariant() switch {
                   "basic"        => AuthMethod.Basic,
                   "totp"         => AuthMethod.TOTP,
                   "certificate"  => AuthMethod.Certificate,
                   "sshkey"       => AuthMethod.SSHKey,
                   "keypin"       => AuthMethod.KeyPin,
                   _              => null
               };

    }


    /// <summary>
    /// A group of logins, and what its members are allowed to do.
    /// </summary>
    /// <remarks>
    /// <b>The group decides, the login belongs.</b> Which ways of signing in
    /// are acceptable, and over which ways of client authentication, is said
    /// once for a whole group rather than on every login. That is the point of
    /// it: a site with forty charging stations in a field test can be stopped
    /// in one move, and a group that is only ever allowed in with a TLS client
    /// certificate stays that way when somebody adds the forty-first.
    ///
    /// <b>It can only narrow.</b> Everything here is held against the settings
    /// of the server as a whole, and the smaller of the two wins. A group that
    /// allows HTTP authentication without TLS on a server which does not
    /// allows nothing; the group cannot hand out what the server does not
    /// offer.
    ///
    /// <b>Empty means nobody.</b> A group with no authentication method left
    /// lets nobody in. That is the same choice the accepted certificate chains
    /// make, and for the same reason: a list that means "everything" when it is
    /// empty is a list that opens the door when somebody deletes the last row.
    /// </remarks>
    /// <param name="Id">What the group is called, in the file and in every login that points at it.</param>
    /// <param name="Name">What it is called on screen.</param>
    /// <param name="Enabled">Whether its members may sign in at the moment.</param>
    /// <param name="AuthMethods">The ways its members may prove who they are.</param>
    /// <param name="ClientAuthentication">The ways of client authentication its members may come in with - OCPP's security profiles.</param>
    /// <param name="AddedAt">When the group was made.</param>
    /// <param name="Description">What it is for, for whoever reads the list later - in as many languages as it is said in.</param>
    /// <param name="SSHChannels">What its members have over their SSH connection besides OCPP, of <see cref="KnownSSHChannels"/>: their time, their names. Null or none: OCPP alone.</param>
    public sealed record WebSocketLoginGroup(String                                       Id,
                                             String                                       Name,
                                             Boolean                                      Enabled,
                                             IReadOnlySet<AuthMethod>                     AuthMethods,
                                             IReadOnlySet<WebSocketClientAuthentication>  ClientAuthentication,
                                             DateTimeOffset                               AddedAt,
                                             I18NString?                                  Description,
                                             IReadOnlySet<String>?                        SSHChannels = null)
    {

        #region Data

        /// <summary>
        /// The group every login belongs to when nobody said otherwise. It
        /// cannot be removed, because a login without a group would be a login
        /// nothing decides about.
        /// </summary>
        public const String  DefaultId      = "default";

        /// <summary>
        /// The longest a group identification may be.
        /// </summary>
        public const Int32   MaxIdLength    = 32;

        /// <summary>
        /// The longest a group name may be.
        /// </summary>
        public const Int32   MaxNameLength  = 60;

        /// <summary>
        /// The longest a description of a group may be, in each language.
        /// </summary>
        public const Int32   MaxDescriptionLength  = 200;

        /// <summary>
        /// How many groups may be listed.
        /// </summary>
        public const Int32   MaxGroups      = 100;

        /// <summary>
        /// NTS key establishment over SSH, of the white paper "NTS Key
        /// Establishment over SSH": a station has its time over the SSH
        /// connection it has anyway.
        /// </summary>
        public const String  NTSKE          = "ntske/1@open.charging.cloud";

        /// <summary>
        /// DNS over SSH, of the white paper "DNS over SSH": a station has its
        /// names over the SSH connection it has anyway.
        /// </summary>
        public const String  DNS            = "dns@open.charging.cloud";

        /// <summary>
        /// What a group may give its members over their SSH connection besides
        /// OCPP. Nothing else: the command line, SFTP and the subsystems of the
        /// accounts are no station's, whatever a group says.
        /// </summary>
        public static readonly IReadOnlySet<String> KnownSSHChannels = new HashSet<String>(StringComparer.Ordinal) { NTSKE, DNS };

        private static readonly IReadOnlySet<String> noChannels = new HashSet<String>(StringComparer.Ordinal);

        #endregion

        #region Properties

        /// <summary>
        /// Whether this is the group that is always there.
        /// </summary>
        public Boolean IsBuiltIn
            => Id == DefaultId;

        /// <summary>
        /// What its members have over their SSH connection besides OCPP - where
        /// the node serves it, and while the group is switched on.
        /// </summary>
        /// <remarks>
        /// A grant of its own, as the white papers have it: a key admitted for
        /// OCPP does not obtain cookies or resolve names by itself. A group
        /// written before there was such a thing gives none.
        /// </remarks>
        public IReadOnlySet<String> Channels
            => SSHChannels ?? noChannels;

        #endregion


        #region (static) Default(Now)

        /// <summary>
        /// The group a controller that has never heard of groups behaves like:
        /// everything its server allows, allowed.
        /// </summary>
        /// <remarks>
        /// Deliberately permissive, and only here. A charging station that
        /// signed in yesterday must sign in today as well, and the file of a
        /// controller updated to a version that knows about groups says nothing
        /// about them. So the group those logins land in has to mean "as
        /// before" - and the narrowing happens where somebody decided it, not
        /// behind their back.
        ///
        /// SSH keys among them, as everything else this controller accepts: a
        /// key does nothing until somebody gives a station one and switches
        /// OCPP over SSH on. A default group that a file written before SSH
        /// keys existed holds is that file's, and stays without them until
        /// somebody adds them - the file said what it accepts.
        ///
        /// Key pins the same way: a pin does nothing until somebody lists one
        /// for a station, and a default group written before key pins existed
        /// stays without them until somebody adds them.
        /// </remarks>
        public static WebSocketLoginGroup Default(DateTimeOffset Now)

            => new (DefaultId,
                    "Default",
                    true,
                    new HashSet<AuthMethod> { AuthMethod.Basic, AuthMethod.TOTP, AuthMethod.Certificate, AuthMethod.SSHKey, AuthMethod.KeyPin },
                    new HashSet<WebSocketClientAuthentication>(WebSocketClientAuthentications.All),
                    Now,
                    null,
                    KnownSSHChannels);

        #endregion

        #region (static) TryCreate(Id, Name, Enabled, AuthMethods, ClientAuthentication, Description, AddedAt, out Group, out Error)

        /// <summary>
        /// A group, with everything about it checked.
        /// </summary>
        public static Boolean TryCreate(String?                                       Id,
                                        String?                                       Name,
                                        Boolean                                       Enabled,
                                        IEnumerable<AuthMethod>?                      AuthMethods,
                                        IEnumerable<WebSocketClientAuthentication>?   ClientAuthentication,
                                        I18NString?                                   Description,
                                        DateTimeOffset                                AddedAt,
                                        [NotNullWhen(true)]  out WebSocketLoginGroup?  Group,
                                        [NotNullWhen(false)] out String?               Error)
        {

            Group  = null;
            Error  = null;

            var id = Id?.Trim().ToLowerInvariant() ?? "";

            if (id.Length == 0)
            {
                Error = "A login group needs an identification.";
                return false;
            }

            if (id.Length > MaxIdLength)
            {
                Error = $"A login group identification may be at most {MaxIdLength} characters long.";
                return false;
            }

            // Kept to what can be put in a URL without escaping, because that
            // is where it ends up: the route that changes one group.
            if (!id.All(character => (character >= 'a' && character <= 'z') ||
                                     (character >= '0' && character <= '9') ||
                                      character == '-'))
            {
                Error = "A login group identification may hold lower-case letters, digits and hyphens only.";
                return false;
            }

            var name = Name?.Trim() ?? "";

            if (name.Length == 0)
                name = id;

            if (name.Length > MaxNameLength)
            {
                Error = $"A login group name may be at most {MaxNameLength} characters long.";
                return false;
            }

            if (!Descriptions.TryCheck(Description, MaxDescriptionLength, out var description, out Error))
                return false;

            var authentications = new HashSet<WebSocketClientAuthentication>(ClientAuthentication ?? []);

            foreach (var authentication in authentications)
                if (!Enum.IsDefined(authentication))
                {
                    Error = $"'{(Int32) authentication}' is no way a client may authenticate.";
                    return false;
                }

            Group = new WebSocketLoginGroup(
                        id,
                        name,
                        Enabled,
                        new HashSet<AuthMethod>(AuthMethods ?? []),
                        authentications,
                        AddedAt,
                        description
                    );

            return true;

        }

        #endregion

        #region (static) TryChannels(Names, out Channels, out Error)

        /// <summary>
        /// The given names as what a group gives its members over their SSH
        /// connection besides OCPP: each one of <see cref="KnownSSHChannels"/>.
        /// </summary>
        public static Boolean TryChannels(IEnumerable<String?>?                         Names,
                                          [NotNullWhen(true)]  out IReadOnlySet<String>?  Channels,
                                          [NotNullWhen(false)] out String?                Error)
        {

            var channels = new HashSet<String>(StringComparer.Ordinal);

            foreach (var name in Names ?? [])
            {

                if (name is null || !KnownSSHChannels.Contains(name.Trim()))
                {
                    Channels  = null;
                    Error     = $"'{name}' is nothing a login group gives its stations over SSH besides OCPP; there are {String.Join(" and ", KnownSSHChannels.Order(StringComparer.Ordinal))}.";
                    return false;
                }

                channels.Add(name.Trim());

            }

            Channels  = channels;
            Error     = null;
            return true;

        }

        #endregion

        #region (static) TryParse(JSON, out Group, out Error)

        /// <summary>
        /// One group, as it stands in the file.
        /// </summary>
        public static Boolean TryParse(JObject                                        JSON,
                                       [NotNullWhen(true)]  out WebSocketLoginGroup?  Group,
                                       [NotNullWhen(false)] out String?               Error,
                                       String?                                        NodeNoun   = null)
        {

            Group  = null;
            Error  = null;

            var methods = new List<AuthMethod>();

            if (JSON["authMethods"] is JArray methodArray)
                foreach (var token in methodArray)
                {

                    var method = AuthMethodExtensions.TryParseAuthMethod(token.Value<String>());

                    if (method is null)
                    {
                        Error = $"'{token}' is not a way of signing in that this {NodeNoun ?? NodeWording.Noun} knows.";
                        return false;
                    }

                    methods.Add(method.Value);

                }

            // OCPP's security profiles were what a group said of the transport
            // before: what reads them now would believe they were obeyed.
            if (JSON.ContainsKey("securityProfiles"))
            {
                Error = "'securityProfiles' of a login group is no more: say how its members may authenticate in 'clientAuthentication', " +
                        $"by {String.Join(", ", WebSocketClientAuthentications.Names.Select(name => $"\"{name}\""))} - OCPP's security profiles 1, 2 and 3.";
                return false;
            }

            var authentications = new List<WebSocketClientAuthentication>();

            if (JSON["clientAuthentication"] is JArray authenticationArray)
                foreach (var token in authenticationArray)
                {

                    if (token.Type != JTokenType.String ||
                        !WebSocketClientAuthentications.TryParse(token.Value<String>(), out var authentication))
                    {
                        Error = $"'{token}' is no way a client may authenticate; they are {String.Join(", ", WebSocketClientAuthentications.Names)}.";
                        return false;
                    }

                    authentications.Add(authentication);

                }

            var addedAt = DateTimeOffset.MinValue;

            DateTimeOffset.TryParse(JSON.Value<String>("addedAt"),
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.RoundtripKind,
                                    out addedAt);

            if (!TryCreate(
                     JSON.Value<String>("id"),
                     JSON.Value<String>("name"),
                     JSON.Value<Boolean?>("enabled") ?? true,
                     methods,
                     authentications,
                     JSON["description"] is JObject descriptionJSON &&
                     I18NString.TryParse(descriptionJSON, out I18NString? description, out _)
                         ? description
                         : null,
                     addedAt,
                     out Group,
                     out Error
                 ))
            {
                return false;
            }

            // A file written before there was such a thing says nothing of it,
            // and gives none: the file said what its stations get.
            if (JSON["sshChannels"] is JToken said)
            {

                if (said is not JArray names ||
                    names.Any(name => name.Type != JTokenType.String))
                {
                    Group  = null;
                    Error  = "'sshChannels' must be a list of the names of SSH subsystems.";
                    return false;
                }

                if (!TryChannels(names.Select(name => name.Value<String>()), out var channels, out Error))
                {
                    Group  = null;
                    return false;
                }

                Group = Group with { SSHChannels = channels };

            }

            return true;

        }

        #endregion

        #region Allows(Method) / Allows(ClientAuthentication)

        /// <summary>
        /// Whether a member of this group may sign in this way.
        /// </summary>
        public Boolean Allows(AuthMethod Method)
            => Enabled && AuthMethods.Contains(Method);

        /// <summary>
        /// Whether a member of this group may come in with this way of client
        /// authentication.
        /// </summary>
        public Boolean Allows(WebSocketClientAuthentication ClientAuthentication)
            => Enabled && this.ClientAuthentication.Contains(ClientAuthentication);

        #endregion

        #region ToJSON(Members = null)

        /// <summary>
        /// This group, for the file and for the web interface alike - there is
        /// nothing secret in it.
        /// </summary>
        /// <param name="Members">How many logins point at it, when the caller counted.</param>
        public JObject ToJSON(Int32? Members = null)
        {

            var json = new JObject(
                           new JProperty("id",                Id),
                           new JProperty("name",              Name),
                           new JProperty("enabled",           Enabled),
                           new JProperty("builtIn",           IsBuiltIn),
                           new JProperty("addedAt",           AddedAt.ToString("o")),
                           new JProperty("authMethods",       new JArray(AuthMethods.Select(method => method.AsText()).Order())),
                           new JProperty("clientAuthentication",  new JArray(ClientAuthentication.Order().Select(authentication => authentication.ToText()))),
                           new JProperty("sshChannels",       new JArray(Channels.Order(StringComparer.Ordinal)))
                       );

            if (Description.IsNotNullOrEmpty())
                json.Add("description", Description.ToJSON());

            if (Members.HasValue)
                json.Add("members", Members.Value);

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"{Id} ({(Enabled ? "on" : "off")}): " +
               $"{(AuthMethods.Count == 0 ? "nothing" : String.Join(", ", AuthMethods.Select(method => method.AsText()).Order()))}, " +
               $"client authentication {(ClientAuthentication.Count == 0 ? "none" : String.Join(", ", ClientAuthentication.Order().Select(authentication => authentication.ToText())))}" +
               (Channels.Count > 0 ? $", over SSH besides OCPP {String.Join(", ", Channels.Order(StringComparer.Ordinal))}" : "");

        #endregion

    }

}
