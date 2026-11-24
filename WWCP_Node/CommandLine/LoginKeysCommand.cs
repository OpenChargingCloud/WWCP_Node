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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The SSH keys the logins of a WebSocket server of a node sign in with
    /// over SSH: listed, given, and taken away - the charging stations of a
    /// CSMS, the registration authorities of a PKI.
    /// </summary>
    /// <remarks>
    /// <para>
    /// &lt;command&gt; lists every login's keys; &lt;command&gt; &lt;login&gt;
    /// one login's; &lt;command&gt; &lt;login&gt; add &lt;authorized_keys
    /// line&gt; gives it a key - adding the login where it is not listed yet,
    /// with from= and expiry-time= holding as in OpenSSH's authorized_keys -
    /// and &lt;command&gt; &lt;login&gt; remove &lt;fingerprint&gt; takes one
    /// away: a session the key opened ends at once. A fingerprint may be
    /// written as OpenSSH writes it, "SHA256:...", or by enough of its
    /// beginning to be only one key's.
    /// </para>
    /// <para>
    /// What the web interface asks of the same account is asked here: reading
    /// the resource to list, changing it to give or take a key. The console
    /// may do everything.
    /// </para>
    /// <para>
    /// A key does not let a login in on its own: the login must be switched
    /// on, its group must take SSH keys, and the node must serve its subsystem
    /// over SSH. Where one of them is missing, the answer says so.
    /// </para>
    /// </remarks>
    public abstract class LoginKeysCommand : ACLICommand<NodeCLI>,
                                             ICLICommand
    {

        #region Properties

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public String  Name        { get; }

        /// <summary>
        /// The resource read to list the keys and changed to give or take one.
        /// </summary>
        public String  Resource    { get; }

        /// <summary>
        /// The logins whose keys these are.
        /// </summary>
        protected abstract WebSocketLogins        Logins         { get; }

        /// <summary>
        /// What a login is: "charging station".
        /// </summary>
        protected abstract String                 LoginNoun      { get; }

        /// <summary>
        /// What a login is called in the help: "station".
        /// </summary>
        protected abstract String                 LoginWord      { get; }

        /// <summary>
        /// What the keys let a login do: "for OCPP-over-SSH".
        /// </summary>
        protected abstract String                 KeysAreFor     { get; }

        /// <summary>
        /// What the log says of each change, beside "auth" and "ssh".
        /// </summary>
        protected abstract IReadOnlyList<String>  LogTags        { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The command for the given command line, typed as the given name, at
        /// the given resource.
        /// </summary>
        protected LoginKeysCommand(NodeCLI  CLI,
                                   String   Name,
                                   String   Resource)

            : base(CLI)

        {

            this.Name      = Name;
            this.Resource  = Resource;

        }

        #endregion


        #region (protected) TryAddKey(...) / WhyNoLoginSignsIn()

        /// <summary>
        /// Give a login a key: what the logins do, where the kind of node has
        /// nothing to say against it.
        /// </summary>
        protected virtual Boolean TryAddKey(User_Id                               Login,
                                            String                                Line,
                                            String                                CreatedBy,
                                            [NotNullWhen(true)]  out UserSSHKey?  Key,
                                            [NotNullWhen(false)] out String?      Error)

            => Logins.TryAddSSHKey(Login, Line, null, null, null, CreatedBy, out Key, out Error, out _);

        /// <summary>
        /// What keeps every login out - the node.
        /// </summary>
        protected abstract IEnumerable<String> WhyNoLoginSignsIn();

        #endregion


        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return Name.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandCompleted(Name) ]
                           : [];

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            var rest  = Arguments.Skip(1).ToArray();
            var verb  = rest.Length < 2 ? "list" : rest[1].ToLowerInvariant();

            var needs = verb == "list"
                            ? Permission.Read(Resource)
                            : Permission.Edit(Resource);

            if (!cli.MayDo(needs, Name, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            return Task.FromResult(
                       rest.Length switch {
                           0 => EveryLoginsKeys(),
                           1 => Listed(User_Id.Parse(rest[0])),
                           _ => verb switch {
                                    "add"                           => Add(User_Id.Parse(rest[0]), String.Join(" ", rest[2..])),
                                    "remove" when rest.Length == 3  => Remove(User_Id.Parse(rest[0]), rest[2]),
                                    _                               => [ $"Usage: {Help()}" ]
                                }
                       }
                   );

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{Name} [<{LoginWord}> [add <authorized_keys line> | remove <fingerprint>]] - the SSH keys {LoginNoun}s sign in with {KeysAreFor}";

        #endregion


        #region (private) EveryLoginsKeys() / Listed(Login)

        private String[] EveryLoginsKeys()
        {

            var lines = new List<String>();

            foreach (var login in Logins.Logins.Where(login => login.HasSSHKey).OrderBy(login => login.Login))
            {
                lines.Add($"{login.Login}:");
                lines.AddRange(login.Keys.Select(key => "  " + Line(key)));
                lines.AddRange(WhyNoKeyLetsIn(login).Select(why => "  " + why));
            }

            if (lines.Count == 0)
                lines.Add($"No {LoginNoun} of this {cli.Node.Kind.Name} has an SSH key.");

            lines.AddRange(WhyNoLoginSignsIn());

            return [ .. lines ];

        }

        private String[] Listed(User_Id Login)
        {

            if (!Logins.TryGet(Login, out var login))
                return [ $"'{Login}' is no {LoginNoun} of this {cli.Node.Kind.Name}." ];

            if (!login.HasSSHKey)
                return [ $"'{login.Login}' has no SSH key." ];

            return [ .. login.Keys.Select(Line),
                     .. WhyNoKeyLetsIn(login),
                     .. WhyNoLoginSignsIn() ];

        }

        /// <summary>
        /// One key, as a line: its fingerprint, when and by whom it was given,
        /// the options in front of it, and what it is called - as sshKeys
        /// shows an account's.
        /// </summary>
        private static String Line(UserSSHKey Key)
        {

            var options  = Key.Key.Options.Count > 0
                               ? "  " + String.Join(",", Key.Key.Options)
                               : "";

            var called   = Key.Label ?? (Key.Key.PublicKey.Comment is { Length: > 0 } comment ? comment : null);

            return $"{Key.Fingerprint}  {Key.Created.ToLocalTime():yyyy-MM-dd HH:mm}" +
                   (Key.CreatedBy is not null ? $" by {Key.CreatedBy}" : "") +
                   options +
                   (Key.IsDisabled ? ", switched off" : "") +
                   (called is not null ? $"  {called}" : "");

        }

        #endregion

        #region (private) Add(Login, Line)

        private String[] Add(User_Id Login,
                             String  Line)
        {

            if (Line.Trim().Length == 0)
                return [ $"Usage: {Help()}" ];

            var listed = Logins.TryGet(Login, out _);

            if (!TryAddKey(Login,
                           Line,
                           cli.Caller.Account?.Id.ToString() ?? "the console",
                           out var key,
                           out var error))
            {
                return [ $"The key was not given: {error}" ];
            }

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} gave the {LoginNoun} '{Login}' the SSH key {key.Fingerprint}.",
                cli.Caller.Tags([ .. LogTags, "auth", "ssh" ])
            );

            Logins.TryGet(Login, out var login);

            return [ listed
                         ? $"'{Login}' signs in over SSH with the key {key.Fingerprint} now."
                         : $"'{Login}' is a {LoginNoun} of this {cli.Node.Kind.Name} now, in the group '{login?.GroupId}', and signs in over SSH with the key {key.Fingerprint}.",
                     .. login is not null ? WhyNoKeyLetsIn(login) : [],
                     .. WhyNoLoginSignsIn() ];

        }

        #endregion

        #region (private) Remove(Login, Fingerprint)

        private String[] Remove(User_Id Login,
                                String  Fingerprint)
        {

            if (!Logins.TryGet(Login, out var login))
                return [ $"'{Login}' is no {LoginNoun} of this {cli.Node.Kind.Name}." ];

            var wanted   = UserSSHKey.FingerprintFromURL(Fingerprint)["SHA256:".Length..];
            var matching = login.Keys.
                               Where(key => key.Fingerprint["SHA256:".Length..].StartsWith(wanted, StringComparison.Ordinal)).
                               ToArray();

            if (wanted.Length == 0 || matching.Length == 0)
                return [ $"'{login.Login}' has no key {Fingerprint}." ];

            if (matching.Length > 1 && !matching.Any(key => key.Fingerprint == "SHA256:" + wanted))
                return [ $"'{Fingerprint}' is the beginning of {matching.Length} keys of '{login.Login}': {String.Join(", ", matching.Select(key => key.Fingerprint))}." ];

            var key = matching.FirstOrDefault(key => key.Fingerprint == "SHA256:" + wanted) ?? matching[0];

            if (!Logins.TryRemoveSSHKey(login.Login, key.Fingerprint, out var error, out _))
                return [ $"The key was not taken away: {error}" ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} took the SSH key {key.Fingerprint} of the {LoginNoun} '{login.Login}' away.",
                cli.Caller.Tags([ .. LogTags, "auth", "ssh" ])
            );

            return [ $"The key {key.Fingerprint} lets '{login.Login}' in no more." ];

        }

        #endregion

        #region (private) WhyNoKeyLetsIn(Login)

        /// <summary>
        /// What keeps this login out whatever key it has - the login, or its
        /// group.
        /// </summary>
        private IEnumerable<String> WhyNoKeyLetsIn(WebSocketLogin Login)
        {

            if (!Login.Enabled)
                yield return $"'{Login.Login}' is switched off: no key lets it in.";

            var group = Logins.GroupOf(Login);

            if (group is null)
                yield return $"The group '{Login.GroupId}' of '{Login.Login}' is gone: no key lets it in.";

            else if (!group.Enabled)
                yield return $"The group '{group.Id}' of '{Login.Login}' is switched off: no key lets it in.";

            else if (!group.Allows(AuthMethod.SSHKey))
                yield return $"The group '{group.Id}' of '{Login.Login}' does not accept SSH keys: no key lets it in.";

        }

        #endregion

    }

}
