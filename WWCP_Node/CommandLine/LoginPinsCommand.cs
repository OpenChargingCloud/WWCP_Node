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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The key pins the logins of a WebSocket server of a node are let in by:
    /// listed, given, and taken away - the charging stations of a CSMS, the
    /// registration authorities of a PKI.
    /// </summary>
    /// <remarks>
    /// <para>
    /// &lt;command&gt; lists every login's key pins; &lt;command&gt;
    /// &lt;login&gt; one login's; &lt;command&gt; &lt;login&gt; add &lt;key
    /// pin&gt; [&lt;label&gt;] gives it one - adding the login where it is not
    /// listed yet - and &lt;command&gt; &lt;login&gt; remove &lt;key pin&gt;
    /// takes one away. A key pin is SHA-256 over the public key: 64
    /// hexadecimal digits, with or without colons, or "sha256//" and Base64.
    /// </para>
    /// <para>
    /// What the web interface asks of the same account is asked here: reading
    /// the resource to list, changing it to give or take a key pin. The
    /// console may do everything.
    /// </para>
    /// <para>
    /// A key pin does not let a login in on its own: the login must be
    /// switched on, its group must take key pins and TLS client certificates,
    /// and the port must speak TLS. Where one of them is missing, the answer
    /// says so.
    /// </para>
    /// </remarks>
    public abstract class LoginPinsCommand : ACLICommand<NodeCLI>,
                                             ICLICommand
    {

        #region Properties

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public String  Name        { get; }

        /// <summary>
        /// The resource read to list the key pins and changed to give or take one.
        /// </summary>
        public String  Resource    { get; }

        /// <summary>
        /// The logins whose key pins these are.
        /// </summary>
        protected abstract WebSocketLogins        Logins                     { get; }

        /// <summary>
        /// What a login is: "charging station".
        /// </summary>
        protected abstract String                 LoginNoun                  { get; }

        /// <summary>
        /// What a login is called in the help: "station".
        /// </summary>
        protected abstract String                 LoginWord                  { get; }

        /// <summary>
        /// Where the key pins let a login in: "on the station port".
        /// </summary>
        protected abstract String                 PinsAreFor                 { get; }

        /// <summary>
        /// What a TLS client certificate is called where a group does not
        /// take one: "a TLS client certificate (security profile 3)".
        /// </summary>
        protected virtual  String                 TLSClientCertificateWords
            => "a TLS client certificate";

        /// <summary>
        /// What the log says of each change, beside "auth" and "tls".
        /// </summary>
        protected abstract IReadOnlyList<String>  LogTags                    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The command for the given command line, typed as the given name, at
        /// the given resource.
        /// </summary>
        protected LoginPinsCommand(NodeCLI  CLI,
                                   String   Name,
                                   String   Resource)

            : base(CLI)

        {

            this.Name      = Name;
            this.Resource  = Resource;

        }

        #endregion


        #region (protected) WhyNoLoginSignsIn()

        /// <summary>
        /// What keeps every login out - the port.
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
                           0 => EveryLoginsPins(),
                           1 => Listed(User_Id.Parse(rest[0])),
                           _ => verb switch {
                                    "add"    when rest.Length >= 3  => Add   (User_Id.Parse(rest[0]), rest[2], rest.Length > 3 ? String.Join(" ", rest[3..]) : null),
                                    "remove" when rest.Length == 3  => Remove(User_Id.Parse(rest[0]), rest[2]),
                                    _                               => [ $"Usage: {Help()}" ]
                                }
                       }
                   );

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{Name} [<{LoginWord}> [add <key pin> [<label>] | remove <key pin>]] - the key pins {LoginNoun}s are let in by {PinsAreFor}";

        #endregion


        #region (private) EveryLoginsPins() / Listed(Login)

        private String[] EveryLoginsPins()
        {

            var lines = new List<String>();

            foreach (var login in Logins.Logins.Where(login => login.HasKeyPin).OrderBy(login => login.Login))
            {
                lines.Add($"{login.Login}:");
                lines.AddRange(login.Pins.Select(pin => "  " + Line(pin)));
                lines.AddRange(WhyNoPinLetsIn(login).Select(why => "  " + why));
            }

            if (lines.Count == 0)
                lines.Add($"No {LoginNoun} of this {cli.Node.Kind.Name} has a key pin.");

            lines.AddRange(WhyNoLoginSignsIn());

            return [ .. lines ];

        }

        private String[] Listed(User_Id Login)
        {

            if (!Logins.TryGet(Login, out var login))
                return [ $"'{Login}' is no {LoginNoun} of this {cli.Node.Kind.Name}." ];

            if (!login.HasKeyPin)
                return [ $"'{login.Login}' has no key pin." ];

            return [ .. login.Pins.Select(Line),
                     .. WhyNoPinLetsIn(login),
                     .. WhyNoLoginSignsIn() ];

        }

        /// <summary>
        /// One key pin, as a line: the pin, when and by whom it was given, and
        /// what it is called.
        /// </summary>
        private static String Line(LoginKeyPin Pin)

            => $"{Pin.Pin}  {Pin.Added.ToLocalTime():yyyy-MM-dd HH:mm}" +
               (Pin.AddedBy is not null ? $" by {Pin.AddedBy}" : "") +
               (Pin.Label   is not null ? $"  {Pin.Label}"     : "");

        #endregion

        #region (private) Add(Login, Pin, Label)

        private String[] Add(User_Id  Login,
                             String   Pin,
                             String?  Label)
        {

            var listed = Logins.TryGet(Login, out _);

            if (!Logins.TryAddKeyPin(Login,
                                     Pin,
                                     Label,
                                     GroupId:      null,
                                     Description:  null,
                                     AddedBy:      cli.Caller.Account?.Id.ToString() ?? "the console",
                                     out var keyPin,
                                     out var error,
                                     out _))
            {
                return [ $"The key pin was not given: {error}" ];
            }

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} gave the {LoginNoun} '{Login}' the key pin {keyPin.Pin}.",
                cli.Caller.Tags([ .. LogTags, "auth", "tls" ])
            );

            Logins.TryGet(Login, out var login);

            return [ listed
                         ? $"'{Login}' is let in by the key pin {keyPin.Pin} now."
                         : $"'{Login}' is a {LoginNoun} of this {cli.Node.Kind.Name} now, in the group '{login?.GroupId}', and is let in by the key pin {keyPin.Pin}.",
                     .. login is not null ? WhyNoPinLetsIn(login) : [],
                     .. WhyNoLoginSignsIn() ];

        }

        #endregion

        #region (private) Remove(Login, Pin)

        private String[] Remove(User_Id Login,
                                String  Pin)
        {

            if (!Logins.TryGet(Login, out var login))
                return [ $"'{Login}' is no {LoginNoun} of this {cli.Node.Kind.Name}." ];

            if (!org.GraphDefined.Vanaheimr.Hermod.KeyPin.TryParse(Pin, out var pin) ||
                login.FindKeyPin(pin) is null)
                return [ $"'{login.Login}' has no key pin {Pin}." ];

            if (!Logins.TryRemoveKeyPin(login.Login, pin.ToHex(), out var error, out _))
                return [ $"The key pin was not taken away: {error}" ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} took the key pin {pin} of the {LoginNoun} '{login.Login}' away.",
                cli.Caller.Tags([ .. LogTags, "auth", "tls" ])
            );

            return [ $"The key pin {pin} lets '{login.Login}' in no more." ];

        }

        #endregion

        #region (private) WhyNoPinLetsIn(Login)

        /// <summary>
        /// What keeps this login out whatever pin it has - the login, or its
        /// group.
        /// </summary>
        private IEnumerable<String> WhyNoPinLetsIn(WebSocketLogin Login)
        {

            if (!Login.Enabled)
                yield return $"'{Login.Login}' is switched off: no key pin lets it in.";

            var group = Logins.GroupOf(Login);

            if (group is null)
                yield return $"The group '{Login.GroupId}' of '{Login.Login}' is gone: no key pin lets it in.";

            else if (!group.Enabled)
                yield return $"The group '{group.Id}' of '{Login.Login}' is switched off: no key pin lets it in.";

            else if (!group.Allows(AuthMethod.KeyPin))
                yield return $"The group '{group.Id}' of '{Login.Login}' does not accept key pins: no key pin lets it in.";

            else if (!group.Allows(WebSocketClientAuthentication.TLSClientCertificate))
                yield return $"The group '{group.Id}' of '{Login.Login}' does not accept {TLSClientCertificateWords}, which a client key is: no key pin lets it in.";

        }

        #endregion

    }

}
