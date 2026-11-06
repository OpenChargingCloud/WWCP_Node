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

using System.Net;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The SSH access rules: listed, added, taken out, moved - and asked, before they are relied on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// sshAccessRules lists them, numbered, the first that matches deciding.
    /// sshAccessRules add [at &lt;n&gt;] &lt;rule&gt; adds one - at the end, or as rule n -
    /// written <c>deny principal=account:* service=shell source=10.0.0.0/8 local=10.10.0.1 auth=password # why</c>.
    /// sshAccessRules remove &lt;n&gt; takes rule n out; sshAccessRules move &lt;n&gt; &lt;m&gt; makes rule n rule m.
    /// </para>
    /// <para>
    /// sshAccessRules test &lt;principal&gt; [service=..] [source=..] [local=..] [auth=..] says which rule
    /// decides for such a session, and what: <c>sshAccessRules test account:root service=shell source=10.0.0.5</c>.
    /// </para>
    /// <para>
    /// Every change is saved in the "ssh" section of the configuration file, in effect at once - every
    /// session open now is asked again - and written down in the log with who made it. Reading and
    /// testing needs to read the SSH server's settings; changing them, to edit them.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class SSHAccessRulesCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                                     ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "sshAccessRules";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                           : [];

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            var rest = Arguments.Skip(1).ToArray();
            var verb = rest.Length == 0 ? "list" : rest[0].ToLowerInvariant();

            var needs = verb is "list" or "test"
                            ? Permission.Read(NodeResources.SSH)
                            : Permission.Edit(NodeResources.SSH);

            if (!cli.MayDo(needs, CommandName, out var refused))
                return [ refused ];

            switch (verb)
            {

                case "list":
                    return Listed();

                case "add":
                    return await Add(rest[1..]);

                case "remove":
                    return rest.Length == 2 && Int32.TryParse(rest[1], out var number)
                               ? await Remove(number)
                               : [ $"Usage: {Help()}" ];

                case "move":
                    return rest.Length == 3 && Int32.TryParse(rest[1], out var from) && Int32.TryParse(rest[2], out var to)
                               ? await Move(from, to)
                               : [ $"Usage: {Help()}" ];

                case "test":
                    return Test(rest[1..]);

                default:
                    return [ $"Usage: {Help()}" ];

            }

        }

        #endregion

        #region Help()

        public override String Help()
            => $"{CommandName} [add [at <n>] <rule> | remove <n> | move <n> <m> | test <principal> [service=..] [source=..] [local=..] [auth=..]] - who may sign in over SSH, from where, to use what";

        #endregion


        #region (private) Listed()

        private String[] Listed()
        {

            var rules = cli.Node.SSHAccessRules.Rules;

            if (rules.Count == 0)
                return [ $"No SSH access rules: the accounts of this {cli.Node.Kind.Name}, their roles and keys decide alone who signs in over SSH." ];

            var width = rules.Count.ToString().Length;

            return [ "The first rule that matches decides; where none does, the accounts, their roles and keys decide alone.",
                     .. rules.Select((rule, index) => $"{(index + 1).ToString().PadLeft(width)}  {rule}") ];

        }

        #endregion

        #region (private) Add(Words)

        private async Task<String[]> Add(String[] Words)
        {

            var rules    = cli.Node.SSHAccessRules.Rules.ToList();
            var position = rules.Count + 1;

            if (Words.Length >= 2 && Words[0].Equals("at", StringComparison.OrdinalIgnoreCase))
            {

                if (!Int32.TryParse(Words[1], out position) || position < 1 || position > rules.Count + 1)
                    return [ $"There is no place {Words[1]}: a rule goes in at 1 to {rules.Count + 1}." ];

                Words = Words[2..];

            }

            if (Words.Length == 0)
                return [ $"Usage: {Help()}" ];

            if (!SSHAccessRule.TryParseLine(String.Join(" ", Words), out var rule, out var error))
                return [ error ];

            if (rules.Count >= SSHAccessRules.MaxRules)
                return [ $"This {cli.Node.Kind.Name} keeps at most {SSHAccessRules.MaxRules} SSH access rules." ];

            rules.Insert(position - 1, rule);

            return await Saved(rules, $"added SSH access rule {position}: {rule}");

        }

        #endregion

        #region (private) Remove(Number)

        private async Task<String[]> Remove(Int32 Number)
        {

            var rules = cli.Node.SSHAccessRules.Rules.ToList();

            if (Number < 1 || Number > rules.Count)
                return [ rules.Count == 0 ? "There are no SSH access rules." : $"There is no rule {Number}: they are numbered 1 to {rules.Count}." ];

            var rule = rules[Number - 1];

            rules.RemoveAt(Number - 1);

            return await Saved(rules, $"took out SSH access rule {Number}: {rule}");

        }

        #endregion

        #region (private) Move(From, To)

        private async Task<String[]> Move(Int32 From, Int32 To)
        {

            var rules = cli.Node.SSHAccessRules.Rules.ToList();

            if (From < 1 || From > rules.Count || To < 1 || To > rules.Count)
                return [ rules.Count == 0 ? "There are no SSH access rules." : $"The rules are numbered 1 to {rules.Count}." ];

            var rule = rules[From - 1];

            rules.RemoveAt(From - 1);
            rules.Insert(To - 1, rule);

            return await Saved(rules, $"made SSH access rule {From} rule {To}: {rule}");

        }

        #endregion

        #region (private) Saved(Rules, Done)

        private async Task<String[]> Saved(List<SSHAccessRule> Rules, String Done)
        {

            var change = await cli.Node.TryUpdateSSHAccessRules(new SSHAccessRules(Rules));

            if (!change.IsChanged)
                return [ $"Nothing was changed: {change.Error}" ];

            cli.Node.Log.Notice($"{cli.Caller.Asker} {Done}.", cli.Caller.Tags("ssh", "security"));

            return [ $"{Done[..1].ToUpperInvariant()}{Done[1..]}.", .. Listed() ];

        }

        #endregion

        #region (private) Test(Words)

        /// <summary>
        /// Which rule decides for a session as described, and what.
        /// </summary>
        private String[] Test(String[] Words)
        {

            if (Words.Length == 0 || Words[0].IndexOf(':') <= 0)
                return [ $"Usage: {Help()} - e.g. {CommandName} test account:root service=shell source=10.0.0.5" ];

            var kind    = Words[0][..Words[0].IndexOf(':')].ToLowerInvariant();
            var name    = Words[0][(Words[0].IndexOf(':') + 1)..];

            // An account's groups are its roles, as at sign-in.
            var groups  = kind == SSHPrincipal.Account &&
                          User_Id.TryParse(name) is User_Id userId &&
                          cli.Node.ExtAPI.TryGetUser(userId, out var user) && user is not null
                              ? (IReadOnlyList<String>) [ .. cli.Node.RolesOf(user).Select(role => role.Name) ]
                              : [];

            String?    service = null;
            IPAddress? source  = null, local = null;
            var        auth    = "publickey";

            foreach (var word in Words[1..])
            {

                var equals = word.IndexOf('=');
                var value  = equals > 0 ? word[(equals + 1)..] : "";

                switch (equals > 0 ? word[..equals].ToLowerInvariant() : word)
                {
                    case "service":  service = value;  break;
                    case "auth":     auth    = value;  break;
                    case "source" when IPAddress.TryParse(value, out var address):  source = address;  break;
                    case "local"  when IPAddress.TryParse(value, out var address):  local  = address;  break;
                    default:
                        return [ $"'{word}' is no service=, source=<address>, local=<address> or auth=." ];
                }

            }

            var request  = new SSHAccessRequest(new SSHPrincipal(kind, name, groups), service, source, local, auth);
            var decision = cli.Node.SSHAccessRules.For(request);
            var what     = service is null ? "signing in" : service;

            return [ decision.Number is null
                         ? $"No rule matches {kind}:{name} {what}: the accounts, their roles and keys decide alone."
                         : service is null && decision.Rule?.Service is not null
                               ? $"Let in at sign-in: {decision} names a service, so what {kind}:{name} may use is asked service by service."
                               : $"{decision} {(decision.Allowed ? "lets on" : "refuses")} {kind}:{name} {what}." +
                                 (decision.Allowed ? " The accounts, their roles and keys decide the rest." : "") ];

        }

        #endregion

    }

}
