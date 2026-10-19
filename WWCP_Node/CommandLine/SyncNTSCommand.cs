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

using System.Globalization;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// Ask a node's time servers what the time is, or one of them
    /// everything.
    /// </summary>
    /// <remarks>
    /// Without a server, the same thing the NTS page does with 'Sync now'. Both
    /// end in <see cref="WWCPNode.SyncTimeAsync"/>, which asks the same
    /// group of servers, writes every step into the log and keeps the result
    /// as the last synchronisation the page shows - so the log book reads the
    /// same whichever of the two was used, apart from the one line that says
    /// who asked. A command that did any of that itself would be the beginning
    /// of a node disagreeing with itself about what it did.
    ///
    /// With one, the same thing as that server's Test button on the page:
    /// <see cref="WWCPNode.TestTimeServerAsync"/>, on the ports the
    /// server is configured with, step by step. Only a server of the node
    /// is tested. Anything else is answered with the servers there are, and
    /// nothing is asked - a name that was mistyped would otherwise be a key
    /// exchange with whoever answers to it.
    ///
    /// Neither steps the clock: they say whether the time servers can be
    /// reached and what they think of the local clock.
    ///
    /// Of the legal group unless the first word names another - "syncNTS
    /// local", "syncNTS local lc1.local" - as the page asks the group of the
    /// tab it shows. A first word that is no group's name is a server of the
    /// legal group, which is what it was before there were groups.
    ///
    /// Every kind of node had a copy of this, six of them alike but for the
    /// name of the node, and the local controller's older than the rest: no
    /// server to test, and none to complete.
    /// </remarks>
    /// <param name="CLI">The command line of the node to ask.</param>
    public class SyncNTSCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                               ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as. Taken from the class name, as everywhere
        /// else: "SyncNTSCommand" without its last seven characters. Found in
        /// any case - "syncnts" is the same command.
        /// </summary>
        public static readonly String CommandName = nameof(SyncNTSCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        /// <summary>
        /// Complete the command, then its first argument from the groups and
        /// the legal group's time servers, and after a group from that
        /// group's servers.
        /// </summary>
        /// <remarks>
        /// What there is to offer is offered as soon as the command is whole,
        /// and not only once something of it has been typed. The command line
        /// is split on whitespace and keeps no empty word at its end, so
        /// "syncNTS " arrives here as "syncNTS" alone - and a Tab there that
        /// answered with the command it already was would never show the list
        /// it is there to show.
        /// </remarks>
        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            #region The command itself - and, once it is whole, what may follow it

            if (Arguments.Length == 1)
            {

                if (CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                {

                    var all = FirstWords().
                                  Select(word => SuggestionResponse.ParameterPrefix($"{CommandName} {word}")).
                                  ToArray();

                    return all.Length > 0
                               ? all
                               : [ SuggestionResponse.CommandCompleted(CommandName) ];

                }

                if (CommandName.StartsWith(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                    return [ SuggestionResponse.CommandCompleted(CommandName) ];

                return [];

            }

            #endregion

            if (!CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                return [];

            #region ... a group, or a server of the legal group

            if (Arguments.Length == 2)
                return Offered(FirstWords(), Arguments[1], CommandName);

            #endregion

            #region ... and after a group, one of its servers

            if (Arguments.Length == 3 && cli.Node.NTSGroupOf(Arguments[1]) is NTSGroup group)
                return Offered(TimeServers(group), Arguments[2], $"{CommandName} {group.Id}");

            #endregion

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (Arguments.Length > 3)
                return [ $"Usage: {Help()}" ];

            // What 'Sync now' and the Test button need on the page: running the
            // time servers. The console may do everything; an account over SSH
            // what its roles let it.
            if (!cli.MayDo(Permission.Run(NodeResources.NTS), CommandName, out var refused))
                return [ refused ];

            #region Which group: the one named first, or the legal one

            // A word that is the name of a group is that group, and anything
            // else a server of the legal group, which is what this command was
            // before there were groups: "syncNTS ptbtime2.ptb.de" still tests
            // that server.
            var named  = Arguments.Length >= 2 ? cli.Node.NTSGroupOf(Arguments[1]) : null;
            var group  = named ?? cli.Node.NTSGroupOf(NTSGroup.LegalId);
            var next   = named is null ? 1 : 2;

            if (Arguments.Length > next + 1)
                return [ $"Usage: {Help()}" ];

            if (group is null)
            {

                var groups = cli.Node.NTSGroups.Select(other => other.Id).ToArray();

                return [ groups.Length > 0
                             ? $"This {cli.Node.Kind.Name} has no legal time to ask about. Name one of its NTS groups: {String.Join(", ", groups)}."
                             : $"This {cli.Node.Kind.Name} checks its clock against no group of time servers." ];

            }

            #endregion

            #region One server of it, in detail

            if (Arguments.Length == next + 1)
            {

                var wanted  = Arguments[next].Trim().TrimEnd('.');
                var server  = group.Sources.Sources.FirstOrDefault(source => String.Equals(source.Hostname.Trimmed,
                                                                                           wanted,
                                                                                           StringComparison.OrdinalIgnoreCase));

                // Said and nothing more. Not written to the log either: nothing
                // was asked of anybody, which is what the log is a book of.
                if (server is null)
                {

                    var servers = TimeServers(group).ToArray();

                    return [ servers.Length == 0
                                 ? $"NTS group '{group.Id}' names no time server."
                                 : group.IsLegal
                                       ? $"'{Arguments[next]}' is none of this {cli.Node.Kind.Name}'s time servers, which are {String.Join(", ", servers)}."
                                       : $"'{Arguments[next]}' is none of the time servers of NTS group '{group.Id}', which are {String.Join(", ", servers)}." ];

                }

                // The name as the page sends it for the Test button of that
                // row - as it is read, without the root's dot - so that the
                // line the log gets is the page's line, with the command line
                // where the page names the account and "cli" where it says
                // "web".
                var host = server.Hostname.Trimmed;

                cli.Node.Log.Info(
                    $"{cli.Caller.Asker} asked this {cli.Node.Kind.Name} to test the time server '{host}'" +
                    (group.IsLegal ? "." : $" of the NTS group '{group.Id}'."),
                    cli.Caller.Tags("nts", "test")
                );

                return Tested(await cli.Node.TestTimeServerAsync(group, host, CancellationToken));

            }

            #endregion

            // The line the web interface writes when 'Sync now' is pressed, in
            // the same words, at the same level and with the tags it carries
            // there - "cli" where it says "web", and "ssh" beside it over SSH.
            // There it names the account that pressed the button; over SSH it
            // names the account signed in, and at the console it is whoever is
            // there, which the node cannot tell apart. Said before anything is
            // asked, because the entries that follow record which servers were
            // asked and what came of it, and nothing in them says who wanted it.
            cli.Node.Log.Notice(
                group.IsLegal
                    ? $"{cli.Caller.Asker} asked this {cli.Node.Kind.Name} to synchronise its time."
                    : $"{cli.Caller.Asker} asked this {cli.Node.Kind.Name} to check its time against the NTS group '{group.Id}'.",
                cli.Caller.Tags("nts", "test")
            );

            var result = await cli.Node.SyncTimeAsync(group, CancellationToken);

            return Outcome(result);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [<group>] [<time server>] - ask a group of time servers what the time is, the legal one " +
                "unless another is named, as 'Sync now' on the NTS page does, or test one of its servers in detail, as " +
                "its Test button does; the clock is not stepped";

        #endregion


        #region (private) FirstWords()

        /// <summary>
        /// What may follow the command: the name of every group but the legal
        /// one, which is what the command asks without a name, and the legal
        /// group's time servers.
        /// </summary>
        private IEnumerable<String> FirstWords()
        {

            foreach (var group in cli.Node.NTSGroups.Where(group => !group.IsLegal))
                yield return group.Id;

            if (cli.Node.NTSGroupOf(NTSGroup.LegalId) is NTSGroup legal)
                foreach (var server in TimeServers(legal))
                    yield return server;

        }

        #endregion

        #region (private static) TimeServers(Group)

        /// <summary>
        /// The time servers of a group, switched on or not, as somebody types
        /// them: without the root's dot.
        /// </summary>
        /// <remarks>
        /// Switched-off ones as well, because the page tests those too: finding
        /// out whether a server answers is what somebody does before switching
        /// it on.
        /// </remarks>
        private static IEnumerable<String> TimeServers(NTSGroup Group)

            => Group.Sources.Sources.Select(source => source.Hostname.Trimmed);

        #endregion

        #region (private static) Offered(Words, Typed, Before)

        /// <summary>
        /// The words that begin with what was typed, each after what came
        /// before it: completed where it is the whole word, a prefix otherwise.
        /// </summary>
        private static IEnumerable<SuggestionResponse> Offered(IEnumerable<String>  Words,
                                                               String               Typed,
                                                               String               Before)
        {

            foreach (var word in Words)
            {

                if (!word.StartsWith(Typed, StringComparison.CurrentCultureIgnoreCase))
                    continue;

                yield return word.Equals(Typed, StringComparison.CurrentCultureIgnoreCase)
                                 ? SuggestionResponse.ParameterCompleted($"{Before} {word}")
                                 : SuggestionResponse.ParameterPrefix   ($"{Before} {word}");

            }

        }

        #endregion


        #region (private static) Outcome(Result)

        /// <summary>
        /// What the NTS page shows after 'Sync now', as lines for the console:
        /// how it went, and what each server said.
        /// </summary>
        /// <remarks>
        /// The servers get a line each because the log does not have them: it
        /// records that the group was asked and what the group concluded, and
        /// which server was the one that did not answer is only in here and on
        /// the page.
        /// </remarks>
        private static String[] Outcome(JObject Result)
        {

            var lines    = new List<String>();
            var servers  = Result["servers"] as JArray ?? [];
            var took     = Result.Value<Int64?>("runtime_ms") is Int64 runtime
                               ? $" after {runtime} ms"
                               : "";

            if (Result.Value<Boolean>("ok"))
            {

                var group = Result["group"] as JObject;

                lines.Add($"succeeded{took}: {group?.Value<Int32?>("answered")} of {servers.Count} server(s) answered " +
                          $"({group?.Value<Int32?>("required")} required), " +
                          $"offset {Milliseconds(group?.Value<Double?>("offset_ms"), Signed: true)}, " +
                          $"spread {Milliseconds(group?.Value<Double?>("spread_ms"))}");

                if (group?.Value<Boolean?>("deviationExceeded") == true)
                    lines.Add("  The servers disagree by more than the agreed deviation - see the log.");

            }
            else
                lines.Add($"failed{took}: {Result.Value<String>("error") ?? "no reason was given"}");

            if (servers.Count > 0)
            {

                // Without the root's dot, as the banner writes them:
                // "ptbtime1.ptb.de." is correct and nobody reads it that way.
                static String Hostname(JToken Server)
                    => (Server.Value<String>("hostname") ?? "").TrimEnd('.');

                var width = servers.Max(server => Hostname(server).Length);

                foreach (var server in servers.OfType<JObject>())
                    lines.Add($"  {Hostname(server).PadRight(width)}  {ServerSaid(server)}");

            }

            return [.. lines];

        }

        #endregion

        #region (private static) Tested(Result)

        /// <summary>
        /// What the Test button's dialog shows, as lines for the console: whether
        /// the server answered, and then every step with when it happened.
        /// </summary>
        /// <remarks>
        /// All of the steps and not a summary, because they are the answer: a
        /// test is asked for when something did not work, and which step it
        /// got to is the whole of what somebody needs. The log has only the
        /// beginning and the end of it, as it has for the button.
        ///
        /// Warnings and errors say so, where the page says it in colour.
        /// </remarks>
        private static String[] Tested(JObject Result)
        {

            var host   = (Result.Value<String>("host") ?? "").TrimEnd('.');
            var steps  = (Result["steps"] as JArray ?? []).OfType<JObject>().ToArray();
            var at     = steps.Select(step => $"+{step.Value<Int64>("at_ms")} ms").ToArray();
            var width  = at.Length > 0 ? at.Max(when => when.Length) : 0;

            var lines  = new List<String> {
                             $"{host} {(Result.Value<Boolean>("ok") ? "answered" : "did not answer")}, " +
                             $"{Result.Value<Int64>("runtime_ms")} ms altogether:"
                         };

            for (var i = 0; i < steps.Length; i++)
            {

                var level = steps[i].Value<String>("level");

                lines.Add($"  {at[i].PadLeft(width)}  " +
                          (level is "warning" or "error" ? $"{level}: " : "") +
                          steps[i].Value<String>("text"));

            }

            return [.. lines];

        }

        #endregion

        #region (private static) ServerSaid(Server)

        /// <summary>
        /// What one server said: its offset and round trip when its answer
        /// counted, and otherwise why it did not.
        /// </summary>
        /// <remarks>
        /// An answer that did not authenticate is said to be one. The page
        /// writes "no answer" for it, and on a console that is the difference
        /// between a server that is down and one that is not the server it
        /// claims to be.
        /// </remarks>
        private static String ServerSaid(JObject Server)
        {

            if (Server.Value<Boolean>("ok"))
                return $"{Milliseconds(Server.Value<Double?>("offset_ms"), Signed: true)}, " +
                       $"round trip {Milliseconds(Server.Value<Double?>("roundTrip_ms"))}, " +
                       $"key exchange {Server.Value<String>("keyExchange") ?? "unknown"}";

            if (Server.Value<String>("error") is String error && error.Length > 0)
                return error;

            if (Server.Value<Boolean?>("authenticated") == false)
                return "answered, but the answer did not authenticate";

            return "no answer";

        }

        #endregion

        #region (private static) Milliseconds(Value, Signed = false)

        /// <summary>
        /// The one place a number with a fraction is written, and so the one
        /// place the culture has to be kept out: these sentences are English,
        /// and a node in a German locale would otherwise write "+1,2 ms" in
        /// the middle of one.
        /// </summary>
        internal static String Milliseconds(Double? Value, Boolean Signed = false)

            => Value is Double value
                   ? value.ToString(Signed ? "+0.0;-0.0;0.0" : "0.0", CultureInfo.InvariantCulture) + " ms"
                   : "unknown";

        #endregion

    }

}
