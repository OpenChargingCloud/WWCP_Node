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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// Have the node look a name up, the way it looks up anything - or ask one
    /// of its name servers alone.
    /// </summary>
    /// <remarks>
    /// "queryDNS csms.example.org", "queryDNS example.org MX TXT",
    /// "queryDNS _ntske._tcp.example.org SRV @dns-1": the name first, then the
    /// record types, and a name server after an "@", as dig takes one. The
    /// order of the record types and the server does not matter; the name is
    /// the first word.
    ///
    /// The same thing as the DNS test of the web interface and as QueryDNS
    /// of OCPP: all three end in <see cref="WWCPNode.ResolveAsync"/>, so that
    /// none of them can say something about a name server the others do not.
    /// It was made for whoever looks for a fault - a person at the console, or
    /// an agent over SSH - and so says everything the answer had, the server
    /// it came from and what was made of that server's certificate, and not
    /// only the addresses.
    ///
    /// Without a server, the question is put to the name servers the way the
    /// node puts every other one, cache included. With one, only that server
    /// is asked, and without the cache. A server is named by its id, by its
    /// place in the list counted from 1, or by its address - and only the
    /// configured ones can be named: a name server somebody typed in would be
    /// a question to whoever answers at that address, from inside a network
    /// whose firewall lets the node reach its own name servers and no others.
    /// </remarks>
    /// <param name="CLI">The command line of the node to ask.</param>
    public class QueryDNSCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                                ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: "QueryDNSCommand" without its last seven
        /// characters. Found in any case - "querydns" is the same command.
        /// </summary>
        public static readonly String CommandName = nameof(QueryDNSCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// The record types offered when Tab is pressed after the name: those
        /// somebody looking for a fault in the names of a charging network asks
        /// for. Any other is asked for all the same, by its mnemonic or its
        /// number.
        /// </summary>
        public static readonly IReadOnlyList<String> OfferedRecordTypes = [
            "A", "AAAA", "CNAME", "PTR", "SRV", "SVCB", "HTTPS", "TXT", "TLSA", "MX", "NS", "SOA", "CAA", "DS", "DNSKEY"
        ];

        #endregion

        #region Suggest(Arguments)

        /// <summary>
        /// Complete the command; after the name, the record types and, after
        /// an "@", the ids of the name servers.
        /// </summary>
        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
            {

                if (CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                    return [ SuggestionResponse.CommandHelp(Help()) ];

                if (CommandName.StartsWith(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                    return [ SuggestionResponse.CommandCompleted(CommandName) ];

                return [];

            }

            // The name is somebody's to type.
            if (!CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase) ||
                Arguments.Length < 3)
            {
                return [];
            }

            var before = String.Join(" ", Arguments[..^1]);
            var typed  = Arguments[^1];

            return typed.StartsWith('@')
                       ? Offered(cli.Node.DNSServerIds.Select(id => $"@{id}"), typed, before)
                       : Offered(OfferedRecordTypes,                           typed, before);

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (Arguments.Length < 2)
                return [ $"Usage: {Help()}" ];

            // What the DNS test of the web interface needs: running a test of
            // the name servers. The console may do everything; an account over
            // SSH what its roles let it.
            if (!cli.MayDo(Permission.Run(NodeResources.DNS), CommandName, out var refused))
                return [ refused ];

            #region The name, the record types and the server

            var name     = Arguments[1].Trim();
            var servers  = Arguments.Skip(2).Where(argument => argument.StartsWith('@')).ToArray();
            var types    = Arguments.Skip(2).Where(argument => !argument.StartsWith('@')).ToArray();

            if (servers.Length > 1)
                return [ $"Name one name server at most, not {String.Join(" and ", servers)}." ];

            if (!WWCPNode.TryParseRecordTypes(types, out var recordTypes, out var error, out _))
                return [ error ];

            Int32? server = null;

            if (servers.Length == 1)
            {

                // Said and nothing more, and not written to the log: nothing
                // was asked of anybody, which is what the log is a book of.
                server = cli.Node.DNSServerIndexOf(servers[0][1..]);

                if (server is null)
                {

                    var ids = cli.Node.DNSServerIds;

                    return [ ids.Count == 0
                                 ? $"This {cli.Node.Kind.Name} has no name server to ask on its own."
                                 : $"'{servers[0][1..]}' is none of this {cli.Node.Kind.Name}'s name servers, which are {String.Join(", ", ids)}." ];

                }

            }

            #endregion

            // The line the web interface writes, with the command line where
            // it names the account and "cli" where it says "web".
            cli.Node.Log.Info(
                $"{cli.Caller.Asker} asked this {cli.Node.Kind.Name} to resolve '{name}'.",
                cli.Caller.Tags("dns", "test")
            );

            return Answered(await cli.Node.ResolveAsync(name, recordTypes, server, CancellationToken));

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <name> [<record type> ...] [@<name server>] - look a name or an address up the way this node " +
                "does, or ask one of its name servers alone, by its id, its place in the list or its address, without the " +
                "cache; record types by mnemonic or number, A and AAAA unless others are named";

        #endregion


        #region (static) Answered(Result)

        /// <summary>
        /// What came back, as lines for the console: the question, what the
        /// answer was and where it came from, each record, and what was made
        /// of the certificate of every server asked over TLS or HTTPS.
        /// </summary>
        /// <remarks>
        /// Everything the answer had, because the command is asked when
        /// something does not work, and the one fact left out is the one that
        /// was needed. A refused certificate in particular is said with the
        /// steps that refused it: that a server over TLS answered nothing is
        /// mostly that.
        /// </remarks>
        public static String[] Answered(JObject Result)
        {

            var lines        = new List<String>();
            var name         = Result.Value<String>("name") ?? "";
            var recordTypes  = String.Join(", ", (Result["recordTypes"] as JArray ?? []).Select(type => type.ToString()));
            var serverId     = Result.Value<String>("serverId");
            var took         = Result.Value<Int64?>("runtime_ms") is Int64 runtime
                                   ? $" in {runtime} ms"
                                   : "";

            if (Result.Value<String>("turnedAround") is String turnedAround)
                lines.Add(turnedAround);

            var question     = $"{name} {recordTypes}" + (serverId is not null ? $" @{serverId}" : "");

            if (Result.Value<String>("responseCode") is String responseCode)
            {

                var flags = new[] {
                                Result.Value<Boolean?>("authoritative") == true ? "authoritative" : null,
                                Result.Value<Boolean?>("truncated")     == true ? "truncated"     : null,
                                Result.Value<String>  ("dnssec") is String dnssec ? $"DNSSEC {dnssec}" : null
                            }.Where(flag => flag is not null).ToArray();

                lines.Add($"{question} -> {responseCode} from {Result.Value<String>("answeredBy") ?? "unknown"}{took}" +
                          (flags.Length > 0 ? $", {String.Join(", ", flags)}" : ""));

            }
            else
                lines.Add($"{question} -> {(Result.Value<Boolean?>("timedOut") == true ? "timed out" : "failed")}{took}: " +
                          $"{Result.Value<String>("error") ?? "no reason was given"}");

            #region The records

            var answers = (Result["answers"] as JArray ?? []).OfType<JObject>().ToArray();

            if (answers.Length > 0)
            {

                var nameWidth = answers.Max(answer => (answer.Value<String>("name") ?? "").Length);
                var typeWidth = answers.Max(answer => (answer.Value<String>("type") ?? "").Length);
                var ttlWidth  = answers.Max(answer => answer.Value<Int64>("timeToLive").ToString().Length);

                foreach (var answer in answers)
                    lines.Add($"  {(answer.Value<String>("name") ?? "").PadRight(nameWidth)}  " +
                              $"{(answer.Value<String>("type") ?? "").PadRight(typeWidth)}  " +
                              $"{answer.Value<Int64>("timeToLive").ToString().PadLeft(ttlWidth)}  " +
                              $"{answer.Value<String>("value")}");

            }
            else if (Result.Value<String>("responseCode") is not null)
                lines.Add("  no records");

            if (Result.Value<Int64?>("more") is Int64 more && more > 0)
                lines.Add($"  ... and {more} more, not shown");

            #endregion

            #region The certificates

            foreach (var certificate in (Result["certificates"] as JArray ?? []).OfType<JObject>())
            {

                var accepted = certificate.Value<Boolean>("accepted");

                lines.Add($"  certificate of {certificate.Value<String>("server")}: " +
                          $"{WWCPNode.CertificateStatusOf(certificate.Value<String>("outcome"))}" +
                          (accepted ? "" : ", refused") +
                          (certificate.Value<String>("certificate") is String fingerprint ? $", SHA-256 {fingerprint}"      : "") +
                          (certificate.Value<String>("root")        is String root        ? $", root SHA-256 {root}"        : ""));

                // Why it was refused: where it was accepted, every step said
                // so, and nobody needs to read that again.
                if (!accepted)
                    foreach (var step in (certificate["steps"] as JArray ?? []).OfType<JObject>())
                        lines.Add($"    {step.Value<String>("level")}: {step.Value<String>("text")}");

            }

            #endregion

            return [.. lines];

        }

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

                if (!word.StartsWith(Typed, StringComparison.OrdinalIgnoreCase))
                    continue;

                yield return word.Equals(Typed, StringComparison.OrdinalIgnoreCase)
                                 ? SuggestionResponse.ParameterCompleted($"{Before} {word}")
                                 : SuggestionResponse.ParameterPrefix   ($"{Before} {word}");

            }

        }

        #endregion

    }

}
