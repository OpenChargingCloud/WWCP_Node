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
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// Multicast DNS at a node's command line (mDNS-Concept.md, B.5): how it is
    /// set and what it is doing, and a name under ".local" asked for.
    /// </summary>
    /// <remarks>
    /// "mdns status", "mdns resolve lc1.local". What the Multicast DNS card of
    /// the DNS page shows, read at the right to read the DNS settings; asking
    /// for a name at the right to run the DNS test, as queryDNS does.
    /// </remarks>
    /// <param name="CLI">The command line of the node.</param>
    public class MulticastDNSCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                                    ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "mdns";

        private static readonly String[] Subcommands = [ "status", "resolve" ];

        #endregion

        #region Suggest(Arguments)

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

            if (!CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase) || Arguments.Length != 2)
                return [];

            return Subcommands.Where (word => word.StartsWith(Arguments[1], StringComparison.OrdinalIgnoreCase)).
                               Select(word => word.Equals(Arguments[1], StringComparison.OrdinalIgnoreCase)
                                                  ? SuggestionResponse.ParameterCompleted($"{CommandName} {word}")
                                                  : SuggestionResponse.ParameterPrefix   ($"{CommandName} {word}"));

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (Arguments.Length < 2)
                return [ $"Usage: {Help()}" ];

            switch (Arguments[1].ToLowerInvariant())
            {

                case "status":
                    {

                        if (!cli.MayDo(Permission.Read(NodeResources.DNS), CommandName, out var refused))
                            return [ refused ];

                        return Status(cli.Node.DNSConfigurationJSON()["multicast"] as JObject ?? []);

                    }

                case "resolve":
                    {

                        if (Arguments.Length != 3)
                            return [ $"Usage: {Help()}" ];

                        if (!cli.MayDo(Permission.Run(NodeResources.DNS), CommandName, out var refused))
                            return [ refused ];

                        var name = Arguments[2].Trim();

                        if (!MulticastDNS.IsLocalName(name))
                            return [ $"'{name}' is no name of Multicast DNS: those end in .local. Ask queryDNS for it." ];

                        cli.Node.Log.Info($"{cli.Caller.Asker} asked this {cli.Node.Kind.Name} to resolve '{name}' by Multicast DNS.",
                                          cli.Caller.Tags("dns", "mdns", "test"));

                        var resolved = await cli.Node.ResolveHostAsync(name, CancellationToken);

                        return resolved.Found
                                   ? [ $"{name}: {String.Join(", ", resolved.Addresses)}" ]
                                   : [ $"{name}: {resolved.Error}" ];

                    }

                default:
                    return [ $"'{Arguments[1]}' is no subcommand of {CommandName}; there are {String.Join(" and ", Subcommands)}." ];

            }

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} status | resolve <name>.local - how Multicast DNS is set and what it is doing, and a name under .local asked for";

        #endregion


        #region (private static) Status(Multicast)

        /// <summary>
        /// The lines of "mdns status".
        /// </summary>
        private static String[] Status(JObject Multicast)
        {

            var lines      = new List<String>();
            var responder  = Multicast["responder"] as JObject ?? [];
            var interfaces = (Multicast["interfaces"] as JArray ?? []).Select(name => name.ToString()).ToArray();

            lines.Add($"asking:     {(Multicast.Value<Boolean>("enabled") ? (Multicast.Value<Boolean>("asking") ? "on" : "on, from the first name under .local") : "off")}");
            lines.Add($"interfaces: {(interfaces.Length > 0 ? String.Join(", ", interfaces) : "all that can multicast")}" +
                      $", over {(Multicast.Value<Boolean>("ipv4") && Multicast.Value<Boolean>("ipv6") ? "IPv4 and IPv6" : Multicast.Value<Boolean>("ipv4") ? "IPv4" : "IPv6")}");
            lines.Add($"answering:  {(responder.Value<Boolean>("enabled") ? $"{responder.Value<String>("name")}, {responder.Value<String>("state")}" : "off")}" +
                      ((responder["addresses"] as JArray)?.Count > 0 ? $" ({String.Join(", ", responder["addresses"]!.Select(address => address.ToString()))})" : ""));

            if (responder.Value<String>("problem") is String problem)
                lines.Add($"            {problem}");

            foreach (var answer in (Multicast["answers"] as JArray ?? []).OfType<JObject>())
                lines.Add($"asked:      {answer.Value<String>("name")} -> " +
                          (answer.Value<Boolean>("answered")
                               ? String.Join(", ", (answer["addresses"] as JArray ?? []).Select(address => address.ToString()))
                               : answer.Value<Boolean>("timedOut") ? "nobody answered" : "no address"));

            return [.. lines];

        }

        #endregion

    }

}
