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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The connections of a node at its command line: which there are and how
    /// they stand, and the key of a server that waits for an admin to confirm
    /// it - confirmed or turned down (mDNS-Concept.md, B.4 and B.5).
    /// </summary>
    /// <remarks>
    /// "connection list", "connection confirm-key cs1 SHA256:...",
    /// "connection reject-key cs1". The same as the buttons of the Connections
    /// page, at the same right: confirming a key decides whom this node
    /// believes. Confirm-key takes the key that was shown as well, so that one
    /// that took its place meanwhile (Q7) is not confirmed unseen; without it,
    /// whichever waits.
    /// </remarks>
    /// <param name="CLI">The command line of the node.</param>
    public class ConnectionCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                                  ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: "ConnectionCommand" without its last seven
        /// characters.
        /// </summary>
        public static readonly String CommandName = nameof(ConnectionCommand)[..^7].ToLowerFirstChar();

        private static readonly String[] Subcommands = [ "list", "confirm-key", "reject-key" ];

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

            if (!CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                return [];

            var before = String.Join(" ", Arguments[..^1]);

            // The subcommand, then the connections that wait.
            var offered = Arguments.Length == 2
                              ? Subcommands
                              : Arguments.Length == 3 && Arguments[1] is "confirm-key" or "reject-key"
                                    ? cli.Node.Connections.Connections.Where(entry => entry.KeyAwaiting is not null || entry.SshLearnedHostKey is not null || entry.ServerKeyPinLearned is not null).
                                                                       Select(entry => entry.Id).
                                                                       ToArray()
                                    : [];

            return offered.Where (word => word.StartsWith(Arguments[^1], StringComparison.OrdinalIgnoreCase)).
                           Select(word => word.Equals(Arguments[^1], StringComparison.OrdinalIgnoreCase)
                                              ? SuggestionResponse.ParameterCompleted($"{before} {word}")
                                              : SuggestionResponse.ParameterPrefix   ($"{before} {word}"));

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (Arguments.Length < 2)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            if (cli.Node.Connections is null)
                return Task.FromResult<String[]>([ $"This {cli.Node.Kind.Name} keeps no connections." ]);

            switch (Arguments[1].ToLowerInvariant())
            {

                case "list":
                    {

                        if (!cli.MayDo(Permission.Read(cli.Node.ConnectionsResource), CommandName, out var refused))
                            return Task.FromResult<String[]>([ refused ]);

                        return Task.FromResult(List());

                    }

                case "confirm-key":
                case "reject-key":
                    {

                        if (Arguments.Length < 3 || Arguments.Length > (Arguments[1] == "confirm-key" ? 4 : 3))
                            return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

                        if (!cli.MayDo(Permission.Edit(cli.Node.ConnectionsResource), CommandName, out var refused))
                            return Task.FromResult<String[]>([ refused ]);

                        var id   = Arguments[2];
                        var who  = cli.Caller.Account?.Id.ToString() ?? "the console";

                        if (Arguments[1] == "confirm-key")
                        {

                            if (!cli.Node.Connections.TryConfirmKey(id, who, Arguments.Length == 4 ? Arguments[3] : null, out var confirmed, out var error))
                                return Task.FromResult<String[]>([ error ]);

                            cli.Node.Log.Notice($"{cli.Caller.Asker} confirmed the key {confirmed} of connection '{id}' at the command line.",
                                                cli.Caller.Tags("ocpp", "connections", "security"));

                            return Task.FromResult<String[]>([ $"Confirmed {confirmed} for '{id}': it is pinned from now on, and the connection is made again with it." ]);

                        }

                        else
                        {

                            if (!cli.Node.Connections.TryRejectKey(id, who, out var rejected, out var error))
                                return Task.FromResult<String[]>([ error ]);

                            cli.Node.Log.Notice($"{cli.Caller.Asker} turned down the key {rejected} of connection '{id}' at the command line.",
                                                cli.Caller.Tags("ocpp", "connections", "security"));

                            return Task.FromResult<String[]>([ $"Turned down {rejected} for '{id}': the connection is not made until somebody saves it again or confirms a key." ]);

                        }

                    }

                default:
                    return Task.FromResult<String[]>([ $"'{Arguments[1]}' is no subcommand of {CommandName}; there are {String.Join(", ", Subcommands)}." ]);

            }

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} list | confirm-key <id> [<key>] | reject-key <id> - the connections and how they stand, and the key " +
                "of a server that waits for an admin: confirmed, and pinned from now on, or turned down";

        #endregion


        #region (private) List()

        /// <summary>
        /// One line for each connection: its id, its URL, how it stands, and a
        /// key that waits.
        /// </summary>
        private String[] List()
        {

            var states  = cli.Node.ConnectionStates;
            var lines   = new List<String>();

            foreach (var entry in cli.Node.Connections.Connections.OrderBy(entry => entry.Id))
            {

                var status = states.TryGetValue(entry.Id, out var state) ? state.Status.ToString() : "not tried";

                lines.Add($"{entry.Id}  {entry.URL}  {status}  {entry.Description.FirstText()}");

                if (entry.KeyAwaiting is String awaiting)
                    lines.Add($"    waits for an admin to confirm {awaiting}: {CommandName} confirm-key {entry.Id} {awaiting}");

                else if ((entry.SshLearnedHostKey ?? entry.ServerKeyPinLearned?.ToString()) is String learned)
                    lines.Add($"    learned {learned} on its first connection, on probation: {CommandName} confirm-key {entry.Id} {learned}");

                if (entry.KeyRejected is String rejected)
                    lines.Add($"    {entry.KeyRejectedBy ?? "an admin"} turned down {rejected}; save the connection again to have it asked anew");

            }

            return lines.Count > 0
                       ? [.. lines]
                       : [ $"This {cli.Node.Kind.Name} has no connections." ];

        }

        #endregion

    }

}
