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
    /// Who is at this node's command line over SSH now: which account, from
    /// where, with which key, since when.
    /// </summary>
    /// <remarks>
    /// What the configuration is read with on the web interface is what this
    /// needs: who is signed in, and from where, is about the node and not about
    /// the one who asks.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class WhoCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                           ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(WhoCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(NodeResources.Configuration), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var sessions = cli.Node.CommandLineSessions;

            if (sessions.Count == 0)
                return Task.FromResult<String[]>([ $"Nobody is at the command line of this {cli.Node.Kind.Name} over SSH." ]);

            var mine  = cli.Caller.Session?.ConnectionId;
            var width = sessions.Max(session => session.Account.Length);

            return Task.FromResult<String[]>([
                       .. sessions.Select(session => $"{session.Account.PadRight(width)}  from {session.From}, since {session.Since.ToLocalTime():HH:mm}" +
                                                     (session.Key is not null ? $", key {session.Key}" : "") +
                                                     (session.Id == mine ? "  <- this one" : ""))
                   ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - who is at this command line over SSH now";

        #endregion

    }

}
