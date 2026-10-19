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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The groups of time servers of a node, one to a line: its name, whether
    /// it is asked, whom, how often, and what the last check found.
    /// </summary>
    /// <remarks>
    /// What the tabs of the NTS page say, at the permission that reads it. The
    /// names are the ones syncNTS takes, so that the next thing somebody types
    /// can be "syncNTS local".
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class ListNTSGroupsCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                                     ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(ListNTSGroupsCommand)[..^7].ToLowerFirstChar();

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

            if (Arguments.Length > 1)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            if (!cli.MayDo(Permission.Read(NodeResources.NTS), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var groups = cli.Node.NTSGroups;

            if (groups.Count == 0)
                return Task.FromResult<String[]>([ $"This {cli.Node.Kind.Name} checks its clock against no group of time servers." ]);

            var named  = groups.Select(group => group.DisplayName is { } name ? $"{group.Id} \"{NameOf(name)}\"" : group.Id).ToArray();
            var width  = named.Max(name => name.Length);
            var lines  = new List<String>();

            for (var i = 0; i < groups.Count; i++)
                lines.Add($"{named[i].PadRight(width)}  {(groups[i].Enabled ? "on " : "off")}  {Said(groups[i])}");

            if (cli.Node.NTSGroupOf(NTSGroup.LegalId) is null)
                lines.Add($"No group is legal time on this {cli.Node.Kind.Name}.");

            return Task.FromResult<String[]>([.. lines]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - the groups of time servers: whether each is asked, whom, how often, and what its last check found";

        #endregion


        #region (private static) Said(Group)

        /// <summary>
        /// One group after its name and its switch: its servers, how many of
        /// them must answer, how often it is asked, and its last check.
        /// </summary>
        private static String Said(NTSGroup Group)
        {

            var servers  = Group.Sources.Sources.Select(source => source.Hostname.Trimmed).ToArray();
            var asked    = servers.Length == 0
                               ? "no time server yet"
                               : String.Join(", ", servers) +
                                 (servers.Length > 1 ? $" - {Group.Sources.MinServers} must answer" : "");

            var every    = Group.CheckEvery.TotalSeconds % 60 == 0
                               ? $"every {Group.CheckEvery.TotalMinutes.ToString("0", CultureInfo.InvariantCulture)} min"
                               : $"every {Group.CheckEvery.TotalSeconds.ToString("0", CultureInfo.InvariantCulture)} s";

            var checkedAt = Group.LastCheck is DateTimeOffset at
                                ? $"checked {at.ToLocalTime():HH:mm:ss}, {SyncNTSCommand.Milliseconds(Group.LastCheckOffset?.TotalMilliseconds, Signed: true)}" +
                                  (Group.LastCheckAnswered is Int32 answered && Group.LastCheckAsked is Int32 of ? $", {answered} of {of} answered" : "")
                                : "never checked";

            return $"{asked}; {every}; {checkedAt}" +
                   (Group.IsLegal && Group.Authority is String authority ? $"; legal time of {authority}, as the operator says" : "");

        }

        #endregion

        #region (private static) NameOf(DisplayName)

        /// <summary>
        /// What a console calls a group, which speaks English: the name for
        /// every language, then the English one, then any.
        /// </summary>
        private static String NameOf(IReadOnlyDictionary<String, String> DisplayName)

            => DisplayName.GetValueOrDefault(NTSConfiguration.AnyLanguage) ??
               DisplayName.GetValueOrDefault("en")                         ??
               DisplayName.Values.First();

        #endregion

    }

}
