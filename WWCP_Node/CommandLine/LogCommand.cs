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

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// How much of the log this command line shows: from which level up, or
    /// none of it.
    /// </summary>
    /// <remarks>
    /// For a session over SSH, which has a log of its own - see
    /// <see cref="SessionLog"/> - and starts at the level the console shows.
    /// Somebody chasing something asks for the debug entries without anybody
    /// else getting them, and somebody who wants to type in peace switches it
    /// off. The console's level is the switches' at the start, --verbose and
    /// --quiet, and stays what they said.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class LogCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                           ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(LogCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// What can be said after it, from the most to the least.
        /// </summary>
        private static readonly String[] Levels = [ "debug", "info", "notice", "warning", "error", "off" ];

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
            {

                if (CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase))
                    return Levels.Select(level => SuggestionResponse.ParameterPrefix($"{CommandName} {level}"));

                if (CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase))
                    return [ SuggestionResponse.CommandCompleted(CommandName) ];

                return [];

            }

            if (Arguments.Length == 2 && CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase))
                return Levels.Where (level => level.StartsWith(Arguments[1], StringComparison.OrdinalIgnoreCase)).
                              Select(level => level.Equals(Arguments[1], StringComparison.OrdinalIgnoreCase)
                                                  ? SuggestionResponse.ParameterCompleted($"{CommandName} {level}")
                                                  : SuggestionResponse.ParameterPrefix   ($"{CommandName} {level}"));

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (Arguments.Length > 2)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            if (cli.Caller.AtTheConsole)
                return Task.FromResult<String[]>([ "The console shows the log as --verbose and --quiet said at the start; " +
                                                   "a session over SSH chooses its own." ]);

            if (cli.SessionLog is not SessionLog sessionLog)
                return Task.FromResult<String[]>([ $"'{cli.Caller.Account!.Id}' may not read the log of this {cli.Node.Kind.Name}." ]);

            if (Arguments.Length == 1)
                return Task.FromResult<String[]>([ sessionLog.MinimumLevel is LogLevel shown
                                                       ? $"This session shows the log from {Name(shown)} up."
                                                       : "This session shows no log." ]);

            var wanted = Arguments[1].ToLowerInvariant();

            if (!Levels.Contains(wanted))
                return Task.FromResult<String[]>([ $"'{Arguments[1]}' is no level. Use one of {String.Join(", ", Levels)}." ]);

            sessionLog.MinimumLevel = wanted switch {
                                          "debug"    => LogLevel.Debug,
                                          "info"     => LogLevel.Info,
                                          "notice"   => LogLevel.Notice,
                                          "warning"  => LogLevel.Warning,
                                          "error"    => LogLevel.Error,
                                          _          => null
                                      };

            return Task.FromResult<String[]>([ sessionLog.MinimumLevel is LogLevel level
                                                   ? $"This session shows the log from {Name(level)} up now."
                                                   : "This session shows no log now." ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [debug|info|notice|warning|error|off] - how much of the log this session shows";

        #endregion


        #region (private static) Name(Level)

        private static String Name(LogLevel Level)

            => Level.ToString().ToLowerInvariant();

        #endregion

    }

}
