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

using System.Threading.Channels;

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The node's log as one command line shows it: above the line being
    /// typed, from a level of its own, while it is open.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What the console has, for a session over SSH: the log writing while
    /// somebody types, and the half-typed line surviving it. Each session has
    /// its own, so that one who asks for the debug entries does not get them
    /// shown to everybody else.
    /// </para>
    /// <para>
    /// The log calls its listeners on the thread that is logging, and a
    /// session is at the far end of a network. So an entry is only put in a
    /// queue here and written by a task of its own: a client that reads slowly,
    /// or not at all, never holds up the node. The queue is bounded, and what
    /// does not fit is left out and said to have been - "12 entries left out" -
    /// rather than kept until the process runs out of memory for somebody who
    /// has stopped reading.
    /// </para>
    /// <para>
    /// Whether the account may read the log is asked before every entry, as
    /// the event stream of the web interface asks it: a role taken away stops
    /// the entries at once, not at the next sign-in.
    /// </para>
    /// </remarks>
    public sealed class SessionLog : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// How many entries wait to be written before the next is left out.
        /// </summary>
        public const Int32 QueueLength = 500;

        private readonly EventLog                 log;
        private readonly ICLI                     cli;
        private readonly Func<Boolean>            mayRead;
        private readonly Action<LogEntry>         handler;
        private readonly Channel<LogEntry>        queue    = Channel.CreateBounded<LogEntry>(new BoundedChannelOptions(QueueLength) {
                                                                 FullMode      = BoundedChannelFullMode.Wait,
                                                                 SingleReader  = true
                                                             });
        private readonly Task                     writer;
        private          Int64                    leftOut;

        #endregion

        #region Properties

        /// <summary>
        /// Entries below this level are not shown here; null shows none.
        /// </summary>
        public LogLevel?  MinimumLevel  { get; set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Show the given log on the given command line, from the given level.
        /// </summary>
        /// <param name="Log">The node's log.</param>
        /// <param name="CLI">The command line to show it on.</param>
        /// <param name="MinimumLevel">The level shown from; null for none.</param>
        /// <param name="MayRead">Whether the account may read the log now.</param>
        public SessionLog(EventLog       Log,
                          ICLI           CLI,
                          LogLevel?      MinimumLevel,
                          Func<Boolean>  MayRead)
        {

            this.log           = Log;
            this.cli           = CLI;
            this.MinimumLevel  = MinimumLevel;
            this.mayRead       = MayRead;

            this.handler       = Queue;
            this.writer        = Task.Run(WriteAsync);

            log.OnLogged      += handler;

        }

        #endregion


        #region (private) Queue(Entry)

        private void Queue(LogEntry Entry)
        {

            if (MinimumLevel is not LogLevel level || Entry.Level < level)
                return;

            if (!queue.Writer.TryWrite(Entry))
                Interlocked.Increment(ref leftOut);

        }

        #endregion

        #region (private) WriteAsync()

        private async Task WriteAsync()
        {
            try
            {
                await foreach (var entry in queue.Reader.ReadAllAsync())
                {

                    if (!mayRead())
                        continue;

                    var missed = Interlocked.Exchange(ref leftOut, 0);

                    cli.WriteBlock(terminal => {

                        if (missed > 0)
                            terminal.WriteLine($"... {missed} entr{(missed == 1 ? "y" : "ies")} left out: this session did not take them as fast as they came.", ConsoleColor.DarkGray);

                        Write(terminal, entry);

                    });

                }
            }
            catch
            {
                // The terminal is gone, or has stopped taking what it is sent:
                // nothing more is shown here, and the node carries on.
            }
        }

        #endregion

        #region (static) Write(Terminal, Entry)

        /// <summary>
        /// One entry, on one line, coloured as the console colours it.
        /// </summary>
        public static void Write(ICLITerminal  Terminal,
                                 LogEntry      Entry)
        {

            Terminal.Write(Entry.Timestamp.ToLocalTime().ToString("HH:mm:ss.fff") + " ", ConsoleColor.DarkGray);
            Terminal.Write(Entry.LevelName.PadRight(8), ConsoleLog.ColourOf(Entry.Level));

            if (Entry.Tags.Count > 0)
                Terminal.Write(String.Join(" ", Entry.Tags) + " ", ConsoleColor.DarkCyan);

            Terminal.WriteLine(Entry.Message);

        }

        #endregion

        #region DisposeAsync()

        /// <summary>
        /// Show nothing more.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            log.OnLogged -= handler;

            queue.Writer.TryComplete();

            try
            {
                await writer.WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            { }

        }

        #endregion

    }

}
