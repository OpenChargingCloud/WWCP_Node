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

using System.Reflection;
using System.Runtime.InteropServices;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The command line of a running node: what every kind of node can be told
    /// at its console, and the console itself, from the first prompt until
    /// 'quit', Ctrl+C or a service manager's SIGTERM.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything a command needs is reachable from here: the node, and
    /// through it its configuration, its log and everything the JSON API can
    /// do. A command is a second way of asking for the same thing as the web
    /// interface - never an implementation of its own.
    /// </para>
    /// <para>
    /// Commands are not listed anywhere. The commands every node has are found
    /// in this library, as anything that implements ICLICommand and can be
    /// built from a NodeCLI; a kind of node derives its own command line from
    /// this one and registers its type as well, so that its commands - built
    /// from that type - are found in its assembly. A new command is a new file
    /// and nothing else.
    /// </para>
    /// <para>
    /// Every kind of node had a command line of its own, and all eight were
    /// this: a node, a prompt, and the same seven-and-forty lines of console
    /// in its Program.cs - and the command they all had, syncNTS, in a copy of
    /// its own, one of them older than the rest.
    /// </para>
    /// <para>
    /// Not in a namespace called CLI: Styx's command line class is called
    /// that, and a namespace of the same name nearer to a kind's code would be
    /// found first.
    /// </para>
    /// </remarks>
    public class NodeCLI : org.GraphDefined.Vanaheimr.CLI.CLI
    {

        #region Properties

        /// <summary>
        /// The node these commands are about.
        /// </summary>
        public WWCPNode  Node  { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the command line of the given node, with the commands every
        /// node has. A kind of node that derives its own registers its type
        /// for its own commands.
        /// </summary>
        /// <param name="Node">The running node.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands.</param>
        public NodeCLI(WWCPNode           Node,
                       params Assembly[]  AssembliesWithCLICommands)

            : base(AssembliesWithCLICommands)

        {

            this.Node = Node;

            RegisterCLIType(typeof(NodeCLI));

        }

        #endregion


        #region (protected override) GetPrompt()

        /// <summary>
        /// What stands in front of the command being typed: the kind of node,
        /// unless it says better - so that the consoles of a bench full of
        /// nodes need not be told apart by what scrolls past on them.
        /// </summary>
        protected override String GetPrompt()

            => $"{Node.Kind.Name}> ";

        #endregion


        #region RunUntilStopped(AlsoStoppedBy = null)

        /// <summary>
        /// The console, until 'quit', Ctrl+C, SIGTERM or the given task says
        /// the node is to stop: a prompt where somebody can type, and nothing
        /// but waiting where nobody can.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Whether anybody can type here at all. Started from a script, from a
        /// service manager or in CI, the process has no terminal on its input
        /// and Console.ReadKey throws rather than waiting - and there would be
        /// nobody to type anyway. Then the node simply runs, and the web
        /// interface is how it is spoken to. The output counts too: the prompt
        /// is drawn by moving the cursor, and with the output going into
        /// "| tee" or a file there is no cursor to move. Measured on Windows
        /// with the vehicle, whose prompt then looked at its input only: the
        /// prompt threw while drawing itself, before a key was pressed, and the
        /// program was gone within 200 ms of its banner - with exit code 0.
        /// </para>
        /// <para>
        /// Ctrl+C means stop; the prompt adds a handler of its own for it,
        /// which cancels whatever command is running, and both fire. 'quit' is
        /// the same thing said politely. SIGTERM, what a service manager sends,
        /// means stop as well - the energy meter's, which runs as a service,
        /// was the first to listen for it.
        /// </para>
        /// </remarks>
        /// <param name="AlsoStoppedBy">A task whose end stops the node as well, as the energy meter's Modbus server's does.</param>
        public async Task RunUntilStopped(Task? AlsoStoppedBy = null)
        {

            var canBeTypedAt = !Console.IsInputRedirected &&
                               !Console.IsOutputRedirected;

            Console.WriteLine(canBeTypedAt
                                  ? "Type 'help' for what can be typed here, 'quit' or Ctrl+C to stop."
                                  : "Press Ctrl+C to stop. (No terminal here, so nothing to type at.)");
            Console.WriteLine();

            var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            void OnCancelKeyPress(Object? Sender, ConsoleCancelEventArgs Event)
            {
                Event.Cancel = true;
                stopped.TrySetResult();
            }

            Console.CancelKeyPress += OnCancelKeyPress;

            PosixSignalRegistration? terminated = null;

            try
            {
                terminated = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => {
                                 context.Cancel = true;
                                 stopped.TrySetResult();
                             });
            }
            catch (PlatformNotSupportedException)
            {
                // Where there is no SIGTERM there is nothing that sends one.
            }

            _ = AlsoStoppedBy?.ContinueWith(_ => stopped.TrySetResult(), TaskScheduler.Default);

            var promptLeft = false;

            try
            {

                if (canBeTypedAt)
                    promptLeft = await Prompt(stopped.Task);

                else
                    await stopped.Task;

            }
            finally
            {

                // The console back to the log alone. A prompt left standing -
                // Ctrl+C, SIGTERM or the task stopped the node while somebody
                // was typing - would otherwise be put back under every entry
                // the shutdown writes, and stay the last line on the screen.
                // Its line is ended first, or the first of those entries would
                // start right behind what was typed. With a lock of its own,
                // as after a prompt that broke.
                var padlock = new Lock();

                lock (padlock)
                {

                    Node.ShareConsoleWith(write => { lock (padlock) { write(); } });

                    if (promptLeft)
                        Console.WriteLine();

                }

                Console.CancelKeyPress -= OnCancelKeyPress;
                terminated?.Dispose();

            }

        }

        #endregion

        #region (private) Prompt(Stopped)

        /// <summary>
        /// The prompt, until it is quit or the node is to stop - and a new one
        /// where one broke. Says whether a prompt is still standing, with
        /// whatever was being typed at it when the node was told to stop.
        /// </summary>
        private async Task<Boolean> Prompt(Task Stopped)
        {

            var brokeAtOnce = false;

            while (true)
            {

                // From here two things write on one screen: this command line,
                // and the node's log from whichever thread did the thing it is
                // reporting. So the log stops writing of its own accord and
                // asks the command line for the screen instead - which takes
                // the half-typed command off it, writes the entry whole, and
                // puts the command back with the cursor where it was.
                Node.ShareConsoleWith(WriteBlock);

                // On a thread of its own, because Console.ReadKey blocks the one
                // it is called on: awaited directly, the command line would keep
                // this thread inside ReadKey and Ctrl+C would have nobody left
                // to wake.
                var since   = System.Diagnostics.Stopwatch.GetTimestamp();
                var typing  = Task.Run(Run);

                await Task.WhenAny(Stopped, typing);

                // Quit - or stopped, and then the prompt is still reading keys.
                if (!typing.IsFaulted)
                    return !typing.IsCompleted;

                // A command line that broke is not somebody asking for the node
                // to stop. What broke it first, in the vehicle and the charging
                // station, was a line typed wider than the window: until Styx
                // learned to show such a line through a window onto it, it
                // threw out of the line editor - measured in 80 columns,
                // "Parameter 'left', actual value was 80" - and a program that
                // took that for 'quit' shut down with exit code 0. That cause is
                // gone; this is for the next one.
                //
                // The console goes back to the log first, with a lock of its
                // own, because the command line's way of writing may be what
                // broke: a prompt that fails while drawing itself stays
                // registered as the line on the screen, and every entry after
                // that fails trying to take it off again.
                //
                // Then a new prompt - unless the last one was already a new one
                // and broke again the moment it started. That is a console a
                // prompt cannot be drawn on at all, and asking a third time
                // would only fail a third time. How fast the first one broke
                // says nothing: a line pasted in straight after the start is
                // still a line.
                var padlock = new Lock();

                Node.ShareConsoleWith(write => { lock (padlock) { write(); } });

                var atOnce = System.Diagnostics.Stopwatch.GetElapsedTime(since) < TimeSpan.FromSeconds(1);
                var giveUp = atOnce && brokeAtOnce;

                brokeAtOnce = atOnce;

                // On one line, as every entry is: the message of an exception
                // may carry line breaks of its own, and a second line of an
                // entry has no time, no level and no tags.
                var why = typing.Exception?.GetBaseException().Message.ReplaceLineEndings(" ");

                Node.Log.Warning(
                    $"The command line stopped working: {why} " +
                    (giveUp
                         ? $"A new one broke again as soon as it started, so there is none; the {Node.Kind.Name} keeps running, and Ctrl+C stops it."
                         : "A new one is started."),
                    "cli"
                );

                if (giveUp)
                {
                    await Stopped;
                    return false;
                }

            }

        }

        #endregion

    }

}
