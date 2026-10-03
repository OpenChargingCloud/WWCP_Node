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

using System.Diagnostics;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// Whether a node that was told to stop actually does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These exist because it once did not. A browser on the Logs page holds a
    /// request open that is waiting for the next log entry rather than for its
    /// socket, so the server closing that socket underneath it does not wake
    /// it - and Hermod waits for every request it started before it reports
    /// itself stopped. A node with one browser watching would therefore never
    /// finish shutting down, which on a machine being restarted means waiting
    /// out a kill timeout instead of stopping. Stop() ends the event streams
    /// before it stops the server - the node's own, where each kind of node
    /// used to end them itself - and these tests are what says it still does.
    /// </para>
    /// <para>
    /// One thing cannot be undone once it happens: a stop that never returns
    /// cannot be cancelled, so a test that hits it leaves it running, and a
    /// later test in the same run can then stop in milliseconds where on its
    /// own it hangs. So the first such test poisons the rest: every stopping
    /// test after one that was left waiting is reported inconclusive rather
    /// than passed. The run still shows the real failure, and shows plainly
    /// that it cannot vouch for what came after it.
    /// </para>
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region Data

        /// <summary>
        /// How long stopping may take before this counts as not stopping.
        /// </summary>
        /// <remarks>
        /// Stopping takes single-digit milliseconds when it works, and forever
        /// when it does not - so anything in between is a slow machine rather
        /// than a near miss, and this is set where a slow machine still passes.
        /// </remarks>
        private static readonly TimeSpan  MustStopWithin = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Whether a stop in this run was given up on and left running -
        /// static, and never reset: the abandoned stop is still there for the
        /// rest of the process.
        /// </summary>
        private static Boolean  aStopWasLeftRunning;

        /// <summary>
        /// Whether this test's node is the one whose stop was left running -
        /// which TearDown then does not ask to stop a second time, and wait on
        /// for ever too.
        /// </summary>
        private Boolean  nodeLeftRunning;

        #endregion

        #region (private) NothingLeftRunning()

        private static void NothingLeftRunning()
        {

            if (aStopWasLeftRunning)
                Assert.Inconclusive(
                    "An earlier test in this run was left waiting for a stop that never returned, and that stop is " +
                    "still running. Whatever this test would report cannot be trusted - run it on its own."
                );

        }

        #endregion

        #region (private) NoHeartbeat()

        /// <summary>
        /// No heartbeat on the event streams opened from here on.
        /// </summary>
        /// <remarks>
        /// So that a stream the node does not end itself waits for ever, as it
        /// did before there was a heartbeat - which is what the tests of a stop
        /// with browsers watching are about. With one, the next heartbeat finds
        /// the socket gone and ends the stream fifteen seconds later, and those
        /// tests passed against a node that left its streams to that.
        /// </remarks>
        private void NoHeartbeat()
        {

            Assert.That(Node.JSONAPI, Is.Not.Null, $"This {Node.Kind.Name} has no JSON API.");

            Node.JSONAPI!.EventStreamHeartbeat = TimeSpan.Zero;

        }

        #endregion

        #region (private) HoldTheStopUntilItsLineIsRead(Streams)

        /// <summary>
        /// Hold the stop at its first line - "The ... is shutting down." -
        /// until every one of the given streams has been sent it; and say,
        /// once it has stopped, whether they all were.
        /// </summary>
        /// <remarks>
        /// <para>
        /// That line is written into the log before the node ends its streams,
        /// and so into every stream that is open: it wakes each parked handler,
        /// which writes it and parks again. Written while the socket is still
        /// open, that is all it does. But it used to rescue a node that left its
        /// streams open, now and then: where the line came after the server had
        /// closed the socket, its write failed, which ended the stream, and the
        /// stop got through. The roaming hub caught such a node in seven runs
        /// out of eight.
        /// </para>
        /// <para>
        /// Held here until every stream has the line, it always finds its
        /// socket open, and a stream the node does not end itself is parked
        /// again for good - so such a node hangs every time. The listener runs
        /// on the thread that logs the line, which is the one stopping the
        /// node, and outside the log's lock.
        /// </para>
        /// </remarks>
        private Func<Boolean> HoldTheStopUntilItsLineIsRead(params EventStream[] Streams)
        {

            var line  = $"The {Node.Kind.Name} is shutting down.";
            var read  = false;

            void Hold(LogEntry Entry)
            {
                if (Entry.Message == line)
                    read = Streams.All(stream => stream.ReadUntil(line).GetAwaiter().GetResult());
            }

            Node.Log.OnLogged += Hold;

            return () => read;

        }

        #endregion

        #region (private) TimeTheStop(Node)

        /// <summary>
        /// How long it took to stop - and, when it does not stop at all, how
        /// long this test was prepared to wait.
        /// </summary>
        /// <remarks>
        /// The stop is raced against a timer rather than simply awaited,
        /// because the failure this is about is a stop that never returns:
        /// awaiting it would hang the test run instead of failing it, and a
        /// hung run says nothing about which test hung.
        /// </remarks>
        private async Task<TimeSpan> TimeTheStop(WWCPNode Node)
        {

            var clock     = Stopwatch.StartNew();

            var stopping  = Node.Stop();
            var giveUp    = Task.Delay(MustStopWithin);

            var first     = await Task.WhenAny(stopping, giveUp);

            clock.Stop();

            if (first == stopping)
            {
                // Observed, so that a stop which failed rather than hung is
                // reported as the exception it threw.
                await stopping;
                return clock.Elapsed;
            }

            // Left running, because there is no way not to: awaiting the stop
            // that did not finish is exactly the hang this is here to report
            // instead of. What can be done is to stop trusting what comes next.
            aStopWasLeftRunning  = true;
            nodeLeftRunning      = true;

            return MustStopWithin + TimeSpan.FromSeconds(1);

        }

        #endregion


        #region StopsWithNobodyWatching()

        [Test]
        public async Task StopsWithNobodyWatching()
        {

            NothingLeftRunning();

            var elapsed = await TimeTheStop(Node);

            Assert.That(elapsed, Is.LessThan(MustStopWithin),
                        $"An idle {Node.Kind.Name} took {elapsed.TotalSeconds:F1} s to stop.");

        }

        #endregion

        #region StopsWithABrowserOnTheLogsPage()

        /// <summary>
        /// The regression test: one open event stream, which is what a browser
        /// showing the Logs page is, and then a stop.
        /// </summary>
        [Test]
        public async Task StopsWithABrowserOnTheLogsPage()
        {

            NothingLeftRunning();
            NoHeartbeat();

            using var http   = await SignedIn();

            // Settled, not merely opened: a handler that is still writing is
            // ended by its socket closing, and this test would then pass
            // against a node that cannot shut down at all.
            using var stream = await EventStream.OpenAndSettle(Node, http);

            // And now left alone, which is what a browser sitting on the Logs
            // page is when the node is told to stop - except for the stop's own
            // line, which it is sent before anything else happens.
            var lineRead     = HoldTheStopUntilItsLineIsRead(stream);

            var elapsed      = await TimeTheStop(Node);

            Assert.Multiple(() => {

                Assert.That(lineRead(), Is.True,
                            "The stream was not sent the line the stop begins with, so this cannot tell a stop that ends the streams from one that line rescues.");

                Assert.That(elapsed, Is.LessThan(MustStopWithin),
                            $"This {Node.Kind.Name} with one open event stream took {elapsed.TotalSeconds:F1} s to stop. " +
                            "The streams are not being ended before the server is.");

            });

        }

        #endregion

        #region StopsWithSeveralBrowsersOnTheLogsPage()

        /// <summary>
        /// Several of them, because ending the streams has to end all of them -
        /// one cancellation token that only the first stream observed would
        /// pass the test above and hang a real node.
        /// </summary>
        [Test]
        public async Task StopsWithSeveralBrowsersOnTheLogsPage()
        {

            NothingLeftRunning();
            NoHeartbeat();

            var browsers = new List<HttpClient>();
            var streams  = new List<EventStream>();

            try
            {

                for (var i = 0; i < 4; i++)
                {
                    var browser = await SignedIn();
                    browsers.Add(browser);
                    streams. Add(await EventStream.OpenAndSettle(Node, browser));
                }

                var lineRead = HoldTheStopUntilItsLineIsRead([.. streams]);

                var elapsed  = await TimeTheStop(Node);

                Assert.Multiple(() => {

                    Assert.That(lineRead(), Is.True,
                                "Not every stream was sent the line the stop begins with, so this cannot tell a stop that ends the streams from one that line rescues.");

                    Assert.That(elapsed, Is.LessThan(MustStopWithin),
                                $"This {Node.Kind.Name} with {streams.Count} open event streams took {elapsed.TotalSeconds:F1} s to stop.");

                });

            }
            finally
            {
                foreach (var stream  in streams)   stream. Dispose();
                foreach (var browser in browsers)  browser.Dispose();
            }

        }

        #endregion

        #region StopsAfterItsStreamHasSentAHeartbeat()

        /// <summary>
        /// One open event stream that has said ": keep-alive" at least once, and
        /// then a stop.
        /// </summary>
        /// <remarks>
        /// A stream that has sent a heartbeat is waiting for its next event
        /// across it, with its question to the enumerator still open, and an
        /// enumerator that is still waiting cannot be disposed: the stream
        /// cancels it and waits for it to stop before it lets go. That is a
        /// stop the other tests here never reach - their streams are stopped
        /// long before the default heartbeat of 15 seconds is due. A heartbeat
        /// of a second: longer than the quiet moment OpenAndSettle leaves, so
        /// that it comes after the stream has settled rather than while it
        /// does.
        /// </remarks>
        [Test]
        public async Task StopsAfterItsStreamHasSentAHeartbeat()
        {

            NothingLeftRunning();

            Assert.That(Node.JSONAPI, Is.Not.Null, $"This {Node.Kind.Name} has no JSON API.");

            Node.JSONAPI!.EventStreamHeartbeat = TimeSpan.FromSeconds(1);

            using var http   = await SignedIn();
            using var stream = await EventStream.OpenAndSettle(Node, http);

            Assert.That(await stream.ReadUntil(": keep-alive"), Is.True,
                        $"No comment came down the stream within {EventStream.Timeout.TotalSeconds} seconds, so there was no heartbeat to stop after.");

            var elapsed      = await TimeTheStop(Node);

            Assert.That(elapsed, Is.LessThan(MustStopWithin),
                        $"This {Node.Kind.Name}, whose event stream had sent a heartbeat, took {elapsed.TotalSeconds:F1} s to stop. " +
                        "The stream is not stopping the enumerator it waits on.");

        }

        #endregion

        #region StoppingTwiceIsHarmless()

        /// <summary>
        /// DisposeAsync stops as well, and a node inside a using block that was
        /// also stopped by hand is an ordinary thing to write.
        /// </summary>
        [Test]
        public async Task StoppingTwiceIsHarmless()
        {

            NothingLeftRunning();

            await Node.Stop();

            await Assert.DoesNotThrowAsync(async () => {
                await Node.Stop();
                await Node.DisposeAsync();
            });

        }

        #endregion

    }

}
