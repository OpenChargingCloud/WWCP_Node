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

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a signed log notices about somebody who edits it afterwards.
    /// </summary>
    /// <remarks>
    /// The Modbus/TLS energy meter's tests of its signed log, which moved here
    /// with it. Written against the log directly rather than through a node:
    /// what is under test is the chain and the signatures, and a node logging
    /// away in the background would make every one of these race with it.
    /// </remarks>
    public class SignedLogTests
    {

        #region Data

        private const String  Prefix     = "node";

        private String        directory  = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-signed-log-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region AnUntouchedLog_Verifies()

        /// <summary>
        /// A log nobody has been at checks out, line by line.
        /// </summary>
        [Test]
        public void AnUntouchedLog_Verifies()
        {

            var head = WriteSomeEntries(6);

            using var log    = new SignedLog(directory, Prefix);
            var       result = log.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.True, result.FirstProblem);
                Assert.That(result.Entries,       Is.EqualTo(6));
                Assert.That(result.Head,          Is.EqualTo(head), "the walk ended somewhere else than the writing did");
                Assert.That(result.FirstProblem,  Is.Null);
            });

        }

        #endregion

        #region AnEditedLine_IsFound()

        /// <summary>
        /// Changing what a line says breaks its own hash.
        /// </summary>
        [Test]
        public void AnEditedLine_IsFound()
        {

            WriteSomeEntries(6);

            Rewrite(lines => {
                lines[3] = lines[3].Replace("entry 4", "entry 4 (nothing happened)");
                return lines;
            });

            using var log    = new SignedLog(directory, Prefix);
            var       result = log.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.False);
                Assert.That(result.FirstProblem,  Does.Contain("does not match its own hash"));
            });

        }

        #endregion

        #region ARemovedLine_IsFound()

        /// <summary>
        /// Taking a line out entirely breaks the line that followed it - which
        /// is the whole reason for the chain, because a removed line leaves
        /// nothing of its own behind to check.
        /// </summary>
        [Test]
        public void ARemovedLine_IsFound()
        {

            WriteSomeEntries(6);

            Rewrite(lines => { lines.RemoveAt(3); return lines; });

            using var log    = new SignedLog(directory, Prefix);
            var       result = log.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.False);
                Assert.That(result.FirstProblem,  Does.Contain("does not follow the line before it"));
            });

        }

        #endregion

        #region AReorderedLog_IsFound()

        /// <summary>
        /// So does moving two of them around each other.
        /// </summary>
        [Test]
        public void AReorderedLog_IsFound()
        {

            WriteSomeEntries(6);

            Rewrite(lines => {
                (lines[2], lines[3]) = (lines[3], lines[2]);
                return lines;
            });

            using var log    = new SignedLog(directory, Prefix);
            var       result = log.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.False);
                Assert.That(result.FirstProblem,  Does.Contain("does not follow the line before it"));
            });

        }

        #endregion

        #region ALineFromAnotherNode_IsFound()

        /// <summary>
        /// A line signed by a different key does not pass, even when it is
        /// perfectly well formed.
        /// </summary>
        [Test]
        public void ALineFromAnotherNode_IsFound()
        {

            WriteSomeEntries(3);

            // Another node's log, with its own key, and one of its lines pasted
            // into this one.
            var elsewhere = Path.Combine(directory, "elsewhere");

            using (var other = new SignedLog(elsewhere, Prefix))
                other.Append(new LogEntry(99, DateTimeOffset.UtcNow, LogLevel.Info, ["node"], "a line from somewhere else"));

            var theirs = File.ReadAllLines(Directory.GetFiles(elsewhere, $"{Prefix}-*.jsonl")[0])[0];

            Rewrite(lines => { lines[1] = theirs; return lines; });

            using var log    = new SignedLog(directory, Prefix);
            var       result = log.Verify();

            Assert.That(result.IsIntact, Is.False);

        }

        #endregion

        #region ATruncatedLog_StillVerifies_WhichIsWhatTheHeadIsFor()

        /// <summary>
        /// Cutting the end off a log leaves something that checks out perfectly
        /// - and this is the limit of what signing a file can do.
        /// </summary>
        /// <remarks>
        /// Every line that is left is genuine, follows the one before it, and is
        /// properly signed. Nothing inside the file says how long it was meant to
        /// be, and nothing can: the last line of any log looks exactly like the
        /// last line of a log.
        ///
        /// What catches it is the head, compared against a copy of it kept
        /// somewhere this node cannot reach. A test for a hole rather than for a
        /// feature, so that nobody later reads the green tests and concludes that
        /// the log cannot be cut.
        /// </remarks>
        [Test]
        public void ATruncatedLog_StillVerifies_WhichIsWhatTheHeadIsFor()
        {

            var head = WriteSomeEntries(6);

            Rewrite(lines => [.. lines.Take(3)]);

            using var log    = new SignedLog(directory, Prefix);
            var       result = log.Verify();

            Assert.Multiple(() => {

                Assert.That(result.IsIntact,  Is.True,
                            "the remaining lines are genuine, and the file cannot know it was cut");

                Assert.That(result.Entries,   Is.EqualTo(3));

                Assert.That(result.Head,      Is.Not.EqualTo(head),
                            "but it no longer ends where it ended - which is what the head is compared for");

            });

        }

        #endregion

        #region TheChainCarriesOnAcrossARestart()

        /// <summary>
        /// A log opened again on the same directory continues the chain rather
        /// than beginning a new one.
        /// </summary>
        [Test]
        public void TheChainCarriesOnAcrossARestart()
        {

            WriteSomeEntries(3);

            using var second = new SignedLog(directory, Prefix);

            var (entries, lastId) = second.Load(100);

            second.Append(new LogEntry(4, DateTimeOffset.UtcNow, LogLevel.Info, ["node"], "entry 4 after a restart"));

            var verified = second.Verify();

            Assert.Multiple(() => {
                Assert.That(entries.Select(entry => entry.Message),  Is.EqualTo(new[] { "entry 1", "entry 2", "entry 3" }));
                Assert.That(lastId,                                  Is.EqualTo(3));
                Assert.That(verified.IsIntact,                       Is.True,
                            $"the first line after the restart did not follow the last one before it: {verified.FirstProblem}");
            });

        }

        #endregion

        #region TheChainCarriesOnWithoutBeingReadBack()

        /// <summary>
        /// A log opened only to be written to carries on the chain as well.
        /// </summary>
        /// <remarks>
        /// The meter's log picked up the head of its chain while it read its
        /// entries back, so a log that was written to without being asked what
        /// it held began a second chain in the middle of the day's file - and a
        /// check of it said a line pointed back at a line that was not there.
        /// </remarks>
        [Test]
        public void TheChainCarriesOnWithoutBeingReadBack()
        {

            var head = WriteSomeEntries(3);

            using var second = new SignedLog(directory, Prefix);

            Assert.That(second.Head, Is.EqualTo(head), "opened without the head of the chain it holds");

            second.Append(new LogEntry(4, DateTimeOffset.UtcNow, LogLevel.Info, ["node"], "entry 4 after a restart"));

            var verified = second.Verify();

            Assert.That(verified.IsIntact, Is.True, verified.FirstProblem);

        }

        #endregion

        #region AMetrologicalEntryIsReadBackAsOne()

        /// <summary>
        /// What is written as metrological comes back as metrological, and what
        /// is not does not say so on its line at all.
        /// </summary>
        [Test]
        public void AMetrologicalEntryIsReadBackAsOne()
        {

            using (var log = new SignedLog(directory, Prefix))
            {
                log.Append(new LogEntry(1, DateTimeOffset.UtcNow, LogLevel.Info,   ["node"], "ordinary"));
                log.Append(new LogEntry(2, DateTimeOffset.UtcNow, LogLevel.Notice, ["nts"],  "the clock was checked", Metrological: true));
            }

            using var again = new SignedLog(directory, Prefix);

            var entries = again.Load(10).Entries;
            var lines   = File.ReadAllLines(Directory.GetFiles(directory, $"{Prefix}-*.jsonl")[0]);

            Assert.Multiple(() => {
                Assert.That(entries.Select(entry => entry.Metrological),  Is.EqualTo(new[] { false, true }));
                Assert.That(lines[0],                                     Does.Not.Contain("metrological"));
                Assert.That(lines[1],                                     Does.Contain("\"metrological\":true"));
                Assert.That(again.Verify().IsIntact,                      Is.True, again.Verify().FirstProblem);
            });

        }

        #endregion

        #region AFileOfAnotherPrefixIsNoneOfItsBusiness()

        /// <summary>
        /// A second log in the same directory, or a file somebody put there, is
        /// neither read back nor checked as part of this one.
        /// </summary>
        [Test]
        public void AFileOfAnotherPrefixIsNoneOfItsBusiness()
        {

            WriteSomeEntries(2);

            File.WriteAllText(Path.Combine(directory, $"{Prefix}-backup-2026-09-24.jsonl"), "not a line of this log\n");
            File.WriteAllText(Path.Combine(directory, $"{Prefix}s-2026-09-24.jsonl"),       "nor this\n");

            using var log = new SignedLog(directory, Prefix);

            Assert.Multiple(() => {
                Assert.That(log.Load(10).Entries.Count,  Is.EqualTo(2));
                Assert.That(log.Verify().IsIntact,       Is.True, log.Verify().FirstProblem);
            });

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// Write a few entries and hand back the head they ended at.
        /// </summary>
        private String WriteSomeEntries(Int32 Count)
        {

            using var log = new SignedLog(directory, Prefix);

            for (var i = 1; i <= Count; i++)
                log.Append(
                    new LogEntry(
                        (UInt64) i,
                        DateTimeOffset.UtcNow,
                        LogLevel.Info,
                        ["node", "test"],
                        $"entry {i}"
                    )
                );

            return log.Head;

        }

        /// <summary>
        /// Somebody with write access to the directory, having a go at it.
        /// </summary>
        private void Rewrite(Func<List<String>, List<String>> Change)
        {

            var file  = Directory.GetFiles(directory, $"{Prefix}-*.jsonl")[0];
            var lines = Change([.. File.ReadAllLines(file)]);

            File.WriteAllLines(file, lines);

        }

        #endregion

    }

}
