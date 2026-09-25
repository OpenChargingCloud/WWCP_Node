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

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a signed log does while its file cannot be written.
    /// </summary>
    /// <remarks>
    /// The Modbus/TLS energy meter's tests of the gap its signed log writes
    /// down, which moved here with it. The first failure is said once, and the
    /// first line that makes it afterwards is preceded by a signed line of the
    /// chain saying how many are missing, since when, and which numbers they
    /// had - where a log that simply carried on from the last line that made it
    /// would call itself intact with a hole in it.
    ///
    /// The file is read back rather than the log asked what it believes it
    /// wrote, and the failure is made the way the vehicle's and the charging
    /// station's tests make it: a directory standing where the day's file
    /// should be. What the log says about itself is caught where it says it,
    /// through <see cref="SignedLog.Complain"/>.
    /// </remarks>
    public class SignedLogGapTests
    {

        #region Data

        private String        directory  = "";
        private List<String>  said       = [];

        /// <summary>
        /// Two seconds before midnight, UTC: the next entries belong to a day
        /// whose file does not exist yet, which is where a failure can be made.
        /// </summary>
        private static readonly DateTimeOffset  lateOnTheDay  = new (2026, 9, 24, 23, 59, 58, TimeSpan.Zero);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-signed-gap-" + Guid.NewGuid().ToString("N")[..12]);
            said      = [];

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
            catch
            { }

        }

        #endregion


        #region (helpers) Log(), Entry(Id), DayFile(Day), Block(Day), Unblock(Day), Lines(Day)

        private SignedLog Log()

            => new (directory, "node") {
                   Complain = said.Add
               };

        /// <summary>
        /// Entry number Id, a second after the one before it.
        /// </summary>
        private static LogEntry Entry(UInt64 Id)

            => new (Id,
                    lateOnTheDay.AddSeconds(Id),
                    LogLevel.Info,
                    [ "node", "test" ],
                    $"entry {Id}",
                    Metrological: true);

        private String DayFile(Int32 Day)
            => Path.Combine(directory, $"node-2026-09-{Day:00}.jsonl");

        /// <summary>
        /// What a broken disk looks like from here, made on purpose: something
        /// the day's file cannot be opened as.
        /// </summary>
        private void Block(Int32 Day)
            => Directory.CreateDirectory(DayFile(Day));

        private void Unblock(Int32 Day)
            => Directory.Delete(DayFile(Day));

        /// <summary>
        /// The day's file as it is on disk, read while the log still holds it
        /// open - sharing write, as the log's own reader does.
        /// </summary>
        private JObject[] Lines(Int32 Day)
        {

            using var stream = new FileStream(DayFile(Day), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);

            return [.. reader.ReadToEnd().Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).Select(JObject.Parse)];

        }

        #endregion


        #region AFileThatCannotBeWrittenIsSaidOnceAndItsGapWrittenDown()

        /// <summary>
        /// Three entries while the day's file is blocked: said once, and the
        /// first entry that makes it afterwards is preceded by the gap.
        /// </summary>
        [Test]
        public void AFileThatCannotBeWrittenIsSaidOnceAndItsGapWrittenDown()
        {

            using var log = Log();

            log.Append(Entry(1));

            Block(25);

            log.Append(Entry(2));
            log.Append(Entry(3));
            log.Append(Entry(4));

            String[] whileBlocked = [.. said];

            Unblock(25);

            log.Append(Entry(5));

            var today = Lines(25);
            var gap   = today[0];

            Assert.Multiple(() =>
            {

                Assert.That(whileBlocked,                   Has.Length.EqualTo(1),  "not said once: " + String.Join(" | ", whileBlocked));
                Assert.That(whileBlocked.FirstOrDefault(),  Does.Contain("could not be written").And.Contain(directory));

                Assert.That(today,                          Has.Length.EqualTo(2),  "the gap and the entry that made it");

                Assert.That(gap.Value<String>("message"),   Does.StartWith("3 entries since 2026-09-25T00:00:00.000Z could not be written here"));
                Assert.That(gap.Value<String>("message"),   Does.Contain("numbers 2 to 4"));
                Assert.That(gap.Value<String>("level"),     Is.EqualTo("warning"));
                Assert.That(gap.Value<UInt64>("id"),        Is.EqualTo(4),          "numbered as the last of the entries it stands for");
                Assert.That(gap["tags"]!.Values<String>(),  Is.EqualTo(new[] { "log" }));
                Assert.That(gap.Value<Boolean>("metrological"),  Is.True,           "a gap in a metrological log is part of the metrological log");

                Assert.That(today[1].Value<String>("message"),  Is.EqualTo("entry 5"));

                Assert.That(said.Skip(1).FirstOrDefault(),  Does.Contain("being written again").And.Contain("3 entries"));

            });

            // And the chain walks through it: the gap is a line of the log like
            // any other, signed and pointing back at the last line that made it
            // before the failure.
            var verified = log.Verify();

            Assert.Multiple(() =>
            {
                Assert.That(verified.IsIntact,  Is.True,              verified.FirstProblem);
                Assert.That(verified.Entries,   Is.EqualTo(3));
                Assert.That(verified.Head,      Is.EqualTo(log.Head));
            });

        }

        #endregion

        #region ASecondFailureIsSaidAgainAndCountedAfresh()

        /// <summary>
        /// Once writing works again, the next failure is a new one: said again,
        /// and its own gap counted from zero.
        /// </summary>
        [Test]
        public void ASecondFailureIsSaidAgainAndCountedAfresh()
        {

            using var log = Log();

            log.Append(Entry(1));

            Block(25);
            log.Append(Entry(2));
            Unblock(25);

            log.Append(Entry(3));

            // A day later, the same again.
            Block(26);
            log.Append(new LogEntry(4, lateOnTheDay.AddDays(1).AddSeconds(4), LogLevel.Info, [ "node", "test" ], "entry 4"));
            log.Append(new LogEntry(5, lateOnTheDay.AddDays(1).AddSeconds(5), LogLevel.Info, [ "node", "test" ], "entry 5"));
            Unblock(26);

            log.Append(new LogEntry(6, lateOnTheDay.AddDays(1).AddSeconds(6), LogLevel.Info, [ "node", "test" ], "entry 6"));

            Assert.Multiple(() =>
            {

                Assert.That(said.Count(line => line.Contains("could not be written")),  Is.EqualTo(2),  String.Join(" | ", said));
                Assert.That(said.Count(line => line.Contains("being written again")),   Is.EqualTo(2),  String.Join(" | ", said));

                Assert.That(Lines(25)[0].Value<String>("message"),  Does.StartWith("1 entry since").And.Contain("number 2"));
                Assert.That(Lines(26)[0].Value<String>("message"),  Does.StartWith("2 entries since").And.Contain("numbers 4 to 5"));

                Assert.That(log.Verify().IsIntact,  Is.True,  log.Verify().FirstProblem);

            });

        }

        #endregion

    }

}
