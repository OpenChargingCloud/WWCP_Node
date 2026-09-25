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

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The metrological log beside the ordinary one: what goes into it, where
    /// it is kept, and how its numbers carry on.
    /// </summary>
    /// <remarks>
    /// Half of these ask the event log with a store that only takes notes, so
    /// that what reaches a store can be counted; the other half ask a node,
    /// and read what it wrote back from the disk.
    /// </remarks>
    public class MetrologicalLogTests
    {

        #region Data

        private String directory = "";

        private String LogPath
            => Path.Combine(directory, "logs");

        private String MetrologicalPath
            => Path.Combine(LogPath, WWCPNode.DefaultMetrologicalLogDirectory);

        #endregion

        #region (class) NoteTaker

        /// <summary>
        /// A store that keeps what it is handed in a list, and can be told to
        /// throw instead.
        /// </summary>
        private sealed class NoteTaker(IEnumerable<LogEntry>? Before = null) : IEventLogStore
        {

            public List<LogEntry>  Kept      { get; } = [];
            public Boolean         Throwing  { get; set; }

            public (IReadOnlyList<LogEntry> Entries, UInt64 LastId) Load(Int32 Limit)
                => ([.. (Before ?? []).TakeLast(Limit)], Before?.Max(entry => entry.Id) ?? 0);

            public void Append(LogEntry Entry)
            {

                if (Throwing)
                    throw new IOException("the disk is full");

                Kept.Add(Entry);

            }

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-metrological-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(LogPath, MetrologicalLogPath = null)

        private WWCPNode Node(String?  LogPath,
                              String?  MetrologicalLogPath   = null)

            => new (
                   AccountsPath:         Path.Combine(directory, "accounts"),
                   ConfigFile:           new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                   CertificatesPath:     Path.Combine(directory, "certificates"),
                   LogToConsole:         false,
                   LogPath:              LogPath,
                   MetrologicalLogPath:  MetrologicalLogPath,
                   BridgeDebugLog:       false
               );

        #endregion


        #region OnlyWhatIsSaidToBeMetrologicalReachesTheMetrologicalLog()

        /// <summary>
        /// An entry written as metrological reaches the metrological store, and
        /// one written at any level as anything else does not.
        /// </summary>
        [Test]
        public void OnlyWhatIsSaidToBeMetrologicalReachesTheMetrologicalLog()
        {

            var metrological = new NoteTaker();
            var log          = new EventLog(MetrologicalStore: metrological);

            log.Critical("a critical entry, but about nothing that is measured", "http");
            log.Metrological(LogLevel.Info, "the clock was checked", "nts");
            log.Notice("somebody signed in", "web");
            log.Metrological(LogLevel.Warning, "the time servers disagree", new JObject(new JProperty("spread_ms", 812)), "nts");

            Assert.Multiple(() => {
                Assert.That(metrological.Kept.Select(entry => entry.Message),       Is.EqualTo(new[] { "the clock was checked", "the time servers disagree" }));
                Assert.That(metrological.Kept.Select(entry => entry.Id),            Is.EqualTo(new UInt64[] { 2, 4 }),  "numbered in the log's own sequence");
                Assert.That(metrological.Kept.All(entry => entry.Metrological),     Is.True);
                Assert.That(metrological.Kept[1].Data?.Value<Int32>("spread_ms"),   Is.EqualTo(812));
                Assert.That(log.Recent(10).Count(entry => entry.Metrological),      Is.EqualTo(2),  "the page could not tell them apart");
            });

        }

        #endregion

        #region AStoreOfEverythingIsHandedEveryEntryInTheOrderOfItsNumbers()

        /// <summary>
        /// A store of every entry gets every entry, metrological or not, in the
        /// order of the numbers - from however many threads they came.
        /// </summary>
        [Test]
        public void AStoreOfEverythingIsHandedEveryEntryInTheOrderOfItsNumbers()
        {

            var everything    = new NoteTaker();
            var metrological  = new NoteTaker();
            var log           = new EventLog(Store: everything, MetrologicalStore: metrological);

            Parallel.For(0, 400, i => {
                if (i % 4 == 0)
                    log.Metrological(LogLevel.Info, $"metrological {i}", "test");
                else
                    log.Info($"ordinary {i}", "test");
            });

            Assert.Multiple(() => {
                Assert.That(everything.  Kept,                          Has.Count.EqualTo(400));
                Assert.That(everything.  Kept.Select(entry => entry.Id),  Is.Ordered,  "not in the order of the numbers");
                Assert.That(metrological.Kept,                          Has.Count.EqualTo(100));
                Assert.That(metrological.Kept.Select(entry => entry.Id),  Is.Ordered,  "not in the order of the numbers");
            });

        }

        #endregion

        #region TheNumbersCarryOnFromTheHighestAStoreHolds()

        /// <summary>
        /// A log made on stores that hold entries carries on numbering after the
        /// highest of them, and shows what the store of everything held.
        /// </summary>
        [Test]
        public void TheNumbersCarryOnFromTheHighestAStoreHolds()
        {

            var now           = DateTimeOffset.UtcNow;

            var everything    = new NoteTaker([ new LogEntry(7, now, LogLevel.Info, ["test"], "seven") ]);
            var metrological  = new NoteTaker([ new LogEntry(9, now, LogLevel.Info, ["test"], "nine", Metrological: true) ]);

            var log           = new EventLog(Store: everything, MetrologicalStore: metrological);

            Assert.Multiple(() => {
                Assert.That(log.LastId,                                   Is.EqualTo(9),  "a number the metrological log holds would be handed out again");
                Assert.That(log.Recent(10).Select(entry => entry.Message),  Is.EqualTo(new[] { "seven" }),  "the page shows the store of everything");
                Assert.That(log.Info("next", "test").Id,                  Is.EqualTo(10));
            });

        }

        #endregion

        #region WithOnlyAMetrologicalLogThePageOpensOnIt()

        /// <summary>
        /// Without a store of everything, the page opens on what the
        /// metrological log held before the restart, rather than on nothing.
        /// </summary>
        [Test]
        public void WithOnlyAMetrologicalLogThePageOpensOnIt()
        {

            var now   = DateTimeOffset.UtcNow;
            var log   = new EventLog(MetrologicalStore: new NoteTaker([
                                                            new LogEntry(3, now, LogLevel.Notice, ["nts"], "the clock was checked", Metrological: true),
                                                            new LogEntry(5, now, LogLevel.Notice, ["nts"], "and again",             Metrological: true)
                                                        ]));

            Assert.Multiple(() => {
                Assert.That(log.Recent(10).Select(entry => entry.Message),  Is.EqualTo(new[] { "the clock was checked", "and again" }));
                Assert.That(log.LastId,                                   Is.EqualTo(5));
                Assert.That(log.KnownTags,                                Does.Contain("nts"));
            });

        }

        #endregion

        #region OneStoreCannotKeepBoth()

        /// <summary>
        /// One store handed in for both is refused: it would be handed every
        /// metrological entry twice.
        /// </summary>
        [Test]
        public void OneStoreCannotKeepBoth()
        {

            var store = new NoteTaker();

            Assert.Throws<ArgumentException>(() => new EventLog(Store: store, MetrologicalStore: store));

        }

        #endregion

        #region AStoreThatThrowsIsSaidOnceAndTakesNothingWithIt()

        /// <summary>
        /// A store that throws does not take the entry, nor whoever logged it,
        /// with it: it is said once while it keeps failing, and again once it
        /// has worked in between.
        /// </summary>
        [Test]
        public void AStoreThatThrowsIsSaidOnceAndTakesNothingWithIt()
        {

            var said         = new List<String>();
            var metrological = new NoteTaker { Throwing = true };
            var log          = new EventLog(MetrologicalStore: metrological) {
                                   ComplaintBlock = write => {
                                       var stderr = Console.Error;
                                       using var captured = new StringWriter();
                                       Console.SetError(captured);
                                       try     { write(); }
                                       finally { Console.SetError(stderr); }
                                       said.Add(captured.ToString().Trim());
                                   }
                               };

            var heard = new List<LogEntry>();
            log.OnLogged += heard.Add;

            log.Metrological(LogLevel.Info, "one",   "test");
            log.Metrological(LogLevel.Info, "two",   "test");
            log.Metrological(LogLevel.Info, "three", "test");

            var whileFailing = said.Count;

            metrological.Throwing = false;
            log.Metrological(LogLevel.Info, "four", "test");

            metrological.Throwing = true;
            log.Metrological(LogLevel.Info, "five", "test");

            Assert.Multiple(() => {
                Assert.That(heard.Select(entry => entry.Message),          Is.EqualTo(new[] { "one", "two", "three", "four", "five" }),  "an entry was lost with the store");
                Assert.That(whileFailing,                                  Is.EqualTo(1),  String.Join(" | ", said));
                Assert.That(said.FirstOrDefault(),                         Does.Contain("metrological store failed").And.Contain("the disk is full"));
                Assert.That(said,                                          Has.Count.EqualTo(2),  "a store that failed again after working was not said again");
                Assert.That(metrological.Kept.Select(entry => entry.Message),  Is.EqualTo(new[] { "four" }));
            });

        }

        #endregion


        #region ANodeWithLogFilesKeepsAMetrologicalLogBesideThem()

        /// <summary>
        /// A node that writes log files keeps a metrological log below them,
        /// signed, and says where on its Configuration page.
        /// </summary>
        [Test]
        public async Task ANodeWithLogFilesKeepsAMetrologicalLogBesideThem()
        {

            String? keyId;

            await using (var node = Node(LogPath))
            {

                Assert.That(node.MetrologicalLog,  Is.Not.Null);

                var json = node.ConfigurationJSON()["log"]?["metrological"];

                keyId = json?.Value<String>("keyId");

                Assert.Multiple(() => {
                    Assert.That(node.MetrologicalLog!.Path,        Is.EqualTo(Path.GetFullPath(MetrologicalPath)));
                    Assert.That(json?.Value<String>("path"),       Is.EqualTo(Path.GetFullPath(MetrologicalPath)));
                    Assert.That(keyId,                             Has.Length.EqualTo(16));
                    Assert.That(File.Exists(Path.Combine(MetrologicalPath, LogSigner.PublicKeyFileName)),  Is.True,  "no public key to check it with");
                });

            }

            using var written  = new SignedLog(MetrologicalPath, NodeKind.Default.LogFilePrefix);
            var       verified = written.Verify();
            var       entries  = written.Load(100).Entries;

            Assert.Multiple(() => {
                Assert.That(verified.IsIntact,                    Is.True,  verified.FirstProblem);
                Assert.That(verified.KeyId,                       Is.EqualTo(keyId));
                Assert.That(entries.Select(entry => entry.Message),  Has.Some.Contains("starting up"));
                Assert.That(entries.All(entry => entry.Metrological),  Is.True);
            });

        }

        #endregion

        #region ANodeWithoutLogFilesKeepsNone()

        /// <summary>
        /// A node that writes no log files keeps no metrological log either,
        /// unless it is given a place for one.
        /// </summary>
        [Test]
        public async Task ANodeWithoutLogFilesKeepsNone()
        {

            await using (var node = Node(null))
            {
                Assert.That(node.MetrologicalLog,                                   Is.Null);
                Assert.That(node.ConfigurationJSON()["log"]?["metrological"]?.Type,  Is.EqualTo(JTokenType.Null));
            }

            var elsewhere = Path.Combine(directory, "evidence");

            await using (var node = Node(null, elsewhere))
                Assert.That(node.MetrologicalLog?.Path,  Is.EqualTo(Path.GetFullPath(elsewhere)));

        }

        #endregion

        #region AChangeToTheTimeServersIsMetrologicalAndOneToTheNameServersIsNot()

        /// <summary>
        /// Who the clock is checked against is written into the metrological
        /// log; how names are resolved is not.
        /// </summary>
        [Test]
        public async Task AChangeToTheTimeServersIsMetrologicalAndOneToTheNameServersIsNot()
        {

            await using (var node = Node(LogPath))
            {

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out var error),  Is.True,  error);
                Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "useCache": false }"""),                          out error),  Is.True,  error);

            }

            using var written = new SignedLog(MetrologicalPath, NodeKind.Default.LogFilePrefix);

            var said = written.Load(100).Entries.Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(said,  Has.Some.StartsWith("NTS configuration changed").And.Contains("a.example, b.example"),  String.Join(" | ", said));
                Assert.That(said,  Has.None.StartsWith("DNS configuration changed"),                                      String.Join(" | ", said));
            });

        }

        #endregion

        #region ARestartedNodeCarriesOnItsMetrologicalNumbers()

        /// <summary>
        /// A node started again on the same log files numbers on after its
        /// metrological log, and that log stays one chain.
        /// </summary>
        [Test]
        public async Task ARestartedNodeCarriesOnItsMetrologicalNumbers()
        {

            UInt64 before;

            await using (var node = Node(LogPath))
            {
                node.Log.Metrological(LogLevel.Notice, "something that mattered", "test");
                before = node.Log.LastId;
            }

            await using (var again = Node(LogPath))
            {

                Assert.Multiple(() => {
                    Assert.That(again.Log.LastId,  Is.GreaterThan(before),  "a number of the metrological log was handed out again");
                    Assert.That(again.Log.Recent(100).Select(entry => entry.Message),  Has.Some.EqualTo("something that mattered"),
                                "the page did not open on what mattered before the restart");
                });

            }

            using var written  = new SignedLog(MetrologicalPath, NodeKind.Default.LogFilePrefix);
            var       verified = written.Verify();

            Assert.That(verified.IsIntact,  Is.True,  verified.FirstProblem);

        }

        #endregion

        #region AMetrologicalLogCannotBeGivenToALogThatWasHandedIn()

        /// <summary>
        /// A place for a metrological log beside a log that was handed in is
        /// refused, rather than quietly kept nowhere.
        /// </summary>
        [Test]
        public void AMetrologicalLogCannotBeGivenToALogThatWasHandedIn()
        {

            Assert.Throws<ArgumentException>(() => new WWCPNode(
                                                       AccountsPath:         Path.Combine(directory, "accounts"),
                                                       ConfigFile:           new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                                       Log:                  new EventLog(),
                                                       LogToConsole:         false,
                                                       MetrologicalLogPath:  Path.Combine(directory, "evidence"),
                                                       BridgeDebugLog:       false
                                                   ));

        }

        #endregion

    }

}
