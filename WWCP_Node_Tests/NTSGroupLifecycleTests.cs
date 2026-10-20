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
using System.Net;
using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Groups of time servers made and taken away while a node runs: made
    /// switched off, taken away only switched off, and taken away whole - its
    /// timer, the checks running against it, its client and its place in the
    /// file.
    /// </summary>
    public class NTSGroupLifecycleTests
    {

        #region Data

        private String directory = "";

        private String ConfigurationPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        private JObject OnDisk
            => JObject.Parse(File.ReadAllText(ConfigurationPath));

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-nts-lifecycle-" + Guid.NewGuid().ToString("N")[..12]);

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
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helper) Node(Configuration = null, DNSClient = null)

        private WWCPNode Node(String?     Configuration  = null,
                              DNSClient?  DNSClient      = null)
        {

            if (Configuration is not null)
                File.WriteAllText(ConfigurationPath, Configuration);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       DNSClient:         DNSClient,
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Added(Node, Id, DisplayName = null)

        private static NTSGroup Added(WWCPNode                              Node,
                                      String                                Id,
                                      IReadOnlyDictionary<String, String>?  DisplayName = null)
        {

            Assert.That(Node.TryAddNTSGroup(Id, DisplayName, out var group, out var error, out _),  Is.True,  error);

            return group!;

        }

        #endregion

        #region (helper) Updated(Node, Group, JSON)

        private static void Updated(WWCPNode  Node,
                                    NTSGroup  Group,
                                    String    JSON)
        {
            Assert.That(Node.TryUpdateNTSConfiguration(Group, JObject.Parse(JSON), out var error, out _),  Is.True,  error);
        }

        #endregion


        #region AGroupIsAddedSwitchedOffAndWrittenDown()

        [Test]
        public void AGroupIsAddedSwitchedOffAndWrittenDown()
        {

            var node   = Node();
            var local  = Added(node, "local", new Dictionary<String, String> { [ "en" ] = "Local time", [ "de" ] = "Lokale Zeit" });
            var again  = Node();

            Assert.Multiple(() => {

                Assert.That(node.NTSGroups.Select(group => group.Id),                        Is.EqualTo(new[] { "legal", "local" }));
                Assert.That(node.NTSGroupOf("local"),                                        Is.SameAs(local));
                Assert.That(local.Enabled,                                                   Is.False,  "a group has nothing to ask when it is made");
                Assert.That(local.Sources.Sources,                                           Is.Empty);
                Assert.That(local.Client,                                                    Is.Null);
                Assert.That(local.DisplayName?["de"],                                        Is.EqualTo("Lokale Zeit"));

                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?.Type,                        Is.EqualTo(JTokenType.Object),  "the legal group as the node made it, the PTB's four");
                Assert.That(OnDisk["nts"]?["groups"]?["local"]?.Value<Boolean>("enabled"),   Is.False);
                Assert.That(OnDisk["nts"]?["groups"]?["local"]?["displayName"]?.Value<String>("en"),  Is.EqualTo("Local time"));

                Assert.That(again.NTSGroups.Select(group => group.Id),                       Is.EqualTo(new[] { "legal", "local" }),  "and the next start has it");
                Assert.That(again.NTSGroupOf("local")?.Enabled,                              Is.False);
                Assert.That(again.LegalTime.Sources.Sources.Count(),                         Is.EqualTo(4));

                Assert.That(node.Log.Recent(50).Select(entry => entry.Message),              Has.Some.EqualTo("NTS group 'local' added, switched off."));

            });

        }

        #endregion

        #region AddingToAFlatFileMovesItIntoTheLegalGroup()

        [Test]
        public void AddingToAFlatFileMovesItIntoTheLegalGroup()
        {

            var node = Node("""{ "nts": { "groups": { "legal": { "hostname": "a.example", "checkEverySeconds": 600 } } } }""");

            Added(node, "grid");

            Assert.Multiple(() => {
                Assert.That(((JObject) OnDisk["nts"]!).Properties().Select(property => property.Name),  Is.EqualTo(new[] { "groups" }));
                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?.Value<String>("hostname"),             Is.EqualTo("a.example"));
                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?.Value<Int32>("checkEverySeconds"),     Is.EqualTo(600));
                Assert.That(OnDisk["nts"]?["groups"]?["grid"]?.Value<Boolean>("enabled"),              Is.False);
            });

        }

        #endregion

        #region WhatCannotBeAGroupIsNotAdded(Id, Says)

        [TestCase("Local",  "cannot be the name of a group")]
        [TestCase("1st",    "cannot be the name of a group")]
        [TestCase("legal",  "has an NTS group 'legal' already")]
        public void WhatCannotBeAGroupIsNotAdded(String Id, String Says)
        {

            var node    = Node("""{ "nts": { "groups": { "legal": { } } } }""");
            var before  = File.ReadAllText(ConfigurationPath);

            Assert.Multiple(() => {
                Assert.That(node.TryAddNTSGroup(Id, null, out var group, out var error, out var notSaved),  Is.False);
                Assert.That(error,                                Does.Contain(Says));
                Assert.That(notSaved,                             Is.False);
                Assert.That(group,                                Is.Null);
                Assert.That(node.NTSGroups.Select(g => g.Id),     Is.EqualTo(new[] { "legal" }));
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before));
            });

        }

        [Test]
        public void AGroupIsNotAddedTwice()
        {

            var node = Node();

            Added(node, "local");

            Assert.Multiple(() => {
                Assert.That(node.TryAddNTSGroup("local", null, out _, out var error, out _),  Is.False);
                Assert.That(error,                                                           Does.Contain("has an NTS group 'local' already"));
                Assert.That(node.NTSGroups.Count(group => group.Id == "local"),              Is.EqualTo(1));
            });

        }

        [Test]
        public void ADisplayNameThatIsNoneIsNotAdded()
        {

            var node = Node();

            Assert.Multiple(() => {
                Assert.That(node.TryAddNTSGroup("local", new Dictionary<String, String> { [ "english" ] = "Local time" }, out _, out var error, out _),  Is.False);
                Assert.That(error,                       Does.Contain("'english' is not a language").And.Contain("Nothing was changed"));
                Assert.That(node.NTSGroupOf("local"),    Is.Null);
                Assert.That(File.Exists(ConfigurationPath) && File.ReadAllText(ConfigurationPath).Contains("local"),  Is.False);
            });

        }

        #endregion

        #region AGroupSwitchedOnIsNotRemoved()

        /// <summary>
        /// Switching a group off is the decision, taking it away is the tidying:
        /// nothing stops checking the clock as a side effect of tidying up.
        /// </summary>
        [Test]
        public async Task AGroupSwitchedOnIsNotRemoved()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { }, "local": { "servers": [ "lc1.local" ] } } } }""");
            var before = File.ReadAllText(ConfigurationPath);

            var (removed, error, notSaved) = await node.TryRemoveNTSGroupAsync("local");

            Assert.Multiple(() => {
                Assert.That(removed,                              Is.False);
                Assert.That(error,                                Does.Contain("switch it off before removing it"));
                Assert.That(notSaved,                             Is.False);
                Assert.That(node.NTSGroupOf("local")?.Enabled,    Is.True);
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before));
            });

        }

        [Test]
        public async Task WhatIsNoGroupIsNotRemoved()
        {

            var (removed, error, _) = await Node().TryRemoveNTSGroupAsync("local");

            Assert.Multiple(() => {
                Assert.That(removed,  Is.False);
                Assert.That(error,    Does.Contain("has no NTS group 'local'"));
            });

        }

        #endregion

        #region ASaveRacingTheRemovalDoesNotBringTheGroupBack()

        /// <summary>
        /// A save that came in while its group was being taken away: whichever
        /// is first, what the node has and what the file says agree afterwards -
        /// the save does not write the removed group back into the file, where
        /// it would come back switched on at the next start.
        /// </summary>
        /// <remarks>
        /// The two are started together, many times, because the window was
        /// the time a save took between asking whether its group is there and
        /// taking the lock.
        /// </remarks>
        [Test]
        public async Task ASaveRacingTheRemovalDoesNotBringTheGroupBack()
        {

            var node = Node();

            for (var round = 0; round < 200; round++)
            {

                var local = Added(node, "local");
                var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

                var save    = Task.Run(async () => { await start.Task; return node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "servers": [ "lc1.local" ] }"""), out _, out _); });
                var remove  = Task.Run(async () => { await start.Task; return (await node.TryRemoveNTSGroupAsync("local")).Removed; });

                start.SetResult();

                await Task.WhenAll(save, remove);

                var inFile = OnDisk["nts"]?["groups"]?["local"] is not null;
                var inNode = node.NTSGroupOf("local") is not null;

                Assert.That(inFile, Is.EqualTo(inNode),
                            $"round {round}: the file {(inFile ? "names" : "does not name")} 'local', the node {(inNode ? "has" : "has not")} - saved {save.Result}, removed {remove.Result}");

                if (inNode)
                    Assert.That((await node.TryRemoveNTSGroupAsync("local")).Removed, Is.True);

            }

        }

        #endregion

        #region AGroupSwitchedOffIsRemovedWhole()

        [Test]
        public async Task AGroupSwitchedOffIsRemovedWhole()
        {

            var node   = Node();
            var local  = Added(node, "local");

            Updated(node, local, """{ "servers": [ "lc1.local" ], "enabled": true }""");
            Updated(node, local, """{ "enabled": false }""");

            var (removed, error, _) = await node.TryRemoveNTSGroupAsync("local");

            var synced   = await node.SyncTimeAsync(local);
            var refused  = node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "enabled": true }"""), out var updateError, out _);
            var again    = Node();

            Assert.Multiple(() => {

                Assert.That(removed,                                        Is.True,  error);
                Assert.That(node.NTSGroups.Select(group => group.Id),       Is.EqualTo(new[] { "legal" }));
                Assert.That(local.IsDisposed,                               Is.True);
                Assert.That(local.IsChecking,                               Is.False);
                Assert.That(local.Client,                                   Is.Null,   "its client let go of");
                Assert.That(OnDisk["nts"]?["groups"]?["local"],             Is.Null,   "and out of the file");
                Assert.That(OnDisk["nts"]?["groups"]?["legal"],             Is.Not.Null);

                Assert.That(synced.Value<Boolean>("ok"),                    Is.False,  "a group taken away is asked no more");
                Assert.That(synced.Value<String>("error"),                  Does.Contain("was removed"));
                Assert.That(refused,                                        Is.False,  "and changed no more");
                Assert.That(updateError,                                    Does.Contain("has no NTS group 'local'"));

                Assert.That(again.NTSGroupOf("local"),                      Is.Null,   "nor made again at the next start");

                Assert.That(node.Log.Recent(50).Select(entry => entry.Message),  Has.Some.EqualTo("NTS group 'local' removed."));

            });

        }

        #endregion

        #region TheLegalGroupSwitchedOffIsRemovedAndCanComeBack()

        /// <summary>
        /// A country without legal time for charging stations: the legal group
        /// switched off, taken away, and gone at the next start - not back as
        /// the default. And back once it is added again, switched off, the
        /// PTB's four.
        /// </summary>
        [Test]
        public async Task TheLegalGroupSwitchedOffIsRemovedAndCanComeBack()
        {

            var node   = Node();
            var legal  = node.LegalTime;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "enabled": false }"""), out var error),  Is.True,  error);

            var (removed, removeError, _) = await node.TryRemoveNTSGroupAsync("legal");

            Assert.That(removed,  Is.True,  removeError);

            var again  = Node();

            Assert.Multiple(() => {

                Assert.That(node.NTSGroups,                                         Is.Empty);
                Assert.That(node.LegalTime,                                         Is.Not.SameAs(legal),  "replaced by one listed nowhere");
                Assert.That(node.NTSEnabled,                                        Is.False);
                Assert.That(node.NTSClient,                                         Is.Not.Null,           "which still has a client to name");
                Assert.That(node.ClockJSON().Value<Boolean>("legal"),               Is.False);
                Assert.That(legal.IsDisposed,                                       Is.True);

                Assert.That(JToken.DeepEquals(OnDisk["nts"], JObject.Parse("""{ "groups": { } }""")),  Is.True,  OnDisk.ToString());

                Assert.That(again.NTSGroups,                                        Is.Empty,  "not back as the default at the next start");
                Assert.That(again.NTSEnabled,                                       Is.False);

                Assert.That(node.Log.Recent(50).Select(entry => entry.Message),     Has.Some.Contains("NTS group 'legal' removed: this"));

            });

            var back = Added(node, "legal");

            Assert.Multiple(() => {
                Assert.That(node.NTSGroups.Select(group => group.Id),  Is.EqualTo(new[] { "legal" }));
                Assert.That(back,                                      Is.SameAs(node.LegalTime));
                Assert.That(back.Enabled,                              Is.False);
                Assert.That(back.Sources.Sources.Count(),              Is.EqualTo(4),  "the PTB's four");
                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?.Value<Boolean>("enabled"),  Is.False);
            });

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "enabled": true }"""), out error),  Is.True,  error);
            Assert.That(node.NTSEnabled,  Is.True,  "and legal time rests on it once it is switched on");

        }

        #endregion

        #region RemovingAGroupEndsTheCheckRunningAgainstIt()

        /// <summary>
        /// A check still running when its group is taken away - "Sync now"
        /// pressed before it was switched off, or the last one its timer began
        /// - is cancelled and waited for: taking the group away returns once it
        /// has ended, and it ended without writing anything into the group.
        /// </summary>
        /// <remarks>
        /// Against a server that takes the connection and never says a word, so
        /// that the check is running for as long as nobody ends it: its key
        /// exchange would give up after ten seconds. Its name is in the cache
        /// of the node's own DNS client, as in the pinning tests, so that
        /// nothing is asked of the network.
        /// </remarks>
        [Test]
        public async Task RemovingAGroupEndsTheCheckRunningAgainstIt()
        {

            using var silent    = new TcpListener(System.Net.IPAddress.Loopback, 0);
            silent.Start();

            var port            = ((IPEndPoint) silent.LocalEndpoint).Port;
            var connected       = new TaskCompletionSource<Socket>(TaskCreationOptions.RunContinuationsAsynchronously);

            _ = Task.Run(async () => {
                    try
                    {
                        connected.TrySetResult(await silent.AcceptSocketAsync());
                    }
                    catch (Exception e)
                    {
                        connected.TrySetException(e);
                    }
                });

            var name            = DomainName.Parse("silent.test");
            var dns             = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

            dns.DNSCache.Add      (DNSServiceName.Parse(name.ToString()), new A(name, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost));
            dns.DNSCache.AddNoData(DNSServiceName.Parse(name.ToString()), DNSResourceRecordTypes.AAAA, TimeSpan.FromHours(1));

            await using var node = Node(DNSClient: dns);

            var local           = Added(node, "local");

            Updated(node, local, $$"""{ "servers": [ { "hostname": "silent.test", "ntsKEPort": {{port}} } ], "enabled": true }""");

            var sync            = node.SyncTimeAsync(local);
            var socket          = await connected.Task.WaitAsync(TimeSpan.FromSeconds(10));

            Assert.That(local.Running,  Is.EqualTo(1),  "the check is on its way, and waiting for an answer");

            Updated(node, local, """{ "enabled": false }""");

            var clock           = Stopwatch.StartNew();
            var (removed, error, _) = await node.TryRemoveNTSGroupAsync("local").WaitAsync(TimeSpan.FromSeconds(30));
            clock.Stop();

            Assert.Multiple(() => {

                Assert.That(removed,                                 Is.True,  error);
                Assert.That(sync.IsCompleted,                        Is.True,  "taking the group away returned before the check had ended");
                Assert.That(local.Running,                           Is.EqualTo(0));
                Assert.That(clock.Elapsed,                           Is.LessThan(TimeSpan.FromSeconds(8)),  "cancelled rather than left to time out");

                Assert.That(sync.IsCompleted ? sync.Result.Value<String>("error") : null,  Does.Contain("was removed"));
                Assert.That(local.LastSync,                          Is.Null,  "nothing written into a group nobody has");
                Assert.That(local.LastCheck,                         Is.Null);
                Assert.That(node.Log.Recent(100).Select(entry => entry.Message),  Has.None.Contains("produced no time"),             "and nothing into the log about it");
                Assert.That(node.Log.Recent(100).Select(entry => entry.Message),  Has.None.Contains("asking group 'local' failed"));

            });

            socket.Dispose();

        }

        #endregion

        #region TakingAGroupAwayEndsItsTimer()

        /// <summary>
        /// A group switched on in a running node is checked on a timer of its
        /// own; switched off, that timer ends; and none is left for a group
        /// taken away, or once the node is let go of.
        /// </summary>
        [Test]
        public async Task TakingAGroupAwayEndsItsTimer()
        {

            var clock  = new CountingClock();

            var node   = await TestKit.TestPorts.StartedOnFreshPorts(() => new WWCPNode(
                                 HTTPPort:          IPPort.Parse(TestKit.TestPorts.Free()),
                                 AccountsPath:      Path.Combine(directory, "accounts"),
                                 ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                                 CertificatesPath:  Path.Combine(directory, "certificates"),
                                 LogToConsole:      false,
                                 BridgeDebugLog:    false,
                                 TimeProvider:      clock
                             ));

            var atStart = clock.Live;

            var local  = Added(node, "local");
            var added  = clock.Live;

            Updated(node, local, """{ "servers": [ "lc1.local" ], "enabled": true }""");
            var on     = clock.Live;

            Updated(node, local, """{ "enabled": false }""");
            var off    = clock.Live;

            await node.TryRemoveNTSGroupAsync("local");
            var gone   = clock.Live;

            await node.DisposeAsync();

            Assert.Multiple(() => {
                Assert.That(local.IsChecking,  Is.False);
                Assert.That(added,             Is.EqualTo(atStart),      "made switched off, a group has no timer");
                Assert.That(on,                Is.EqualTo(atStart + 1),  "switched on in a running node, it has one at once");
                Assert.That(off,               Is.EqualTo(atStart),      "and switched off, not any more");
                Assert.That(gone,              Is.EqualTo(atStart));
                Assert.That(clock.CheckTimers, Is.EqualTo(2),            "the legal group's and the one local had");
                Assert.That(clock.Live,        Is.EqualTo(0),            "and none at all once the node is let go of");
            });

        }

        #endregion


        #region (class) CountingClock

        /// <summary>
        /// The system's clock, with timers that never fire and are counted
        /// while they are set - and the ones a clock check sets, by their
        /// period, apart from whatever else a node sets.
        /// </summary>
        private sealed class CountingClock : TimeProvider
        {

            private Int32 live;
            private Int32 checkTimers;

            public Int32 Live         => Volatile.Read(ref live);

            public Int32 CheckTimers  => Volatile.Read(ref checkTimers);

            public override DateTimeOffset GetUtcNow()
                => TimeProvider.System.GetUtcNow();

            public override ITimer CreateTimer(TimerCallback  Callback,
                                               Object?        State,
                                               TimeSpan       DueTime,
                                               TimeSpan       Period)
            {

                // The clock check's first check is a minute in; nothing else a
                // node sets waits exactly that long first.
                if (DueTime == TimeSpan.FromMinutes(1))
                    Interlocked.Increment(ref checkTimers);

                return new Counted(this, DueTime == TimeSpan.FromMinutes(1));

            }

            private sealed class Counted : ITimer
            {

                private readonly CountingClock  clock;
                private readonly Boolean        counted;
                private          Int32          disposed;

                public Counted(CountingClock Clock, Boolean Counted)
                {

                    clock    = Clock;
                    counted  = Counted;

                    if (counted)
                        Interlocked.Increment(ref clock.live);

                }

                public Boolean Change(TimeSpan DueTime, TimeSpan Period)
                    => true;

                public void Dispose()
                {
                    if (counted && Interlocked.Exchange(ref disposed, 1) == 0)
                        Interlocked.Decrement(ref clock.live);
                }

                public ValueTask DisposeAsync()
                {
                    Dispose();
                    return ValueTask.CompletedTask;
                }

            }

        }

        #endregion

    }

}
