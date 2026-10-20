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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The white paper's "errorLogging" and "maxErrors" for every group of time
    /// servers: the checks in a row that produced no time, written down at the
    /// one, limiting what rests on the group at the other, and written down
    /// again once a check produces a time.
    /// </summary>
    /// <remarks>
    /// The checks here fail at once: their one server is a name the node's own
    /// resolver knows to have no address, from its cache, so that nothing is
    /// asked of the network. A check that produces a time again is the pinning
    /// tests' to show, against a time server of their own - see
    /// <see cref="TimeServerPinningIntegrationTests"/>.
    /// </remarks>
    [TestFixture]
    public class NTSErrorCountTests
    {

        #region Data

        private static readonly DomainName  nowhere   = DomainName.Parse("nowhere.test");

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

            directory = Path.Combine(Path.GetTempPath(), "node-nts-errors-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helpers) Node(NTS) / Failing(Group) / Updated(Node, Group, JSON) / Said(Node, Since)

        /// <summary>
        /// A node with the given "nts" section, whose resolver knows that
        /// "nowhere.test" has no address - so that a check asking it fails at
        /// once.
        /// </summary>
        private WWCPNode Node(String NTS)
        {

            File.WriteAllText(ConfigurationPath, $$"""{ "dns": { "enabled": false }, "nts": {{NTS}} }""");

            // Somebody to ask, so that the cache is consulted at all - at a port
            // nothing listens on, which nobody is asked at: both records are
            // cached as having none.
            var dns = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

            dns.DNSCache.AddNoData(DNSServiceName.Parse(nowhere.ToString()), DNSResourceRecordTypes.A,    TimeSpan.FromHours(1));
            dns.DNSCache.AddNoData(DNSServiceName.Parse(nowhere.ToString()), DNSResourceRecordTypes.AAAA, TimeSpan.FromHours(1));

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       DNSClient:         dns,
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        /// <summary>
        /// A group asking nobody who answers, switched on, with the given
        /// numbers.
        /// </summary>
        private static String Failing(String Numbers)

            => $$"""{ "enabled": true, "servers": [ "{{nowhere.Trimmed}}" ], "minServers": 1{{(Numbers.Length > 0 ? ", " + Numbers : "")}} }""";

        private static void Updated(WWCPNode  Node,
                                    NTSGroup  Group,
                                    String    JSON)
        {
            Assert.That(Node.TryUpdateNTSConfiguration(Group, JObject.Parse(JSON), out var error, out _),  Is.True,  error);
        }

        /// <summary>
        /// What the node wrote about runs of failed checks since the given
        /// entry.
        /// </summary>
        private static LogEntry[] Said(WWCPNode  Node,
                                       UInt64    Since)

            => [.. Node.Log.Recent(500, Since, null).Where(entry => entry.Tags.Contains("errors"))];

        private static async Task Fail(WWCPNode  Node,
                                       NTSGroup  Group,
                                       Int32     Times)
        {
            for (var i = 0; i < Times; i++)
            {
                var result = await Node.SyncTimeAsync(Group);
                Assert.That(result.Value<Boolean>("ok"),  Is.False,  result.ToString());
            }
        }

        #endregion


        #region TheNumbersAreTheWhitePapersWhereTheFileNamesNone()

        [Test]
        public async Task TheNumbersAreTheWhitePapersWhereTheFileNamesNone()
        {

            await using var node = Node("""
                                        { "groups": {
                                            "legal": { "enabled": false },
                                            "local": { "enabled": false },
                                            "grid":  { "enabled": false }
                                        } }
                                        """);

            Assert.Multiple(() => {
                Assert.That(node.NTSGroups.Select(group => $"{group.Id} {group.ErrorLogging}/{group.MaxErrors}"),
                            Is.EqualTo(new[] { "legal 5/10", "local 5/50", "grid 5/10" }),
                            "five and ten, and fifty for the local group, whose load management can wait longer than a tariff");
                Assert.That(node.NTSGroups.Select(group => group.ErrorsInARow),  Is.All.EqualTo(0));
                Assert.That(node.NTSGroups.Select(group => group.IsLimited),     Is.All.False);
            });

        }

        #endregion

        #region TheNumbersAreReadWrittenAndRefusedOutsideTheirRange()

        [Test]
        public async Task TheNumbersAreReadWrittenAndRefusedOutsideTheirRange()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false }, "local": { "enabled": false, "errorLogging": 3 } } }""");

            var local    = node.NTSGroupOf("local")!;
            var none     = node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "maxErrors": 0 }"""),      out var noneError, out _);
            var tooMany  = node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "errorLogging": 65536 }"""), out var tooManyError, out _);
            var notOne   = node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "maxErrors": 2.5 }"""),    out var notOneError, out _);

            Updated(node, local, """{ "maxErrors": 7 }""");

            var settings = node.NTSConfigurationJSON(local)["settings"]!;

            Assert.Multiple(() => {

                Assert.That(none,          Is.False);
                Assert.That(noneError,     Is.EqualTo("'nts.groups.local.maxErrors' must be between 1 and 65535."));
                Assert.That(tooMany,       Is.False);
                Assert.That(tooManyError,  Is.EqualTo("'nts.groups.local.errorLogging' must be between 1 and 65535."));
                Assert.That(notOne,        Is.False);
                Assert.That(notOneError,   Is.EqualTo("'nts.groups.local.maxErrors' must be a whole number."));

                Assert.That(local.ErrorLogging,                                     Is.EqualTo(3),  "read from the file");
                Assert.That(local.MaxErrors,                                        Is.EqualTo(7),  "and changed by a save");
                Assert.That(OnDisk["nts"]!["groups"]!["local"]!["errorLogging"]?.Value<Int32>(),  Is.EqualTo(3),  "the file keeps what the save did not name");
                Assert.That(OnDisk["nts"]!["groups"]!["local"]!["maxErrors"]?.   Value<Int32>(),  Is.EqualTo(7));

                Assert.That(settings["errorLogging"]?.Value<Int32>(),               Is.EqualTo(3));
                Assert.That(settings["maxErrors"]?.   Value<Int32>(),               Is.EqualTo(7));
                Assert.That(node.NTSConfigurationJSON(local)["limits"]!["maxErrorCount"]?.Value<Int32>(),  Is.EqualTo(65535));

                Assert.That(node.Log.Recent(100).Select(entry => entry.Message),
                            Has.Some.EqualTo("NTS group 'local' changed: limited after 7 errors in a row."));

            });

        }

        #endregion

        #region ARunOfFailuresIsWrittenDownOnceAtEachNumber()

        [Test]
        public async Task ARunOfFailuresIsWrittenDownOnceAtEachNumber()
        {

            await using var node = Node($$"""{ "groups": { "legal": { "enabled": false }, "local": {{Failing(""" "errorLogging": 2, "maxErrors": 3 """)}} } }""");

            var local    = node.NTSGroupOf("local")!;
            var told     = new List<(String, Boolean)>();
            var before   = node.Log.LastId;

            node.OnNTSGroupLimited += (group, limited) => told.Add((group.Id, limited));

            await Fail(node, local, 1);
            var afterOne = Said(node, before);

            await Fail(node, local, 4);
            var said     = Said(node, before);

            var json     = node.NTSConfigurationJSON(local)["errors"]!;
            var summary  = node.NTSGroupJSON(local);

            Assert.Multiple(() => {

                Assert.That(afterOne,                         Is.Empty,  "one failed check is no run yet");

                Assert.That(said.Select(entry => entry.Message), Is.EqualTo(new[] {
                    "NTS: group 'local' has produced no time 2 checks in a row ('errorLogging' is 2).",
                    "NTS: group 'local' has produced no time 3 checks in a row ('maxErrors' is 3): what rests on its time is limited until it produces one again."
                }), "once at each number, and nothing for the fourth and fifth");
                Assert.That(said.Select(entry => entry.Level),   Is.EqualTo(new[] { LogLevel.Warning, LogLevel.Error }));
                Assert.That(said.Select(entry => entry.Metrological),  Is.All.False,  "a group legal time does not rest on is no evidence about it");

                Assert.That(node.Log.Recent(500, before, null).Count(entry => entry.Message.StartsWith("NTS: group 'local' produced no time after")),
                            Is.EqualTo(5),
                            "every failed check is written down besides, as before");

                Assert.That(local.ErrorsInARow,               Is.EqualTo(5));
                Assert.That(local.IsLimited,                  Is.True);
                Assert.That(told,                             Is.EqualTo(new[] { ("local", true) }));

                Assert.That(json["inARow"]?. Value<Int32>(),   Is.EqualTo(5));
                Assert.That(json["limited"]?.Value<Boolean>(), Is.True);
                Assert.That(summary["errorsInARow"]?.Value<Int32>(),   Is.EqualTo(5));
                Assert.That(summary["limited"]?.     Value<Boolean>(), Is.True);
                Assert.That(summary["maxErrors"]?.   Value<Int32>(),   Is.EqualTo(3));

            });

        }

        #endregion

        #region TheLegalGroupsRunGoesIntoTheMetrologicalLog()

        [Test]
        public async Task TheLegalGroupsRunGoesIntoTheMetrologicalLog()
        {

            await using var node = Node($$"""{ "groups": { "legal": {{Failing(""" "errorLogging": 1, "maxErrors": 2 """)}} } }""");

            var before = node.Log.LastId;

            await Fail(node, node.LegalTime, 2);

            var said   = Said(node, before);
            var clock  = node.ClockJSON()["nts"]!;

            Assert.Multiple(() => {
                Assert.That(said,                              Has.Length.EqualTo(2));
                Assert.That(said.Select(entry => entry.Metrological),  Is.All.True,  "evidence about the time everything is stamped with");
                Assert.That(said[0].Message,                   Is.EqualTo("NTS: group 'legal' has produced no time 1 check in a row ('errorLogging' is 1)."));
                Assert.That(clock["errorsInARow"]?.Value<Int32>(),   Is.EqualTo(2));
                Assert.That(clock["maxErrors"]?.   Value<Int32>(),   Is.EqualTo(2));
                Assert.That(clock["limited"]?.     Value<Boolean>(), Is.True);
            });

        }

        #endregion

        #region SwitchingOffCountsFromNoneAgainAndIsNoRecovery()

        [Test]
        public async Task SwitchingOffCountsFromNoneAgainAndIsNoRecovery()
        {

            await using var node = Node($$"""{ "groups": { "legal": { "enabled": false }, "local": {{Failing(""" "errorLogging": 1, "maxErrors": 2 """)}} } }""");

            var local   = node.NTSGroupOf("local")!;
            var told    = new List<Boolean>();

            node.OnNTSGroupLimited += (group, limited) => told.Add(limited);

            await Fail(node, local, 3);

            var before  = node.Log.LastId;

            Updated(node, local, """{ "enabled": false }""");

            var said    = Said(node, before);

            Assert.Multiple(() => {
                Assert.That(said.Select(entry => entry.Message), Is.EqualTo(new[] {
                    "NTS: the checks of group 'local' that produced no time are counted from none again, after 3 in a row: it was switched off. What rests on its time is no longer limited."
                }));
                Assert.That(said.Select(entry => entry.Message), Has.None.Contains("produced a time again"),  "nothing produced a time");
                Assert.That(local.ErrorsInARow,  Is.EqualTo(0));
                Assert.That(local.IsLimited,     Is.False);
                Assert.That(told,                Is.EqualTo(new[] { true, false }));
            });

        }

        #endregion

        #region ChangedServersAreCountedFromNone()

        [Test]
        public async Task ChangedServersAreCountedFromNone()
        {

            await using var node = Node($$"""{ "groups": { "legal": { "enabled": false }, "local": {{Failing(""" "errorLogging": 1 """)}} } }""");

            var local   = node.NTSGroupOf("local")!;

            await Fail(node, local, 2);

            var before  = node.Log.LastId;

            Updated(node, local, """{ "servers": [ "nowhere.test", "lc2.local" ] }""");

            var said    = Said(node, before);

            Assert.Multiple(() => {
                Assert.That(said.Select(entry => entry.Message), Is.EqualTo(new[] {
                    "NTS: the checks of group 'local' that produced no time are counted from none again, after 2 in a row: its time servers changed."
                }));
                Assert.That(local.ErrorsInARow,  Is.EqualTo(0),  "what old servers did is not held against new ones");
            });

        }

        #endregion

        #region AMaxErrorsChangedInTheMiddleOfARunLimitsOrFreesAtOnce()

        [Test]
        public async Task AMaxErrorsChangedInTheMiddleOfARunLimitsOrFreesAtOnce()
        {

            await using var node = Node($$"""{ "groups": { "legal": { "enabled": false }, "local": {{Failing(""" "errorLogging": 9, "maxErrors": 5 """)}} } }""");

            var local    = node.NTSGroupOf("local")!;
            var told     = new List<Boolean>();

            node.OnNTSGroupLimited += (group, limited) => told.Add(limited);

            await Fail(node, local, 2);

            var before   = node.Log.LastId;

            Updated(node, local, """{ "maxErrors": 2 }""");
            var lowered  = local.IsLimited;

            Updated(node, local, """{ "maxErrors": 10 }""");
            var raised   = local.IsLimited;

            var said     = Said(node, before);

            Assert.Multiple(() => {
                Assert.That(lowered,  Is.True,   "two failed checks are as many as two");
                Assert.That(raised,   Is.False,  "and fewer than ten");
                Assert.That(told,     Is.EqualTo(new[] { true, false }));
                Assert.That(said.Select(entry => entry.Message), Is.EqualTo(new[] {
                    "NTS: group 'local' has produced no time 2 checks in a row ('maxErrors' is now 2): what rests on its time is limited until it produces one again.",
                    "NTS: what rests on the time of group 'local' is no longer limited: 'maxErrors' is now 10, more than the 2 checks in a row that produced no time."
                }));
                Assert.That(local.ErrorsInARow,  Is.EqualTo(2),  "the run goes on: nothing produced a time, and the servers are the same");
            });

        }

        #endregion

        #region AListenerThatThrowsFailsNothing()

        [Test]
        public async Task AListenerThatThrowsFailsNothing()
        {

            await using var node = Node($$"""{ "groups": { "legal": { "enabled": false }, "local": {{Failing(""" "maxErrors": 1 """)}} } }""");

            var local  = node.NTSGroupOf("local")!;
            var heard  = false;

            node.OnNTSGroupLimited += (_, _) => throw new InvalidOperationException("listener broke");
            node.OnNTSGroupLimited += (_, limited) => heard = limited;

            await Fail(node, local, 1);

            Assert.Multiple(() => {
                Assert.That(heard,            Is.True,  "the second listener heard it all the same");
                Assert.That(local.IsLimited,  Is.True);
                Assert.That(node.Log.Recent(50).Select(entry => entry.Message),
                            Has.Some.EqualTo("Something told that NTS group 'local' is limited failed: listener broke"));
            });

        }

        #endregion

        #region ListNTSGroupsSaysARun()

        [Test]
        public async Task ListNTSGroupsSaysARun()
        {

            await using var node = Node($$"""{ "groups": { "legal": { "enabled": false }, "local": {{Failing(""" "maxErrors": 3 """)}} } }""");

            var local   = node.NTSGroupOf("local")!;
            var cli     = new NodeCLI(node);

            await Fail(node, local, 2);
            var running = (await cli.Execute("listNTSGroups"))[1];

            await Fail(node, local, 1);
            var limited = (await cli.Execute("listNTSGroups"))[1];

            Assert.Multiple(() => {
                Assert.That(running,  Does.EndWith("never checked; 2 in a row produced no time, limited after 3"));
                Assert.That(limited,  Does.EndWith("never checked; 3 in a row produced no time, limited"));
            });

        }

        #endregion

    }

}
