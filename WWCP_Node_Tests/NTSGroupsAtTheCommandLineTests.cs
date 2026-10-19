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

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The groups of time servers at the command line: syncNTS asks the group
    /// named first, or the legal one; listNTSGroups lists them; and the banner
    /// names every group beside the legal one.
    /// </summary>
    /// <remarks>
    /// Every group here is switched off, so nothing asks a time server: what is
    /// read is what the command says and what it writes into the log, which
    /// is what "Sync now" on the page writes.
    /// </remarks>
    [TestFixture]
    public class NTSGroupsAtTheCommandLineTests
    {

        #region Data

        private String     directory  = default!;
        private WWCPNode?  node;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void SetUp()
        {

            directory = Path.Combine(Path.GetTempPath(), $"node-cli-nts-{Guid.NewGuid().ToString("N")[..12]}");

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // A file let go of a moment too late; the temporary directory
                // is the system's to clear.
            }

        }

        #endregion


        #region (helper) Node(NTS)

        /// <summary>
        /// A node with the given "nts" section, never started.
        /// </summary>
        private WWCPNode Node(String NTS)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "dns": { "enabled": false }, "nts": {{NTS}} }""");

            node = new WWCPNode(
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

            return node;

        }

        /// <summary>
        /// The legal group and a local one, both switched off, the local one
        /// with two servers and a name for every language.
        /// </summary>
        private WWCPNode TwoGroups()

            => Node("""
                    { "groups": {
                        "legal": { "enabled": false },
                        "local": { "enabled": false, "servers": [ "lc1.local", "lc2.local" ], "displayName": "Site clock" }
                    } }
                    """);

        #endregion


        #region SyncNTSAsksTheGroupNamedFirst()

        [Test]
        public async Task SyncNTSAsksTheGroupNamedFirst()
        {

            var node   = TwoGroups();
            var cli    = new NodeCLI(node);
            var said   = new List<LogEntry>();

            node.Log.OnLogged += logged => said.Add(logged);

            var local  = await cli.Execute("syncNTS local");
            var legal  = await cli.Execute("syncNTS");

            Assert.Multiple(() => {

                Assert.That(said.Select(entry => entry.Message),
                            Has.Some.EqualTo($"Somebody at the command line asked this {node.Kind.Name} to check its time against the NTS group 'local'."));
                Assert.That(said.Single(entry => entry.Message.Contains("against the NTS group 'local'")).Level,  Is.EqualTo(LogLevel.Notice));

                Assert.That(said.Select(entry => entry.Message),
                            Has.Some.EqualTo($"Somebody at the command line asked this {node.Kind.Name} to synchronise its time."),
                            "and the legal group without a name, as before there were groups");

                Assert.That(local[0],  Does.StartWith("failed").And.Contain("switched off"));
                Assert.That(legal[0],  Does.StartWith("failed").And.Contain("switched off"));

            });

        }

        #endregion

        #region SyncNTSTestsAServerOfTheGroupNamedAndNoOther()

        [Test]
        public async Task SyncNTSTestsAServerOfTheGroupNamedAndNoOther()
        {

            var node      = TwoGroups();
            var cli       = new NodeCLI(node);
            var said      = new List<String>();

            node.Log.OnLogged += logged => said.Add(logged.Message);

            var nowhere   = await cli.Execute("syncNTS local nowhere.example");
            var legalOne  = await cli.Execute("syncNTS local ptbtime1.ptb.de");
            var tested    = await cli.Execute("syncNTS local lc2.local");

            Assert.Multiple(() => {

                Assert.That(nowhere,   Is.EqualTo(new[] { "'nowhere.example' is none of the time servers of NTS group 'local', which are lc1.local, lc2.local." }));
                Assert.That(legalOne,  Is.EqualTo(new[] { "'ptbtime1.ptb.de' is none of the time servers of NTS group 'local', which are lc1.local, lc2.local." }),
                            "a server of another group is not this group's");

                Assert.That(tested[0], Does.StartWith("lc2.local did not answer"));
                Assert.That(said,      Has.Some.EqualTo($"Somebody at the command line asked this {node.Kind.Name} to test the time server 'lc2.local' of the NTS group 'local'."));
                Assert.That(said.Count(line => line.Contains("asked this")),  Is.EqualTo(1),  "the two refused were asked of nobody");

            });

        }

        #endregion

        #region AWordThatIsNoGroupIsAServerOfTheLegalGroup()

        /// <summary>
        /// What syncNTS was before there were groups: "syncNTS
        /// ptbtime2.ptb.de" tests that server of the legal group.
        /// </summary>
        [Test]
        public async Task AWordThatIsNoGroupIsAServerOfTheLegalGroup()
        {

            var node    = TwoGroups();
            var cli     = new NodeCLI(node);
            var said    = new List<String>();

            node.Log.OnLogged += logged => said.Add(logged.Message);

            var tested  = await cli.Execute("syncNTS ptbtime2.ptb.de");
            var none    = await cli.Execute("syncNTS lc1.local");

            Assert.Multiple(() => {
                Assert.That(tested[0],  Does.StartWith("ptbtime2.ptb.de did not answer"));
                Assert.That(said,       Has.Some.EqualTo($"Somebody at the command line asked this {node.Kind.Name} to test the time server 'ptbtime2.ptb.de'."));
                Assert.That(none[0],    Does.StartWith($"'lc1.local' is none of this {node.Kind.Name}'s time servers, which are ptbtime1.ptb.de"));
            });

        }

        #endregion

        #region WithoutALegalGroupSyncNTSNamesTheGroupsThereAre()

        [Test]
        public async Task WithoutALegalGroupSyncNTSNamesTheGroupsThereAre()
        {

            var cli     = new NodeCLI(Node("""{ "groups": { "local": { "enabled": false }, "grid": { "enabled": false } } }"""));
            var answer  = await cli.Execute("syncNTS");

            Assert.That(answer,  Is.EqualTo(new[] { $"This {node!.Kind.Name} has no legal time to ask about. Name one of its NTS groups: local, grid." }));

        }

        #endregion

        #region TheGroupsAndTheirServersAreOffered()

        [Test]
        public async Task TheGroupsAndTheirServersAreOffered()
        {

            var cli       = new NodeCLI(TwoGroups());

            var whole     = (await cli.Suggest("syncNTS")).        Select(suggestion => suggestion.Suggestion).ToArray();
            var begun     = (await cli.Suggest("syncNTS lo")).     Select(suggestion => suggestion.Suggestion).ToArray();
            var ofLocal   = (await cli.Suggest("syncNTS local lc")).Select(suggestion => suggestion.Suggestion).ToArray();

            Assert.Multiple(() => {
                Assert.That(whole,    Does.Contain("syncNTS local").And.Contain("syncNTS ptbtime1.ptb.de"));
                Assert.That(whole,    Does.Not.Contain("syncNTS legal"),  "the legal group is what is asked without a name");
                Assert.That(begun,    Is.EqualTo(new[] { "syncNTS local" }));
                Assert.That(ofLocal,  Is.EquivalentTo(new[] { "syncNTS local lc1.local", "syncNTS local lc2.local" }));
            });

        }

        #endregion

        #region ListNTSGroupsSaysEveryGroupOnALine()

        [Test]
        public async Task ListNTSGroupsSaysEveryGroupOnALine()
        {

            var cli     = new NodeCLI(TwoGroups());
            var listed  = await cli.Execute("listNTSGroups");

            Assert.Multiple(() => {
                Assert.That(listed,     Has.Length.EqualTo(2));
                Assert.That(listed[0],  Does.StartWith($"{"legal".PadRight(18)}  off  ptbtime1.ptb.de, ptbtime2.ptb.de, ptbtime3.ptb.de, ptbtime4.ptb.de - 2 must answer; every 15 min; never checked"),
                            "the names in a column as wide as the longest");
                Assert.That(listed[1],  Is.EqualTo("local \"Site clock\"  off  lc1.local, lc2.local - 2 must answer; every 15 min; never checked"));
            });

        }

        [Test]
        public async Task ListNTSGroupsSaysWhereThereIsNoLegalTime()
        {

            var cli     = new NodeCLI(Node("""{ "groups": { "grid": { "enabled": false } } }"""));
            var listed  = await cli.Execute("listNTSGroups");

            Assert.That(listed,  Is.EqualTo(new[] { "grid  off  no time server yet; every 15 min; never checked",
                                                     $"No group is legal time on this {node!.Kind.Name}." }));

        }

        #endregion

        #region TheBannerNamesEveryGroupBesideTheLegalOne()

        [Test]
        public void TheBannerNamesEveryGroupBesideTheLegalOne()
        {

            var banner  = TwoGroups().Banner();
            var at      = banner.ToList().FindIndex(line => line.StartsWith("  NTS groups"));

            Assert.Multiple(() => {
                Assert.That(banner,              Has.Some.StartsWith("  time servers".PadRight(NodeBanner.Column) + "ptbtime1.ptb.de"),  "the legal group, as before, in the column of 17");
                Assert.That(at,                  Is.GreaterThan(0));
                Assert.That(banner[at],          Is.EqualTo("  NTS groups".PadRight(NodeBanner.Column) + "local: lc1.local,"),
                            "broken after a comma where the line would be wider than 80 columns, as the legal servers are");
                Assert.That(banner[at + 1],      Is.EqualTo(new String(' ', NodeBanner.Column) + "lc2.local - at least 2 must answer (switched off)"));
                Assert.That(banner[at].Length,   Is.LessThanOrEqualTo(NodeUsage.Width));
            });

        }

        [Test]
        public void TheBannerSaysWhereThereIsNoLegalTime()
        {

            var banner = Node("""{ "groups": { "grid": { "enabled": false } } }""").Banner();

            Assert.Multiple(() => {
                Assert.That(banner,  Has.Some.EqualTo("  time servers".PadRight(NodeBanner.Column) + "none for legal time"));
                Assert.That(banner,  Has.Some.EqualTo("  NTS groups".PadRight(NodeBanner.Column)   + "grid: no time server yet (switched off)"));
                Assert.That(banner,  Has.None.Contains("ptbtime"),  "the legal group this node keeps for having none is nobody's to name");
            });

        }

        #endregion

    }

}
