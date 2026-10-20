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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a node makes of a file with several groups of time servers, and
    /// what saving one of them does to the file - and that the flat section of
    /// the files from before there were groups is refused, not read.
    /// </summary>
    /// <remarks>
    /// The nodes are constructed and never started, as in
    /// <see cref="NTSGroupInEffectTests"/>: the constructor is what applies the
    /// file.
    /// </remarks>
    public class NTSGroupsInTheFileTests
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

            directory = Path.Combine(Path.GetTempPath(), "node-nts-groups-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Configuration = null)

        /// <summary>
        /// A node as it stands after reading this configuration file, or after
        /// reading the one that is there.
        /// </summary>
        private WWCPNode Node(String? Configuration = null)
        {

            if (Configuration is not null)
                File.WriteAllText(ConfigurationPath, Configuration);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false
                   );

        }

        #endregion

        #region (helper) Group(Node, Id)

        private static NTSGroup Group(WWCPNode Node, String Id)

            => Node.NTSGroups.Single(group => group.Id == Id);

        #endregion


        #region ANodeWithoutAFileHasTheLegalGroupAlone()

        [Test]
        public void ANodeWithoutAFileHasTheLegalGroupAlone()
        {

            var node = Node();

            Assert.Multiple(() => {
                Assert.That(node.NTSGroups.Select(group => group.Id),  Is.EqualTo(new[] { "legal" }));
                Assert.That(node.LegalTime.Enabled,                    Is.True);
                Assert.That(node.LegalTime.Sources.Sources.Count(),    Is.EqualTo(4),  "the PTB's four");
            });

        }

        #endregion

        #region EveryGroupOfTheFileIsAGroupOfTheNode()

        [Test]
        public void EveryGroupOfTheFileIsAGroupOfTheNode()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal": { "legalTimeAuthority": "PTB" },
                                  "local": { "servers": [ "lc1.local", "lc2.local" ], "minServers": 2, "checkEverySeconds": 30,
                                             "displayName": { "en": "Local time", "de": "Lokale Zeit" } },
                                  "grid":  { "enabled": false }
                              } } }
                              """);

            var local  = Group(node, "local");
            var grid   = Group(node, "grid");

            Assert.Multiple(() => {

                Assert.That(node.NTSGroups.Select(group => group.Id),               Is.EqualTo(new[] { "legal", "local", "grid" }));
                Assert.That(node.LegalTimeAuthority,                                Is.EqualTo("PTB"));
                Assert.That(node.LegalTime.Sources.Sources.Count(),                 Is.EqualTo(4),  "a legal group naming nobody is still the PTB's four");

                Assert.That(local.Enabled,                                          Is.True,   "naming servers and saying nothing about it, a group is on");
                Assert.That(local.Sources.Name,                                     Is.EqualTo("local"));
                Assert.That(local.Sources.Sources.Select(source => source.Hostname.Trimmed),  Is.EqualTo(new[] { "lc1.local", "lc2.local" }));
                Assert.That(local.Sources.MinServers,                               Is.EqualTo(2));
                Assert.That(local.CheckEvery,                                       Is.EqualTo(TimeSpan.FromSeconds(30)));
                Assert.That(local.Client?.Hostname.Trimmed,                         Is.EqualTo("lc1.local"),  "the detailed test starts from the first server it names");
                Assert.That(local.DisplayName?["de"],                               Is.EqualTo("Lokale Zeit"));
                Assert.That(local.Authority,                                        Is.Null);

                Assert.That(grid.Enabled,                                           Is.False);
                Assert.That(grid.Sources.Sources,                                   Is.Empty);
                Assert.That(grid.Client,                                            Is.Null,   "nobody to start a test from");

            });

        }

        #endregion

        #region AFileWithoutALegalGroupIsANodeWithoutLegalTime()

        /// <summary>
        /// A country without legal time for charging stations. The legal group
        /// is switched off and nobody's to list, and the clock says why it is
        /// not legal time rather than having nothing to say.
        /// </summary>
        [Test]
        public void AFileWithoutALegalGroupIsANodeWithoutLegalTime()
        {

            var node  = Node("""{ "nts": { "groups": { "local": { "servers": [ "lc1.local" ] } } } }""");
            var clock = node.ClockJSON();

            Assert.Multiple(() => {
                Assert.That(node.NTSGroups.Select(group => group.Id),  Is.EqualTo(new[] { "local" }));
                Assert.That(node.NTSEnabled,                           Is.False);
                Assert.That(clock.Value<Boolean>("legal"),             Is.False);
                Assert.That(clock["nts"]?.Value<Boolean>("enabled"),   Is.False);
            });

        }

        #endregion

        #region NoGroupsAtAllIsANodeThatAsksNobody()

        [Test]
        public void NoGroupsAtAllIsANodeThatAsksNobody()
        {

            var node = Node("""{ "nts": { "groups": { } } }""");

            Assert.Multiple(() => {
                Assert.That(node.NTSGroups,   Is.Empty);
                Assert.That(node.NTSEnabled,  Is.False);
            });

        }

        #endregion

        #region AFlatFileIsRefusedAtTheStart()

        /// <summary>
        /// The section of the files from before there were groups: the node
        /// does not start with it, says where its settings belong, and leaves
        /// the file as it was.
        /// </summary>
        [Test]
        public void AFlatFileIsRefusedAtTheStart()
        {

            const String file = """{ "nts": { "hostname": "a.example", "checkEverySeconds": 600 } }""";

            var problem = Assert.Throws<InvalidOperationException>(() => Node(file));

            Assert.Multiple(() => {
                Assert.That(problem!.Message,                     Does.Contain("'hostname', 'checkEverySeconds'").
                                                                  And.Contain("move them into 'nts.groups.legal'"));
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(file));
            });

        }

        #endregion

        #region ASaveIntoAFileMadeFlatByHandIsRefused()

        /// <summary>
        /// A file written flat by hand while the node runs is not moved into a
        /// group by the next save: the save is refused as the next start would
        /// refuse the file, and the file is left as it was.
        /// </summary>
        [Test]
        public void ASaveIntoAFileMadeFlatByHandIsRefused()
        {

            var node = Node("""{ "nts": { "groups": { "legal": { "servers": [ "a.example", "b.example" ] } } } }""");

            const String file = """{ "nts": { "servers": [ "a.example", "b.example" ] } }""";

            File.WriteAllText(ConfigurationPath, file);

            Assert.Multiple(() => {
                Assert.That(node.TryUpdateNTSConfiguration(new JObject(new JProperty("minServers", 2)), out var error),  Is.False);
                Assert.That(error,                                Does.Contain("move it into 'nts.groups.legal'"));
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(file));
            });

        }

        #endregion

        #region SavingOneGroupLeavesTheOthersAlone()

        [Test]
        public void SavingOneGroupLeavesTheOthersAlone()
        {

            var node    = Node("""
                               { "nts": { "groups": {
                                   "legal": { "legalTimeAuthority": "PTB", "checkEverySeconds": 600 },
                                   "local": { "enabled": false }
                               } } }
                               """);

            var legal   = OnDisk["nts"]!["groups"]!["legal"]!.DeepClone();
            var local   = Group(node, "local");

            Assert.That(node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "servers": [ "lc1.local" ], "enabled": true, "checkEverySeconds": 30 }"""), out var error, out _),
                        Is.True,  error);

            Assert.Multiple(() => {

                Assert.That(JToken.DeepEquals(OnDisk["nts"]?["groups"]?["legal"], legal),           Is.True,  "the legal group as it was");
                Assert.That(OnDisk["nts"]?["groups"]?["local"]?.Value<Boolean>("enabled"),           Is.True);
                Assert.That(OnDisk["nts"]?["groups"]?["local"]?["servers"]?[0]?.Value<String>(),     Is.EqualTo("lc1.local."));

                Assert.That(local.Enabled,                                                            Is.True);
                Assert.That(local.Client?.Hostname.Trimmed,                                           Is.EqualTo("lc1.local"),  "a group naming its first server is given a client for it");
                Assert.That(local.CheckEvery,                                                         Is.EqualTo(TimeSpan.FromSeconds(30)));
                Assert.That(node.TimeCheckEvery,                                                      Is.EqualTo(TimeSpan.FromSeconds(600)),  "and legal time is checked as often as before");

            });

        }

        #endregion

        #region AGroupOtherThanTheLegalOneIsRefusedLegalTime()

        [Test]
        public void AGroupOtherThanTheLegalOneIsRefusedLegalTime()
        {

            var node    = Node("""{ "nts": { "groups": { "legal": { }, "local": { "servers": [ "lc1.local" ] } } } }""");
            var before  = File.ReadAllText(ConfigurationPath);

            Assert.Multiple(() => {
                Assert.That(node.TryUpdateNTSConfiguration(Group(node, "local"), JObject.Parse("""{ "legalTimeAuthority": "PTB" }"""), out var error, out var notSaved),  Is.False);
                Assert.That(error,                                Does.Contain("only the group 'legal'").And.Contain("Nothing was changed"));
                Assert.That(notSaved,                             Is.False,  "the change was wrong, not the file");
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before));
                Assert.That(Group(node, "local").Authority,       Is.Null);
            });

        }

        #endregion

        #region ANodeWithoutLegalGroupHasNoLegalTimeToChange()

        /// <summary>
        /// What changes legal time without naming a group - the page of a node
        /// that had one, the old route - has nothing to change where there is
        /// none, and does not make one up by saving into it.
        /// </summary>
        [Test]
        public void ANodeWithoutLegalGroupHasNoLegalTimeToChange()
        {

            var node    = Node("""{ "nts": { "groups": { "local": { "servers": [ "lc1.local" ] } } } }""");
            var before  = File.ReadAllText(ConfigurationPath);

            Assert.Multiple(() => {
                Assert.That(node.TryUpdateNTSConfiguration(new JObject(new JProperty("enabled", true)), out var error),  Is.False);
                Assert.That(error,                                Does.Contain("no NTS group 'legal'"));
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before));
                Assert.That(node.NTSEnabled,                      Is.False);
            });

        }

        #endregion

        #region AGroupSwitchedOffNamingNobodyHasNothingToTest()

        [Test]
        public async Task AGroupSwitchedOffNamingNobodyHasNothingToTest()
        {

            var node    = Node("""{ "nts": { "groups": { "legal": { }, "grid": { "enabled": false } } } }""");
            var grid    = Group(node, "grid");

            var synced  = await node.SyncTimeAsync(grid);
            var tested  = await node.TestTimeServerAsync(grid);

            Assert.Multiple(() => {
                Assert.That(synced.Value<Boolean>("ok"),  Is.False);
                Assert.That(tested.Value<Boolean>("ok"),  Is.False);
                Assert.That(grid.LastCheck,               Is.Null);
            });

        }

        #endregion

    }

}
