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

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// When the key exchange with a time server is made again: at a random time
    /// between "minRefreshSeconds" and "maxRefreshSeconds" of its entry after
    /// the last one, or between 12 and 24 hours where the entry says nothing.
    /// </summary>
    /// <remarks>
    /// By the server's name across every group, as its AEAD algorithm is: the
    /// first entry that sets a refresh decides. To a CSMS they are
    /// NTPClientController.MinRefresh and MaxRefresh.
    /// </remarks>
    public class NTSServerRefreshTests
    {

        #region Data

        private static readonly DomainName a = DomainName.Parse("a.example");
        private static readonly DomainName b = DomainName.Parse("b.example");

        private static readonly (TimeSpan?, TimeSpan?) Defaults = (TimeSpan.FromHours(12), TimeSpan.FromHours(24));

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

            directory = Path.Combine(Path.GetTempPath(), "node-nts-refresh-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Configuration) / Refresh(Group, Hostname)

        private WWCPNode Node(String Configuration)
        {

            File.WriteAllText(ConfigurationPath, Configuration);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        /// <summary>
        /// When the given server of the given group makes its key exchange again,
        /// as the time library is told.
        /// </summary>
        private static (TimeSpan?, TimeSpan?) Refresh(NTSGroup    Group,
                                                      DomainName  Hostname)
        {
            var source = Group.Sources.Sources.Single(source => source.Hostname.Equals(Hostname));
            return (source.MinRefresh, source.MaxRefresh);
        }

        private static (TimeSpan?, TimeSpan?) Hours(Double Min, Double Max)

            => (TimeSpan.FromHours(Min), TimeSpan.FromHours(Max));

        #endregion


        #region ARefreshIsWrittenWithItsServerAndReadBack()

        /// <summary>
        /// "minRefreshSeconds" and "maxRefreshSeconds" are written with their
        /// server and read back, and left out where the entry leaves it to the
        /// defaults - so that a server saying nothing else stays a bare host
        /// name, and makes its key exchange again after 12 to 24 hours.
        /// </summary>
        [Test]
        public void ARefreshIsWrittenWithItsServerAndReadBack()
        {

            var held     = new NTSServerConfiguration(a, MinRefresh: TimeSpan.FromHours(1), MaxRefresh: TimeSpan.FromHours(2));
            var json     = held.ToJSON();

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out var read, out var error),  Is.True,  error);

            var endpoint = read!.ToEndpoint();
            var bare     = new NTSServerConfiguration(a).ToEndpoint();

            Assert.Multiple(() => {
                Assert.That(json.Value<Double>("minRefreshSeconds"),   Is.EqualTo(3600));
                Assert.That(json.Value<Double>("maxRefreshSeconds"),   Is.EqualTo(7200));
                Assert.That(read.MinRefresh,                           Is.EqualTo(TimeSpan.FromHours(1)));
                Assert.That(read.MaxRefresh,                           Is.EqualTo(TimeSpan.FromHours(2)));
                Assert.That((endpoint.MinRefresh, endpoint.MaxRefresh), Is.EqualTo(Hours(1, 2)));
                Assert.That(new NTSServerConfiguration(a).ToJSON().Type,
                            Is.EqualTo(JTokenType.String),
                            "a server leaving it to the defaults says nothing about it");
                Assert.That((bare.MinRefresh, bare.MaxRefresh),        Is.EqualTo(Defaults));
                Assert.That(held.ToString(),                           Does.Contain("key exchange again after 1 to 2 hours"));
            });

        }

        #endregion

        #region OneOfThemSetsTheOtherWhereTheDefaultWouldBeOnTheWrongSide()

        /// <summary>
        /// An entry that sets one of the two has the default for the other -
        /// unless that would make the longest time shorter than the shortest,
        /// where it has the one it sets for both.
        /// </summary>
        [Test]
        public void OneOfThemSetsTheOtherWhereTheDefaultWouldBeOnTheWrongSide()
        {

            Assert.Multiple(() => {
                Assert.That(NTSServerConfiguration.RefreshOf(new NTSServerConfiguration(a, MinRefresh: TimeSpan.FromHours(1))),
                            Is.EqualTo((TimeSpan.FromHours(1),  TimeSpan.FromHours(24))));
                Assert.That(NTSServerConfiguration.RefreshOf(new NTSServerConfiguration(a, MinRefresh: TimeSpan.FromHours(48))),
                            Is.EqualTo((TimeSpan.FromHours(48), TimeSpan.FromHours(48))));
                Assert.That(NTSServerConfiguration.RefreshOf(new NTSServerConfiguration(a, MaxRefresh: TimeSpan.FromHours(36))),
                            Is.EqualTo((TimeSpan.FromHours(12), TimeSpan.FromHours(36))));
                Assert.That(NTSServerConfiguration.RefreshOf(new NTSServerConfiguration(a, MaxRefresh: TimeSpan.FromHours(2))),
                            Is.EqualTo((TimeSpan.FromHours(2),  TimeSpan.FromHours(2))));
            });

        }

        #endregion

        #region ARefreshOutsideItsLimitsIsRefused(Entry, Field)

        /// <summary>
        /// A refresh is a number of seconds from a minute to sixty days, and the
        /// longest time is never shorter than the shortest.
        /// </summary>
        [TestCase("""{ "hostname": "a.example", "minRefreshSeconds": 59 }""",                              "minRefreshSeconds")]
        [TestCase("""{ "hostname": "a.example", "maxRefreshSeconds": 5184001 }""",                         "maxRefreshSeconds")]
        [TestCase("""{ "hostname": "a.example", "minRefreshSeconds": "3600" }""",                          "minRefreshSeconds")]
        [TestCase("""{ "hostname": "a.example", "minRefreshSeconds": 7200, "maxRefreshSeconds": 3600 }""", "maxRefreshSeconds")]
        public void ARefreshOutsideItsLimitsIsRefused(String Entry, String Field)
        {

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse(Entry), 0, out _, out var error, "nts.groups.local"),  Is.False);

            Assert.That(error,  Does.StartWith($"'nts.groups.local.servers[0].{Field}'"));

        }

        #endregion


        #region EachServerMakesItsKeyExchangeAgainAsItsEntrySays()

        [Test]
        public void EachServerMakesItsKeyExchangeAgainAsItsEntrySays()
        {

            var node = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ { "hostname": "a.example", "minRefreshSeconds": 3600, "maxRefreshSeconds": 7200 }, "b.example" ] } } } }""");

            Assert.Multiple(() => {
                Assert.That(Refresh(node.LegalTime, a),  Is.EqualTo(Hours(1, 2)));
                Assert.That(Refresh(node.LegalTime, b),  Is.EqualTo(Defaults),  "a server whose entry sets none has 12 to 24 hours");
            });

        }

        #endregion

        #region TheServersOfTheGroupNobodyConfiguredMakeTheirKeyExchangesAgainAfter12To24Hours()

        /// <summary>
        /// The servers a node asks when nobody says otherwise make their key
        /// exchanges again after 12 to 24 hours as well, and not after the half
        /// hour of the time library.
        /// </summary>
        [Test]
        public void TheServersOfTheGroupNobodyConfiguredMakeTheirKeyExchangesAgainAfter12To24Hours()
        {

            var node = Node("""{ }""");

            Assert.That(node.LegalTime.Sources.Sources.Select(source => (source.MinRefresh, source.MaxRefresh)),
                        Has.All.EqualTo(Defaults));

        }

        #endregion

        #region AServerMakesItsKeyExchangeAgainAsTheFirstEntrySettingOneSaysInEveryGroup()

        /// <summary>
        /// A server two groups ask is one server with one key exchange: the first
        /// entry that sets a refresh for it decides, in every group.
        /// </summary>
        [Test]
        public void AServerMakesItsKeyExchangeAgainAsTheFirstEntrySettingOneSaysInEveryGroup()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ "a.example" ] },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "minRefreshSeconds": 3600, "maxRefreshSeconds": 7200 } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example", "minRefreshSeconds": 600, "maxRefreshSeconds": 600 } ] }
                              } } }
                              """);

            Assert.Multiple(() => {
                Assert.That(Refresh(node.LegalTime,             a),  Is.EqualTo(Hours(1, 2)),  "a group saying nothing about it");
                Assert.That(Refresh(node.NTSGroupOf("local")!,  a),  Is.EqualTo(Hours(1, 2)));
                Assert.That(Refresh(node.NTSGroupOf("grid")!,   a),  Is.EqualTo(Hours(1, 2)),  "a later group setting another one");
            });

        }

        #endregion

        #region AChangeOfARefreshIsSaid()

        /// <summary>
        /// A change of when a server's key exchange is made again is a change of
        /// the group, said and written down like one; the page's list sent back
        /// as it was shown changes nothing.
        /// </summary>
        [Test]
        public void AChangeOfARefreshIsSaid()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "hostname": "a.example", "minRefreshSeconds": 3600, "maxRefreshSeconds": 7200 }, "b.example" ] }"""),
                                                       out var error,
                                                       out _),
                        Is.True,
                        error);

            var held   = OnDisk["nts"]?["groups"]?["legal"]?["servers"]?[0];
            var after  = Refresh(node.LegalTime, a);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "hostname": "a.example", "minRefreshSeconds": 3600, "maxRefreshSeconds": 7200 }, "b.example" ] }"""),
                                                       out error,
                                                       out _),
                        Is.True,
                        error);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""),
                                                       out error,
                                                       out _),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(told.Count,                                  Is.EqualTo(2),  "the list sent again as it was changed nothing");
                Assert.That(told.FirstOrDefault(),                       Has.Some.EqualTo("a.example makes its key exchange again after 1 to 2 hours"));
                Assert.That(told.LastOrDefault(),                        Has.Some.EqualTo("a.example makes its key exchange again after 12 to 24 hours"));
                Assert.That(held?.Value<Double>("minRefreshSeconds"),    Is.EqualTo(3600),  "written down");
                Assert.That(after,                                       Is.EqualTo(Hours(1, 2)));
                Assert.That(Refresh(node.LegalTime, a),                  Is.EqualTo(Defaults),  "and taken back");
            });

        }

        #endregion

        #region TheNodeShowsEachEntrysRefresh()

        /// <summary>
        /// Each server shows the refresh its own entry sets, which is what a page
        /// sends back with it - and not what another group's entry makes it,
        /// which a save of this group would otherwise write into it. What an
        /// entry may set, and the defaults, are among the limits.
        /// </summary>
        [Test]
        public void TheNodeShowsEachEntrysRefresh()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ { "hostname": "a.example", "minRefreshSeconds": 3600 }, "b.example" ] },
                                  "local":  { "enabled": false, "servers": [ "a.example" ] }
                              } } }
                              """);

            var legal  = node.NTSConfigurationJSON(node.LegalTime);
            var local  = node.NTSConfigurationJSON(node.NTSGroupOf("local")!);

            Assert.Multiple(() => {
                Assert.That(legal["timeSources"]?.Select(source => source["minRefreshSeconds"]?.Type == JTokenType.Null ? (Double?) null : source.Value<Double>("minRefreshSeconds")),
                            Is.EqualTo(new Double?[] { 3600, null }));
                Assert.That(legal["timeSources"]?.Select(source => source["maxRefreshSeconds"]?.Type),
                            Has.All.EqualTo(JTokenType.Null),
                            "set by no entry");
                Assert.That(local["timeSources"]?[0]?["minRefreshSeconds"]?.Type,
                            Is.EqualTo(JTokenType.Null),
                            "made again as the legal group says, but not by its own entry");
                Assert.That(legal["limits"]?.Value<Double>("minRefresh"),         Is.EqualTo(60));
                Assert.That(legal["limits"]?.Value<Double>("maxRefresh"),         Is.EqualTo(5184000));
                Assert.That(legal["limits"]?.Value<Double>("defaultMinRefresh"),  Is.EqualTo(43200));
                Assert.That(legal["limits"]?.Value<Double>("defaultMaxRefresh"),  Is.EqualTo(86400));
            });

        }

        #endregion

        #region ARemovedGroupNoLongerSetsAnotherGroupsServersRefresh()

        /// <summary>
        /// Where the entry that set a server's refresh goes with its group, the
        /// groups left decide.
        /// </summary>
        [Test]
        public async Task ARemovedGroupNoLongerSetsAnotherGroupsServersRefresh()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "minRefreshSeconds": 3600, "maxRefreshSeconds": 7200 } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example" } ] }
                              } } }
                              """);

            var grid   = node.NTSGroupOf("grid")!;
            var before = Refresh(grid, a);

            var (removed, error, _) = await node.TryRemoveNTSGroupAsync("local");

            Assert.That(removed,  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(before,            Is.EqualTo(Hours(1, 2)));
                Assert.That(Refresh(grid, a),  Is.EqualTo(Defaults));
            });

        }

        #endregion

    }

}
