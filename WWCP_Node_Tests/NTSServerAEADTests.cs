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
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The AEAD algorithm a time server's key exchange offers: the one its
    /// entry names, "aead", or where it names none, every one the time library
    /// offers - AES-128-GCM-SIV, then AES-SIV-CMAC-256 - the server choosing.
    /// </summary>
    /// <remarks>
    /// By the server's name across every group, as what it is held to is: the
    /// first entry that names an algorithm decides. To a CSMS it is
    /// NTPClientController.AEADAlgorithm.
    /// </remarks>
    public class NTSServerAEADTests
    {

        #region Data

        private static readonly DomainName a = DomainName.Parse("a.example");
        private static readonly DomainName b = DomainName.Parse("b.example");

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

            directory = Path.Combine(Path.GetTempPath(), "node-nts-aead-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Configuration)

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

        #endregion

        #region (helper) Offered(Group, Hostname)

        /// <summary>
        /// What the given server of the given group is offered at its key
        /// exchanges, or null for the client's own list.
        /// </summary>
        private static AEADAlgorithms[]? Offered(NTSGroup    Group,
                                                 DomainName  Hostname)

            => Group.Sources.Sources.Single(source => source.Hostname.Equals(Hostname)).OfferedAEADAlgorithms?.ToArray();

        #endregion


        #region AnAlgorithmIsWrittenWithItsServerAndReadBack()

        /// <summary>
        /// "aead" is written by the name the file, the page and OCPP know it
        /// by, read whatever its case, and left out where the server chooses -
        /// so that a server saying nothing else stays a bare host name.
        /// </summary>
        [Test]
        public void AnAlgorithmIsWrittenWithItsServerAndReadBack()
        {

            var held    = new NTSServerConfiguration(a, AEAD: AEADAlgorithms.AES_SIV_CMAC_256);
            var json    = held.ToJSON();

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out var read, out var error),  Is.True,  error);

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "a.example", "aead": "aes-128-gcm-siv" }"""), 0, out var lower, out var lowerError),
                        Is.True,
                        lowerError);

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "a.example", "aead": "" }"""), 0, out var blank, out var blankError),
                        Is.True,
                        blankError);

            Assert.Multiple(() => {
                Assert.That(json.Value<String>("aead"),            Is.EqualTo("AES-SIV-CMAC-256"));
                Assert.That(read!.AEAD,                            Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256));
                Assert.That(read.ToEndpoint().OfferedAEADAlgorithms,
                            Is.EqualTo(new[] { AEADAlgorithms.AES_SIV_CMAC_256 }));
                Assert.That(lower!.AEAD,                           Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV));
                Assert.That(lower.ToJSON().Value<String>("aead"),  Is.EqualTo("AES-128-GCM-SIV"),  "written as it is named");
                Assert.That(blank!.AEAD,                           Is.Null,                         "a blank field is one left empty");
                Assert.That(new NTSServerConfiguration(a).ToJSON().Type,
                            Is.EqualTo(JTokenType.String),
                            "a server the server chooses for says nothing about it");
                Assert.That(new NTSServerConfiguration(a).ToEndpoint().OfferedAEADAlgorithms,
                            Is.Null);
            });

        }

        #endregion

        #region WhatThisNodeDoesNotOfferIsRefused(Value)

        /// <summary>
        /// Only what the time library offers can be named: not an algorithm it
        /// can perform but never ran against another implementation's server,
        /// not one it cannot perform, and not the library's own spelling.
        /// </summary>
        [TestCase("\"AES-256-GCM-SIV\"")]
        [TestCase("\"CHACHA20-POLY1305\"")]
        [TestCase("\"AES_SIV_CMAC_256\"")]
        [TestCase("15")]
        public void WhatThisNodeDoesNotOfferIsRefused(String Value)
        {

            var json = JObject.Parse($$"""{ "hostname": "a.example", "aead": {{Value}} }""");

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out _, out var error, "nts.groups.local"),  Is.False);

            Assert.That(error,  Does.StartWith("'nts.groups.local.servers[0].aead'"));

            if (Value.StartsWith('"'))
                Assert.That(error,  Does.EndWith("which are AES-128-GCM-SIV and AES-SIV-CMAC-256."));

        }

        #endregion


        #region EachServerIsOfferedWhatItsEntryNames()

        [Test]
        public void EachServerIsOfferedWhatItsEntryNames()
        {

            var node = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" }, "b.example" ] } } } }""");

            Assert.Multiple(() => {
                Assert.That(Offered(node.LegalTime, a),  Is.EqualTo(new[] { AEADAlgorithms.AES_SIV_CMAC_256 }));
                Assert.That(Offered(node.LegalTime, b),  Is.Null,  "a server whose entry names none is offered the client's own list");
            });

        }

        #endregion

        #region AServerIsOfferedWhatTheFirstEntryNamingOneSaysInEveryGroup()

        /// <summary>
        /// A server two groups ask is one server with one key exchange: the
        /// first entry that names an algorithm for it decides, in every group -
        /// not the group that happens to ask it first.
        /// </summary>
        [Test]
        public void AServerIsOfferedWhatTheFirstEntryNamingOneSaysInEveryGroup()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ "a.example" ] },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example", "aead": "AES-128-GCM-SIV" } ] }
                              } } }
                              """);

            var siv    = new[] { AEADAlgorithms.AES_SIV_CMAC_256 };

            Assert.Multiple(() => {
                Assert.That(Offered(node.LegalTime,             a),  Is.EqualTo(siv),  "a group saying nothing about it");
                Assert.That(Offered(node.NTSGroupOf("local")!,  a),  Is.EqualTo(siv));
                Assert.That(Offered(node.NTSGroupOf("grid")!,   a),  Is.EqualTo(siv),  "a later group naming another one");
            });

        }

        #endregion

        #region AChangeOfWhatAServerIsOfferedIsSaid()

        /// <summary>
        /// A change of what a server is offered is a change of the group, said
        /// and written down like one; the page's list sent back as it was
        /// shown changes nothing.
        /// </summary>
        [Test]
        public void AChangeOfWhatAServerIsOfferedIsSaid()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" }, "b.example" ] }"""),
                                                       out var error,
                                                       out _),
                        Is.True,
                        error);

            var held   = OnDisk["nts"]?["groups"]?["legal"]?["servers"]?[0];
            var after  = Offered(node.LegalTime, a);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" }, "b.example" ] }"""),
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
                Assert.That(told.Count,                         Is.EqualTo(2),  "the list sent again as it was changed nothing");
                Assert.That(told.FirstOrDefault(),              Has.Some.EqualTo("a.example offered AES-SIV-CMAC-256 alone"));
                Assert.That(told.LastOrDefault(),               Has.Some.EqualTo("a.example offered AES-128-GCM-SIV and AES-SIV-CMAC-256"));
                Assert.That(held?.Value<String>("aead"),        Is.EqualTo("AES-SIV-CMAC-256"),  "written down");
                Assert.That(after,                              Is.EqualTo(new[] { AEADAlgorithms.AES_SIV_CMAC_256 }));
                Assert.That(Offered(node.LegalTime, a),         Is.Null,  "and taken back");
            });

        }

        #endregion

        #region TheNodeShowsWhatEachEntryOffers()

        /// <summary>
        /// Each server shows what its own entry offers, which is what a page
        /// sends back with it - and not what another group's entry makes it
        /// offer, which a save of this group would otherwise write into it.
        /// The algorithms an entry may name are among the limits.
        /// </summary>
        [Test]
        public void TheNodeShowsWhatEachEntryOffers()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" }, "b.example" ] },
                                  "local":  { "enabled": false, "servers": [ "a.example" ] }
                              } } }
                              """);

            var legal  = node.NTSConfigurationJSON(node.LegalTime);
            var local  = node.NTSConfigurationJSON(node.NTSGroupOf("local")!);

            Assert.Multiple(() => {
                Assert.That(legal["timeSources"]?.Select(source => source.Value<String>("aead")),
                            Is.EqualTo(new[] { "AES-SIV-CMAC-256", null }));
                Assert.That(local["timeSources"]?.Select(source => source.Value<String>("aead")),
                            Is.EqualTo(new String?[] { null }),
                            "offered what the legal group says, but not by its own entry");
                Assert.That(legal["limits"]?["aeadAlgorithms"]?.Values<String>(),
                            Is.EqualTo(new[] { "AES-128-GCM-SIV", "AES-SIV-CMAC-256" }));
            });

        }

        #endregion

        #region TheDetailedTestOffersWhatItsServerIsOffered()

        /// <summary>
        /// The client the detailed test of a group starts from offers what its
        /// server is offered, and is made anew when that changes: a client
        /// offering something else would test a key exchange the group never
        /// makes.
        /// </summary>
        [Test]
        public void TheDetailedTestOffersWhatItsServerIsOffered()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false }, "local": { "enabled": false, "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" } ] } } } }""");
            var local  = node.NTSGroupOf("local")!;
            var before = local.Client?.OfferedAEADAlgorithms.ToArray();

            Assert.That(node.TryUpdateNTSConfiguration(local,
                                                       JObject.Parse("""{ "servers": [ "a.example" ] }"""),
                                                       out var error,
                                                       out _),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(before,                                       Is.EqualTo(new[] { AEADAlgorithms.AES_SIV_CMAC_256 }));
                Assert.That(local.Client?.Hostname,                       Is.EqualTo(a));
                Assert.That(local.Client?.OfferedAEADAlgorithms.ToArray(),
                            Is.EqualTo(new[] { AEADAlgorithms.AES_128_GCM_SIV, AEADAlgorithms.AES_SIV_CMAC_256 }));
            });

        }

        #endregion

        #region ARemovedGroupNoLongerSaysWhatAnotherGroupsServerIsOffered()

        /// <summary>
        /// Where the entry that decided what a server is offered goes with its
        /// group, the groups left decide.
        /// </summary>
        [Test]
        public async Task ARemovedGroupNoLongerSaysWhatAnotherGroupsServerIsOffered()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "aead": "AES-SIV-CMAC-256" } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example" } ] }
                              } } }
                              """);

            var grid   = node.NTSGroupOf("grid")!;
            var before = Offered(grid, a);

            var (removed, error, _) = await node.TryRemoveNTSGroupAsync("local");

            Assert.That(removed,  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(before,             Is.EqualTo(new[] { AEADAlgorithms.AES_SIV_CMAC_256 }));
                Assert.That(Offered(grid, a),   Is.Null);
            });

        }

        #endregion

    }

}
