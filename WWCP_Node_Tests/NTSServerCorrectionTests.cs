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
    /// How the offsets measured with a time server are corrected for what is
    /// known about the path to it: "delayAsymmetryMs", added to every offset,
    /// and "delayVarAsymmetry", where a hold-up of the delays is.
    /// </summary>
    /// <remarks>
    /// By the server's name across every group, as its AEAD algorithm and its
    /// refresh are: the first entry that sets either decides both. To a CSMS
    /// they are NTPClientController.DelayAsymmetry and DelayVarAsymmetry.
    /// </remarks>
    public class NTSServerCorrectionTests
    {

        #region Data

        private static readonly DomainName a = DomainName.Parse("a.example");
        private static readonly DomainName b = DomainName.Parse("b.example");

        private static readonly (TimeSpan?, Double?) None = (null, null);

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

            directory = Path.Combine(Path.GetTempPath(), "node-nts-correction-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Configuration) / Correction(Group, Hostname) / Shift(Milliseconds, Asymmetry)

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
        /// How the offsets of the given server of the given group are corrected,
        /// as the time library is told.
        /// </summary>
        private static (TimeSpan?, Double?) Correction(NTSGroup    Group,
                                                       DomainName  Hostname)
        {
            var source = Group.Sources.Sources.Single(source => source.Hostname.Equals(Hostname));
            return (source.DelayAsymmetry, source.DelayVarAsymmetry);
        }

        private static (TimeSpan?, Double?) Shift(Double? Milliseconds, Double? Asymmetry)

            => (Milliseconds is Double ms ? TimeSpan.FromMilliseconds(ms) : null, Asymmetry);

        #endregion


        #region ACorrectionIsWrittenWithItsServerAndReadBack()

        /// <summary>
        /// "delayAsymmetryMs" and "delayVarAsymmetry" are written with their
        /// server and read back, and left out where nothing is corrected - zero
        /// included, which corrects nothing - so that a server saying nothing
        /// else stays a bare host name.
        /// </summary>
        [Test]
        public void ACorrectionIsWrittenWithItsServerAndReadBack()
        {

            var held      = new NTSServerConfiguration(a, DelayAsymmetry: TimeSpan.FromMilliseconds(-0.05), DelayVarAsymmetry: -0.5);
            var json      = held.ToJSON();

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out var read, out var error),  Is.True,  error);

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "a.example", "delayAsymmetryMs": 0, "delayVarAsymmetry": 0 }"""), 0, out var zero, out var zeroError),
                        Is.True,
                        zeroError);

            var endpoint  = read!.ToEndpoint();

            Assert.Multiple(() => {
                Assert.That(json.Value<Double>("delayAsymmetryMs"),               Is.EqualTo(-0.05).Within(1e-9));
                Assert.That(json.Value<Double>("delayVarAsymmetry"),              Is.EqualTo(-0.5));
                Assert.That(read.DelayAsymmetry,                                  Is.EqualTo(TimeSpan.FromMilliseconds(-0.05)));
                Assert.That(read.DelayVarAsymmetry,                               Is.EqualTo(-0.5));
                Assert.That((endpoint.DelayAsymmetry, endpoint.DelayVarAsymmetry), Is.EqualTo(Shift(-0.05, -0.5)));
                Assert.That(zero!.ToJSON().Type,                                  Is.EqualTo(JTokenType.String),  "zero corrects nothing, and is written as nothing");
                Assert.That(held.ToString(),                                      Does.Contain("offsets corrected by -0.05 ms and for an asymmetry of -0.5"));
            });

        }

        #endregion

        #region ACorrectionOutsideItsLimitsIsRefused(Entry, Field)

        /// <summary>
        /// The correction is at most a second either way, and a hold-up is put
        /// on one way at most wholly: -0.5 to +0.5.
        /// </summary>
        [TestCase("""{ "hostname": "a.example", "delayAsymmetryMs": 1000.5 }""",   "delayAsymmetryMs")]
        [TestCase("""{ "hostname": "a.example", "delayAsymmetryMs": "-0.05" }""",  "delayAsymmetryMs")]
        [TestCase("""{ "hostname": "a.example", "delayVarAsymmetry": 0.6 }""",     "delayVarAsymmetry")]
        [TestCase("""{ "hostname": "a.example", "delayVarAsymmetry": -0.51 }""",   "delayVarAsymmetry")]
        public void ACorrectionOutsideItsLimitsIsRefused(String Entry, String Field)
        {

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse(Entry), 0, out _, out var error, "nts.groups.local"),  Is.False);

            Assert.That(error,  Does.StartWith($"'nts.groups.local.servers[0].{Field}'"));

        }

        #endregion


        #region EachServerIsCorrectedAsItsEntrySays()

        [Test]
        public void EachServerIsCorrectedAsItsEntrySays()
        {

            var node = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ { "hostname": "a.example", "delayAsymmetryMs": 1.5, "delayVarAsymmetry": 0.25 }, "b.example" ] } } } }""");

            Assert.Multiple(() => {
                Assert.That(Correction(node.LegalTime, a),  Is.EqualTo(Shift(1.5, 0.25)));
                Assert.That(Correction(node.LegalTime, b),  Is.EqualTo(None),  "a server whose entry corrects nothing");
            });

        }

        #endregion

        #region AServerIsCorrectedAsTheFirstEntrySettingOneSaysInEveryGroup()

        /// <summary>
        /// The path to a server is the same whichever group asks it: the first
        /// entry that corrects its offsets decides, in every group.
        /// </summary>
        [Test]
        public void AServerIsCorrectedAsTheFirstEntrySettingOneSaysInEveryGroup()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ "a.example" ] },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "delayVarAsymmetry": -0.5 } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example", "delayAsymmetryMs": 3 } ] }
                              } } }
                              """);

            Assert.Multiple(() => {
                Assert.That(Correction(node.LegalTime,             a),  Is.EqualTo(Shift(null, -0.5)),  "a group saying nothing about it");
                Assert.That(Correction(node.NTSGroupOf("local")!,  a),  Is.EqualTo(Shift(null, -0.5)));
                Assert.That(Correction(node.NTSGroupOf("grid")!,   a),  Is.EqualTo(Shift(null, -0.5)),  "a later group setting another one");
            });

        }

        #endregion

        #region AChangeOfACorrectionIsSaid()

        /// <summary>
        /// A change of how a server's offsets are corrected is a change of the
        /// group, said and written down like one; the page's list sent back as
        /// it was shown changes nothing.
        /// </summary>
        [Test]
        public void AChangeOfACorrectionIsSaid()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            const String corrected = """{ "servers": [ { "hostname": "a.example", "delayAsymmetryMs": -0.05, "delayVarAsymmetry": -0.5 }, "b.example" ] }""";

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse(corrected), out var error, out _),  Is.True,  error);

            var held   = OnDisk["nts"]?["groups"]?["legal"]?["servers"]?[0];
            var after  = Correction(node.LegalTime, a);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse(corrected), out error, out _),  Is.True,  error);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""),
                                                       out error,
                                                       out _),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(told.Count,                                  Is.EqualTo(2),  "the list sent again as it was changed nothing");
                Assert.That(told.FirstOrDefault(),                       Has.Some.EqualTo("a.example's offsets corrected by -0.05 ms and for an asymmetry of -0.5"));
                Assert.That(told.LastOrDefault(),                        Has.Some.EqualTo("a.example's offsets corrected not"));
                Assert.That(held?.Value<Double>("delayVarAsymmetry"),    Is.EqualTo(-0.5),  "written down");
                Assert.That(after,                                       Is.EqualTo(Shift(-0.05, -0.5)));
                Assert.That(Correction(node.LegalTime, a),               Is.EqualTo(None),  "and taken back");
            });

        }

        #endregion

        #region TheNodeShowsEachEntrysCorrection()

        /// <summary>
        /// Each server shows how its own entry corrects its offsets, which is
        /// what a page sends back with it. The bounds are among the limits.
        /// </summary>
        [Test]
        public void TheNodeShowsEachEntrysCorrection()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ { "hostname": "a.example", "delayAsymmetryMs": 2 }, "b.example" ] },
                                  "local":  { "enabled": false, "servers": [ "a.example" ] }
                              } } }
                              """);

            var legal  = node.NTSConfigurationJSON(node.LegalTime);
            var local  = node.NTSConfigurationJSON(node.NTSGroupOf("local")!);

            Assert.Multiple(() => {
                Assert.That(legal["timeSources"]?[0]?.Value<Double>("delayAsymmetryMs"),  Is.EqualTo(2));
                Assert.That(legal["timeSources"]?[1]?["delayAsymmetryMs"]?.Type,          Is.EqualTo(JTokenType.Null));
                Assert.That(legal["timeSources"]?[0]?["delayVarAsymmetry"]?.Type,         Is.EqualTo(JTokenType.Null));
                Assert.That(local["timeSources"]?[0]?["delayAsymmetryMs"]?.Type,          Is.EqualTo(JTokenType.Null),  "corrected as the legal group says, but not by its own entry");
                Assert.That(legal["limits"]?.Value<Double>("maxDelayAsymmetryMs"),        Is.EqualTo(1000));
                Assert.That(legal["limits"]?.Value<Double>("maxDelayVarAsymmetry"),       Is.EqualTo(0.5));
            });

        }

        #endregion

        #region ARemovedGroupNoLongerCorrectsAnotherGroupsServer()

        /// <summary>
        /// Where the entry that corrected a server's offsets goes with its group,
        /// the groups left decide.
        /// </summary>
        [Test]
        public async Task ARemovedGroupNoLongerCorrectsAnotherGroupsServer()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "delayAsymmetryMs": 2 } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example" } ] }
                              } } }
                              """);

            var grid   = node.NTSGroupOf("grid")!;
            var before = Correction(grid, a);

            var (removed, error, _) = await node.TryRemoveNTSGroupAsync("local");

            Assert.That(removed,  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(before,               Is.EqualTo(Shift(2, null)));
                Assert.That(Correction(grid, a),  Is.EqualTo(None));
            });

        }

        #endregion

    }

}
