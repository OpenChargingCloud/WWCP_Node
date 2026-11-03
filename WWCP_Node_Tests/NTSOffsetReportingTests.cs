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

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

using BCBigInteger = Org.BouncyCastle.Math.BigInteger;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The legal group's "offsetReportingThresholdSeconds" as a file and a save
    /// say it: five seconds where nothing does, false for never, and only in
    /// the legal group.
    /// </summary>
    [TestFixture]
    public class NTSOffsetThresholdTests
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
            directory = Path.Combine(Path.GetTempPath(), "node-nts-offsets-" + Guid.NewGuid().ToString("N")[..12]);
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

        private WWCPNode Node(String NTS)
        {

            File.WriteAllText(ConfigurationPath, $$"""{ "dns": { "enabled": false }, "nts": {{NTS}} }""");

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        private static JToken? Threshold(WWCPNode Node, NTSGroup Group)
            => Node.NTSConfigurationJSON(Group)["settings"]?[NTSConfiguration.OffsetReportingThresholdKey];


        #region TheThresholdIsFiveSecondsWhereNothingSaysOtherwise()

        [Test]
        public async Task TheThresholdIsFiveSecondsWhereNothingSaysOtherwise()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false }, "local": { "enabled": false } } }""");

            var local = node.NTSGroupOf("local")!;

            Assert.Multiple(() => {
                Assert.That(node.LegalTime.OffsetReportingThreshold,  Is.EqualTo(TimeSpan.FromSeconds(5)),  "the white paper's five seconds");
                Assert.That(local.OffsetReportingThreshold,           Is.Null,                              "only the legal group's offsets are reported");
                Assert.That(Threshold(node, node.LegalTime)?.Type,    Is.EqualTo(JTokenType.Integer));
                Assert.That(Threshold(node, node.LegalTime)?.Value<Int32>(),  Is.EqualTo(5));
                Assert.That(Threshold(node, local)?.Type,             Is.EqualTo(JTokenType.Boolean));
                Assert.That(Threshold(node, local)?.Value<Boolean>(), Is.False);
                Assert.That(node.NTSConfigurationJSON(node.LegalTime)["limits"]!["minOffsetReportingThreshold"]?.Value<Int32>(),  Is.EqualTo(1));
                Assert.That(node.NTSConfigurationJSON(node.LegalTime)["limits"]!["maxOffsetReportingThreshold"]?.Value<Int32>(),  Is.EqualTo(86400));
            });

        }

        #endregion

        #region TheThresholdIsReadWrittenSwitchedOffAndRefusedOutsideItsRange()

        [Test]
        public async Task TheThresholdIsReadWrittenSwitchedOffAndRefusedOutsideItsRange()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false, "offsetReportingThresholdSeconds": 7 } } }""");

            var legal    = node.LegalTime;
            var read     = legal.OffsetReportingThreshold;

            var zero     = node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": 0 }"""),     out var zeroError,  out _);
            var half     = node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": 2.5 }"""),   out var halfError,  out _);
            var on       = node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": true }"""),  out var onError,    out _);
            var tooLong  = node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": 86401 }"""), out var longError,  out _);

            var before   = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": false }"""), out var error, out _),  Is.True,  error);

            var off      = legal.OffsetReportingThreshold;
            var offJSON  = Threshold(node, legal);
            var offFile  = OnDisk["nts"]!["groups"]!["legal"]![NTSConfiguration.OffsetReportingThresholdKey];

            Assert.That(node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "enabled": false }"""), out error, out _),  Is.True,  error);

            var kept     = legal.OffsetReportingThreshold;

            Assert.That(node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": 12 }"""), out error, out _),  Is.True,  error);

            var twelve   = legal.OffsetReportingThreshold;

            Assert.That(node.TryUpdateNTSConfiguration(legal, JObject.Parse("""{ "offsetReportingThresholdSeconds": "" }"""), out error, out _),  Is.True,  error);

            var emptied  = legal.OffsetReportingThreshold;
            var said     = node.Log.Recent(100, before, null).Select(entry => entry.Message).Where(message => message.StartsWith("NTS configuration changed")).ToArray();

            Assert.Multiple(() => {

                Assert.That(read,       Is.EqualTo(TimeSpan.FromSeconds(7)),  "read from the file");

                Assert.That(zero,       Is.False);
                Assert.That(zeroError,  Is.EqualTo("'nts.groups.legal.offsetReportingThresholdSeconds' must be a whole number of seconds between 1 and 86400, or false for never."));
                Assert.That(half,       Is.False,  "OCPP's threshold is an integer");
                Assert.That(halfError,  Is.EqualTo(zeroError));
                Assert.That(on,         Is.False,  "true says no threshold");
                Assert.That(onError,    Is.EqualTo(zeroError));
                Assert.That(tooLong,    Is.False);
                Assert.That(longError,  Is.EqualTo(zeroError));

                Assert.That(off,        Is.Null,   "false is never");
                Assert.That(offJSON?.Type,  Is.EqualTo(JTokenType.Boolean));
                Assert.That(offFile?.Type,  Is.EqualTo(JTokenType.Boolean),  "never is written down, and is not the key left out, which is five seconds");
                Assert.That(offFile?.Value<Boolean>(),  Is.False);
                Assert.That(kept,       Is.Null,   "a save that does not name it keeps it");
                Assert.That(twelve,     Is.EqualTo(TimeSpan.FromSeconds(12)));
                Assert.That(OnDisk["nts"]!["groups"]!["legal"]![NTSConfiguration.OffsetReportingThresholdKey]?.Type,  Is.EqualTo(JTokenType.Boolean),
                            "an emptied field is never, as false is");
                Assert.That(emptied,    Is.Null);

                Assert.That(said,  Is.EqualTo(new[] {
                                       "NTS configuration changed: offsets not reported.",
                                       "NTS configuration changed: offsets reported from 12 s.",
                                       "NTS configuration changed: offsets not reported."
                                   }));

            });

        }

        #endregion

        #region OnlyTheLegalGroupHasAThreshold()

        [Test]
        public async Task OnlyTheLegalGroupHasAThreshold()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false }, "local": { "enabled": false } } }""");

            var number = node.TryUpdateNTSConfiguration(node.NTSGroupOf("local")!, JObject.Parse("""{ "offsetReportingThresholdSeconds": 5 }"""),     out var numberError, out _);
            var never  = node.TryUpdateNTSConfiguration(node.NTSGroupOf("local")!, JObject.Parse("""{ "offsetReportingThresholdSeconds": false }"""), out var neverError,  out _);

            Assert.Multiple(() => {
                Assert.That(number,      Is.False);
                Assert.That(numberError, Does.StartWith("'nts.groups.local.offsetReportingThresholdSeconds': only the group 'legal' carries legal time."));
                Assert.That(never,       Is.False,  "not even to say never");
                Assert.That(neverError,  Is.EqualTo(numberError));
            });

        }

        #endregion

    }


    /// <summary>
    /// The offsets reported, where they happen: a node asking a time server
    /// of its own legal group whose clock runs ahead of this machine's.
    /// </summary>
    /// <remarks>
    /// Against Norn's NTS server on the loopback interface, as the pinning
    /// tests do, with a clock of its own that the tests set ahead: the node
    /// does not set its clock, so what it measures is how far ahead it is.
    /// </remarks>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSOffsetReportingTests
    {

        #region Data

        private static readonly DomainName  hostname   = DomainName.Parse("ntske.test");

        private static readonly IPPort      ntsKEPort  = FindFreeTCPPort();
        private static readonly IPPort      ntpPort    = FindFreeUDPPort();

        private readonly Ahead              clock      = new ();

        private System.Security.Cryptography.X509Certificates.X509Certificate2  ca      = default!;
        private System.Security.Cryptography.X509Certificates.X509Certificate2  served  = default!;
        private NTSServer?                  server;

        private String                      directory  = "";

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheTimeServer()
        {

            ca      = TimeServerPinningTests.CA("NTS Offset Test CA");

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            served  = TimeServerPinningTests.Leaf(hostname.Trimmed, ca, key);

            var parameters = key.ExportParameters(includePrivateParameters: true);

            server  = new NTSServer(
                          NTSKEPort:           ntsKEPort,
                          NTSPort:             ntpPort,
                          MasterKeysFilePath:  null,
                          TLSCertificate:      new X509CertificateParser().ReadCertificate(served.RawData),
                          TLSPrivateKey:       new ECPrivateKeyParameters("ECDSA", new BCBigInteger(1, parameters.D), SecObjectIdentifiers.SecP256r1),
                          KeyPair:             new KeyPair(
                                                   Id:                  1,
                                                   PrivateKey:          "2bs8BuOqUr5I9b8ksVdW3xTu8KmDr1fHLvusDxI34J4=".FromBASE64(),
                                                   PublicKey:           "BNJ9BLZTcAeuPMHDDDXA0RiVNse8WH4b+/r/bA9HhDsDtTSBsrvmjbnA3w3JlC7ipvhHEkdGbFEIH+ZT0ZEekTA=".FromBASE64(),
                                                   Description:         I18NString.Create(Languages.en, "Test public key"),
                                                   EllipticCurve:       "secp256r1",
                                                   SignatureAlgorithm:  "SHA256withECDSA",
                                                   NotBefore:           Timestamp.Now,
                                                   NotAfter:            Timestamp.Now.AddMonths(1)
                                               ),
                          TimeProvider:        clock
                      );

            await server.Start();

        }

        [OneTimeTearDown]
        public void StopTheTimeServer()
        {
            server?.Shutdown();
            ca.    Dispose();
            served.Dispose();
        }

        [SetUp]
        public void Setup()
        {
            clock.By   = TimeSpan.Zero;
            directory  = Path.Combine(Path.GetTempPath(), "node-offsets-live-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helpers) Node(More) / Offsets(Node, Since) / Check(Node)

        /// <summary>
        /// A node whose legal group asks the test's time server alone, and
        /// which trusts the test's CA as a TLS root.
        /// </summary>
        private WWCPNode Node(String More = "")
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""
                                              { "nts": { "groups": { "legal": { "servers": [ { "hostname": "{{hostname.Trimmed}}", "ntsKEPort": {{ntsKEPort}}, "ntpPort": {{ntpPort}} } ], "minServers": 1{{(More.Length > 0 ? ", " + More : "")}} } } } }
                                              """);

            // As the pinning tests' node: the name from the cache, both records.
            var dns  = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

            dns.DNSCache.Add(DNSServiceName.Parse(hostname.ToString()), new A(hostname, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost));
            dns.DNSCache.AddNoData(DNSServiceName.Parse(hostname.ToString()), DNSResourceRecordTypes.AAAA, TimeSpan.FromHours(1));

            var node = new WWCPNode(
                           AccountsPath:      Path.Combine(directory, "accounts"),
                           ConfigFile:        new WWCPConfigFile(configuration),
                           CertificatesPath:  Path.Combine(directory, "certificates"),
                           DNSClient:         dns,
                           LogToConsole:      false,
                           BridgeDebugLog:    false
                       );

            Assert.That(node.Certificates.Import(System.Text.Encoding.ASCII.GetBytes(ca.ExportCertificatePem()),
                                                 CertificateKind.TLSRoot, null, "NTS Offset Test CA", out _, out var error),
                        Is.True,
                        error);

            return node;

        }

        /// <summary>
        /// What the node wrote into the metrological log about offsets since the
        /// given entry.
        /// </summary>
        private static LogEntry[] Offsets(WWCPNode Node, UInt64 Since)

            => [.. Node.Log.Recent(200, Since, null).Where(entry => entry.Metrological && entry.Tags.Contains("offset"))];

        private static async Task Check(WWCPNode Node)
        {
            var result = await Node.SyncTimeAsync();
            Assert.That(result.Value<Boolean>("ok"),  Is.True,  result.ToString());
        }

        #endregion


        #region AnOffsetReachingTheThresholdIsReportedOnceUntilACheckIsBelowIt()

        /// <summary>
        /// Seven seconds ahead, twice: written down as security critical and
        /// told once. On time: written down as within again, and told nothing.
        /// Seven seconds ahead once more: told again.
        /// </summary>
        [Test]
        public async Task AnOffsetReachingTheThresholdIsReportedOnceUntilACheckIsBelowIt()
        {

            await using var node = Node();

            var told    = new List<TimeSpan>();
            var before  = node.Log.LastId;

            node.OnNTSOffsetReached += (_, _)      => throw new InvalidOperationException("listener broke");
            node.OnNTSOffsetReached += (group, offset) => { if (group.IsLegal) told.Add(offset); };

            clock.By    = TimeSpan.FromSeconds(7);

            await Check(node);
            await Check(node);

            var ahead   = Offsets(node, before);

            clock.By    = TimeSpan.Zero;

            await Check(node);

            var onTime  = Offsets(node, before);

            clock.By    = TimeSpan.FromSeconds(7);

            await Check(node);

            var said    = Offsets(node, before);

            Assert.Multiple(() => {

                Assert.That(told,                                Has.Count.EqualTo(2),  "once when reached, and once when reached again");
                Assert.That(told.Select(offset => offset.TotalSeconds),  Is.All.InRange(6.5, 7.5),  "seven seconds ahead");

                Assert.That(ahead,                               Has.Length.EqualTo(1),  "the second check found what the first did, and says nothing new");
                Assert.That(ahead[0].Level,                      Is.EqualTo(LogLevel.Critical));
                Assert.That(ahead[0].Metrological,               Is.True,  "evidence about the time everything is stamped with");
                Assert.That(ahead[0].Tags,                       Does.Contain("security"));
                Assert.That(ahead[0].Message,                    Does.Match(@"^NTS: the clock of this .+ is \+[67]\.\d{3} s off the time of group 'legal', at least the 5 s of 'offsetReportingThresholdSeconds'\.$"));

                Assert.That(onTime,                              Has.Length.EqualTo(2));
                Assert.That(onTime[1].Level,                     Is.EqualTo(LogLevel.Notice));
                Assert.That(onTime[1].Metrological,              Is.True);
                Assert.That(onTime[1].Message,                   Does.Match(@"^NTS: the clock of this .+ is within 5 s of the time of group 'legal' again: [+-]?0\.\d{3} s\.$"));

                Assert.That(said,                                Has.Length.EqualTo(3));
                Assert.That(said[2].Level,                       Is.EqualTo(LogLevel.Critical));

                Assert.That(node.Log.Recent(200, before, null).Select(entry => entry.Message),
                            Has.Some.Match(@"^Something told that the clock is \+[67]\.\d{3} s off the time of NTS group 'legal' failed: listener broke$"),
                            "a listener that throws keeps neither the next one from hearing it nor the check from ending");

            });

        }

        #endregion

        #region AThresholdLoweredUnderAnOffsetReportsItAtTheNextCheck()

        /// <summary>
        /// Two seconds ahead is below five, and reported once the threshold is
        /// one second. Switched off, nothing is reported or written down; set
        /// again, it is reported at the next check.
        /// </summary>
        [Test]
        public async Task AThresholdLoweredUnderAnOffsetReportsItAtTheNextCheck()
        {

            await using var node = Node();

            var told    = 0;

            node.OnNTSOffsetReached += (_, _) => told++;

            clock.By    = TimeSpan.FromSeconds(2);

            await Check(node);

            var belowFive = told;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "offsetReportingThresholdSeconds": 1 }"""), out var error),  Is.True,  error);

            await Check(node);

            var aboveOne  = told;
            var before    = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "offsetReportingThresholdSeconds": false }"""), out error),  Is.True,  error);

            await Check(node);

            var never     = told;
            var neverSaid = Offsets(node, before);

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "offsetReportingThresholdSeconds": 1 }"""), out error),  Is.True,  error);

            await Check(node);

            Assert.Multiple(() => {
                Assert.That(belowFive,  Is.EqualTo(0),  "two seconds are below the five");
                Assert.That(aboveOne,   Is.EqualTo(1),  "and above the one, at the next check");
                Assert.That(never,      Is.EqualTo(1),  "never is never");
                Assert.That(neverSaid,  Is.Empty,       "and is not \"within again\" either");
                Assert.That(told,       Is.EqualTo(2),  "a threshold set again is reached again");
            });

        }

        #endregion

        #region (private) Ahead

        /// <summary>
        /// This machine's clock, set ahead by as much as a test says.
        /// </summary>
        private sealed class Ahead : TimeProvider
        {

            public TimeSpan By { get; set; }

            public override DateTimeOffset GetUtcNow()
                => TimeProvider.System.GetUtcNow() + By;

        }

        #endregion

        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {
            using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            return IPPort.Parse(((IPEndPoint) listener.LocalEndpoint).Port);
        }

        private static IPPort FindFreeUDPPort()
        {
            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);
        }

        #endregion

    }

}
