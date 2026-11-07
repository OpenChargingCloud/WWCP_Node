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

using BCBigInteger = Org.BouncyCastle.Math.BigInteger;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A group's "preflightSeconds": after how long without a round its servers
    /// are first sent a query whose answer is ignored - the Preflight of the
    /// Secure Time Synchronization white paper, chrony's "presend" - or false
    /// for never, as where nothing says.
    /// </summary>
    [TestFixture]
    public class NTSPreflightTests
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
            directory = Path.Combine(Path.GetTempPath(), "node-nts-preflight-" + Guid.NewGuid().ToString("N")[..12]);
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

        private static JToken? Preflight(WWCPNode Node, NTSGroup Group)
            => Node.NTSConfigurationJSON(Group)["settings"]?[NTSConfiguration.PreflightKey];


        #region APreflightIsReadWrittenSwitchedOffAndRefusedOutsideItsRange()

        [Test]
        public void APreflightIsReadWrittenSwitchedOffAndRefusedOutsideItsRange()
        {

            static (Boolean Read, NTSConfiguration? Configuration, String? Error) Read(String JSON)
            {
                var read = NTSConfiguration.TryParse(JObject.Parse(JSON), out var configuration, out var error, "nts.groups.legal");
                return (read, configuration, error);
            }

            var sixty   = Read("""{ "preflightSeconds": 60 }""");
            var off     = Read("""{ "preflightSeconds": false }""");
            var blank   = Read("""{ "preflightSeconds": "" }""");
            var zero    = Read("""{ "preflightSeconds": 0 }""");
            var day     = Read("""{ "preflightSeconds": 86401 }""");

            Assert.Multiple(() => {
                Assert.That(sixty.Configuration?.Preflight,                               Is.EqualTo(TimeSpan.FromSeconds(60)));
                Assert.That(sixty.Configuration?.ToJSON()["preflightSeconds"]?.Value<Int32>(),  Is.EqualTo(60));
                Assert.That(off.  Configuration?.Preflight,                               Is.EqualTo(TimeSpan.Zero),  "false is never, and a value of its own");
                Assert.That(off.  Configuration?.ToJSON()["preflightSeconds"]?.Type,      Is.EqualTo(JTokenType.Boolean));
                Assert.That(blank.Configuration?.Preflight,                               Is.EqualTo(TimeSpan.Zero),  "an emptied field is never");
                Assert.That(zero. Read,                                                   Is.False);
                Assert.That(zero. Error,                                                  Does.StartWith("'nts.groups.legal.preflightSeconds' must be a whole number of seconds between 1 and 86400, or false for never."));
                Assert.That(day.  Read,                                                   Is.False);
            });

        }

        #endregion

        #region ThereIsNoPreflightWhereNothingSaysOtherwise()

        [Test]
        public async Task ThereIsNoPreflightWhereNothingSaysOtherwise()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false }, "local": { "enabled": false, "preflightSeconds": 60 } } }""");

            var local = node.NTSGroupOf("local")!;

            Assert.Multiple(() => {
                Assert.That(node.LegalTime.Preflight,                       Is.Null);
                Assert.That(Preflight(node, node.LegalTime)?.Type,          Is.EqualTo(JTokenType.Boolean));
                Assert.That(Preflight(node, node.LegalTime)?.Value<Boolean>(), Is.False);
                Assert.That(local.Preflight,                                Is.EqualTo(TimeSpan.FromSeconds(60)),  "every group may have one, not the legal one alone");
                Assert.That(Preflight(node, local)?.Value<Int32>(),         Is.EqualTo(60));
            });

        }

        #endregion

        #region ARoundBeginsWithAPreflightOnceItsTimeHasPassedWithoutOne()

        /// <summary>
        /// The first round begins with a preflight, the next one within the time
        /// does not, and one after the time without a round does again - and a
        /// group without a preflight never does.
        /// </summary>
        [Test]
        public async Task ARoundBeginsWithAPreflightOnceItsTimeHasPassedWithoutOne()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false, "preflightSeconds": 60 }, "local": { "enabled": false } } }""");

            var legal = node.LegalTime;
            var local = node.NTSGroupOf("local")!;
            var t0    = DateTimeOffset.Parse("2026-11-07T12:00:00Z");

            Assert.Multiple(() => {
                Assert.That(legal.BeginRound(t0),                          Is.True,   "none before");
                Assert.That(legal.BeginRound(t0.AddSeconds(30)),           Is.False,  "within the time");
                Assert.That(legal.BeginRound(t0.AddSeconds(89)),           Is.False,  "measured from the last round, not the last preflight");
                Assert.That(legal.BeginRound(t0.AddSeconds(149)),          Is.True,   "the time without a round passed");
                Assert.That(legal.LastAsked,                               Is.EqualTo(t0.AddSeconds(149)));
                Assert.That(local.BeginRound(t0),                          Is.False,  "a group without a preflight");
            });

        }

        #endregion

        #region AChangeOfThePreflightIsSaidAndWritten()

        [Test]
        public async Task AChangeOfThePreflightIsSaidAndWritten()
        {

            await using var node = Node("""{ "groups": { "legal": { "enabled": false } } }""");

            var told = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse("""{ "preflightSeconds": 60 }"""), out var error, out _),     Is.True,  error);

            var written = OnDisk["nts"]?["groups"]?["legal"]?["preflightSeconds"]?.Value<Int32>();

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse("""{ "preflightSeconds": false }"""), out error, out _),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(told.FirstOrDefault(),                                                       Has.Some.EqualTo("preflight after 60 s without a round"));
                Assert.That(told.LastOrDefault(),                                                        Has.Some.EqualTo("no preflight"));
                Assert.That(written,                                                                     Is.EqualTo(60));
                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?["preflightSeconds"]?.Value<Boolean>(),  Is.False,  "never, written down as false");
                Assert.That(node.LegalTime.Preflight,                                                    Is.Null);
            });

        }

        #endregion

    }


    /// <summary>
    /// A group's preflight against a time server of Norn's own on the loopback
    /// interface, whose certificate a CA of the test's issued.
    /// </summary>
    [TestFixture]
    public class NTSPreflightRoundTests
    {

        #region Data

        private static readonly DomainName  hostname   = DomainName.Parse("ntske.test");

        private static readonly IPPort      ntsKEPort  = FindFreeTCPPort();
        private static readonly IPPort      ntpPort    = FindFreeUDPPort();

        private System.Security.Cryptography.X509Certificates.X509Certificate2  ca      = default!;
        private System.Security.Cryptography.X509Certificates.X509Certificate2  served  = default!;
        private NTSServer?                  server;

        private String                      directory  = "";

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheTimeServer()
        {

            ca      = TimeServerPinningTests.CA("NTS Preflight Test CA");

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
                                               )
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
            directory  = Path.Combine(Path.GetTempPath(), "node-preflight-live-" + Guid.NewGuid().ToString("N")[..12]);
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

        #region (helper) Node(More)

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
                                                 CertificateKind.TLSRoot, null, "NTS Preflight Test CA", out _, out var error),
                        Is.True,
                        error);

            return node;

        }

        #endregion


        #region TheFirstRoundOfAGroupWithAPreflightSendsOneAndTheNextDoesNot()

        /// <summary>
        /// With a minute of preflight, the first round sends the server its
        /// query a first time and says so, and the round right after does not;
        /// without one, no round does.
        /// </summary>
        [Test]
        public async Task TheFirstRoundOfAGroupWithAPreflightSendsOneAndTheNextDoesNot()
        {

            await using var with     = Node("\"preflightSeconds\": 60");

            var first   = await with.SyncTimeAsync();
            var second  = await with.SyncTimeAsync();

            await using var without  = Node();

            var plain   = await without.SyncTimeAsync();

            Assert.Multiple(() => {
                Assert.That(first. Value<Boolean>("ok"),                    Is.True,   first. ToString());
                Assert.That(first ["servers"]?[0]?.Value<Boolean>("preflight"),  Is.True,   "the first round");
                Assert.That(second["servers"]?[0]?.Value<Boolean>("preflight"),  Is.False,  "a round within the minute");
                Assert.That(plain ["servers"]?[0]?.Value<Boolean>("preflight"),  Is.False,  "a group without a preflight");
            });

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
