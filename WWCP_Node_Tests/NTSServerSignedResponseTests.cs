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
    /// "signedResponses": a time server asked for a digitally signed response
    /// after every measurement, which goes into the metrological log - the
    /// SignedResponses of the Secure Time Synchronization white paper.
    /// </summary>
    public class NTSServerSignedResponseTests
    {

        #region Data

        private static readonly DomainName a = DomainName.Parse("a.example");
        private static readonly DomainName b = DomainName.Parse("b.example");

        private String directory = "";

        private String ConfigurationPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-nts-signed-" + Guid.NewGuid().ToString("N")[..12]);
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

        private static Boolean Signed(NTSGroup Group, DomainName Hostname)
            => Group.Sources.Sources.Single(source => source.Hostname.Equals(Hostname)).SignedResponses;


        #region AskingForSignedResponsesIsWrittenWithItsServerAndReadBack()

        [Test]
        public void AskingForSignedResponsesIsWrittenWithItsServerAndReadBack()
        {

            var held  = new NTSServerConfiguration(a, SignedResponses: true);
            var json  = held.ToJSON();

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out var read, out var error),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(json.Value<Boolean>("signedResponses"),               Is.True);
                Assert.That(read!.SignedResponses,                                 Is.True);
                Assert.That(read.ToEndpoint().SignedResponses,                     Is.True);
                Assert.That(new NTSServerConfiguration(a).ToJSON().Type,           Is.EqualTo(JTokenType.String),  "a server not asked says nothing about it");
                Assert.That(held.ToString(),                                       Does.Contain("signed responses"));
            });

        }

        #endregion

        #region AServerIsAskedForSignedResponsesWhereAnyEntryAsks()

        /// <summary>
        /// A server is asked for signed responses where any entry for it asks,
        /// in every group that asks it; the others are not.
        /// </summary>
        [Test]
        public void AServerIsAskedForSignedResponsesWhereAnyEntryAsks()
        {

            var node = Node("""
                            { "nts": { "groups": {
                                "legal":  { "enabled": false, "servers": [ "a.example", "b.example" ] },
                                "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "signedResponses": true } ] }
                            } } }
                            """);

            Assert.Multiple(() => {
                Assert.That(Signed(node.LegalTime,             a),  Is.True,   "a group saying nothing about it");
                Assert.That(Signed(node.NTSGroupOf("local")!,  a),  Is.True);
                Assert.That(Signed(node.LegalTime,             b),  Is.False);
            });

        }

        #endregion

        #region AChangeOfAskingIsSaidAndShown()

        [Test]
        public void AChangeOfAskingIsSaidAndShown()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse("""{ "servers": [ { "hostname": "a.example", "signedResponses": true }, "b.example" ] }"""), out var error, out _),  Is.True,  error);

            var shown  = node.NTSConfigurationJSON(node.LegalTime)["timeSources"]?.Select(source => source.Value<Boolean>("signedResponses")).ToArray();

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out error, out _),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(told.FirstOrDefault(),          Has.Some.EqualTo("a.example asked for signed responses"));
                Assert.That(told.LastOrDefault(),           Has.Some.EqualTo("a.example no longer asked for signed responses"));
                Assert.That(shown,                          Is.EqualTo(new[] { true, false }));
                Assert.That(Signed(node.LegalTime, a),      Is.False,  "and taken back");
            });

        }

        #endregion

    }


    /// <summary>
    /// Signed responses against a time server of Norn's own on the loopback
    /// interface, which signs with its key 1.
    /// </summary>
    [TestFixture]
    public class NTSServerSignedResponseRoundTests
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

            ca      = TimeServerPinningTests.CA("NTS Signed Response Test CA");

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
            directory  = Path.Combine(Path.GetTempPath(), "node-signed-live-" + Guid.NewGuid().ToString("N")[..12]);
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

        private WWCPNode Node(String More)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "nts": { "groups": { "legal": { "servers": [ { "hostname": "{{hostname.Trimmed}}", "ntsKEPort": {{ntsKEPort}}, "ntpPort": {{ntpPort}}{{More}} } ], "minServers": 1 } } } }""");

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
                                                 CertificateKind.TLSRoot, null, "NTS Signed Response Test CA", out _, out var error),
                        Is.True,
                        error);

            return node;

        }

        #endregion


        #region EverySignedResponseGoesIntoTheMetrologicalLog()

        /// <summary>
        /// A server asked for signed responses answers every round with one,
        /// checked against its key 1 and written into the metrological log with
        /// the response itself; a server not asked has none.
        /// </summary>
        [Test]
        public async Task EverySignedResponseGoesIntoTheMetrologicalLog()
        {

            await using var asked  = Node(""", "signedResponses": true""");

            var before  = asked.Log.LastId;
            var first   = await asked.SyncTimeAsync();
            var second  = await asked.SyncTimeAsync();
            var written = asked.Log.Recent(200, before, null).Where(entry => entry.Metrological && entry.Tags.Contains("signed")).ToArray();

            await using var plain  = Node("");

            var plainBefore = plain.Log.LastId;
            var unsigned    = await plain.SyncTimeAsync();

            Assert.Multiple(() => {
                Assert.That(first. Value<Boolean>("ok"),                               Is.True,  first.ToString());
                Assert.That(first ["servers"]?[0]?["signed"]?.Value<Boolean>("verified"),  Is.True);
                Assert.That(written,                                                    Has.Length.EqualTo(2),  "once per round");
                Assert.That(written[0].Level,                                           Is.EqualTo(LogLevel.Info));
                Assert.That(written[0].Message,                                         Is.EqualTo("NTS: ntske.test signed its response with its key 1."));
                Assert.That(Convert.FromBase64String(written[0].Data?.Value<String>("response") ?? "").Length,  Is.GreaterThan(48),  "the response itself, signature included");
                Assert.That(unsigned["servers"]?[0]?["signed"]?.Type,                  Is.EqualTo(JTokenType.Null));
                Assert.That(plain.Log.Recent(200, plainBefore, null).Where(entry => entry.Tags.Contains("signed")),  Is.Empty);
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
