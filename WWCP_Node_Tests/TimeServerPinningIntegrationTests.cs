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
using System.Security.Cryptography.X509Certificates;

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
    /// Pinning where it happens: a node asking a time server of its own group
    /// for the time, over a real key exchange, and what the pin makes of it.
    /// </summary>
    /// <remarks>
    /// Against Norn's NTS server on the loopback interface, with a certificate
    /// for "ntske.test" issued by a CA of the test's own, which the node trusts
    /// as a TLS root of its store. The name is one only the node's resolver
    /// knows, from its cache: the key exchange finds the server through the
    /// node's own DNS client, as the group's key exchanges do.
    /// </remarks>
    [TestFixture]
    [Category("LocalIntegration")]
    public class TimeServerPinningIntegrationTests
    {

        #region Data

        private static readonly DomainName  hostname   = DomainName.Parse("ntske.test");

        private static readonly IPPort      ntsKEPort  = FindFreeTCPPort();
        private static readonly IPPort      ntpPort    = FindFreeUDPPort();

        private X509Certificate2  ca        = default!;
        private X509Certificate2  served    = default!;
        private X509Certificate2  another   = default!;
        private NTSServer?        server;

        private String            directory = "";

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheTimeServer()
        {

            ca       = TimeServerPinningTests.CA("NTS Test CA");

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            served   = TimeServerPinningTests.Leaf(hostname.Trimmed, ca, key);
            another  = TimeServerPinningTests.Leaf(hostname.Trimmed, ca);

            // The certificate and its key as the TLS library of the server wants
            // them: the certificate as it is, and the key by its curve's name, as
            // the server makes its own - see NTSKE_TLSService.
            var parameters = key.ExportParameters(includePrivateParameters: true);

            server   = new NTSServer(
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

            ca.     Dispose();
            served. Dispose();
            another.Dispose();

        }

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-pinning-live-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helpers) Node(Pins) / Held(Pins) / Metrological(Node, Since)

        /// <summary>
        /// A node whose one time server is the test's, held to what is given,
        /// and which trusts the test's CA as a TLS root.
        /// </summary>
        private WWCPNode Node(String Pins = "")
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""
                                              { "nts": { "servers": [ {{Held(Pins)}} ], "minServers": 1 } }
                                              """);

            // Somebody to ask, so that the cache is consulted at all - at a port
            // nothing listens on, so that asking fails at once.
            var dns  = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

            dns.DNSCache.Add(
                DNSServiceName.Parse(hostname.ToString()),
                new A(hostname, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost)
            );

            var node = new WWCPNode(
                           AccountsPath:      Path.Combine(directory, "accounts"),
                           ConfigFile:        new WWCPConfigFile(configuration),
                           CertificatesPath:  Path.Combine(directory, "certificates"),
                           DNSClient:         dns,
                           LogToConsole:      false,
                           BridgeDebugLog:    false
                       );

            Assert.That(node.Certificates.Import(System.Text.Encoding.ASCII.GetBytes(ca.ExportCertificatePem()),
                                                 CertificateKind.TLSRoot, null, "NTS Test CA", out _, out var error),
                        Is.True,
                        error);

            return node;

        }

        private static String Held(String Pins)

            => $$"""{ "hostname": "{{hostname.Trimmed}}", "ntsKEPort": {{ntsKEPort}}, "ntpPort": {{ntpPort}}{{(Pins.Length > 0 ? ", " + Pins : "")}} }""";

        private static String[] Metrological(WWCPNode Node, UInt64 Since)

            => [.. Node.Log.Recent(200, Since, null).Where(entry => entry.Metrological).Select(entry => entry.Message)];

        #endregion


        #region AServerShowingTheCertificateItIsHeldToGivesTheTime()

        /// <summary>
        /// The key exchange goes ahead, and the group has its time.
        /// </summary>
        [Test]
        public async Task AServerShowingTheCertificateItIsHeldToGivesTheTime()
        {

            await using var node = Node($$""" "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(served)}}" """);

            var result    = await node.SyncTimeAsync();
            var judgement = node.LastJudgementOf(hostname);

            Assert.Multiple(() => {
                Assert.That(result.Value<Boolean>("ok"),  Is.True,  result.ToString());
                Assert.That(judgement?.Outcome,          Is.EqualTo("accepted"));
                Assert.That(judgement?.AnchoredBy,       Is.EqualTo("NTS Test CA"));
                Assert.That(node.ClockIsSynchronised,    Is.True,  "a clock the group found a time for is not called synchronised");
            });

        }

        #endregion

        #region AServerShowingAnotherCertificateIsRefusedAndGivesNoTime()

        /// <summary>
        /// The key exchange is refused, the group has no time, and the
        /// metrological log says which certificate it showed.
        /// </summary>
        [Test]
        public async Task AServerShowingAnotherCertificateIsRefusedAndGivesNoTime()
        {

            await using var node = Node($$""" "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(another)}}" """);

            var before    = node.Log.LastId;
            var result    = await node.SyncTimeAsync();
            var said      = Metrological(node, before);

            Assert.Multiple(() => {
                Assert.That(result.Value<Boolean>("ok"),              Is.False,  result.ToString());
                Assert.That(node.LastJudgementOf(hostname)?.Outcome,  Is.EqualTo("pinMismatch"));
                Assert.That(said,  Has.Some.Contains("was refused").And.Contains(CertificateEntry.ThumbprintOf(served)),  String.Join(" | ", said));
                Assert.That(said,  Has.Some.Contains("produced no time"),                                                String.Join(" | ", said));
                Assert.That(node.ClockIsSynchronised,  Is.False,  "a clock no server gave a time for is called synchronised");
            });

        }

        #endregion

        #region AServerShowingAnotherCertificateGivesTheTimeWhereItIsOnlyRecorded()

        /// <summary>
        /// With "onMismatch": "record", the group has its time - and the
        /// metrological log says that the certificate was not the one.
        /// </summary>
        [Test]
        public async Task AServerShowingAnotherCertificateGivesTheTimeWhereItIsOnlyRecorded()
        {

            await using var node = Node($$""" "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(another)}}", "onMismatch": "record" """);

            var before    = node.Log.LastId;
            var result    = await node.SyncTimeAsync();
            var said      = Metrological(node, before);

            Assert.Multiple(() => {
                Assert.That(result.Value<Boolean>("ok"),              Is.True,  result.ToString());
                Assert.That(node.LastJudgementOf(hostname)?.Outcome,  Is.EqualTo("recorded"));
                Assert.That(said,  Has.Some.Contains("used all the same"),  String.Join(" | ", said));
            });

        }

        #endregion

        #region APinGivenLaterCountsAtTheNextRoundAndNotHalfAnHourLater()

        /// <summary>
        /// A server held to a fingerprint while it has a key exchange is judged
        /// by the pin at the very next round, and not when the key exchange it
        /// had runs out.
        /// </summary>
        /// <remarks>
        /// The key exchange is reused for as long as its cookies last, and its
        /// certificate is only looked at when one is made: without forgetting
        /// it, the server would go on giving the time on the strength of a
        /// handshake nobody held it to anything in.
        /// </remarks>
        [Test]
        public async Task APinGivenLaterCountsAtTheNextRoundAndNotHalfAnHourLater()
        {

            await using var node = Node();

            var first = await node.SyncTimeAsync();

            Assert.That(first.Value<Boolean>("ok"),  Is.True,  first.ToString());

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse($$"""{ "servers": [ {{Held($$""" "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(another)}}" """)}} ] }"""),
                                                       out var error),
                        Is.True,
                        error);

            var second = await node.SyncTimeAsync();

            Assert.Multiple(() => {
                Assert.That(second.Value<Boolean>("ok"),              Is.False,  "the key exchange from before the pin was reused: " + second);
                Assert.That(node.LastJudgementOf(hostname)?.Outcome,  Is.EqualTo("pinMismatch"));
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
