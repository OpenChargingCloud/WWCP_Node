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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Which certificates of its name servers a node believes, where it reaches
    /// them over TLS: the TLS roots of its store for "dns", and what each
    /// server is held to - asked of a name server of Hermod's own on the
    /// loopback, whose certificate signed itself.
    /// </summary>
    public class NameServerPinningTests
    {

        #region Data

        private String            directory    = "";
        private X509Certificate2  certificate  = default!;
        private X509Certificate2  another      = default!;
        private DNSServer         server       = default!;
        private IPPort            port;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory    = Path.Combine(Path.GetTempPath(), "node-dns-pinning-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            certificate  = SelfSigned();
            another      = SelfSigned();

            server       = new DNSServer(
                               new AuthoritativeDNSRequestHandler(
                                   new InMemoryDNSZone().
                                       Add(new A(
                                               DomainName. Parse("api.example.test."),
                                               DNSQueryClasses.IN,
                                               TimeSpan.   FromMinutes(5),
                                               IPv4Address.Parse("127.0.0.42")
                                           ))
                               ),
                               new DNSServerOptions {
                                   EnableUDPUnicast      = false,
                                   EnableUDPMulticast    = false,
                                   EnableTCPUnicast      = false,
                                   EnableTLSUnicast      = true,
                                   TLSUnicastSocket      = new IPSocket(IPv4Address.Localhost, IPPort.Parse(0)),
                                   TLSServerCertificate  = certificate
                               }
                           );

            await server.Start();

            port         = server.ActiveTLSUnicastSocket!.Value.Port;

        }

        [TearDown]
        public async Task TearDown()
        {

            await server.Stop();

            certificate.Dispose();
            another.    Dispose();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (helpers) SelfSigned() / Pem(Certificate) / Fingerprint(Certificate)

        /// <summary>
        /// A certificate for the loopback that signed itself, with its key.
        /// </summary>
        private static X509Certificate2 SelfSigned()
        {

            using var rsa  = RSA.Create(2048);

            var request    = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names      = new SubjectAlternativeNameBuilder();

            names.AddDnsName  ("localhost");
            names.AddIpAddress(System.Net.IPAddress.Loopback);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
            request.CertificateExtensions.Add(names.Build());

            using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

            return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);

        }

        private static Byte[] Pem(X509Certificate2 Certificate)
            => System.Text.Encoding.ASCII.GetBytes(Certificate.ExportCertificatePem());

        private static String Fingerprint(X509Certificate2 Certificate)
            => CertificateEntry.ThumbprintOf(Certificate);

        #endregion

        #region (helper) Node(Entry)

        /// <summary>
        /// A node whose one name server is the test's, over TLS, with whatever
        /// else its entry says - and no time server to ask.
        /// </summary>
        private WWCPNode Node(String Entry = "")
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration,
                              $$"""
                              {
                                "nts": { "enabled": false },
                                "dns": { "servers": [ { "address": "127.0.0.1", "port": {{port.ToUInt16()}}, "transport": "TLS" {{Entry}} } ],
                                         "maxRetries": 0, "useCache": false }
                              }
                              """);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Ask(Node)

        /// <summary>
        /// The node's own test of its name servers - the one there is - asked
        /// through the node's own client, whose connection is kept open between
        /// queries as it is for everything else; and what it said.
        /// </summary>
        private static async Task<(String[] Answers, JObject Judgement)> Ask(WWCPNode Node)
        {

            var said      = await Node.ResolveAsync("api.example.test", [ DNSResourceRecordTypes.A ]);
            var answers   = said["answers"] is JArray array
                                ? array.Select(answer => answer.Value<String>("value") ?? "").ToArray()
                                : [];
            var judgement = said["certificates"] is JArray judged && judged.Count > 0 && judged[^1] is JObject last
                                ? last
                                : new JObject();

            return (answers, judgement);

        }

        #endregion


        #region ANameServerOverTLSIsBelievedThroughARootOfTheNodesOwnForDNS()

        /// <summary>
        /// A certificate nobody's machine trusts, kept as a TLS root for the
        /// name servers: believed - and remembered with the certificate it
        /// showed.
        /// </summary>
        [Test]
        public async Task ANameServerOverTLSIsBelievedThroughARootOfTheNodesOwnForDNS()
        {

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(certificate), CertificateKind.TLSRoot, null, "our resolver",
                                                 [ CertificateUsages.DNS ], out _, out var error),  Is.True,  error);

            var (answers, judgement) = await Ask(node);

            Assert.Multiple(() => {
                Assert.That(answers,                                  Has.Some.Contains("127.0.0.42"));
                Assert.That(judgement.Value<String>("outcome"),       Is.EqualTo("accepted"));
                Assert.That(judgement.Value<String>("anchoredBy"),    Is.EqualTo("our resolver"));
                Assert.That(node.KnownServers.Get(CertificateUsages.DNS, $"tls://127.0.0.1:{port}")?.Certificate,
                            Is.EqualTo(Fingerprint(certificate)));
            });

        }

        #endregion

        #region ARootForTheTimeServersAloneVouchesForNoNameServer()

        [Test]
        public async Task ARootForTheTimeServersAloneVouchesForNoNameServer()
        {

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(certificate), CertificateKind.TLSRoot, null, "our clocks",
                                                 [ CertificateUsages.NTS ], out _, out var error),  Is.True,  error);

            var (answers, judgement) = await Ask(node);

            Assert.Multiple(() => {
                Assert.That(answers,                              Is.Empty, "a name server was believed through a root for the time servers");
                Assert.That(judgement.Value<String>("outcome"),   Is.EqualTo("untrusted"));
            });

        }

        #endregion

        #region ANameServerHeldToAnotherCertificateIsRefused()

        /// <summary>
        /// Held to another certificate than the one it shows, a name server is
        /// refused, and the refusal is said as a matter of security.
        /// </summary>
        [Test]
        public async Task ANameServerHeldToAnotherCertificateIsRefused()
        {

            await using var node = Node($$""", "certificateFingerprint": "{{Fingerprint(another)}}" """);

            Assert.That(node.Certificates.Import(Pem(certificate), CertificateKind.TLSRoot, null, null,
                                                 [ CertificateUsages.DNS ], out _, out var error),  Is.True,  error);

            var before               = node.Log.LastId;
            var (answers, judgement) = await Ask(node);

            Assert.Multiple(() => {
                Assert.That(answers,                              Is.Empty);
                Assert.That(judgement.Value<String>("outcome"),   Is.EqualTo("pinMismatch"));
                Assert.That(node.Log.Recent(100, before, "security").Select(entry => entry.Message),
                            Has.Some.Contains("was refused").And.Contains(Fingerprint(certificate)));
                Assert.That(node.Log.Recent(100, before, null).Any(entry => entry.Metrological),
                            Is.False,
                            "a name server bears on nothing the metrological log is for, unless its entry says \"record\"");
            });

        }

        #endregion

        #region ANameServerLearnsItsCertificateOnFirstUse()

        [Test]
        public async Task ANameServerLearnsItsCertificateOnFirstUse()
        {

            await using var node = Node(""", "trustOnFirstUse": "certificate" """);

            Assert.That(node.Certificates.Import(Pem(certificate), CertificateKind.TLSRoot, null, null,
                                                 [ CertificateUsages.DNS ], out _, out var error),  Is.True,  error);

            var (answers, judgement) = await Ask(node);

            var entry = (JObject) JObject.Parse(File.ReadAllText(node.ConfigFile.Path))["dns"]!["servers"]![0]!;

            Assert.Multiple(() => {
                Assert.That(answers,                                        Has.Some.Contains("127.0.0.42"));
                Assert.That(judgement.Value<String>("learned"),             Is.EqualTo("certificate"));
                Assert.That(entry.Value<String>("certificateFingerprint"),  Is.EqualTo(Fingerprint(certificate)), "written down as a pin somebody typed would be");
                Assert.That(node.PinsOf(new DNSServerConfig(IPv4Address.Localhost, port, DNSTransport.TLS))?.Certificates,
                            Is.EqualTo(new[] { Fingerprint(certificate) }));
            });

        }

        #endregion

        #region AChangeToWhatANameServerIsHeldToIsSaidAndCountsAtOnce()

        /// <summary>
        /// A pin changed from a page counts from the next query, not from the
        /// next time a connection kept open happens to close.
        /// </summary>
        [Test]
        public async Task AChangeToWhatANameServerIsHeldToIsSaidAndCountsAtOnce()
        {

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(certificate), CertificateKind.TLSRoot, null, null,
                                                 [ CertificateUsages.DNS ], out _, out var error),  Is.True,  error);

            var (before, _)  = await Ask(node);
            var logged       = node.Log.LastId;

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""
                            { "servers": [ { "address": "127.0.0.1", "port": {{port.ToUInt16()}}, "transport": "TLS",
                                             "certificateFingerprint": "{{Fingerprint(another)}}" } ] }
                            """), out error),
                        Is.True, error);

            var (after, judgement) = await Ask(node);

            Assert.Multiple(() => {
                Assert.That(before,                               Has.Some.Contains("127.0.0.42"));
                Assert.That(after,                                Is.Empty, "a connection kept open from before was used on the strength of a handshake nobody held to anything");
                Assert.That(judgement.Value<String>("outcome"),   Is.EqualTo("pinMismatch"));
                Assert.That(node.Log.Recent(100, logged, null).Select(entry => entry.Message),
                            Has.Some.Contains($"tls://127.0.0.1:{port} held to certificate {Fingerprint(another)}"));
            });

        }

        #endregion

        #region PinsNeedAServerThatShowsACertificate()

        [Test]
        public void PinsNeedAServerThatShowsACertificate()
        {

            Assert.That(DNSConfiguration.TryParse(JObject.Parse($$"""
                            { "servers": [ "192.168.1.1", { "address": "192.168.1.2", "rootFingerprint": "{{new String('a', 64)}}" } ] }
                            """), out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("'dns.servers[1]' is held to a certificate and asked over UDP"));

        }

        #endregion

        #region PinsTravelWithTheirServerThroughTheFile()

        [Test]
        public void PinsTravelWithTheirServerThroughTheFile()
        {

            var root = new String('b', 64);

            Assert.That(DNSConfiguration.TryParse(JObject.Parse($$"""
                            { "servers": [ { "address": "1.1.1.1", "transport": "TLS", "rootFingerprint": "{{root}}", "onMismatch": "accept" },
                                           "192.168.1.1" ] }
                            """), out var configuration, out var error),
                        Is.True, error);

            var written = configuration!.ToJSON()["servers"] as JArray;

            Assert.Multiple(() => {
                Assert.That(configuration.Pins,                                Has.Count.EqualTo(1));
                Assert.That(configuration.Pins!.Values.Single().Roots,         Is.EqualTo(new[] { root }));
                Assert.That(written![0]!.Value<String>("rootFingerprint"),     Is.EqualTo(root));
                Assert.That(written![0]!.Value<String>("onMismatch"),          Is.EqualTo("accept"));
                Assert.That(((JObject) written![1]!).ContainsKey("rootFingerprint"),  Is.False);
            });

        }

        #endregion

    }

}
