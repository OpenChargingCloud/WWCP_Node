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
    /// "ntsKEHostname": the key exchange server a time server's keys and
    /// cookies come from, where it is another than the server itself - the
    /// NTSKEServerURL of the Secure Time Synchronization white paper. The
    /// server is asked for as the NTP server.
    /// </summary>
    /// <remarks>
    /// By the server's name across every group, as its AEAD algorithm is: the
    /// first entry that names a key exchange server decides.
    /// </remarks>
    public class NTSServerKeyExchangeTests
    {

        #region Data

        private static readonly DomainName a  = DomainName.Parse("a.example");
        private static readonly DomainName b  = DomainName.Parse("b.example");
        private static readonly DomainName ke = DomainName.Parse("ke.example");

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
            directory = Path.Combine(Path.GetTempPath(), "node-nts-ke-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helper) Node(Configuration) / KeyExchange(Group, Hostname)

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

        private static DomainName? KeyExchange(NTSGroup    Group,
                                               DomainName  Hostname)

            => Group.Sources.Sources.Single(source => source.Hostname.Equals(Hostname)).NTSKEHost;

        #endregion


        #region AKeyExchangeServerIsWrittenWithItsServerAndReadBack()

        /// <summary>
        /// "ntsKEHostname" is written with its server and read back, and left
        /// out where the server is its own key exchange server - named as
        /// itself, or empty - so that a server saying nothing else stays a bare
        /// host name.
        /// </summary>
        [Test]
        public void AKeyExchangeServerIsWrittenWithItsServerAndReadBack()
        {

            var held     = new NTSServerConfiguration(a, NTSKEHostname: ke);
            var json     = held.ToJSON();

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out var read, out var error),  Is.True,  error);

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "a.example", "ntsKEHostname": "a.example" }"""), 0, out var itself, out var itselfError),  Is.True,  itselfError);
            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "a.example", "ntsKEHostname": "" }"""),          0, out var empty,  out var emptyError),   Is.True,  emptyError);

            Assert.Multiple(() => {
                Assert.That(json.Value<String>("ntsKEHostname"),     Is.EqualTo(ke.ToString()));
                Assert.That(read!.NTSKEHostname,                      Is.EqualTo(ke));
                Assert.That(read.ToEndpoint().NTSKEHost,             Is.EqualTo(ke));
                Assert.That(read.ToEndpoint().Hostname,              Is.EqualTo(a),  "the server is still the server");
                Assert.That(itself!.ToJSON().Type,                    Is.EqualTo(JTokenType.String),  "the server itself is no other key exchange server");
                Assert.That(empty!. ToJSON().Type,                    Is.EqualTo(JTokenType.String));
                Assert.That(held.ToString(),                         Does.Contain("keys from ke.example"));
            });

        }

        #endregion

        #region AKeyExchangeServerThatIsNoNameIsRefused()

        [Test]
        public void AKeyExchangeServerThatIsNoNameIsRefused()
        {

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "a.example", "ntsKEHostname": "ke example" }"""), 0, out _, out var error, "nts.groups.local"),  Is.False);
            Assert.That(error,  Does.StartWith("'nts.groups.local.servers[0].ntsKEHostname'"));

        }

        #endregion


        #region EachServerHasTheKeyExchangeServerItsEntryNames()

        [Test]
        public void EachServerHasTheKeyExchangeServerItsEntryNames()
        {

            var node = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ { "hostname": "a.example", "ntsKEHostname": "ke.example" }, "b.example" ] } } } }""");

            Assert.Multiple(() => {
                Assert.That(KeyExchange(node.LegalTime, a),  Is.EqualTo(ke));
                Assert.That(KeyExchange(node.LegalTime, b),  Is.Null,  "a server whose entry names none is its own");
            });

        }

        #endregion

        #region AServerHasTheKeyExchangeServerTheFirstEntryNamingOneSaysInEveryGroup()

        [Test]
        public void AServerHasTheKeyExchangeServerTheFirstEntryNamingOneSaysInEveryGroup()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false, "servers": [ "a.example" ] },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "ntsKEHostname": "ke.example" } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example", "ntsKEHostname": "other.example" } ] }
                              } } }
                              """);

            Assert.Multiple(() => {
                Assert.That(KeyExchange(node.LegalTime,             a),  Is.EqualTo(ke),  "a group saying nothing about it");
                Assert.That(KeyExchange(node.NTSGroupOf("local")!,  a),  Is.EqualTo(ke));
                Assert.That(KeyExchange(node.NTSGroupOf("grid")!,   a),  Is.EqualTo(ke),  "a later group naming another one");
            });

        }

        #endregion

        #region AChangeOfAKeyExchangeServerIsSaidAndShown()

        /// <summary>
        /// A change of a server's key exchange server is a change of the group,
        /// said and written down like one, and each server shows what its own
        /// entry names.
        /// </summary>
        [Test]
        public void AChangeOfAKeyExchangeServerIsSaidAndShown()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "hostname": "a.example", "ntsKEHostname": "ke.example" }, "b.example" ] }"""),
                                                       out var error,
                                                       out _),
                        Is.True,
                        error);

            var held   = OnDisk["nts"]?["groups"]?["legal"]?["servers"]?[0];
            var shown  = node.NTSConfigurationJSON(node.LegalTime)["timeSources"];
            var after  = KeyExchange(node.LegalTime, a);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""),
                                                       out error,
                                                       out _),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(told.FirstOrDefault(),                       Has.Some.EqualTo("a.example's keys from ke.example"));
                Assert.That(told.LastOrDefault(),                        Has.Some.EqualTo("a.example's keys from itself"));
                Assert.That(held?.Value<String>("ntsKEHostname"),        Is.EqualTo(ke.ToString()),  "written down");
                Assert.That(shown?.Select(source => source.Value<String>("ntsKEHostname")),
                            Is.EqualTo(new[] { ke.ToString(), null }));
                Assert.That(after,                                       Is.EqualTo(ke));
                Assert.That(KeyExchange(node.LegalTime, a),              Is.Null,  "and taken back");
            });

        }

        #endregion

        #region ARemovedGroupNoLongerNamesAnotherGroupsServersKeyExchangeServer()

        [Test]
        public async Task ARemovedGroupNoLongerNamesAnotherGroupsServersKeyExchangeServer()
        {

            var node   = Node("""
                              { "nts": { "groups": {
                                  "legal":  { "enabled": false },
                                  "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "ntsKEHostname": "ke.example" } ] },
                                  "grid":   { "enabled": false, "servers": [ { "id": "grid-a", "hostname": "a.example" } ] }
                              } } }
                              """);

            var grid   = node.NTSGroupOf("grid")!;
            var before = KeyExchange(grid, a);

            var (removed, error, _) = await node.TryRemoveNTSGroupAsync("local");

            Assert.That(removed,  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(before,                 Is.EqualTo(ke));
                Assert.That(KeyExchange(grid, a),   Is.Null);
            });

        }

        #endregion

    }


    /// <summary>
    /// A time server whose keys come from a key exchange server of its own,
    /// against a server of Norn's own on the loopback interface, whose
    /// certificate a CA of the test's issued for the key exchange server.
    /// </summary>
    [TestFixture]
    public class NTSServerKeyExchangeRoundTests
    {

        #region Data

        private static readonly DomainName  keyExchange  = DomainName.Parse("ntske.test");
        private static readonly DomainName  unknown      = DomainName.Parse("time.example.invalid");

        private static readonly IPPort      ntsKEPort    = FindFreeTCPPort();
        private static readonly IPPort      ntpPort      = FindFreeUDPPort();

        private System.Security.Cryptography.X509Certificates.X509Certificate2  ca      = default!;
        private System.Security.Cryptography.X509Certificates.X509Certificate2  served  = default!;
        private NTSServer?                  server;

        private String                      directory  = "";

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheTimeServer()
        {

            ca      = TimeServerPinningTests.CA("NTS Key Exchange Test CA");

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            served  = TimeServerPinningTests.Leaf(keyExchange.Trimmed, ca, key);

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
            directory  = Path.Combine(Path.GetTempPath(), "node-ke-live-" + Guid.NewGuid().ToString("N")[..12]);
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

        #region (helper) Node(Server)

        /// <summary>
        /// A node whose legal group asks the given server alone, which knows the
        /// key exchange server's name and no other, and trusts the test's CA.
        /// </summary>
        private WWCPNode Node(String Server)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "nts": { "groups": { "legal": { "servers": [ {{Server}} ], "minServers": 1 } } } }""");

            var dns  = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

            dns.DNSCache.Add(DNSServiceName.Parse(keyExchange.ToString()), new A(keyExchange, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost));
            dns.DNSCache.AddNoData(DNSServiceName.Parse(keyExchange.ToString()), DNSResourceRecordTypes.AAAA, TimeSpan.FromHours(1));

            var node = new WWCPNode(
                           AccountsPath:      Path.Combine(directory, "accounts"),
                           ConfigFile:        new WWCPConfigFile(configuration),
                           CertificatesPath:  Path.Combine(directory, "certificates"),
                           DNSClient:         dns,
                           LogToConsole:      false,
                           BridgeDebugLog:    false
                       );

            Assert.That(node.Certificates.Import(System.Text.Encoding.ASCII.GetBytes(ca.ExportCertificatePem()),
                                                 CertificateKind.TLSRoot, null, "NTS Key Exchange Test CA", out _, out var error),
                        Is.True,
                        error);

            return node;

        }

        #endregion


        #region AServerNobodyKnowsIsAskedThroughItsKeyExchangeServer()

        /// <summary>
        /// A time server whose name no resolver knows is no time; with a key
        /// exchange server of its own, its keys come from there, and - the
        /// response naming no NTP server - its time too.
        /// </summary>
        [Test]
        public async Task AServerNobodyKnowsIsAskedThroughItsKeyExchangeServer()
        {

            await using var alone    = Node($$"""{ "hostname": "{{unknown.Trimmed}}", "ntsKEPort": {{ntsKEPort}}, "ntpPort": {{ntpPort}} }""");
            var without              = await alone.SyncTimeAsync();

            await using var through  = Node($$"""{ "hostname": "{{unknown.Trimmed}}", "ntsKEHostname": "{{keyExchange.Trimmed}}", "ntsKEPort": {{ntsKEPort}}, "ntpPort": {{ntpPort}} }""");
            var with                 = await through.SyncTimeAsync();

            Assert.Multiple(() => {
                Assert.That(without.Value<Boolean>("ok"),  Is.False,  "a name nobody knows was reached");
                Assert.That(with.   Value<Boolean>("ok"),  Is.True,   with.ToString());
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
