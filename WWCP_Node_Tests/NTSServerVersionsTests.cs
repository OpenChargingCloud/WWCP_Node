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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using BCBigInteger = Org.BouncyCastle.Math.BigInteger;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// "versions": the versions of NTP a time server is asked in, the preferred
    /// one first - the Versions of the Secure Time Synchronization white paper
    /// (section 3.2.4).
    /// </summary>
    public class NTSServerVersionsTests
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
            directory = Path.Combine(Path.GetTempPath(), "node-nts-versions-" + Guid.NewGuid().ToString("N")[..12]);
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

        private static IReadOnlyList<Byte> Versions(NTSGroup Group, DomainName Hostname)
            => Group.Sources.Sources.Single(source => source.Hostname.Equals(Hostname)).NTPVersions;

        private static Boolean TryParse(String JSON, out NTSServerConfiguration? Configuration, out String? Error)
            => NTSServerConfiguration.TryParse(JToken.Parse(JSON), 0, out Configuration, out Error);


        #region TheVersionsAreWrittenWithTheirServerAndReadBack()

        /// <summary>
        /// The versions of an entry are read in their order, in any case, written
        /// back as "v5" and "v4", and put on the endpoint; NTPv4 alone, written or
        /// not, is the default and written as nothing.
        /// </summary>
        [Test]
        public void TheVersionsAreWrittenWithTheirServerAndReadBack()
        {

            Assert.That(TryParse("""{ "hostname": "a.example", "versions": [ "V5", "v4" ] }""", out var both,   out var error),  Is.True,  error);
            Assert.That(TryParse("""{ "hostname": "a.example", "versions": [ "v4" ] }""",       out var v4Only, out error),      Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(both!.Versions,                                    Is.EqualTo(new Byte[] { 5, 4 }));
                Assert.That(both.ToJSON()["versions"]?.Values<String>(),       Is.EqualTo(new[] { "v5", "v4" }));
                Assert.That(both.ToEndpoint().NTPVersions,                     Is.EqualTo(new Byte[] { 5, 4 }));
                Assert.That(both.ToEndpoint().NextProtocolsOffered,            Is.EqualTo(new UInt16[] { 0x8001, 0 }));
                Assert.That(both.ToString(),                                   Does.Contain("asked in NTPv5 and NTPv4"));
                Assert.That(v4Only!.Versions,                                  Is.Null,  "the default");
                Assert.That(v4Only.ToJSON().Type,                              Is.EqualTo(JTokenType.String),  "written as nothing");
                Assert.That(new NTSServerConfiguration(a).ToEndpoint().NTPVersions,  Is.EqualTo(new Byte[] { 4 }));
            });

        }

        #endregion

        #region WhatIsNoListOfVersionsIsRefused()

        /// <summary>
        /// A version this node does not ask in, a version twice, no version at all,
        /// and NTPv5 for a server asked for signed responses - an extension of
        /// NTPv4 - are refused, saying why.
        /// </summary>
        [Test]
        public void WhatIsNoListOfVersionsIsRefused()
        {

            Assert.Multiple(() => {

                Assert.That(TryParse("""{ "hostname": "a.example", "versions": [ "v3" ] }""",        out _, out var v3),      Is.False);
                Assert.That(v3,      Does.Contain("'v3' is not a version of NTP this node asks in"));

                Assert.That(TryParse("""{ "hostname": "a.example", "versions": [ "v5", "v5" ] }""",  out _, out var twice),   Is.False);
                Assert.That(twice,   Does.Contain("names v5 twice"));

                Assert.That(TryParse("""{ "hostname": "a.example", "versions": [ ] }""",             out _, out var none),    Is.False);
                Assert.That(none,    Does.Contain("names no version"));

                Assert.That(TryParse("""{ "hostname": "a.example", "signedResponses": true, "versions": [ "v5", "v4" ] }""", out _, out var signed), Is.False);
                Assert.That(signed,  Does.Contain("signed responses is asked in v4 alone"));

                Assert.That(TryParse("""{ "hostname": "a.example", "signedResponses": true, "versions": [ "v4" ] }""",       out _, out var fine),   Is.True,  fine);

            });

        }

        #endregion

        #region AServerIsAskedInTheVersionsOfTheFirstEntryThatNamesThem()

        /// <summary>
        /// By the server's name across every group: the first entry that names
        /// versions decides, and a group that says nothing about them does not
        /// undo it; another server is asked in NTPv4 alone.
        /// </summary>
        [Test]
        public void AServerIsAskedInTheVersionsOfTheFirstEntryThatNamesThem()
        {

            var node = Node("""
                            { "nts": { "groups": {
                                "legal":  { "enabled": false, "servers": [ "a.example", "b.example" ] },
                                "local":  { "enabled": false, "servers": [ { "hostname": "a.example", "versions": [ "v5", "v4" ] } ] }
                            } } }
                            """);

            Assert.Multiple(() => {
                Assert.That(Versions(node.LegalTime,             a),  Is.EqualTo(new Byte[] { 5, 4 }),  "a group saying nothing about it");
                Assert.That(Versions(node.NTSGroupOf("local")!,  a),  Is.EqualTo(new Byte[] { 5, 4 }));
                Assert.That(Versions(node.LegalTime,             b),  Is.EqualTo(new Byte[] { 4 }));
            });

        }

        #endregion

        #region AChangeOfVersionsIsSaidAndShown()

        [Test]
        public void AChangeOfVersionsIsSaidAndShown()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse("""{ "servers": [ { "hostname": "a.example", "versions": [ "v5", "v4" ] }, "b.example" ] }"""), out var error, out _),  Is.True,  error);

            var shown  = node.NTSConfigurationJSON(node.LegalTime)["timeSources"]?.Select(source => source["versions"]?.Type == JTokenType.Array ? String.Join(",", source["versions"]!.Values<String>()) : null).ToArray();

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime, JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out error, out _),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(told.FirstOrDefault(),         Has.Some.EqualTo("a.example asked in NTPv5 and NTPv4"));
                Assert.That(told.LastOrDefault(),          Has.Some.EqualTo("a.example asked in NTPv4 alone"));
                Assert.That(shown,                         Is.EqualTo(new[] { "v5,v4", null }));
                Assert.That(Versions(node.LegalTime, a),   Is.EqualTo(new Byte[] { 4 }),  "and taken back");
            });

        }

        #endregion

    }


    /// <summary>
    /// The versions against a time server of Norn's own on the loopback
    /// interface that speaks NTPv5 of the draft.
    /// </summary>
    [TestFixture]
    public class NTSServerVersionsRoundTests
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

            ca      = TimeServerPinningTests.CA("NTS Versions Test CA");

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            served  = TimeServerPinningTests.Leaf(hostname.Trimmed, ca, key);

            var parameters = key.ExportParameters(includePrivateParameters: true);

            server  = new NTSServer(
                          NTSKEPort:           ntsKEPort,
                          NTSPort:             ntpPort,
                          MasterKeysFilePath:  null,
                          TLSCertificate:      new X509CertificateParser().ReadCertificate(served.RawData),
                          TLSPrivateKey:       new ECPrivateKeyParameters("ECDSA", new BCBigInteger(1, parameters.D), SecObjectIdentifiers.SecP256r1),
                          NTPv5:               NTPv5Support.Draft
                      );

            await server.Start();

        }

        [OneTimeTearDown]
        public void StopTheTimeServer()
        {
            server?.Dispose();
            ca.    Dispose();
            served.Dispose();
        }

        [SetUp]
        public void Setup()
        {
            directory  = Path.Combine(Path.GetTempPath(), "node-versions-live-" + Guid.NewGuid().ToString("N")[..12]);
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
                                                 CertificateKind.TLSRoot, null, "NTS Versions Test CA", out _, out var error),
                        Is.True,
                        error);

            return node;

        }

        #endregion


        #region AServerAskedInNTPv5FirstIsCheckedInNTPv5()

        /// <summary>
        /// A server asked in NTPv5 first is checked in NTPv5 under NTS, and says
        /// so; one asked as before is checked in NTPv4.
        /// </summary>
        [Test]
        public async Task AServerAskedInNTPv5FirstIsCheckedInNTPv5()
        {

            var answeredBefore      = server!.Metrics.NTPv5AuthenticatedResponsesSent;

            await using var v5      = Node(""", "versions": [ "v5", "v4" ]""");

            var check               = await v5.SyncTimeAsync();
            var shown               = v5.NTSConfigurationJSON(v5.LegalTime)["timeSources"]?[0];

            await using var v4      = Node("");

            var plainCheck          = await v4.SyncTimeAsync();
            var plainShown          = v4.NTSConfigurationJSON(v4.LegalTime)["timeSources"]?[0];

            Assert.Multiple(() => {
                Assert.That(check.Value<Boolean>("ok"),                         Is.True,  check.ToString());
                Assert.That(shown?.Value<String>("ntpVersion"),                 Is.EqualTo("v5"));
                Assert.That(server.Metrics.NTPv5AuthenticatedResponsesSent,     Is.GreaterThan(answeredBefore),  "answered in NTPv5 under NTS");
                Assert.That(plainCheck.Value<Boolean>("ok"),                    Is.True,  plainCheck.ToString());
                Assert.That(plainShown?.Value<String>("ntpVersion"),            Is.EqualTo("v4"));
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
