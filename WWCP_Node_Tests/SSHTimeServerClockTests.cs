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
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using BCBigInteger = Org.BouncyCastle.Math.BigInteger;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the time server of the SSH logins ("ssh.nts") says about its clock, as the check of
    /// the clock against the legal group finds it: a local time server of stratum 2 is the legal
    /// group, and its clock is set ahead where a test says.
    /// </summary>
    [TestFixture]
    public class SSHTimeServerClockTests
    {

        #region Data

        private static readonly DomainName  hostname   = DomainName.Parse("ntske.test");

        private readonly Ahead              clock      = new ();

        private System.Security.Cryptography.X509Certificates.X509Certificate2  ca      = default!;
        private System.Security.Cryptography.X509Certificates.X509Certificate2  served  = default!;
        private NTSServer?                  upstream;

        private String                      directory  = "";
        private readonly List<WWCPNode>     nodes      = [];
        private readonly List<String>       said       = [];

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheUpstreamTimeServer()
        {

            ca      = TimeServerPinningTests.CA("SSH Time Server Clock Test CA");

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            served  = TimeServerPinningTests.Leaf(hostname.Trimmed, ca, key);

            var parameters = key.ExportParameters(includePrivateParameters: true);

            upstream = await FreePortsStart(() => new NTSServer(
                                                      NTSKEPort:           FindFreeTCPPort(),
                                                      NTSPort:             FindFreeUDPPort(),
                                                      MasterKeysFilePath:  null,
                                                      TLSCertificate:      new X509CertificateParser().ReadCertificate(served.RawData),
                                                      TLSPrivateKey:       new ECPrivateKeyParameters("ECDSA", new BCBigInteger(1, parameters.D), SecObjectIdentifiers.SecP256r1),
                                                      Stratum:             2,
                                                      ReferenceIdentifier: ReferenceIdentifier.From(10, 0, 0, 1),
                                                      RootDelay:           TimeSpan.FromMilliseconds(20),
                                                      RootDispersion:      TimeSpan.FromMilliseconds(30),
                                                      TimeProvider:        clock
                                                  ));

        }

        [OneTimeTearDown]
        public async Task StopTheUpstreamTimeServer()
        {
            if (upstream is not null)
                await upstream.ShutdownAsync();
            ca.    Dispose();
            served.Dispose();
        }

        [SetUp]
        public void Setup()
        {
            clock.By   = TimeSpan.Zero;
            directory  = Path.Combine(Path.GetTempPath(), "node-ssh-time-clock-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
            lock (said) said.Clear();
        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var node in nodes)
            {
                try { await node.DisposeAsync(); } catch (Exception) { }
            }

            nodes.Clear();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region TheTimeServer_SaysWhatTheCheckOfTheClockFound

        /// <summary>
        /// Not checked yet: not synchronised, and no client takes the time. Checked against a
        /// server of stratum 2 and found right: stratum 3, that server as the reference, its root
        /// delay and dispersion and more. Found seven seconds off: not synchronised again, and
        /// said so in the log. Right again: synchronised again.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task TheTimeServer_SaysWhatTheCheckOfTheClockFound(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started();

            var unchecked_      = await AskPlainAsync(ntpPort);
            var uncheckedClock  = node.TimeServerOfSSHLoginsClock;

            await Check(node);

            var right           = await AskPlainAsync(ntpPort);
            var rightClock      = node.TimeServerOfSSHLoginsClock;
            var rightJSON       = node.SSHConfigurationJSON()["nts"]!["clock"]!;

            clock.By            = TimeSpan.FromSeconds(7);

            await Check(node);

            var off             = await AskPlainAsync(ntpPort);
            var offJSON         = node.SSHConfigurationJSON()["nts"]!["clock"]!;

            clock.By            = TimeSpan.Zero;

            await Check(node);

            var again           = await AskPlainAsync(ntpPort);

            Assert.Multiple(() => {

                Assert.That(uncheckedClock?.Why,           Is.EqualTo("neverChecked"));
                Assert.That(LeapIndicatorOf(unchecked_),   Is.EqualTo(3),   "a clock never checked is handed out as synchronised");
                Assert.That(unchecked_[1],                 Is.EqualTo(16));

                Assert.That(LeapIndicatorOf(right),        Is.EqualTo(0));
                Assert.That(right[1],                      Is.EqualTo(3),   "not one stratum below its server");
                Assert.That(right.AsSpan(12, 4).ToArray(), Is.EqualTo(new Byte[] { 127, 0, 0, 1 }), "not its server as the reference");
                Assert.That(Seconds(right, 4),             Is.GreaterThanOrEqualTo(0.020), "the root delay of its server is missing");
                Assert.That(Seconds(right, 8),             Is.GreaterThanOrEqualTo(0.030), "the root dispersion of its server is missing");
                Assert.That(rightClock?.Upstream?.Hostname,                Is.EqualTo("ntske.test"));
                Assert.That(rightJSON["stratum"]?.Value<Int32>(),          Is.EqualTo(3));
                Assert.That(rightJSON["reference"]?.Value<String>(),       Is.EqualTo("ntske.test"));
                Assert.That(rightJSON["synchronised"]?.Value<Boolean>(),   Is.True);
                Assert.That(Said("at stratum 3, from ntske.test"),         Is.True, "the log does not say it");

                Assert.That(LeapIndicatorOf(off),          Is.EqualTo(3),   "a clock found seven seconds off is handed out as synchronised");
                Assert.That(off[1],                        Is.EqualTo(16));
                Assert.That(offJSON["synchronised"]?.Value<Boolean>(),     Is.False);
                Assert.That(offJSON["why"]?.Value<String>(),               Is.EqualTo("offBy"));
                Assert.That(Said("is not synchronised, and no station takes its time"), Is.True, "the log does not say it");

                Assert.That(LeapIndicatorOf(again),        Is.EqualTo(0),   "right again, and still not synchronised");
                Assert.That(again[1],                      Is.EqualTo(3));

            });

        }

        #endregion

        #region AClockNotChecked_IsAnUncalibratedLocalClock

        /// <summary>
        /// NTS switched off for this node: the time server says what Norn says by default.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task AClockNotChecked_IsAnUncalibratedLocalClock(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(LegalEnabled: false);

            var answer = await AskPlainAsync(ntpPort);

            Assert.Multiple(() => {
                Assert.That(node.TimeServerOfSSHLoginsClock,  Is.Null);
                Assert.That(LeapIndicatorOf(answer),          Is.EqualTo(0));
                Assert.That(answer[1],                        Is.EqualTo(1));
                Assert.That(System.Text.Encoding.ASCII.GetString(answer, 12, 4), Is.EqualTo("LOCL"));
                Assert.That(node.SSHConfigurationJSON()["nts"]!["clock"]!["reference"]?.Value<String>(), Is.EqualTo("LOCL"));
            });

        }

        #endregion


        #region (private) Started(LegalEnabled = true)

        private async Task<(WWCPNode Node, IPPort NTPPort)> Started(Boolean LegalEnabled = true)
        {

            var ntpPort        = FindFreeUDPPort();
            var configuration  = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            var node = await TestPorts.StartedOnFreshPorts(() => {

                ntpPort = FindFreeUDPPort();

                File.WriteAllText(configuration,
                                  $$"""
                                  {
                                    "nts": { "groups": { "legal": { "enabled": {{(LegalEnabled ? "true" : "false")}}, "servers": [ { "hostname": "{{hostname.Trimmed}}", "ntsKEPort": {{upstream!.TCPPort}}, "ntpPort": {{upstream.UDPPort}} } ], "minServers": 1 },
                                                         "local": { "enabled": false } } },
                                    "ssh": { "enabled": true, "port": {{TestPorts.Free()}}, "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1", "plainNTP": true } }
                                  }
                                  """);

                // The name from the cache, both records.
                var dns  = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

                dns.DNSCache.Add(DNSServiceName.Parse(hostname.ToString()), new A(hostname, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost));
                dns.DNSCache.AddNoData(DNSServiceName.Parse(hostname.ToString()), DNSResourceRecordTypes.AAAA, TimeSpan.FromHours(1));

                var made = new WWCPNode(HTTPPort:          TestPorts.Free(),
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(configuration),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        DNSClient:         dns,
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                Assert.That(made.Certificates.Import(System.Text.Encoding.ASCII.GetBytes(ca.ExportCertificatePem()),
                                                     CertificateKind.TLSRoot, null, "SSH Time Server Clock Test CA", out _, out var error),
                            Is.True,
                            error);

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                nodes.Add(made);

                return made;

            });

            Assert.That(node.TimeServerOfSSHLogins,            Is.Not.Null, node.SSHNamesAndTimeProblem);
            Assert.That(node.TimeServerOfSSHLogins!.PlainNTP,  Is.True);

            return (node, ntpPort);

        }

        #endregion

        #region (private static) Check(Node) / AskPlainAsync(NTPPort) / LeapIndicatorOf / Seconds

        private static async Task Check(WWCPNode Node)
        {
            var result = await Node.SyncTimeAsync();
            Assert.That(result.Value<Boolean>("ok"), Is.True, result.ToString());
        }

        /// <summary>
        /// The time server's answer to a plain NTP request: its header is what it says about its clock.
        /// </summary>
        private static async Task<Byte[]> AskPlainAsync(IPPort NTPPort)
        {

            using var udpClient  = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            var request          = new Byte[48];
            request[0]           = 0x23;
            Random.Shared.NextBytes(request.AsSpan(40, 8));

            await udpClient.SendAsync(request, new IPEndPoint(System.Net.IPAddress.Loopback, NTPPort.ToUInt16()));

            var answer = (await udpClient.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5))).Buffer;

            Assert.That(answer.Length, Is.GreaterThanOrEqualTo(48));

            return answer;

        }

        private static Int32 LeapIndicatorOf(Byte[] Answer)
            => Answer[0] >> 6;

        /// <summary>
        /// A 16.16 fixed-point count of seconds of the header, RFC 5905 § 6.
        /// </summary>
        private static Double Seconds(Byte[] Answer, Int32 At)
            => ((UInt32) (Answer[At] << 24 | Answer[At + 1] << 16 | Answer[At + 2] << 8 | Answer[At + 3])) / 65536.0;

        #endregion

        #region (private) Said(What)

        private Boolean Said(String What)
        {
            lock (said)
                return said.Any(line => line.Contains(What, StringComparison.Ordinal));
        }

        #endregion

        #region (private static) FreePortsStart(Make) / FindFreeTCPPort() / FindFreeUDPPort()

        /// <summary>
        /// The upstream time server, started - on other ports, where somebody took one in between.
        /// </summary>
        private static async Task<NTSServer> FreePortsStart(Func<NTSServer> Make)
        {
            for (var attempt = 1; ; attempt++)
            {
                var server = Make();
                try
                {
                    await server.Start();
                    return server;
                }
                catch (SocketException) when (attempt < 10)
                {
                    await server.ShutdownAsync();
                }
            }
        }

        private static IPPort FindFreeTCPPort()
        {
            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();
            return IPPort.Parse(port);
        }

        private static IPPort FindFreeUDPPort()
        {
            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Any, 0));
            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);
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

    }

}
