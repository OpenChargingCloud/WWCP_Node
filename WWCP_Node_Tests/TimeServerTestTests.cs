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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The detailed test of one time server, against a real one: Norn's own,
    /// on this machine, with the self-signed certificate it makes itself.
    /// </summary>
    /// <remarks>
    /// Nothing goes out. The node gets a name server of its own, which knows
    /// "localhost" from its cache and asks nobody else: its one server is a
    /// port on this machine that nothing listens on. The time server listens
    /// on the loopback ports found free for it.
    /// </remarks>
    [TestFixture]
    public class TimeServerTestTests
    {

        #region (private static) FreeUDPPort()

        private static IPPort FreeUDPPort()
        {

            using var udp = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse((UInt16) ((IPEndPoint) udp.Client.LocalEndPoint!).Port);

        }

        #endregion


        #region ARefusedCertificateIsDescribedBeforeTheExchangeIsSaidToHaveFailed()

        /// <summary>
        /// The test says what the certificate was and why it was refused,
        /// before it says that the key exchange failed over it.
        /// </summary>
        /// <remarks>
        /// It used to go from the timings straight to "The key exchange
        /// failed", with nothing about the certificate it had failed over -
        /// the one moment somebody most needs to be told what it was.
        /// </remarks>
        [Test]
        public async Task ARefusedCertificateIsDescribedBeforeTheExchangeIsSaidToHaveFailed()
        {

            // The key exchange's port is held from before the server starts until
            // the test is over, so that nobody asking for a free port is given it
            // in between - see ClosedPort. The server binds 127.0.0.1 next to
            // what holds it: its default, every IPv4 address, could not be bound
            // there on Windows.
            using var ntsKEPort  = new ClosedPort();
            var ntpPort          = FreeUDPPort();

            ntsKEPort.HandOver();

            var server     = new NTSServer(ListenIPAddress:     IPv4Address.Localhost,
                                           NTSKEPort:           ntsKEPort.Number,
                                           NTSPort:             ntpPort,
                                           ExternalURLs:        [ URL.Parse($"udp://localhost:{ntpPort}") ],
                                           MasterKeysFilePath:  null);

            await server.Start();

            var directory  = TestNodes.TemporaryDirectory("time-server-test");

            try
            {

                var dnsClient = new DNSClient([ new DNSServerConfig(IPv4Address.Localhost, FreeUDPPort()) ],
                                              QueryTimeout: TimeSpan.FromSeconds(1));

                dnsClient.DNSCache.Add(DNSServiceName.Parse("localhost"),
                                       new A   (DomainName.Parse("localhost"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost),
                                       new AAAA(DomainName.Parse("localhost"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv6Address.Localhost));

                var configuration = new JObject(
                                        new JProperty("nts", new JObject(
                                            new JProperty("servers", new JArray(new JObject(
                                                new JProperty("hostname",   "localhost"),
                                                new JProperty("ntsKEPort",  ntsKEPort.Number.ToUInt16()),
                                                new JProperty("ntpPort",    ntpPort.  ToUInt16())
                                            ))),
                                            new JProperty("timeoutSeconds", 5)
                                        ))
                                    );

                Directory.CreateDirectory(directory);
                File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), configuration.ToString());

                await using var node = new WWCPNode(
                                           DNSClient:         dnsClient,
                                           HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                           AccountsPath:      Path.Combine(directory, "accounts"),
                                           ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                           CertificatesPath:  Path.Combine(directory, "certificates"),
                                           LogToConsole:      false,
                                           BridgeDebugLog:    false
                                       );

                var result  = await node.TestTimeServerAsync("localhost");
                var steps   = result["steps"]!.Select(step => step.Value<String>("text") ?? "").ToArray();

                var certificate  = Array.FindIndex(steps, step => step.StartsWith("Server certificate",      StringComparison.Ordinal));
                var verdict      = Array.FindIndex(steps, step => step.StartsWith("Not validated:",          StringComparison.Ordinal));
                var failed       = Array.FindIndex(steps, step => step.StartsWith("The key exchange failed", StringComparison.Ordinal));

                Assert.Multiple(() => {

                    Assert.That(certificate,  Is.GreaterThanOrEqualTo(0),  String.Join(" | ", steps));
                    Assert.That(steps.ElementAtOrDefault(certificate),  Does.Contain("ntpKE.example.org"));

                    Assert.That(steps.ElementAtOrDefault(verdict),      Does.Contain("its root is not one this machine trusts"),  String.Join(" | ", steps));

                    Assert.That(failed,       Is.GreaterThan(verdict),  "the exchange was said to have failed before its certificate was described");

                });

            }
            finally
            {
                server.Shutdown();
                TestNodes.Remove(directory);
            }

        }

        #endregion

    }

}
