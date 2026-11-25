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

using System.Net.Sockets;

using NUnit.Framework;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// ping on a node's command line: ICMP echo requests to an IPv4 or IPv6
    /// address - with its interface after a "%" -, to a name resolved by the
    /// node's name servers, and to a name under ".local" resolved by Multicast
    /// DNS where that is switched on; and the "multicast" object of the "dns"
    /// section that switches it on.
    /// </summary>
    /// <remarks>
    /// Every echo request goes to the loopback interface: nothing here leaves
    /// this machine. The name server is Hermod's, on TCP at the loopback
    /// address; Multicast DNS goes over Hermod's network in memory, so that no
    /// socket is bound to port 5353.
    /// </remarks>
    public class PingCommandTests
    {

        #region Data

        private String                        directory   = "";
        private DNSServer                     nameServer  = null!;
        private IPPort                        port;
        private WWCPNode?                     node;
        private InMemoryMulticastDNSNetwork   network     = null!;
        private MulticastDNSResponder?        responder;

        #endregion

        #region Setup / TearDown

        /// <summary>
        /// Whether this machine lets the tests send ICMP at all: not every
        /// Linux does for an unprivileged user (WSL's Debian, for one, gives
        /// neither an ICMP datagram socket nor the ping program the right).
        /// </summary>
        private static Boolean icmpAllowed = true;

        [OneTimeSetUp]
        public async Task MayThisMachineSendICMP()
        {

            if (OperatingSystem.IsWindows())
                return;

            using var ping   = new System.Net.NetworkInformation.Ping();
            var stopwatch    = System.Diagnostics.Stopwatch.StartNew();
            var reply        = await ping.SendPingAsync(System.Net.IPAddress.Loopback, TimeSpan.FromSeconds(2));

            icmpAllowed      = reply.Status == System.Net.NetworkInformation.IPStatus.Success ||
                               stopwatch.Elapsed > TimeSpan.FromSeconds(1);

        }

        private static void RequiresICMP()
        {
            if (!icmpAllowed)
                Assert.Ignore("This machine does not let an unprivileged user send ICMP; see WithoutTheRightToSendICMPItIsSaid.");
        }

        [SetUp]
        public async Task Setup()
        {

            directory   = Path.Combine(Path.GetTempPath(), "node-ping-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            var origin  = DomainName.Parse("example.test.");

            nameServer  = new DNSServer(
                              new AuthoritativeDNSRequestHandler(
                                  new InMemoryDNSZone().
                                      AddZoneFileString("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300", Origin: origin).
                                      AddZoneFileString("host.example.test. 300 IN A 127.0.0.1",                                                     Origin: origin).
                                      AddZoneFileString("six.example.test. 300 IN AAAA ::1",                                                         Origin: origin).
                                      AddZoneFileString("both.example.test. 300 IN A 127.0.0.1",                                                     Origin: origin).
                                      AddZoneFileString("both.example.test. 300 IN AAAA ::1",                                                        Origin: origin)
                              ),
                              new DNSServerOptions {
                                  EnableUDPUnicast    = false,
                                  EnableUDPMulticast  = false,
                                  EnableTCPUnicast    = true,
                                  TCPUnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Parse(0))
                              }
                          );

            await nameServer.Start();

            port        = nameServer.ActiveTCPUnicastSocket!.Value.Port;
            network     = new InMemoryMulticastDNSNetwork();
            responder   = null;
            transportOptions.Clear();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            if (responder is not null)
                await responder.DisposeAsync();

            await nameServer.Stop();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // The system's to clear.
            }

        }

        #endregion

        #region (helper) Node(DNS) / NodeWithTheTestsNameServer(Multicast)

        /// <summary>
        /// A node whose "dns" section is the given one, without a legal time to
        /// look for, asking Multicast DNS on the network of this test.
        /// </summary>
        private WWCPNode Node(String DNS)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "dns": {{DNS}}, "nts": { "groups": { "legal": { "enabled": false } } } }""");

            node = new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

            node.MulticastDNSTransportFactory = options => {
                                                     transportOptions.Add(options);
                                                     return network.CreateTransport(IPv4Address.Parse("10.0.0.2"));
                                                 };

            return node;

        }

        private readonly List<UDPMulticastDNSTransportOptions> transportOptions = [];

        /// <summary>
        /// A node asking the name server of this test, with the given
        /// "multicast" object.
        /// </summary>
        private WWCPNode NodeWithTheTestsNameServer(String Multicast = """{ "enabled": false }""")

            => Node($$"""
                      { "servers": [ { "id": "local", "address": "127.0.0.1", "port": {{port}}, "transport": "TCP", "queryTimeoutSeconds": 3 } ],
                        "maxRetries": 0,
                        "useCache": false,
                        "multicast": {{Multicast}} }
                      """);

        /// <summary>
        /// A responder on the network of this test, answering for the given
        /// name with the given address.
        /// </summary>
        private async Task Answering(String Name, String Address)
        {

            responder = new MulticastDNSResponder(network.CreateTransport(IPv4Address.Parse("10.0.0.7")));

            await responder.StartAsync();
            await responder.PublishAsync([ new A(DomainName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse(Address)) ],
                                         Probe: false);

        }

        #endregion


        #region TheNodesCommandLineHasPing()

        /// <summary>
        /// Every node's command line has ping, without anybody listing it.
        /// </summary>
        [Test]
        public void TheNodesCommandLineHasPing()
        {

            using var cli = new NodeCLI(Node("""{ "enabled": false }"""));

            Assert.That(cli.Commands.OfType<PingCommand>().Count(), Is.EqualTo(1));

        }

        #endregion

        #region AnIPv4AddressIsPinged()

        /// <summary>
        /// 127.0.0.1, twice: a reply for each, and the summary.
        /// </summary>
        [Test]
        public async Task AnIPv4AddressIsPinged()
        {

            RequiresICMP();

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("ping 127.0.0.1 -c 2 -i 0.2");

            Assert.Multiple(() => {
                Assert.That(said[0],  Is.EqualTo("PING 127.0.0.1: 2 echo requests of 32 bytes"), String.Join(Environment.NewLine, said));
                Assert.That(said,     Has.Some.Match(@"^  reply from 127\.0\.0\.1: seq=1 time=\d+ ms"));
                Assert.That(said,     Has.Some.Match(@"^  reply from 127\.0\.0\.1: seq=2 time=\d+ ms"));
                Assert.That(said[^1], Does.StartWith("--- 127.0.0.1: 2 sent, 2 received, 0 % lost; round trip min/avg/max "));
            });

        }

        #endregion

        #region AnIPv6AddressIsPinged_WithAndWithoutBrackets()

        /// <summary>
        /// ::1, and [::1]: the same address.
        /// </summary>
        [Test]
        public async Task AnIPv6AddressIsPinged_WithAndWithoutBrackets()
        {

            RequiresICMP();

            if (!Socket.OSSupportsIPv6)
                Assert.Ignore("This machine has no IPv6.");

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var plain     = await cli.Execute("ping ::1 -c 1");
            var brackets  = await cli.Execute("ping [::1] -c 1");

            Assert.Multiple(() => {
                Assert.That(plain[0],     Is.EqualTo("PING ::1: 1 echo request of 32 bytes"), String.Join(Environment.NewLine, plain));
                Assert.That(plain,        Has.Some.Match(@"^  reply from ::1: seq=1 time=\d+ ms"));
                Assert.That(brackets[^1], Does.StartWith("--- [::1]: 1 sent, 1 received, 0 % lost"), String.Join(Environment.NewLine, brackets));
            });

        }

        #endregion

        #region AnIPv6AddressWithItsInterface()

        /// <summary>
        /// An IPv6 address with "%" and its interface, by index or by name:
        /// the index becomes its scope. A link-local address without one is
        /// refused with the interfaces to choose from; an interface this
        /// machine does not have, and one after an IPv4 address, as well.
        /// </summary>
        [Test]
        public void AnIPv6AddressWithItsInterface()
        {

            var loopback = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().
                               FirstOrDefault(networkInterface => networkInterface.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback &&
                                                                  networkInterface.Supports(System.Net.NetworkInformation.NetworkInterfaceComponent.IPv6));

            Assert.Multiple(() => {

                Assert.That(WWCPNode.TryParseHostAddress("fe80::1%7",        out var byIndex,   out var problem), Is.True, problem);
                Assert.That(byIndex.ScopeId,                                                     Is.EqualTo(7));

                Assert.That(WWCPNode.TryParseHostAddress("[fe80::1%7]",      out var bracketed, out problem),     Is.True, problem);
                Assert.That(bracketed.ScopeId,                                                   Is.EqualTo(7));

                if (loopback is not null)
                {
                    Assert.That(WWCPNode.TryParseHostAddress($"fe80::1%{loopback.Name}", out var byName, out problem), Is.True, problem);
                    Assert.That(byName.ScopeId, Is.EqualTo(loopback.GetIPProperties().GetIPv6Properties().Index));
                }

                Assert.That(WWCPNode.TryParseHostAddress("fe80::1",          out _, out problem), Is.False);
                Assert.That(problem,                                                         Does.Contain("link-local").And.Contain("%<interface>"));

                Assert.That(WWCPNode.TryParseHostAddress("fe80::1%no-such-interface", out _, out problem), Is.False);
                Assert.That(problem,                                                         Does.Contain("no network interface 'no-such-interface'"));

                Assert.That(WWCPNode.TryParseHostAddress("192.168.1.1%eth0", out _, out problem), Is.False);
                Assert.That(problem,                                                         Does.Contain("only an IPv6 address"));

                Assert.That(WWCPNode.TryParseHostAddress("fe80::1%",         out _, out problem), Is.False);
                Assert.That(problem,                                                         Does.Contain("no interface after it"));

                // Names, not addresses: nothing to complain about.
                Assert.That(WWCPNode.TryParseHostAddress("lc1.local",        out _, out problem), Is.False);
                Assert.That(problem,                                                         Is.Null);
                Assert.That(WWCPNode.TryParseHostAddress("1234",             out _, out problem), Is.False);
                Assert.That(problem,                                                         Is.Null);

            });

        }

        #endregion

        #region ALinkLocalAddressWithoutItsInterfaceIsNotPinged()

        /// <summary>
        /// "ping fe80::1": said why not, and nothing sent.
        /// </summary>
        [Test]
        public async Task ALinkLocalAddressWithoutItsInterfaceIsNotPinged()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("ping fe80::1 -c 1");

            Assert.That(said, Has.Length.EqualTo(1));
            Assert.That(said[0], Does.StartWith("ping fe80::1: 'fe80::1' is a link-local address, which needs its interface"));

        }

        #endregion

        #region ANameIsResolvedByTheNodesNameServers()

        /// <summary>
        /// host.example.test, which only the name server of this test knows -
        /// so it was the node that resolved it, not the operating system.
        /// </summary>
        [Test]
        public async Task ANameIsResolvedByTheNodesNameServers()
        {

            RequiresICMP();

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("ping host.example.test -c 1");

            Assert.Multiple(() => {
                Assert.That(said[0],  Is.EqualTo("PING host.example.test (127.0.0.1, by DNS): 1 echo request of 32 bytes"), String.Join(Environment.NewLine, said));
                Assert.That(said,     Has.Some.Match(@"^  reply from 127\.0\.0\.1: seq=1 "));
                Assert.That(said[^1], Does.StartWith("--- host.example.test: 1 sent, 1 received, 0 % lost"));
            });

        }

        #endregion

        #region IPv6FirstUnless4IsSaid()

        /// <summary>
        /// A name with both: the address of IPv6 is pinged, and the other one
        /// said; with -4 the one of IPv4, and -6 on a name with IPv4 alone says
        /// there is none.
        /// </summary>
        [Test]
        public async Task IPv6FirstUnless4IsSaid()
        {

            if (!Socket.OSSupportsIPv6)
                Assert.Ignore("This machine has no IPv6.");

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var both   = await cli.Execute("ping both.example.test -c 1");
            var four   = await cli.Execute("ping both.example.test -c 1 -4");
            var none   = await cli.Execute("ping host.example.test -c 1 -6");

            Assert.Multiple(() => {
                Assert.That(both[0],  Is.EqualTo("PING both.example.test (::1, by DNS): 1 echo request of 32 bytes"), String.Join(Environment.NewLine, both));
                Assert.That(both[1],  Is.EqualTo("  both.example.test is also 127.0.0.1"));
                Assert.That(four[0],  Is.EqualTo("PING both.example.test (127.0.0.1, by DNS): 1 echo request of 32 bytes"), String.Join(Environment.NewLine, four));
                Assert.That(none,     Has.Length.EqualTo(1));
                Assert.That(none[0],  Does.Contain("is an address of IPv6"));
            });

        }

        #endregion

        #region ANameNobodyHasIsSaid()

        /// <summary>
        /// A name the zone does not have: said, and nothing sent.
        /// </summary>
        [Test]
        public async Task ANameNobodyHasIsSaid()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("ping missing.example.test -c 1");

            Assert.That(said, Has.Length.EqualTo(1));
            Assert.That(said[0], Is.EqualTo("ping missing.example.test: 'missing.example.test' has no address (NXDomain)."));

        }

        #endregion

        #region ALocalNameWithMulticastDNSSwitchedOff()

        /// <summary>
        /// "ping lc1.local" on a node that does not ask Multicast DNS - the
        /// default: said why, which setting it is, and no socket made.
        /// </summary>
        [Test]
        public async Task ALocalNameWithMulticastDNSSwitchedOff()
        {

            using var cli = new NodeCLI(Node("""{ "servers": [ { "address": "127.0.0.1", "port": 53, "transport": "TCP" } ] }"""));

            await Answering("lc1.local.", "127.0.0.1");

            var said = await cli.Execute("ping lc1.local -c 1");

            Assert.Multiple(() => {
                Assert.That(node!.MulticastDNSEnabled,  Is.False);
                Assert.That(said,                       Has.Length.EqualTo(1));
                Assert.That(said[0],                    Is.EqualTo("ping lc1.local: 'lc1.local' is a name of Multicast DNS, which is switched off on this " +
                                                                   $"{node.Kind.Name} (dns.multicast.enabled)."));
                Assert.That(transportOptions,           Is.Empty);
            });

        }

        #endregion

        #region ALocalNameIsResolvedByMulticastDNS()

        /// <summary>
        /// "ping lc1.local" on a node that asks Multicast DNS on the interfaces
        /// its section names, over IPv4 alone: the responder's address, said
        /// to be found by Multicast DNS, and pinged.
        /// </summary>
        [Test]
        public async Task ALocalNameIsResolvedByMulticastDNS()
        {

            RequiresICMP();

            using var cli = new NodeCLI(NodeWithTheTestsNameServer("""{ "enabled": true, "interfaces": [ "eth-test" ], "ipv6": false }"""));

            await Answering("lc1.local.", "127.0.0.1");

            var said = await cli.Execute("ping lc1.local -c 1");

            Assert.Multiple(() => {
                Assert.That(said[0],                            Is.EqualTo("PING lc1.local (127.0.0.1, by Multicast DNS): 1 echo request of 32 bytes"),
                                                                String.Join(Environment.NewLine, said));
                Assert.That(said,                               Has.Some.Match(@"^  reply from 127\.0\.0\.1: seq=1 "));
                Assert.That(transportOptions,                   Has.Count.EqualTo(1));
                Assert.That(transportOptions[0].InterfaceNames, Is.EqualTo(new[] { "eth-test" }));
                Assert.That(transportOptions[0].EnableIPv4,     Is.True);
                Assert.That(transportOptions[0].EnableIPv6,     Is.False);
            });

        }

        #endregion

        #region MulticastDNSIsSwitchedOnWhileTheNodeRuns()

        /// <summary>
        /// The "dns" section changed while the node runs: "multicast" switched
        /// on - and lc1.local is found; switched off again - and it is not, and
        /// the transport was let go of.
        /// </summary>
        [Test]
        public async Task MulticastDNSIsSwitchedOnWhileTheNodeRuns()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            await Answering("lc1.local.", "127.0.0.1");

            var off = await node!.ResolveHostAsync("lc1.local");

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "multicast": { "enabled": true } }"""), out var problem), Is.True, problem);

            var on  = await node.ResolveHostAsync("lc1.local");

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "multicast": { "enabled": false } }"""), out problem), Is.True, problem);

            var offAgain = await node.ResolveHostAsync("lc1.local");

            Assert.Multiple(() => {
                Assert.That(off.Found,                                                   Is.False);
                Assert.That(on.Found,                                                    Is.True, on.Error);
                Assert.That(on.Via,                                                      Is.EqualTo("Multicast DNS"));
                Assert.That(on.Addresses.Select(address => address.ToString()),          Is.EqualTo(new[] { "127.0.0.1" }));
                Assert.That(offAgain.Found,                                              Is.False);
                Assert.That(offAgain.Error,                                              Does.Contain("switched off"));
                Assert.That(node.DNSConfigurationJSON()["multicast"]?["enabled"]?.Value<Boolean>(), Is.False);
                Assert.That(File.ReadAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName)), Does.Contain("\"multicast\""));
            });

        }

        #endregion

        #region TheNameResolverAsksMulticastDNSForLocalNamesAlone()

        /// <summary>
        /// The node's NameResolver, which every connection it makes is given:
        /// lc1.local by Multicast DNS, host.example.test by the node's name
        /// server - one transport made, for the first, and kept.
        /// </summary>
        [Test]
        public async Task TheNameResolverAsksMulticastDNSForLocalNamesAlone()
        {

            NodeWithTheTestsNameServer("""{ "enabled": true }""");

            await Answering("lc1.local.", "127.0.0.1");

            var local   = await node!.NameResolver.Query(DomainName.Parse("lc1.local."),         [ DNSResourceRecordTypes.A ]);
            var unicast = await node .NameResolver.Query(DomainName.Parse("host.example.test."), [ DNSResourceRecordTypes.A ]);
            var again   = await node .NameResolver.Query(DNSServiceName.Parse("lc1.local."),     [ DNSResourceRecordTypes.A ]);

            Assert.Multiple(() => {
                Assert.That(local.  Answers.OfType<A>().Select(record => record.IPv4Address.ToString()), Is.EqualTo(new[] { "127.0.0.1" }));
                Assert.That(again.  Answers.OfType<A>().Select(record => record.IPv4Address.ToString()), Is.EqualTo(new[] { "127.0.0.1" }));
                Assert.That(unicast.Answers.OfType<A>().Select(record => record.IPv4Address.ToString()), Is.EqualTo(new[] { "127.0.0.1" }));
                Assert.That(unicast.Origin.ToString(),                                                   Does.Contain($"]:{port}").Or.Contain($"127.0.0.1:{port}"));
                Assert.That(transportOptions,                                                            Has.Count.EqualTo(1));
            });

        }

        #endregion

        #region WithMulticastDNSOffALocalNameIsNXDomain()

        /// <summary>
        /// Multicast DNS off: the NameResolver answers lc1.local NXDOMAIN, as
        /// the node's DNS client does for a name under ".local" it may not send
        /// to its servers - and makes no socket.
        /// </summary>
        [Test]
        public async Task WithMulticastDNSOffALocalNameIsNXDomain()
        {

            NodeWithTheTestsNameServer();

            await Answering("lc1.local.", "127.0.0.1");

            var answer = await node!.NameResolver.Query(DomainName.Parse("lc1.local."), [ DNSResourceRecordTypes.A ]);

            Assert.Multiple(() => {
                Assert.That(answer.ResponseCode,  Is.EqualTo(DNSResponseCodes.NameError));
                Assert.That(answer.Answers,       Is.Empty);
                Assert.That(transportOptions,     Is.Empty);
            });

        }

        #endregion

        #region QueryDNSAnswersALocalNameByMulticastDNS()

        /// <summary>
        /// "queryDNS lc1.local A" on the command line: answered by Multicast
        /// DNS, and the answer kept for the DNS page.
        /// </summary>
        [Test]
        public async Task QueryDNSAnswersALocalNameByMulticastDNS()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer("""{ "enabled": true }"""));

            await Answering("lc1.local.", "127.0.0.1");

            var said    = await cli.Execute("queryDNS lc1.local A");
            var answers = node!.DNSConfigurationJSON()["multicast"]?["answers"] as JArray;

            Assert.Multiple(() => {
                Assert.That(said,                                        Has.Some.Match(@"^  lc1\.local\.\s+A\s+\d+\s+127\.0\.0\.1$"), String.Join(Environment.NewLine, said));
                Assert.That(answers,                                     Has.Count.EqualTo(1));
                Assert.That(answers![0]["name"]?.Value<String>(),        Is.EqualTo("lc1.local."));
                Assert.That(answers [0]["addresses"]?.ToObject<String[]>(), Is.EqualTo(new[] { "127.0.0.1" }));
                Assert.That(node.DNSConfigurationJSON()["multicast"]?["asking"]?.Value<Boolean>(), Is.True);
            });

        }

        #endregion

        #region TheConnectionTestFindsALocalHostByMulticastDNS()

        /// <summary>
        /// The test of a connection to ws://lc1.local: the name resolved by
        /// Multicast DNS, as the connection itself would - and with Multicast
        /// DNS off, not resolved, and nothing else asked.
        /// </summary>
        [Test]
        public async Task TheConnectionTestFindsALocalHostByMulticastDNS()
        {

            NodeWithTheTestsNameServer("""{ "enabled": true }""");

            await Answering("lc1.local.", "127.0.0.1");

            var on     = await node!.TestConnection(I18NString.Create("The local controller"), "ws://lc1.local:9/", "CSMS");

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "multicast": { "enabled": false } }"""), out var problem), Is.True, problem);

            var off    = await node.TestConnection(I18NString.Create("The local controller"), "ws://lc1.local:9/", "CSMS");

            static String[] Texts(JObject Result)
                => [.. (Result["steps"] as JArray ?? []).Select(step => step["text"]?.Value<String>() ?? "")];

            Assert.Multiple(() => {
                Assert.That(Texts(on),  Has.Some.EqualTo("'lc1.local' resolves to 127.0.0.1."), String.Join(Environment.NewLine, Texts(on)));
                Assert.That(Texts(off), Has.None.Contains("resolves to"),                        String.Join(Environment.NewLine, Texts(off)));
            });

        }

        #endregion

        #region TheMulticastObjectIsReadAndWritten()

        /// <summary>
        /// "multicast" of a "dns" section: read, written back as it was said,
        /// and refused where it is not an object, has something else than
        /// strings as interfaces, or leaves neither IPv4 nor IPv6.
        /// </summary>
        [Test]
        public void TheMulticastObjectIsReadAndWritten()
        {

            Assert.Multiple(() => {

                Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "multicast": { "enabled": true, "interfaces": [ "eth0", " wlan0 ", "eth0" ], "ipv4": false } }"""),
                                                      out var configuration, out var error), Is.True, error);
                Assert.That(configuration!.Multicast!.Enabled,     Is.True);
                Assert.That(configuration.Multicast.Interfaces,    Is.EqualTo(new[] { "eth0", "wlan0" }));
                Assert.That(configuration.Multicast.IPv4,          Is.False);
                Assert.That(configuration.Multicast.IPv6,          Is.Null);
                Assert.That(configuration.ToJSON()["multicast"]!.ToString(Newtonsoft.Json.Formatting.None),
                                                                   Is.EqualTo("""{"enabled":true,"interfaces":["eth0","wlan0"],"ipv4":false}"""));

                Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "enabled": true }"""), out configuration, out error), Is.True, error);
                Assert.That(configuration!.Multicast,               Is.Null);
                Assert.That(configuration.ToJSON().ContainsKey("multicast"), Is.False);

                Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "multicast": true }"""), out _, out error), Is.False);
                Assert.That(error, Is.EqualTo("'dns.multicast' must be an object."));

                Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "multicast": { "interfaces": [ 1 ] } }"""), out _, out error), Is.False);
                Assert.That(error, Does.Contain("'dns.multicast.interfaces'"));

                Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "multicast": { "ipv4": false, "ipv6": false } }"""), out _, out error), Is.False);
                Assert.That(error, Does.Contain("must keep IPv4 or IPv6"));

            });

        }

        #endregion

        #region WithoutTheRightToSendICMPItIsSaid()

        /// <summary>
        /// On a machine that does not let this user send ICMP: said once, with
        /// where the right comes from, and not tried again - rather than "no
        /// reply", which would blame the host.
        /// </summary>
        [Test]
        public async Task WithoutTheRightToSendICMPItIsSaid()
        {

            if (icmpAllowed)
                Assert.Ignore("This machine lets this user send ICMP.");

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("ping 127.0.0.1 -c 3 -i 0.2");

            Assert.That(said, Is.EqualTo(new[] {
                                  "PING 127.0.0.1: 3 echo requests of 32 bytes",
                                  $"  seq=1: not sent: {PingCommand.GaveUpAtOnce}",
                                  "--- 127.0.0.1: 1 sent, 0 received, 100 % lost"
                              }));

        }

        #endregion

        #region TheArgumentsAreRead()

        /// <summary>
        /// The host and the options in any order; what is wrong with them said
        /// before anything is asked of anybody.
        /// </summary>
        [Test]
        public async Task TheArgumentsAreRead()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            Assert.Multiple(() => {

                Assert.That(PingCommand.TryReadArguments([ "ping", "-c", "3", "lc1.local", "-4" ], out var host, out var count, out _, out var family, out var error), Is.True, error);
                Assert.That(host,   Is.EqualTo("lc1.local"));
                Assert.That(count,  Is.EqualTo(3));
                Assert.That(family, Is.EqualTo(AddressFamily.InterNetwork));

            });

            var said = new List<String>();

            foreach (var line in new[] { "ping", "ping -c 2", "ping a.test b.test", "ping a.test -c 0", "ping a.test -c 101",
                                         "ping a.test -i 0.1", "ping a.test -x", "ping a.test -4 -6", "ping 127.0.0.1 -6" })
                said.Add((await cli.Execute(line))[0]);

            Assert.Multiple(() => {

                Assert.That(said[0],                         Does.StartWith("Usage: ping <host>"));
                Assert.That(said[1],                    Is.EqualTo("Name the host to ping."));
                Assert.That(said[2],           Is.EqualTo("Ping one host at a time, not 'a.test' and 'b.test'."));
                Assert.That(said[3],             Is.EqualTo("-c takes a count from 1 to 100."));
                Assert.That(said[4],           Is.EqualTo("-c takes a count from 1 to 100."));
                Assert.That(said[5],           Does.StartWith("-i takes the seconds"));
                Assert.That(said[6],               Is.EqualTo("'-x' is no option of ping; there are -c, -i, -4 and -6."));
                Assert.That(said[7],            Is.EqualTo("Say -4 or -6, not both."));
                Assert.That(said[8],            Is.EqualTo("'127.0.0.1' is an address of IPv4, and -6 was said."));

            });

        }

        #endregion

    }

}
