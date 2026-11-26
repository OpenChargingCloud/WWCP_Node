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

using NUnit.Framework;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A node answering for its own name by Multicast DNS (mDNS-Concept.md,
    /// B.3): "dns": { "multicast": { "responder": { "enabled", "hostName" } } },
    /// separately from asking (Q1) - found by a client and by another node, not
    /// before it starts, said and not renamed where another host has the name
    /// (Q3), anew after a change of the name, and a goodbye when it stops.
    /// </summary>
    /// <remarks>
    /// On Hermod's network in memory: nothing is bound to port 5353, and every
    /// transport has an address of its own.
    /// </remarks>
    [NonParallelizable]
    public class MulticastDNSResponderTests
    {

        #region Data

        private String                        directory  = "";
        private InMemoryMulticastDNSNetwork   network    = null!;
        private readonly List<WWCPNode>       nodes      = [];
        private readonly List<IAsyncDisposable> others   = [];
        private readonly List<UDPMulticastDNSTransportOptions> transportOptions = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-mdns-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            network   = new InMemoryMulticastDNSNetwork();
            nodes.Clear();
            others.Clear();
            transportOptions.Clear();

        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var node in nodes)
                await node.DisposeAsync();

            foreach (var other in others)
                await other.DisposeAsync();

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

        #region (helper) Node(Name, Address, Multicast)

        /// <summary>
        /// A node with the given "multicast" object, whose transport of Multicast
        /// DNS has the given address on the network of this test, and whose
        /// responder probes fast.
        /// </summary>
        private WWCPNode Node(String Name, String Address, String Multicast)
        {

            var home           = Path.Combine(directory, Name);
            Directory.CreateDirectory(home);

            var configuration  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "dns": { "multicast": {{Multicast}} }, "nts": { "groups": { "legal": { "enabled": false } } } }""");

            var node = new WWCPNode(HTTPPort:          TestPorts.Free(),
                                    AccountsPath:      Path.Combine(home, "accounts"),
                                    ConfigFile:        new WWCPConfigFile(configuration),
                                    CertificatesPath:  Path.Combine(home, "certificates"),
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    SSH:               new SSHSettings(OnByDefault: false));

            node.MulticastDNSTransportFactory  = options => {
                                                     lock (transportOptions)
                                                         transportOptions.Add(options);
                                                     return network.CreateTransport(IPv4Address.Parse(Address));
                                                 };

            node.MulticastDNSResponderOptions  = FastResponder();

            nodes.Add(node);

            return node;

        }

        private static MulticastDNSResponderOptions FastResponder()

            => new () {
                   ProbeInterval           = TimeSpan.FromMilliseconds(20),
                   MaxInitialProbeDelay    = TimeSpan.Zero,
                   AnnouncementInterval    = TimeSpan.FromMilliseconds(20),
                   MinSharedResponseDelay  = TimeSpan.Zero,
                   MaxSharedResponseDelay  = TimeSpan.FromMilliseconds(1)
               };

        /// <summary>
        /// A client of Multicast DNS on the network of this test, as any other
        /// host on the link is.
        /// </summary>
        private async Task<MulticastDNSClient> Client(String Address = "10.0.0.50")
        {

            var transport  = network.CreateTransport(IPv4Address.Parse(Address));
            var client     = new MulticastDNSClient(transport, new MulticastDNSClientOptions {
                                                                   QueryTimeout            = TimeSpan.FromMilliseconds(500),
                                                                   ResponseGracePeriod     = TimeSpan.FromMilliseconds(20),
                                                                   RetransmissionInterval  = TimeSpan.FromMilliseconds(100),
                                                                   CacheSweepInterval      = TimeSpan.FromMilliseconds(50),
                                                                   UseCache                = false
                                                               });

            await client.StartAsync();

            others.Add(client);
            others.Add(transport);

            return client;

        }

        private static async Task<String[]> AddressesOf(MulticastDNSClient Client, String Name)
        {
            var answer = await Client.Query(DomainName.Parse(Name), [ DNSResourceRecordTypes.A ]);
            return [.. answer.Answers.OfType<A>().Select(record => record.IPv4Address.ToString())];
        }

        /// <summary>
        /// Wait until the responder of the given node is in the given state, or
        /// three seconds passed: what the state was then.
        /// </summary>
        private static async Task<String?> ResponderState(WWCPNode Node, String Awaited)
        {

            var until = DateTime.UtcNow.AddSeconds(3);

            String? state;

            do
            {
                state = Node.DNSConfigurationJSON()["multicast"]?["responder"]?["state"]?.Value<String>();
                if (state == Awaited)
                    return state;
                await Task.Delay(20);
            }
            while (DateTime.UtcNow < until);

            return state;

        }

        #endregion


        #region AStartedNodeAnswersForItsName()

        /// <summary>
        /// A node with its responder on, started: probed for lc1.local, and
        /// published with the address of its transport - found by another host
        /// on the link, and by another node through its NameResolver.
        /// </summary>
        [Test]
        public async Task AStartedNodeAnswersForItsName()
        {

            var lc       = Node("lc",   "10.0.0.2", """{ "responder": { "enabled": true, "hostName": "lc1" } }""");
            var station  = Node("cs",   "10.0.0.3", """{ "enabled": true }""");

            await lc.Start();

            var state    = await ResponderState(lc, "Published");
            var client   = await Client();
            var found    = await AddressesOf(client, "lc1.local.");
            var resolved = await station.ResolveHostAsync("lc1.local");
            var json     = lc.DNSConfigurationJSON()["multicast"]?["responder"];

            Assert.Multiple(() => {
                Assert.That(state,                                                     Is.EqualTo("Published"));
                Assert.That(found,                                                     Is.EqualTo(new[] { "10.0.0.2" }));
                Assert.That(resolved.Addresses.Select(address => address.ToString()), Is.EqualTo(new[] { "10.0.0.2" }), resolved.Error);
                Assert.That(resolved.Via,                                              Is.EqualTo("Multicast DNS"));
                Assert.That(json?["name"]?.Value<String>(),                            Is.EqualTo("lc1.local"));
                Assert.That(json?["addresses"]?.ToObject<String[]>(),                  Is.EqualTo(new[] { "10.0.0.2" }));
                Assert.That(lc.MulticastDNSEnabled,                                    Is.False, "Answering does not switch asking on (Q1).");
            });

        }

        #endregion

        #region NothingIsAnsweredBeforeTheStartOrWithTheResponderOff()

        /// <summary>
        /// A node whose responder is on and that is not started, and a started
        /// node whose responder is off: neither makes a transport, and nobody
        /// gets an answer for their names.
        /// </summary>
        [Test]
        public async Task NothingIsAnsweredBeforeTheStartOrWithTheResponderOff()
        {

            Node("lc", "10.0.0.2", """{ "responder": { "enabled": true, "hostName": "lc1" } }""");

            var off  = Node("off", "10.0.0.4", """{ "responder": { "enabled": false, "hostName": "lc2" } }""");

            await off.Start();
            await Task.Delay(100);

            var client = await Client();
            var lc1    = await AddressesOf(client, "lc1.local.");
            var lc2    = await AddressesOf(client, "lc2.local.");

            Assert.Multiple(() => {
                Assert.That(lc1,                                      Is.Empty);
                Assert.That(lc2,                                      Is.Empty);
                Assert.That(transportOptions,                         Is.Empty);
                Assert.That(off.DNSConfigurationJSON()["multicast"]?["responder"]?["state"]?.Value<String>(), Is.EqualTo("off"));
            });

        }

        #endregion

        #region ANameAnotherHostHasIsSaidAndKept()

        /// <summary>
        /// lc1.local answered by another host already: the node's probe finds
        /// it, says so in its state and its log, and does not rename itself.
        /// </summary>
        [Test]
        public async Task ANameAnotherHostHasIsSaidAndKept()
        {

            var otherTransport  = network.CreateTransport(IPv4Address.Parse("10.0.0.9"));
            var other           = new MulticastDNSResponder(otherTransport, FastResponder());

            others.Add(other);
            others.Add(otherTransport);

            await other.StartAsync();
            await other.PublishAsync([ new A(DomainName.Parse("lc1.local."), DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("10.0.0.9")) ],
                                     Probe: false);

            var lc     = Node("lc", "10.0.0.2", """{ "responder": { "enabled": true, "hostName": "lc1" } }""");
            var said   = new List<String>();

            lc.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

            await lc.Start();

            var state  = await ResponderState(lc, "Conflict");
            var json   = lc.DNSConfigurationJSON()["multicast"]?["responder"];

            Assert.Multiple(() => {
                Assert.That(state,                                 Is.EqualTo("Conflict"));
                Assert.That(json?["problem"]?.Value<String>(),     Does.Contain("answers for lc1.local as well").And.Contain("does not rename itself"));
                Assert.That(json?["hostName"]?.Value<String>(),    Is.EqualTo("lc1"));
                lock (said)
                    Assert.That(said,                              Has.Some.Contains("answers for lc1.local as well"));
            });

        }

        #endregion

        #region ANewHostNameIsAnsweredForAtOnce()

        /// <summary>
        /// The host name changed while the node runs: the old name withdrawn,
        /// the new one answered.
        /// </summary>
        [Test]
        public async Task ANewHostNameIsAnsweredForAtOnce()
        {

            var lc      = Node("lc", "10.0.0.2", """{ "responder": { "enabled": true, "hostName": "lc1" } }""");

            await lc.Start();
            Assert.That(await ResponderState(lc, "Published"), Is.EqualTo("Published"));

            Assert.That(lc.TryUpdateDNSConfiguration(JObject.Parse("""{ "multicast": { "responder": { "hostName": "lc2" } } }"""), out var problem), Is.True, problem);

            var until = DateTime.UtcNow.AddSeconds(3);
            while (lc.DNSConfigurationJSON()["multicast"]?["responder"]?["name"]?.Value<String>() != "lc2.local" && DateTime.UtcNow < until)
                await Task.Delay(20);

            var state   = await ResponderState(lc, "Published");
            var client  = await Client();
            var lc2     = await AddressesOf(client, "lc2.local.");
            var lc1     = await AddressesOf(client, "lc1.local.");

            Assert.Multiple(() => {
                Assert.That(state,  Is.EqualTo("Published"));
                Assert.That(lc2,    Is.EqualTo(new[] { "10.0.0.2" }));
                Assert.That(lc1,    Is.Empty);
            });

        }

        #endregion

        #region AStoppedNodeSaysGoodbye()

        /// <summary>
        /// The node stops: its name goes from the caches of the link with a
        /// goodbye, a record with a time to live of zero (RFC 6762 section 10.1).
        /// </summary>
        [Test]
        public async Task AStoppedNodeSaysGoodbye()
        {

            var lc        = Node("lc", "10.0.0.2", """{ "responder": { "enabled": true, "hostName": "lc1" } }""");
            var goodbyes  = 0;

            network.OnDatagramSent += (timestamp, sender, payload, destination) => {
                if (MulticastDNSMessage.TryParse(payload, out var message, out _) &&
                    message.Answers.Any(answer => answer.Record.DomainName.FullName.StartsWith("lc1.local", StringComparison.OrdinalIgnoreCase) &&
                                                  answer.Record.TimeToLive == TimeSpan.Zero))
                    Interlocked.Increment(ref goodbyes);
                return Task.CompletedTask;
            };

            await lc.Start();
            Assert.That(await ResponderState(lc, "Published"), Is.EqualTo("Published"));

            await lc.Stop();

            Assert.Multiple(() => {
                Assert.That(goodbyes, Is.GreaterThan(0));
                Assert.That(lc.DNSConfigurationJSON()["multicast"]?["responder"]?["state"]?.Value<String>(), Is.EqualTo("off"));
            });

        }

        #endregion

        #region AServiceIsAnnouncedAndFound()

        /// <summary>
        /// DNS-SD (mDNS-Concept.md, B.6): a service announced by a node that
        /// answers for its name is found by another node - its host, its port,
        /// its TXT strings and the URL a connection is made with -; withdrawn,
        /// it is not found any more; and a node with Multicast DNS off finds
        /// nothing, and asks nothing.
        /// </summary>
        [Test]
        public async Task AServiceIsAnnouncedAndFound()
        {

            var lc       = Node("lc", "10.0.0.2", """{ "responder": { "enabled": true, "hostName": "lc1" } }""");
            var station  = Node("cs", "10.0.0.3", """{ "enabled": true }""");
            var off      = Node("off", "10.0.0.4", """{ "enabled": false }""");

            lc.AnnounceService(new MulticastDNSService("_ocpp._tcp", "lc1", IPPort.Parse(8443), [ "tls=1", "path=/", "id=lc1" ]));

            await lc.Start();
            Assert.That(await ResponderState(lc, "Published"), Is.EqualTo("Published"));

            var found    = await station.DiscoverAsync("_ocpp._tcp", TimeSpan.FromSeconds(2));
            var nothing  = await off.    DiscoverAsync("_ocpp._tcp", TimeSpan.FromMilliseconds(500));

            Assert.Multiple(() => {
                Assert.That(found,                         Has.Count.EqualTo(1));
                Assert.That(found[0].Instance,             Is.EqualTo("lc1"));
                Assert.That(found[0].Host,                 Is.EqualTo("lc1.local."));
                Assert.That(found[0].Port,                 Is.EqualTo(8443));
                Assert.That(found[0]["tls"],               Is.EqualTo("1"));
                Assert.That(found[0].URL,                  Is.EqualTo("wss://lc1.local:8443/"));
                Assert.That(nothing,                       Is.Empty);
                Assert.That(transportOptions,              Has.Count.EqualTo(2), "The node with Multicast DNS off made a transport.");
            });

            Assert.That(lc.WithdrawService("_ocpp._tcp", "lc1"), Is.True);

            // Published anew without it: its goodbye said, and the name announced again.
            var until = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < until &&
                   ((lc.DNSConfigurationJSON()["multicast"]?["responder"]?["services"] as JArray)?.Count > 0 ||
                    lc.DNSConfigurationJSON()["multicast"]?["responder"]?["state"]?.Value<String>() != "Published"))
                await Task.Delay(20);

            var gone = await station.DiscoverAsync("_ocpp._tcp", TimeSpan.FromSeconds(2));

            Assert.That(gone, Is.Empty, "A service withdrawn was still found.");

        }

        #endregion

        #region OverRealUDP()

        /// <summary>
        /// Two nodes on this machine with Hermod's UDP transport on port 5353,
        /// as they run: one answers for a name of its own, the other one finds
        /// it - beside whatever responder the operating system runs there
        /// (Q10). Only where asked for: it sends to the multicast group of
        /// every interface that can multicast.
        /// </summary>
        [Test, Explicit("Real UDP on port 5353 of every interface that can multicast.")]
        public async Task OverRealUDP()
        {

            var name     = "wwcp-test-" + Guid.NewGuid().ToString("N")[..8];
            var lc       = Node("lc", "10.0.0.2", $$"""{ "ipv6": false, "responder": { "enabled": true, "hostName": "{{name}}" } }""");
            var station  = Node("cs", "10.0.0.3", """{ "enabled": true, "ipv6": false }""");

            lc.     MulticastDNSTransportFactory = options => new UDPMulticastDNSTransport(options);
            station.MulticastDNSTransportFactory = options => new UDPMulticastDNSTransport(options);

            await lc.Start();

            var state    = await ResponderState(lc, "Published");
            var resolved = await station.ResolveHostAsync($"{name}.local");
            var json     = lc.DNSConfigurationJSON()["multicast"]?["responder"];

            var published = json?["addresses"]?.ToString(Newtonsoft.Json.Formatting.None);
            var addresses = String.Join(", ", resolved.Addresses);

            TestContext.Out.WriteLine($"{name}.local: state {state}, published {published}, resolved {addresses} {resolved.Error}");

            Assert.Multiple(() => {
                Assert.That(state,           Is.EqualTo("Published"), json?["problem"]?.Value<String>());
                Assert.That(resolved.Found,  Is.True, resolved.Error);
                Assert.That(resolved.Addresses.Select(address => address.ToString()),
                            Is.SubsetOf(json?["addresses"]?.ToObject<String[]>() ?? []));
            });

        }

        #endregion

        #region TheResponderObjectIsReadAndWritten()

        /// <summary>
        /// "responder": { "enabled", "hostName" }: read, written back, the name
        /// one label of DNS in lower case - refused with ".local", with what a
        /// label may not have, and too long. The machine's name made a label
        /// where the file says none.
        /// </summary>
        [Test]
        public void TheResponderObjectIsReadAndWritten()
        {

            Assert.Multiple(() => {

                Assert.That(MulticastDNSConfiguration.TryParse(JObject.Parse("""{ "responder": { "enabled": true, "hostName": "LC-1" } }"""), out var configuration, out var error), Is.True, error);
                Assert.That(configuration!.ResponderEnabled,  Is.True);
                Assert.That(configuration.HostName,           Is.EqualTo("lc-1"));
                Assert.That(configuration.ToJSON().ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("""{"responder":{"enabled":true,"hostName":"lc-1"}}"""));

                Assert.That(MulticastDNSConfiguration.TryParse(JObject.Parse("""{ "responder": { "hostName": "lc1.local" } }"""), out _, out error), Is.False);
                Assert.That(error, Is.EqualTo("'dns.multicast.responder.hostName' is the name without '.local': 'lc1'."));

                Assert.That(MulticastDNSConfiguration.TryParse(JObject.Parse("""{ "responder": { "hostName": "lc_1" } }"""), out _, out error), Is.False);
                Assert.That(error, Does.Contain("must be one label of DNS"));

                Assert.That(MulticastDNSConfiguration.TryParse(JObject.Parse("""{ "responder": { "hostName": "-lc" } }"""), out _, out error), Is.False);
                Assert.That(MulticastDNSConfiguration.TryParse(JObject.Parse($$"""{ "responder": { "hostName": "{{new String('a', 64)}}" } }"""), out _, out error), Is.False);

                Assert.That(MulticastDNSConfiguration.TryParse(JObject.Parse("""{ "responder": true }"""), out _, out error), Is.False);
                Assert.That(error, Is.EqualTo("'dns.multicast.responder' must be an object."));

                Assert.That(MulticastDNSConfiguration.TryParseHostName(MulticastDNSConfiguration.DefaultHostName(), out _, out error), Is.True, error);

            });

        }

        #endregion

    }

}
