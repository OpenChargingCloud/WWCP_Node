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

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A node that asks only the name servers reached over TLS or HTTPS:
    /// those in clear text it has stay in the file and are not asked, and
    /// none comes that it does not have (Secure DNS paper, sections 2.4 and
    /// 3.1.1, T12).
    /// </summary>
    /// <remarks>
    /// All servers are asked at once and the first answer wins, so beside one
    /// reached over TLS, one asked over UDP is where whoever is on the path
    /// answers first. Nothing here leaves this machine: the addresses are of
    /// the documentation ranges, never asked, or sockets on the loopback
    /// address.
    /// </remarks>
    public class EncryptedOnlyTests
    {

        #region Data

        private const String InClearText  = """{ "id": "plain", "address": "192.0.2.1", "transport": "UDP" }""";
        private const String Encrypted    = """{ "id": "safe",  "address": "192.0.2.2", "transport": "TLS" }""";

        private String directory = "";

        private readonly List<IDisposable> nameServers = [];

        private String ConfigurationPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        private JObject OnDisk
            => JObject.Parse(File.ReadAllText(ConfigurationPath));

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-dns-encrypted-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            foreach (var socket in nameServers)
                socket.Dispose();

            nameServers.Clear();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helper) Node(DNS, DNSClient = null)

        /// <summary>
        /// A node with the given "dns" section, and no time server to ask.
        /// </summary>
        private WWCPNode Node(String      DNS,
                              DNSClient?  DNSClient = null)
        {

            File.WriteAllText(ConfigurationPath, $$"""{ "dns": {{DNS}}, "nts": { "groups": { "legal": { "enabled": false } } } }""");

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       DNSClient:         DNSClient,
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Asked(Node)

        /// <summary>
        /// The servers the node's DNS client asks, as the log names them.
        /// </summary>
        private static String[] Asked(WWCPNode Node)

            => [.. Node.DNSClient.DNSServers.Select(server => server.ToString())];

        #endregion

        #region (helper) SilentNameServer(out Port), QuestionsAsked(NameServer)

        /// <summary>
        /// A name server that takes every question over UDP and answers none.
        /// </summary>
        private UdpClient SilentNameServer(out UInt16 Port)
        {

            var socket = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            nameServers.Add(socket);

            Port = (UInt16) ((IPEndPoint) socket.Client.LocalEndPoint!).Port;

            return socket;

        }

        /// <summary>
        /// How many questions a silent name server was sent, read until none
        /// has come for a quarter of a second.
        /// </summary>
        private static async Task<Int32> QuestionsAsked(UdpClient NameServer)
        {

            var asked = 0;

            while (true)
            {

                using var quiet = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

                try
                {
                    await NameServer.ReceiveAsync(quiet.Token);
                    asked++;
                }
                catch (OperationCanceledException)
                {
                    return asked;
                }

            }

        }

        #endregion


        #region TheFileSaysWhetherOnlyEncryptedServersAreAsked()

        /// <summary>
        /// "encryptedOnly" is read and written as the section's other switches
        /// are: left out, it is not said; anything but true or false is refused.
        /// </summary>
        [Test]
        public void TheFileSaysWhetherOnlyEncryptedServersAreAsked()
        {

            Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "encryptedOnly": true }"""), out var said, out var error), Is.True, error);
            Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ }"""),                        out var none, out error),      Is.True, error);

            Assert.Multiple(() => {
                Assert.That(said!.EncryptedOnly,                       Is.True);
                Assert.That(said. ToJSON().Value<Boolean>("encryptedOnly"),  Is.True);
                Assert.That(none!.EncryptedOnly,                       Is.Null);
                Assert.That(none. ToJSON().ContainsKey("encryptedOnly"),     Is.False);
                Assert.That(DNSConfiguration.TryParse(JObject.Parse("""{ "encryptedOnly": "yes" }"""), out _, out error), Is.False);
                Assert.That(error,                                     Does.Contain("encryptedOnly"));
            });

        }

        #endregion

        #region AServerInClearTextIsNotAsked()

        /// <summary>
        /// A node whose file says so gives its DNS client the encrypted
        /// servers alone - and still shows the other one, which it keeps.
        /// </summary>
        [Test]
        public async Task AServerInClearTextIsNotAsked()
        {

            await using var node = Node($$"""{ "servers": [ {{InClearText}}, {{Encrypted}} ], "encryptedOnly": true }""");

            var shown = node.DNSConfigurationJSON();

            Assert.Multiple(() => {
                Assert.That(Asked(node),                                                  Is.EqualTo(new[] { "tls://192.0.2.2:853" }));
                Assert.That(node.DNSEncryptedOnly,                                        Is.True);
                Assert.That(shown["settings"]!.Value<Boolean>("encryptedOnly"),           Is.True);
                Assert.That(shown["servers"]!.Select(server => server.Value<String>("id")),  Is.EqualTo(new[] { "plain", "safe" }));
            });

        }

        #endregion

        #region SwitchedOnTheServersInClearTextStayAndAreAskedAgainWhenItIsSwitchedOff()

        /// <summary>
        /// Switched on later, the server in clear text stays in the file and
        /// leaves the client, and the change line says so; switched off, it is
        /// asked again.
        /// </summary>
        [Test]
        public async Task SwitchedOnTheServersInClearTextStayAndAreAskedAgainWhenItIsSwitchedOff()
        {

            await using var node = Node($$"""{ "servers": [ {{InClearText}}, {{Encrypted}} ] }""");

            var before = node.Log.LastId;
            var told   = new List<IReadOnlyList<String>>();

            node.OnDNSConfigurationChanged += (changes, origin) => {
                lock (told)
                    told.Add(changes);
            };

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "encryptedOnly": true }"""), out var error), Is.True, error);

            var askedOn = Asked(node);
            var inFile  = OnDisk["dns"]!;

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "encryptedOnly": false }"""), out error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(askedOn,                                                         Is.EqualTo(new[] { "tls://192.0.2.2:853" }));
                Assert.That(inFile.Value<Boolean>("encryptedOnly"),                          Is.True);
                Assert.That(inFile["servers"]!.Select(server => server.Value<String>("id")),  Is.EqualTo(new[] { "plain", "safe" }));
                Assert.That(told.Select(changes => String.Join(", ", changes)),              Is.EqualTo(new[] {
                                                                                                 "encrypted only = True, not asking udp://192.0.2.1:53",
                                                                                                 "encrypted only = False"
                                                                                             }));
                Assert.That(Asked(node),                                                     Is.EquivalentTo(new[] { "udp://192.0.2.1:53", "tls://192.0.2.2:853" }));
                Assert.That(node.Log.Recent(100, before, "dns").Select(entry => entry.Message),
                            Has.Some.Contains("asked in clear text beside name servers reached over TLS or HTTPS"),
                            "switched off again, the list mixes the two, and that is warned about");
            });

        }

        #endregion

        #region AServerInClearTextItHasMayBeSentBackWithTheRest()

        /// <summary>
        /// A page saving its settings sends the list back, the server in clear
        /// text with it - one the node has, and the save is not refused for it,
        /// whatever it is waited for now.
        /// </summary>
        [Test]
        public async Task AServerInClearTextItHasMayBeSentBackWithTheRest()
        {

            await using var node = Node($$"""{ "servers": [ {{InClearText}}, {{Encrypted}} ], "encryptedOnly": true }""");

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""
                            { "servers": [ { "id": "plain", "address": "192.0.2.1", "transport": "UDP", "queryTimeoutSeconds": 2 },
                                           { "id": "safe",  "address": "192.0.2.2", "transport": "TLS" } ],
                              "useCache": false }
                            """), out var error),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(node.DNSClient.UseCache,  Is.False);
                Assert.That(Asked(node),              Is.EqualTo(new[] { "tls://192.0.2.2:853" }));
            });

        }

        #endregion

        #region AServerInClearTextItDoesNotHaveIsRefused(Servers, Index, Transport)

        /// <summary>
        /// One it does not have - a new one, or one whose address, port or
        /// transport changed - is refused, with its entry named, and nothing
        /// is changed.
        /// </summary>
        [TestCase("""{ "id": "plain", "address": "192.0.2.1", "transport": "UDP" }, { "id": "safe", "address": "192.0.2.2", "transport": "TLS" }, { "id": "new", "address": "192.0.2.3", "transport": "UDP" }""", 2, "UDP", TestName = "a new one")]
        [TestCase("""{ "id": "plain", "address": "192.0.2.9", "transport": "UDP" }, { "id": "safe", "address": "192.0.2.2", "transport": "TLS" }""",                                                             0, "UDP", TestName = "another address")]
        [TestCase("""{ "id": "plain", "address": "192.0.2.1", "port": 5353, "transport": "UDP" }, { "id": "safe", "address": "192.0.2.2", "transport": "TLS" }""",                                               0, "UDP", TestName = "another port")]
        [TestCase("""{ "id": "plain", "address": "192.0.2.1", "transport": "UDP" }, { "id": "safe", "address": "192.0.2.2", "transport": "TCP" }""",                                                             1, "TCP", TestName = "an encrypted one moved to TCP")]
        public async Task AServerInClearTextItDoesNotHaveIsRefused(String  Servers,
                                                                   Int32   Index,
                                                                   String  Transport)
        {

            await using var node = Node($$"""{ "servers": [ {{InClearText}}, {{Encrypted}} ], "encryptedOnly": true }""");

            var before = File.ReadAllText(ConfigurationPath);

            Assert.Multiple(() => {
                Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""{ "servers": [ {{Servers}} ] }"""), out var error), Is.False);
                Assert.That(error,                                Does.StartWith($"'dns.servers[{Index}]' would be asked over {Transport}, in clear text"));
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before));
                Assert.That(Asked(node),                          Is.EqualTo(new[] { "tls://192.0.2.2:853" }));
            });

        }

        #endregion

        #region SwitchedOnWithANewServerInClearTextIsRefusedToo()

        /// <summary>
        /// The same where the change switches it on: what is refused is the
        /// server that comes, whenever only encrypted ones are asked after it.
        /// </summary>
        [Test]
        public async Task SwitchedOnWithANewServerInClearTextIsRefusedToo()
        {

            await using var node = Node($$"""{ "servers": [ {{Encrypted}} ] }""");

            Assert.Multiple(() => {
                Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""{ "servers": [ {{Encrypted}}, {{InClearText}} ], "encryptedOnly": true }"""), out var error), Is.False);
                Assert.That(error,                  Does.StartWith("'dns.servers[1]' would be asked over UDP"));
                Assert.That(node.DNSEncryptedOnly,  Is.False);
            });

        }

        #endregion

        #region NoEncryptedServerAtAllIsRefused()

        /// <summary>
        /// None asked is refused as an empty list is - and with an encrypted
        /// server in the same change, it is not.
        /// </summary>
        [Test]
        public async Task NoEncryptedServerAtAllIsRefused()
        {

            await using var node = Node($$"""{ "servers": [ {{InClearText}} ] }""");

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "encryptedOnly": true }"""), out var error), Is.False);

            Assert.Multiple(() => {
                Assert.That(error,                  Does.StartWith("'dns.encryptedOnly': only name servers reached over TLS or HTTPS would be asked, and none of these is"));
                Assert.That(node.DNSEncryptedOnly,  Is.False);
                Assert.That(Asked(node),            Is.EqualTo(new[] { "udp://192.0.2.1:53" }));
            });

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""{ "servers": [ {{InClearText}}, {{Encrypted}} ], "encryptedOnly": true }"""), out error), Is.True, error);
            Assert.That(Asked(node), Is.EqualTo(new[] { "tls://192.0.2.2:853" }));

        }

        #endregion

        #region TheServersItWasStartedWithInClearTextAreRefused()

        /// <summary>
        /// "servers": null gives the servers back the node was started with -
        /// the operating system's, asked over UDP - which are servers in clear
        /// text it does not ask now.
        /// </summary>
        [Test]
        public async Task TheServersItWasStartedWithInClearTextAreRefused()
        {

            using var client = new DNSClient(new[] { new DNSServerConfig(IPv4Address.Parse("192.0.2.53"), IPPort.Parse(53), DNSTransport.UDP) });

            await using var node = Node($$"""{ "servers": [ {{Encrypted}} ], "encryptedOnly": true }""", client);

            Assert.Multiple(() => {
                Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "servers": null }"""), out var error), Is.False);
                Assert.That(error,        Does.StartWith("'dns.servers': the name servers this WWCP node was started with are asked in clear text (udp://192.0.2.53:53)"));
                Assert.That(Asked(node),  Is.EqualTo(new[] { "tls://192.0.2.2:853" }));
            });

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "servers": null, "encryptedOnly": false }"""), out var allowed), Is.True, allowed);

        }

        #endregion

        #region ServersInClearTextAreNotAskedWhenOnlyEncryptedOnesAre()

        /// <summary>
        /// Asked for a name, the node sends the server in clear text a question
        /// while it asks all of them, and none once only encrypted ones are
        /// asked - counted at that server.
        /// </summary>
        [Test]
        public async Task ServersInClearTextAreNotAskedWhenOnlyEncryptedOnesAre()
        {

            var udp      = SilentNameServer(out var port);
            var nowhere  = TestPorts.Free();

            await using var node = Node($$"""
                                          { "servers": [ { "address": "127.0.0.1", "port": {{port}},    "transport": "UDP", "queryTimeoutSeconds": 0.4 },
                                                         { "address": "127.0.0.1", "port": {{nowhere}}, "transport": "TLS", "queryTimeoutSeconds": 0.4 } ],
                                            "maxRetries": 0,
                                            "useCache": false }
                                          """);

            await node.ResolveAsync("all.example");

            var whileAll = await QuestionsAsked(udp);

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "encryptedOnly": true }"""), out var error), Is.True, error);

            await node.ResolveAsync("encrypted.example");

            var whileEncrypted = await QuestionsAsked(udp);

            Assert.Multiple(() => {
                Assert.That(whileAll,        Is.GreaterThan(0), "asking all of them, the node did not ask the server in clear text");
                Assert.That(whileEncrypted,  Is.Zero,           "asking only encrypted servers, the node asked the one in clear text");
            });

        }

        #endregion

        #region TheDryRunAsksAndRefusesAsTheChangeWould()

        /// <summary>
        /// A dry run of switching it on asks no server in clear text, and one of
        /// a server that would be refused says why, as the save would.
        /// </summary>
        [Test]
        public async Task TheDryRunAsksAndRefusesAsTheChangeWould()
        {

            var udp      = SilentNameServer(out var port);
            var nowhere  = TestPorts.Free();

            await using var node = Node($$"""
                                          { "servers": [ { "address": "127.0.0.1", "port": {{port}},    "transport": "UDP", "queryTimeoutSeconds": 0.4 },
                                                         { "address": "127.0.0.1", "port": {{nowhere}}, "transport": "TLS", "queryTimeoutSeconds": 0.4 } ],
                                            "maxRetries": 0 }
                                          """);

            var switchedOn  = await node.ResolveWithAsync(JObject.Parse("""{ "encryptedOnly": true }"""), [ "dry.example" ], TimeSpan.FromSeconds(2));
            var asked       = await QuestionsAsked(udp);

            var refused     = await node.ResolveWithAsync(JObject.Parse($$"""
                                                              { "servers": [ { "address": "127.0.0.1", "port": {{port}}, "transport": "UDP" },
                                                                             { "address": "192.0.2.3", "transport": "UDP" },
                                                                             { "address": "127.0.0.1", "port": {{nowhere}}, "transport": "TLS" } ],
                                                                "encryptedOnly": true }
                                                              """),
                                                          [ "dry.example" ],
                                                          TimeSpan.FromSeconds(2));

            Assert.Multiple(() => {
                Assert.That(switchedOn.Error,             Is.Null);
                Assert.That(switchedOn.Resolves("dry.example"), Is.False);
                Assert.That(asked,                        Is.Zero, "the dry run asked the server in clear text");
                Assert.That(refused.Error,                Does.StartWith("'dns.servers[1]' would be asked over UDP"));
                Assert.That(node.DNSEncryptedOnly,        Is.False, "a dry run put something into effect");
            });

        }

        #endregion

    }

}
