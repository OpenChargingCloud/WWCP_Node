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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a change of the name resolution tells whoever listens, and who it
    /// says made it: once per save, after the change is in effect and the lock
    /// is let go - and a change made from the configuration as it is while
    /// nothing else can change it.
    /// </summary>
    /// <remarks>
    /// What a bridge to OCPP needs from the node: a CSMS told of what changed
    /// on the page, a change of its own told apart from the page's, and the
    /// whole list of name servers written back without losing a server added
    /// on the page in between.
    /// </remarks>
    public class DNSChangeTests
    {

        #region Data

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

            directory = Path.Combine(Path.GetTempPath(), "node-dns-changes-" + Guid.NewGuid().ToString("N")[..12]);

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
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helper) Node()

        /// <summary>
        /// A node with one name server nobody answers on, and no time server to
        /// ask.
        /// </summary>
        private WWCPNode Node()
        {

            File.WriteAllText(ConfigurationPath,
                              """
                              {
                                "nts": { "groups": { "legal": { "enabled": false } } },
                                "dns": { "servers": [ "192.0.2.1" ], "maxRetries": 0 }
                              }
                              """);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Recorded(Node)

        /// <summary>
        /// One change as a listener was told it.
        /// </summary>
        private sealed record Told(IReadOnlyList<String>  Changes,
                                   String?                Origin);

        /// <summary>
        /// Every change the node tells from now on, in the order it tells them.
        /// </summary>
        private static List<Told> Recorded(WWCPNode Node)
        {

            var told = new List<Told>();

            Node.OnDNSConfigurationChanged += (changes, origin) => {
                lock (told)
                    told.Add(new (changes, origin));
            };

            return told;

        }

        #endregion

        #region (helper) Said(Node, Since)

        private static String[] Said(WWCPNode  Node,
                                     UInt64    Since)

            => [.. Node.Log.Recent(100, Since, null).Select(entry => entry.Message)];

        #endregion

        #region (helper) Addresses(Section) / WithServer(Section, Address)

        private static String[] Addresses(JObject Section)

            => [.. (Section["servers"] as JArray ?? []).Select(server => server.Value<String>("address") ?? "")];

        /// <summary>
        /// The list of name servers as a section says it, and one more at its
        /// end: what a bridge sending the whole list back sends.
        /// </summary>
        private static JObject WithServer(JObject  Section,
                                          String   Address)

            => new (
                   new JProperty("servers", new JArray(
                       Addresses(Section).Append(Address).Select(address => new JObject(new JProperty("address", address)))
                   ))
               );

        #endregion


        #region ASaveIsToldOnceWithWhatChangedAndWhoChangedIt()

        [Test]
        public async Task ASaveIsToldOnceWithWhatChangedAndWhoChangedIt()
        {

            await using var node = Node();

            var told    = Recorded(node);
            var before  = node.Log.LastId;

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "useCache": false, "maxRetries": 2 }"""), out var error, out _, ChangeOrigin.Web("alice")),
                        Is.True,
                        error);

            Assert.Multiple(() => {

                Assert.That(told,             Has.Count.EqualTo(1));
                Assert.That(told[0].Changes,  Is.EqualTo(new[] { "use cache = False", "max retries = 2" }));
                Assert.That(told[0].Origin,   Is.EqualTo("web:alice"));

                Assert.That(Said(node, before), Has.Some.EqualTo("DNS configuration changed: use cache = False, max retries = 2 (by web:alice)."),
                            "the log line names who changed the name resolution");

            });

        }

        #endregion

        #region ASaveThatNamesNobodyIsSaidAsBefore()

        [Test]
        public async Task ASaveThatNamesNobodyIsSaidAsBefore()
        {

            await using var node = Node();

            var told    = Recorded(node);
            var before  = node.Log.LastId;

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "useCache": false }"""), out var error),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(told.Select(change => change.Origin),  Is.EqualTo(new String?[] { null }));
                Assert.That(Said(node, before),                    Has.Some.EqualTo("DNS configuration changed: use cache = False."));
            });

        }

        #endregion

        #region ServersSavedAsNullAreTheOnesTheNodeWasStartedWith()

        /// <summary>
        /// A node made with a name server over TLS of its client's own, whose
        /// file holds that one to a root and names another: a save of
        /// "servers": null takes the file's list away and asks the client's own
        /// again, held to nothing - in effect, in the file, at the next start and
        /// in what is told, once. A save of it again changes nothing.
        /// </summary>
        [Test]
        public void ServersSavedAsNullAreTheOnesTheNodeWasStartedWith()
        {

            File.WriteAllText(ConfigurationPath,
                              """
                              {
                                "nts": { "groups": { "legal": { "enabled": false } } },
                                "dns": { "servers": [ { "id": "ours", "address": "198.51.100.1", "transport": "TLS",
                                                        "rootFingerprint": "9d2e4f6a8b0c1d3e5f7a9b1c3d5e7f9a0b2c4d6e8f0a1b3c5d7e9f1a2b4c6d8e" },
                                                      "192.0.2.53" ],
                                         "maxRetries": 0 }
                              }
                              """);

            WWCPNode Made()

                => new (
                       DNSClient:         new DNSClient(ManualDNSServers: [ new DNSServerConfig(IPv4Address.Parse("198.51.100.1"), Transport: DNSTransport.TLS) ]),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

            var node    = Made();
            var told    = Recorded(node);
            var before  = node.DNSConfigurationJSON();

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "servers": null }"""), out var error, out _, ChangeOrigin.Web("root")),  Is.True, error);

            var after   = node.DNSConfigurationJSON();

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "servers": null }"""), out error, out _, ChangeOrigin.Web("root")),      Is.True, error);

            var started = Made().DNSConfigurationJSON();

            Assert.Multiple(() => {

                Assert.That(before.Value<String>("serversFrom"),                  Is.EqualTo("file"));
                Assert.That(Addresses(before),                                    Is.EqualTo(new[] { "198.51.100.1", "192.0.2.53" }));
                Assert.That(before["servers"]?[0]?["rootFingerprint"],            Is.Not.Null);

                Assert.That(after.Value<String>("serversFrom"),                   Is.EqualTo("start"));
                Assert.That(Addresses(after),                                     Is.EqualTo(new[] { "198.51.100.1" }));
                Assert.That(after["servers"]?[0]?["rootFingerprint"],             Is.Null, "held to nothing");
                Assert.That(after["servers"]?[0]?.Value<String>("id"),            Is.EqualTo("dns-1"), "named by its place, as the file's ids went with the file's servers");

                Assert.That(OnDisk["dns"]?["servers"],                            Is.Null, "taken out of the file");
                Assert.That(OnDisk["dns"]?.Value<Int32>("maxRetries"),            Is.EqualTo(0), "and nothing else");

                Assert.That(started.Value<String>("serversFrom"),                 Is.EqualTo("start"));
                Assert.That(Addresses(started),                                   Is.EqualTo(new[] { "198.51.100.1" }));

                Assert.That(told.Select(change => change.Origin),                 Is.EqualTo(new[] { "web:root" }), "once, and not for the save that changed nothing");
                Assert.That(told.SelectMany(change => change.Changes),            Has.Some.EqualTo("servers = tls://198.51.100.1:853, the ones it was started with").
                                                                                  And.Some.EqualTo("server ids = dns-1").
                                                                                  And.Some.EqualTo("tls://198.51.100.1:853 held to no fingerprint"));

            });

        }

        #endregion

        #region (helper) NodeWithServers(Servers)

        /// <summary>
        /// A node with the given name servers, nobody answering on any of them,
        /// and no time server to ask.
        /// </summary>
        private WWCPNode NodeWithServers(String Servers)
        {

            File.WriteAllText(ConfigurationPath,
                              $$"""
                              {
                                "nts": { "groups": { "legal": { "enabled": false } } },
                                "dns": { "servers": {{Servers}}, "maxRetries": 0 }
                              }
                              """);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        /// <summary>
        /// The ids of the servers as a section says them.
        /// </summary>
        private static String?[] IdsIn(JToken? Section)

            => [.. (Section?["servers"] as JArray ?? []).Select(server => server.Value<String>("id"))];

        #endregion

        #region EveryServerIsShownWithItsId()

        /// <summary>
        /// The node shows every name server with an id: the one the file gives
        /// it, or one by its place.
        /// </summary>
        [Test]
        public async Task EveryServerIsShownWithItsId()
        {

            await using var node = NodeWithServers("""[ { "id": "office", "address": "192.0.2.1" }, "192.0.2.2" ]""");

            Assert.Multiple(() => {
                Assert.That(IdsIn(node.DNSConfigurationJSON()),  Is.EqualTo(new[] { "office", "dns-2" }));
                Assert.That(node.DNSServerIds,                   Is.EqualTo(new[] { "office", "dns-2" }));
            });

        }

        #endregion

        #region IdsSentBackStayWhenAServerBeforeThemIsTakenAway()

        /// <summary>
        /// The servers a page or a CSMS sends back with the ids it was shown keep
        /// them when the server before them is taken away - in effect, in the
        /// file and at the next start - and the new ids are told with the new
        /// servers. Sent back without them, the servers would be named by their
        /// new places, the second being "dns-1" to a CSMS that knew "dns-1" as
        /// another one.
        /// </summary>
        [Test]
        public async Task IdsSentBackStayWhenAServerBeforeThemIsTakenAway()
        {

            await using var node = NodeWithServers("""[ "192.0.2.1", "192.0.2.2", "192.0.2.3" ]""");

            var told  = Recorded(node);
            var shown = node.DNSConfigurationJSON();
            var sent  = new JObject(
                            new JProperty("servers", new JArray(
                                (shown["servers"] as JArray ?? []).Skip(1).Select(server => new JObject(
                                    new JProperty("id",       server["id"]),
                                    new JProperty("address",  server["address"])
                                ))
                            ))
                        );

            Assert.That(node.TryUpdateDNSConfiguration(sent, out var error, out _, ChangeOrigin.Web("root")),  Is.True, error);

            await using var started = new WWCPNode(
                                          AccountsPath:      Path.Combine(directory, "accounts"),
                                          ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                                          CertificatesPath:  Path.Combine(directory, "certificates"),
                                          LogToConsole:      false,
                                          BridgeDebugLog:    false
                                      );

            Assert.Multiple(() => {

                Assert.That(IdsIn(shown),                                 Is.EqualTo(new[] { "dns-1", "dns-2", "dns-3" }));

                Assert.That(node.DNSServerIds,                            Is.EqualTo(new[] { "dns-2", "dns-3" }));
                Assert.That(IdsIn(node.DNSConfigurationJSON()),           Is.EqualTo(new[] { "dns-2", "dns-3" }));
                Assert.That(IdsIn(OnDisk["dns"]),                         Is.EqualTo(new[] { "dns-2", "dns-3" }), "written into the file");
                Assert.That(started.DNSServerIds,                         Is.EqualTo(new[] { "dns-2", "dns-3" }), "and read at the next start");

                Assert.That(told,                                         Has.Count.EqualTo(1));
                Assert.That(told.SelectMany(change => change.Changes),    Has.Some.StartsWith("servers = ").
                                                                          And.Some.EqualTo("server ids = dns-2, dns-3"));

            });

        }

        #endregion

        #region AServerAddedIsToldWithItsNewId()

        /// <summary>
        /// A server added without an id takes the next free one, and the ids are
        /// part of the change that is told: to a CSMS, the server is new.
        /// </summary>
        [Test]
        public async Task AServerAddedIsToldWithItsNewId()
        {

            await using var node = NodeWithServers("""[ { "id": "dns-2", "address": "192.0.2.1" } ]""");

            var told = Recorded(node);

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "servers": [ { "id": "dns-2", "address": "192.0.2.1" }, "192.0.2.2" ] }"""),
                                                       out var error, out _, ChangeOrigin.Web("root")),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(node.DNSServerIds,                            Is.EqualTo(new[] { "dns-2", "dns-3" }));
                Assert.That(told.SelectMany(change => change.Changes),    Has.Some.EqualTo("server ids = dns-2, dns-3"));
            });

        }

        #endregion

        #region IdsWrittenDownAsShownChangeNothing()

        /// <summary>
        /// A page sending the list back with the ids it was shown writes them
        /// into the file, where they stay, and changes nothing: they were the
        /// servers' ids before.
        /// </summary>
        [Test]
        public async Task IdsWrittenDownAsShownChangeNothing()
        {

            await using var node = NodeWithServers("""[ "192.0.2.1", "192.0.2.2" ]""");

            var told  = Recorded(node);
            var sent  = new JObject(
                            new JProperty("servers", new JArray(
                                (node.DNSConfigurationJSON()["servers"] as JArray ?? []).Select(server => new JObject(
                                    new JProperty("id",       server["id"]),
                                    new JProperty("address",  server["address"])
                                ))
                            ))
                        );

            Assert.That(node.TryUpdateDNSConfiguration(sent, out var error, out _, ChangeOrigin.Web("root")),  Is.True, error);

            Assert.Multiple(() => {
                Assert.That(told,                   Is.Empty, "nothing changed");
                Assert.That(node.DNSServerIds,      Is.EqualTo(new[] { "dns-1", "dns-2" }));
                Assert.That(IdsIn(OnDisk["dns"]),   Is.EqualTo(new[] { "dns-1", "dns-2" }));
            });

        }

        #endregion

        #region ADryRunOfServersGivenBackAsksTheOnesTheNodeWasStartedWith()

        /// <summary>
        /// A dry run of "servers": null asks the servers the node was started
        /// with, not the file's: a name only they know resolves with it, and not
        /// with the node as it is - which keeps the file's servers.
        /// </summary>
        [Test]
        public async Task ADryRunOfServersGivenBackAsksTheOnesTheNodeWasStartedWith()
        {

            var started = new DNSServer(
                              new AuthoritativeDNSRequestHandler(
                                  new InMemoryDNSZone().
                                      Add(new A(
                                              DomainName. Parse("csms.example.test."),
                                              DNSQueryClasses.IN,
                                              TimeSpan.   FromMinutes(5),
                                              IPv4Address.Parse("127.0.0.42")
                                          ))
                              ),
                              new DNSServerOptions {
                                  EnableUDPUnicast    = false,
                                  EnableUDPMulticast  = false,
                                  EnableTCPUnicast    = true,
                                  TCPUnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Parse(0))
                              }
                          );

            await started.Start();

            try
            {

                File.WriteAllText(ConfigurationPath,
                                  """
                                  {
                                    "nts": { "groups": { "legal": { "enabled": false } } },
                                    "dns": { "servers": [ { "address": "192.0.2.1", "queryTimeoutSeconds": 1 } ], "maxRetries": 0 }
                                  }
                                  """);

                var node    = new WWCPNode(
                                  DNSClient:         new DNSClient(ManualDNSServers: [ new DNSServerConfig(IPv4Address.Localhost, started.ActiveTCPUnicastSocket!.Value.Port, DNSTransport.TCP) ]),
                                  AccountsPath:      Path.Combine(directory, "accounts"),
                                  ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                                  CertificatesPath:  Path.Combine(directory, "certificates"),
                                  LogToConsole:      false,
                                  BridgeDebugLog:    false
                              );

                var now     = await node.ResolveWithAsync(new JObject(),                             [ "csms.example.test" ], TimeSpan.FromSeconds(5));
                var back    = await node.ResolveWithAsync(JObject.Parse("""{ "servers": null }"""),  [ "csms.example.test" ], TimeSpan.FromSeconds(5));

                Assert.Multiple(() => {
                    Assert.That(now. Resolves("csms.example.test"),                   Is.False, "the file's server answers nobody");
                    Assert.That(back.Resolves("csms.example.test"),                   Is.True,  "the one it was started with knows the name");
                    Assert.That(Addresses(node.DNSConfigurationJSON()),               Is.EqualTo(new[] { "192.0.2.1" }), "a dry run");
                });

            }
            finally
            {
                await started.Stop();
            }

        }

        #endregion

        #region ASaveThatChangesNothingTellsNothing()

        [Test]
        public async Task ASaveThatChangesNothingTellsNothing()
        {

            await using var node = Node();

            var json  = """{ "servers": [ "192.0.2.1" ], "maxRetries": 0 }""";
            var told  = Recorded(node);

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse(json), out var error, out _, ChangeOrigin.Web("alice")),  Is.True,  error);

            Assert.That(told, Is.Empty, "the save repeated what was in effect");

        }

        #endregion

        #region AListenerMayChangeTheNodeInTurn()

        /// <summary>
        /// Told once the lock is let go: a listener that changes the node in
        /// turn would otherwise wait for the save that told it, and that save
        /// for the listener.
        /// </summary>
        [Test]
        public async Task AListenerMayChangeTheNodeInTurn()
        {

            await using var node = Node();

            var answered = new List<Boolean>();

            node.OnDNSConfigurationChanged += (changes, origin) => {
                if (origin == "web:alice")
                    answered.Add(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "maxRetries": 3 }"""), out _, out _, "test:listener"));
            };

            var save = Task.Run(() => node.TryUpdateDNSConfiguration(JObject.Parse("""{ "useCache": false }"""), out _, out _, ChangeOrigin.Web("alice")));

            Assert.That(save.Wait(TimeSpan.FromSeconds(10)),  Is.True,  "the listener's change waited for the lock the save that told it still held");

            Assert.Multiple(() => {
                Assert.That(save.Result,                 Is.True);
                Assert.That(answered,                    Is.EqualTo(new[] { true }));
                Assert.That(node.DNSClient.MaxRetries,   Is.EqualTo(3));
            });

        }

        #endregion

        #region AListenerThatFailsKeepsNoOtherFromHearing()

        [Test]
        public async Task AListenerThatFailsKeepsNoOtherFromHearing()
        {

            await using var node = Node();

            node.OnDNSConfigurationChanged += (_, _) => throw new InvalidOperationException("listener down");

            var told    = Recorded(node);
            var before  = node.Log.LastId;

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""{ "useCache": false }"""), out var error),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(told,                     Has.Count.EqualTo(1));
                Assert.That(node.DNSClient.UseCache,  Is.False,  "the save is not undone by a listener");
                Assert.That(Said(node, before),       Has.Some.Contains("the name resolution changed failed: listener down"));
            });

        }

        #endregion


        #region AChangeIsMadeFromTheConfigurationAsItIsWhenItIsWritten()

        /// <summary>
        /// Two changes that each send the whole list back with one server more,
        /// the second asked while the first is being made: the second is made
        /// from the list the first wrote, and neither server is lost. Read
        /// before the lock, the second would be made from the list as it was
        /// and write the first one's server away.
        /// </summary>
        [Test]
        public async Task AChangeIsMadeFromTheConfigurationAsItIsWhenItIsWritten()
        {

            await using var node = Node();

            using var firstIsMade   = new ManualResetEventSlim();
            using var secondAsked   = new ManualResetEventSlim();

            var first   = Task.Run(() => node.TryUpdateDNSConfiguration(section => {
                                                                            firstIsMade.Set();
                                                                            secondAsked.Wait(TimeSpan.FromSeconds(2));
                                                                            return WithServer(section, "192.0.2.10");
                                                                        },
                                                                        out _,
                                                                        out _,
                                                                        ChangeOrigin.OCPP("CSMS1")));

            Assert.That(firstIsMade.Wait(TimeSpan.FromSeconds(10)),  Is.True);

            var second  = Task.Run(() => node.TryUpdateDNSConfiguration(section => {
                                                                            secondAsked.Set();
                                                                            return WithServer(section, "192.0.2.11");
                                                                        },
                                                                        out _,
                                                                        out _,
                                                                        ChangeOrigin.Web("alice")));

            Assert.That(Task.WaitAll([ first, second ], TimeSpan.FromSeconds(10)),  Is.True);

            Assert.Multiple(() => {
                Assert.That(first.Result,                                   Is.True);
                Assert.That(second.Result,                                  Is.True);
                Assert.That(Addresses(node.DNSConfigurationJSON()),         Is.EqualTo(new[] { "192.0.2.1", "192.0.2.10", "192.0.2.11" }));
                Assert.That(Addresses((JObject) OnDisk["dns"]!),            Is.EqualTo(new[] { "192.0.2.1", "192.0.2.10", "192.0.2.11" }));
            });

        }

        #endregion

        #region AChangeThatWouldRatherNotBeMadeChangesNothing()

        [Test]
        public async Task AChangeThatWouldRatherNotBeMadeChangesNothing()
        {

            await using var node = Node();

            var told  = Recorded(node);
            var file  = File.ReadAllText(ConfigurationPath);
            var seen  = new List<String[]>();

            Assert.That(node.TryUpdateDNSConfiguration(section => {
                                                           seen.Add(Addresses(section));
                                                           return null;
                                                       },
                                                       out var error,
                                                       out var notSaved,
                                                       ChangeOrigin.OCPP("CSMS1")),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(seen,                                  Is.EqualTo(new[] { new[] { "192.0.2.1" } }),  "the change was shown the configuration in effect");
                Assert.That(notSaved,                              Is.False);
                Assert.That(told,                                  Is.Empty);
                Assert.That(File.ReadAllText(ConfigurationPath),   Is.EqualTo(file));
            });

        }

        #endregion

    }

}
