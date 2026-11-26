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
using System.Collections.Concurrent;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Names and time for the logins of a kind over the SSH connection they sign in with: "ssh.dns"
    /// passes their questions on to the node's name servers, "ssh.nts" gives them NTS keys over SSH
    /// and NTP with NTS from a time server of the node's own - each off where the file says nothing.
    /// </summary>
    [TestFixture]
    public class SSHNamesAndTimeTests
    {

        #region Data

        private String                      directory  = "";
        private readonly List<WWCPNode>     nodes      = [];
        private readonly List<String>       said       = [];
        private readonly ISshHostKey        cs001Key   = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey        cs002Key   = SshHostKey.GenerateEd25519();

        private DNSServer?                  nameServer;
        private DNSClient?                  nameServerClient;

        #endregion

        #region (class) Stations

        /// <summary>
        /// The logins of a kind: stations, each with one key and the subsystems its group gives it -
        /// of those the node serves now, as a local controller's station logins do.
        /// </summary>
        private sealed class Stations(WWCPNode Node) : ISSHSignIns
        {

            public sealed record Login(Byte[] Key, String[] Subsystems);

            public ConcurrentDictionary<String, Login> Logins { get; } = new (StringComparer.Ordinal);

            public String PrincipalKind
                => "station";

            public Boolean Knows(User_Id Username)
                => Logins.ContainsKey(Username.ToString());

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(Logins.TryGetValue(Request.Username.ToString(), out var login) && login.Key.AsSpan().SequenceEqual(Request.PublicKeyBlob));

            public IReadOnlySet<String> SubsystemsFor(User_Id Username)
                => Logins.TryGetValue(Username.ToString(), out var login)
                       ? new HashSet<String>(login.Subsystems.Intersect(Node.SSHSubsystems.Select(subsystem => subsystem.Name)), StringComparer.Ordinal)
                       : new HashSet<String>(StringComparer.Ordinal);

            public IReadOnlyList<String> GroupsOf(User_Id Username)
                => [ "stations" ];

            public String? WhyNoLongerIn(SshSessionInfo Session)
                => Logins.ContainsKey(Session.Username.ToString()) ? null : $"there is no station '{Session.Username}' any more";

        }

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        /// <summary>
        /// The name server the node asks: it knows "csms.example.test".
        /// </summary>
        [OneTimeSetUp]
        public async Task StartTheNameServer()
        {

            nameServer = new DNSServer(
                             new AuthoritativeDNSRequestHandler(
                                 new InMemoryDNSZone().Add(new A(DomainName.Parse("csms.example.test."),
                                                                 DNSQueryClasses.IN,
                                                                 TimeSpan.FromMinutes(5),
                                                                 IPv4Address.Parse("127.0.0.42")))
                             ),
                             new DNSServerOptions {
                                 UDPUnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Zero),
                                 EnableUDPMulticast  = false,
                                 EnableTCPUnicast    = false
                             }
                         );

            await nameServer.Start();

            nameServerClient = new DNSClient(
                                   IPv4Address.Localhost,
                                   Port:           nameServer.ActiveUDPUnicastSocket!.Value.Port,
                                   QueryTimeout:   TimeSpan.FromSeconds(3),
                                   UseQueryCache:  false
                               );

        }

        [OneTimeTearDown]
        public async Task StopTheNameServer()
        {

            if (nameServerClient is not null)
                await nameServerClient.DisposeAsync();

            if (nameServer is not null)
                await nameServer.Stop();

        }

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-names-and-time-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region NeitherIsServed_WhereTheFileSaysNothing

        [Test]
        [CancelAfter(60000)]
        public async Task NeitherIsServed_WhereTheFileSaysNothing(CancellationToken CancellationToken)
        {

            var (node, _) = await Started(SSHSection: "");

            var json      = node.SSHConfigurationJSON();

            Assert.Multiple(() => {
                Assert.That(node.SSHSubsystems.Select(subsystem => subsystem.Name), Has.None.EqualTo(DNSServer.SSHSubsystemName));
                Assert.That(node.SSHSubsystems.Select(subsystem => subsystem.Name), Has.None.EqualTo(NTSKE_SSH.SubsystemName));
                Assert.That(node.ServesNamesToSSHLogins,             Is.False);
                Assert.That(node.TimeServerOfSSHLogins,              Is.Null);
                Assert.That(json["dns"]!["served"]!.Value<Boolean>(), Is.False);
                Assert.That(json["nts"]!["served"]!.Value<Boolean>(), Is.False);
                Assert.That(json["nts"]!["ntpPort"]!.Value<Int32>(),  Is.EqualTo(123));
            });

        }

        #endregion

        #region AStation_ResolvesANameOverItsSSHConnection_FromTheNodesNameServers

        [Test]
        [CancelAfter(60000)]
        public async Task AStation_ResolvesANameOverItsSSHConnection_FromTheNodesNameServers(CancellationToken CancellationToken)
        {

            var (node, _)    = await Started(SSHSection: """, "dns": { "enabled": true }""",
                                             Logins: [ ("cs001", cs001Key, [ DNSServer.SSHSubsystemName ]) ]);

            await using var cs001 = await SignIn(node, "cs001", cs001Key);
            await using var dns   = new DNSSSHClient(_ => ValueTask.FromResult(cs001), QueryTimeout: TimeSpan.FromSeconds(10));

            var known        = await dns.Query<A>(DomainName.Parse("csms.example.test."), ForceUpdate: true, CancellationToken: CancellationToken);
            var unknown      = await dns.Query<A>(DomainName.Parse("nothing.example.test."), ForceUpdate: true, CancellationToken: CancellationToken);

            Assert.Multiple(() => {
                Assert.That(node.ServesNamesToSSHLogins,                  Is.True);
                Assert.That(known.ResponseCode,                           Is.EqualTo(DNSResponseCodes.NoError));
                Assert.That(known.FilteredAnswers.Single().IPv4Address,   Is.EqualTo(IPv4Address.Parse("127.0.0.42")));
                // Passed on: not this node's to say with authority.
                Assert.That(known.AuthoritativeAnswer,                    Is.False);
                Assert.That(known.RecursionAvailable,                     Is.True);
                Assert.That(unknown.ResponseCode,                         Is.EqualTo(DNSResponseCodes.NameError));
                Assert.That(Said("Names are resolved for the SSH logins"), Is.True, "the log does not say it is served");
            });

        }

        #endregion

        #region AStation_WithoutTheChannel_ResolvesNothing

        [Test]
        [CancelAfter(60000)]
        public async Task AStation_WithoutTheChannel_ResolvesNothing(CancellationToken CancellationToken)
        {

            var (node, _)    = await Started(SSHSection: """, "dns": { "enabled": true }""",
                                             Logins: [ ("cs002", cs002Key, [ NTSKE_SSH.SubsystemName ]) ]);

            await using var cs002 = await SignIn(node, "cs002", cs002Key);

            Assert.That(async () => await cs002.OpenSubsystem(DNSServer.SSHSubsystemName, CancellationToken),
                        Throws.Exception,
                        "a station whose group does not give it DNS opened it");

        }

        #endregion

        #region AStation_GetsItsTimeFromTheNode_KeysOverSSH_NTPOverUDP

        [Test]
        [CancelAfter(60000)]
        public async Task AStation_GetsItsTimeFromTheNode_KeysOverSSH_NTPOverUDP(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: """, "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1" }""",
                                                Logins: [ ("cs001", cs001Key, [ NTSKE_SSH.SubsystemName ]) ]);

            await using var cs001 = await SignIn(node, "cs001", cs001Key);

            var ntsClient   = new NTSClient(DomainName.Localhost, NTP_Port: ntpPort, IPVersionPreference: IPVersionPreference.IPv4Only);
            var keys        = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);

            Assert.That(keys.Success, Is.True, keys.ErrorMessage);

            var time        = await ntsClient.QueryTime(NTSKEResponse: keys.Response!, Timeout: TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {
                Assert.That(time.Success,                                Is.True, time.ErrorMessage);
                Assert.That(node.TimeServerOfSSHLogins,                  Is.Not.Null);
                Assert.That(node.TimeServerOfSSHLogins!.UDPPort,         Is.EqualTo(ntpPort));
                // Over SSH alone: no port for the key exchange over TLS.
                Assert.That(node.TimeServerOfSSHLogins.NTSKEOverTLS,     Is.False);
                // On another port than 123 the station is told where.
                Assert.That(keys.Response!.NTPv4Ports,                   Is.EqualTo(new[] { ntpPort }));
                Assert.That(keys.Response.NTPv4ServerNames,              Is.EqualTo(new[] { "127.0.0.1" }));
                Assert.That(File.Exists(node.NTSMasterKeysPath),         Is.True, "the master keys are not kept beside the SSH host key");
                Assert.That(Said("get their time from it"),              Is.True, "the log does not say it is served");
            });

        }

        #endregion

        #region SwitchedOnAndOffWhileRunning_SavedAndInEffect

        [Test]
        [CancelAfter(60000)]
        public async Task SwitchedOnAndOffWhileRunning_SavedAndInEffect(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: "");

            var on        = await node.TryUpdateSSHConfiguration(JObject.Parse($$"""{ "dns": { "enabled": true }, "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1" } }"""));

            var servedDNS = node.ServesNamesToSSHLogins;
            var servedNTS = node.TimeServerOfSSHLogins is not null;
            var saved     = JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!;

            var off       = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "dns": { "enabled": false }, "nts": { "enabled": false } }"""));

            Assert.Multiple(() => {
                Assert.That(on. IsChanged,                                Is.True, on.Error);
                Assert.That(servedDNS,                                    Is.True);
                Assert.That(servedNTS,                                    Is.True);
                Assert.That(saved["dns"]!["enabled"]!.Value<Boolean>(),   Is.True);
                Assert.That(saved["nts"]!["ntpPort"]!.Value<Int32>(),     Is.EqualTo((Int32) ntpPort.ToUInt16()));
                Assert.That(off.IsChanged,                                Is.True, off.Error);
                Assert.That(node.ServesNamesToSSHLogins,                  Is.False);
                Assert.That(node.TimeServerOfSSHLogins,                   Is.Null);
                Assert.That(node.SSHSubsystems.Select(subsystem => subsystem.Name), Has.None.EqualTo(DNSServer.SSHSubsystemName));
                Assert.That(node.SSHSubsystems.Select(subsystem => subsystem.Name), Has.None.EqualTo(NTSKE_SSH.SubsystemName));
                // Switched off, the port is let go of.
                Assert.That(UDPPortIsFree(node, ntpPort),                       Is.True, $"UDP port {ntpPort} is still bound");
                // The port asked for once stays in the file.
                Assert.That(JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["nts"]!["ntpPort"]!.Value<Int32>(), Is.EqualTo((Int32) ntpPort.ToUInt16()));
            });

        }

        #endregion

        #region AnotherPortWithoutAHost_IsRefused_AndNothingSaved

        [Test]
        [CancelAfter(60000)]
        public async Task AnotherPortWithoutAHost_IsRefused_AndNothingSaved(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: "");

            var before = File.ReadAllText(ConfigPath);

            var change = await node.TryUpdateSSHConfiguration(JObject.Parse($$"""{ "nts": { "enabled": true, "ntpPort": {{ntpPort}} } }"""));

            Assert.Multiple(() => {
                Assert.That(change.IsChanged,              Is.False);
                Assert.That(change.Error,                  Does.Contain("ntpHost"));
                Assert.That(File.ReadAllText(ConfigPath),  Is.EqualTo(before));
                Assert.That(node.TimeServerOfSSHLogins,    Is.Null);
            });

        }

        #endregion

        #region APortThatIsTaken_IsSaid_AndTheNodeRunsOn

        [Test]
        [CancelAfter(60000)]
        public async Task APortThatIsTaken_IsSaid_AndTheNodeRunsOn(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: "");

            using var taker = new UdpClient(new IPEndPoint(ListenAddressOf(node), ntpPort.ToUInt16()));

            var change = await node.TryUpdateSSHConfiguration(JObject.Parse($$"""{ "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1" } }"""));

            Assert.Multiple(() => {
                Assert.That(change.IsChanged,                 Is.True, change.Error);
                Assert.That(change.Notice,                    Does.Contain($"port {ntpPort}"));
                Assert.That(node.TimeServerOfSSHLogins,       Is.Null);
                Assert.That(node.SSHNamesAndTimeProblem,      Does.Contain($"port {ntpPort}"));
                Assert.That(node.SSHSubsystems.Select(subsystem => subsystem.Name), Has.None.EqualTo(NTSKE_SSH.SubsystemName));
                Assert.That(node.SSHConfigurationJSON()["namesAndTimeProblem"]!.Value<String>(), Does.Contain($"port {ntpPort}"));
            });

        }

        #endregion

        #region StoppingTheNode_LetsGoOfThePort

        [Test]
        [CancelAfter(60000)]
        public async Task StoppingTheNode_LetsGoOfThePort(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: """, "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1" }""");

            var boundWhileRunning = !UDPPortIsFree(node, ntpPort);

            await node.Stop();

            Assert.Multiple(() => {
                Assert.That(boundWhileRunning,             Is.True, "the time server never had its port");
                Assert.That(node.TimeServerOfSSHLogins,    Is.Null);
                Assert.That(UDPPortIsFree(node, ntpPort),        Is.True, $"UDP port {ntpPort} is still bound after the node stopped");
            });

        }

        #endregion

        #region AKindThatServesNTSKEItself_KeepsIt

        [Test]
        [CancelAfter(60000)]
        public async Task AKindThatServesNTSKEItself_KeepsIt(CancellationToken CancellationToken)
        {

            // Never started: it binds nothing, and has nothing to let go of.
            var own = new NTSServer(NTSPort: FindFreeUDPPort(), MasterKeysFilePath: null, NTSKEOverTLS: false);

            var (node, ntpPort) = await Started(SSHSection: """, "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1" }""",
                                                Prepare: made => made.ServeNTSKEOverSSH(own));

            Assert.Multiple(() => {
                Assert.That(node.TimeServerOfSSHLogins,    Is.Null);
                Assert.That(node.SSHNamesAndTimeProblem,   Does.Contain("itself"));
                Assert.That(UDPPortIsFree(node, ntpPort),        Is.True, "the time server that was not served kept its port");
            });

        }

        #endregion


        #region AHostSentEmpty_IsTakenAway

        [Test]
        [CancelAfter(60000)]
        public async Task AHostSentEmpty_IsTakenAway(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: "");

            var withHost    = await node.TryUpdateSSHConfiguration(JObject.Parse($$"""{ "nts": { "ntpPort": {{ntpPort}}, "ntpHost": "lc.example.test" } }"""));
            var hostSaved   = JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["nts"]!["ntpHost"]?.Value<String>();

            var cleared     = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "nts": { "ntpPort": 123, "ntpHost": "" } }"""));
            var nts         = (JObject) JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["nts"]!;

            Assert.Multiple(() => {
                Assert.That(withHost.IsChanged,                Is.True, withHost.Error);
                Assert.That(hostSaved,                         Is.EqualTo("lc.example.test"));
                Assert.That(cleared.IsChanged,                 Is.True, cleared.Error);
                Assert.That(nts.ContainsKey("ntpHost"),        Is.False, "the host sent empty is still in the file");
                Assert.That(node.SSHConfigurationJSON()["nts"]!["ntpHost"]!.Type, Is.EqualTo(JTokenType.Null), "the host sent empty is still in effect");
                Assert.That(nts["ntpPort"]!.Value<Int32>(),    Is.EqualTo(123));
            });

        }

        #endregion

        #region TheSection_IsReadAndWrittenAsItSays

        [Test]
        public void TheSection_IsReadAndWrittenAsItSays()
        {

            var read = SSHConfiguration.TryParse(JObject.Parse("""{ "dns": { "enabled": true }, "nts": { "enabled": true, "ntpPort": 1123, "ntpHost": "lc.example.test" } }"""),
                                                 out var configuration, out var error);

            Assert.That(read, Is.True, error);

            Assert.Multiple(() => {

                Assert.That(configuration!.DNS!.Enabled,            Is.True);
                Assert.That(configuration.NTS!.Enabled,             Is.True);
                Assert.That(configuration.NTS.NTPPort,              Is.EqualTo(IPPort.Parse(1123)));
                Assert.That(configuration.NTS.NTPHost,              Is.EqualTo("lc.example.test"));
                Assert.That(configuration.ToJSON().ToString(Newtonsoft.Json.Formatting.None),
                            Is.EqualTo("""{"dns":{"enabled":true},"nts":{"enabled":true,"ntpPort":1123,"ntpHost":"lc.example.test"}}"""));

                Assert.That(SSHConfiguration.TryParse(JObject.Parse("""{ "nts": true }"""),                       out _, out var notAnObject), Is.False);
                Assert.That(notAnObject,  Does.Contain("'ssh.nts' must be an object"));

                Assert.That(SSHConfiguration.TryParse(JObject.Parse("""{ "dns": { "enabled": "yes" } }"""),       out _, out var notABoolean), Is.False);
                Assert.That(notABoolean,  Does.Contain("ssh.dns.enabled"));

                Assert.That(SSHConfiguration.TryParse(JObject.Parse("""{ "nts": { "ntpHost": "lc.example.test/time" } }"""), out _, out var aPath), Is.False);
                Assert.That(aPath,        Does.Contain("'ssh.nts.ntpHost'"));

                Assert.That(SSHConfiguration.TryParse(JObject.Parse("""{ "nts": { "ntpPort": 0 } }"""),           out _, out var noPort), Is.False);
                Assert.That(noPort,       Does.Contain("ssh.nts.ntpPort"));

            });

        }

        #endregion


        #region PlainNTP_IsAnsweredOnlyWhereTheFileSaysSo

        /// <summary>
        /// The time server answers NTS alone where the file says nothing: a plain NTP request gets
        /// no answer. "plainNTP": true - saved, and in effect at once - and it is answered; false
        /// again, and it is not.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task PlainNTP_IsAnsweredOnlyWhereTheFileSaysSo(CancellationToken CancellationToken)
        {

            var (node, ntpPort) = await Started(SSHSection: """, "nts": { "enabled": true, "ntpPort": {{ntpPort}}, "ntpHost": "127.0.0.1" }""");

            var byDefault      = await AskPlainAsync(node, ntpPort);
            var byDefaultJSON  = node.SSHConfigurationJSON()["nts"]!["plainNTP"]!.Value<Boolean>();
            var ignored        = node.TimeServerOfSSHLogins!.Metrics.NTPPlainRequestsIgnored;

            var on             = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "nts": { "plainNTP": true } }"""));

            var answered       = await AskPlainAsync(node, ntpPort);
            var onJSON         = node.SSHConfigurationJSON()["nts"]!["plainNTP"]!.Value<Boolean>();
            var saved          = JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["nts"]!;

            var off            = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "nts": { "plainNTP": false } }"""));

            var again          = await AskPlainAsync(node, ntpPort);

            Assert.Multiple(() => {
                Assert.That(byDefault,                                    Is.Null,     "plain NTP answered where the file says nothing");
                Assert.That(byDefaultJSON,                                Is.False);
                Assert.That(ignored,                                      Is.EqualTo(1), "the request left unanswered is not counted");
                Assert.That(on.IsChanged,                                 Is.True,     on.Error);
                Assert.That(answered,                                     Is.Not.Null, "plain NTP not answered where the file says so");
                Assert.That(onJSON,                                       Is.True);
                Assert.That(saved["plainNTP"]?.Value<Boolean>(),          Is.True,     "not saved");
                Assert.That(saved["ntpPort"]?.Value<Int32>(),             Is.EqualTo((Int32) ntpPort.ToUInt16()), "the port was lost on the way");
                Assert.That(off.IsChanged,                                Is.True,     off.Error);
                Assert.That(again,                                        Is.Null,     "plain NTP still answered after it was switched off");
                Assert.That(node.TimeServerOfSSHLogins!.PlainNTP,         Is.False);
                Assert.That(Said("and no plain NTP"),                     Is.True,     "the log does not say it");
                Assert.That(Said("and plain NTP"),                        Is.True,     "the log does not say it");
            });

        }

        #endregion


        #region (private) Started(SSHSection, Logins = null, Prepare = null) / SignIn(...) / helpers

        private String ConfigPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// A node with SSH on, the given text added to its "ssh" section ({{ntpPort}} replaced by a
        /// free UDP port, which is returned), the given station logins, and what the test adds
        /// before it starts.
        /// </summary>
        private async Task<(WWCPNode Node, IPPort NTPPort)> Started(String                                                      SSHSection,
                                                                    (String Name, ISshHostKey Key, String[] Subsystems)[]?    Logins    = null,
                                                                    Action<WWCPNode>?                                           Prepare   = null)
        {

            var ntpPort = FindFreeUDPPort();

            var node = await TestPorts.StartedOnFreshPorts(() => {

                ntpPort = FindFreeUDPPort();

                File.WriteAllText(ConfigPath,
                                  $$"""
                                  {
                                    "nts":   { "groups": { "legal": { "enabled": false } } },
                                    "ssh":   { "enabled": true, "port": {{TestPorts.Free()}}{{SSHSection.Replace("{{ntpPort}}", ntpPort.ToString())}} }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          TestPorts.Free(),
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(ConfigPath),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        DNSClient:         nameServerClient,
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                if (Logins is not null)
                {
                    var stations = new Stations(made);
                    foreach (var (name, key, subsystems) in Logins)
                        stations.Logins[name] = new Stations.Login(key.PublicKeyBlob, subsystems);
                    made.AddSSHSignIns(stations);
                }

                Prepare?.Invoke(made);

                nodes.Add(made);

                return made;

            });

            return (node, ntpPort);

        }

        /// <summary>
        /// Signed in as the given login with the given key, against the host key the node shows.
        /// </summary>
        private static ValueTask<SSHClient> SignIn(WWCPNode     Node,
                                                   String       Username,
                                                   ISshHostKey  Key)

            => SSHClient.Connect("127.0.0.1",
                                 Node.SSHPort!.Value,
                                 new SSHClientOptions {
                                     Username       = User_Id.Parse(Username),
                                     VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                     Credentials    = [ Key ]
                                 });

        private Boolean Said(String What)
        {
            lock (said)
                return said.Any(line => line.Contains(What, StringComparison.Ordinal));
        }

        /// <summary>
        /// The answer of the time server to a plain NTP request - RFC 5905, version 4, mode 3 - or
        /// null where none came within two seconds.
        /// </summary>
        private static async Task<Byte[]?> AskPlainAsync(WWCPNode Node, IPPort NTPPort)
        {

            var address          = ListenAddressOf(Node);
            using var udpClient  = new UdpClient(address.AddressFamily);

            var request          = new Byte[48];
            request[0]           = 0x23;
            Random.Shared.NextBytes(request.AsSpan(40, 8));

            await udpClient.SendAsync(request, new IPEndPoint(address, NTPPort.ToUInt16()));

            try
            {
                return (await udpClient.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2))).Buffer;
            }
            catch (TimeoutException)
            {
                return null;
            }

        }

        private static IPPort FindFreeUDPPort()
        {
            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Any, 0));
            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);
        }

        /// <summary>
        /// The address the node listens on, as its SSH page says: where its time server binds too.
        /// </summary>
        private static System.Net.IPAddress ListenAddressOf(WWCPNode Node)

            => System.Net.IPAddress.Parse(Node.SSHConfigurationJSON()["listenAddress"]!.Value<String>()!.Trim('[', ']'));

        /// <summary>
        /// Whether the given UDP port can be had on the address the node listens on - which on
        /// Windows a socket on 0.0.0.0 would not tell: it shares a port with one on 127.0.0.1.
        /// </summary>
        private static Boolean UDPPortIsFree(WWCPNode Node, IPPort Port)
        {
            try
            {
                using var udpClient = new UdpClient(ListenAddressOf(Node).AddressFamily);
                udpClient.Client.ExclusiveAddressUse = true;
                udpClient.Client.Bind(new IPEndPoint(ListenAddressOf(Node), Port.ToUInt16()));
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        #endregion

    }

}
