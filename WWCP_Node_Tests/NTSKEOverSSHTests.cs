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
using System.Text;
using System.Net.Sockets;
using System.Collections.Concurrent;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// NTS key establishment on the node's SSH server (section 8.3 of the NTS-over-SSH white paper):
    /// a station gets its NTS keys and cookies with the key it signs in with, over the connection it
    /// has for OCPP anyway, and the cookies work with the NTP server they are for.
    /// </summary>
    [TestFixture]
    public class NTSKEOverSSHTests
    {

        #region Data

        /// <summary>
        /// Stands in for OCPP: another subsystem on the same connection.
        /// </summary>
        private const String Echo = "echo@test.open.charging.cloud";

        private static readonly Permission  UseNTSKE   = Permission.Run("ntske");

        private static readonly IPPort      ntsKEPort  = IPPort.Parse(TestPorts.Free());
        private static readonly IPPort      ntpPort    = FindFreeUDPPort();

        private NTSServer?                  server;

        private String                      directory  = "";
        private readonly List<WWCPNode>     nodes      = [];
        private readonly List<String>       said       = [];
        private readonly ISshHostKey        rootKey    = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey        cs001Key   = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey        cs002Key   = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey        backendKey = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey        supportKey = SshHostKey.GenerateEd25519();

        #endregion

        #region (class) Stations

        /// <summary>
        /// The logins of a kind: stations, each with one key and the subsystems it may use.
        /// </summary>
        private sealed class Stations : ISSHSignIns
        {

            public sealed record Login(Byte[] Key, String[] Subsystems);

            public ConcurrentDictionary<String, Login> Logins { get; } = new (StringComparer.Ordinal);

            public String PrincipalKind
                => "station";

            public Boolean Knows(String Username)
                => Logins.ContainsKey(Username);

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(Logins.TryGetValue(Request.Username, out var login) && login.Key.AsSpan().SequenceEqual(Request.PublicKeyBlob));

            public IReadOnlySet<String> SubsystemsFor(String Username)
                => Logins.TryGetValue(Username, out var login)
                       ? new HashSet<String>(login.Subsystems, StringComparer.Ordinal)
                       : new HashSet<String>(StringComparer.Ordinal);

            public IReadOnlyList<String> GroupsOf(String Username)
                => [ "stations" ];

            public String? WhyNoLongerIn(SshSessionInfo Session)
                => Logins.ContainsKey(Session.Username) ? null : $"there is no station '{Session.Username}' any more";

        }

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        /// <summary>
        /// The NTS server whose keys and cookies the node hands out: no SSH listener of its own, the
        /// node's is the one.
        /// </summary>
        [OneTimeSetUp]
        public async Task StartTheTimeServer()
        {

            server = new NTSServer(
                         NTSKEPort:           ntsKEPort,
                         NTSPort:             ntpPort,
                         MasterKeysFilePath:  null
                     );

            await server.Start();

        }

        [OneTimeTearDown]
        public async Task StopTheTimeServer()
        {
            if (server is not null)
                await server.ShutdownAsync();
        }

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-ntske-over-ssh-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region AStation_GetsItsKeysOverTheNodesSSHServer_AndTheCookiesWork

        [Test]
        [CancelAfter(60000)]
        public async Task AStation_GetsItsKeysOverTheNodesSSHServer_AndTheCookiesWork(CancellationToken CancellationToken)
        {

            var node = await Started(made => {
                           made.AddSSHSignIns(StationsWith(("cs001", cs001Key, [ NTSKE_SSH.SubsystemName ])));
                           made.ServeNTSKEOverSSH(server!);
                       });

            await using var cs001  = await SignIn(node, "cs001", cs001Key);
            var ntsClient          = NewNTSClient();

            var ntsKEResult        = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);

            Assert.That(ntsKEResult.Success, Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.Response!.Cookies.Count(), Is.EqualTo(NTSServer.MaxCookiesPerResponse));

            // The node's SSH server hands the handler the exporter of the station's connection, so
            // the station gets option A.
            Assert.That(SelectedMethodOf(ntsKEResult), Is.EqualTo(SSHKeyBindingMethods.Exporter));

            // The server put its keys into the cookies, the station derived its own from the
            // exporter of its connection: a query both sides can read proves they are the same.
            var ntsQueryResult     = await ntsClient.QueryTime(NTSKEResponse: ntsKEResult.Response,
                                                               Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success, Is.True, ntsQueryResult.ErrorMessage);
            Assert.That(await SaidWithin("the station 'cs001' opened NTS-KE over SSH", TimeSpan.FromSeconds(5)), Is.True,
                        "the log does not say who opened NTS-KE");

        }

        #endregion

        #region AStation_WithoutTheSubsystem_IsRefused_AndToldSo

        [Test]
        [CancelAfter(60000)]
        public async Task AStation_WithoutTheSubsystem_IsRefused_AndToldSo(CancellationToken CancellationToken)
        {

            var node = await Started(made => {
                           made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing()));
                           made.AddSSHSignIns(StationsWith(("cs002", cs002Key, [ Echo ])));
                           made.ServeNTSKEOverSSH(server!);
                       });

            await using var cs002  = await SignIn(node, "cs002", cs002Key);

            var ntsKEResult        = await NewNTSClient().GetNTSKERecordsOverSSH(cs002, CancellationToken: CancellationToken);

            Assert.That(ntsKEResult.Success,       Is.False);
            Assert.That(ntsKEResult.ErrorCategory, Is.EqualTo(NTSKEErrorCategory.SSHSubsystem), ntsKEResult.ErrorMessage);

        }

        #endregion

        #region OCPPAndNTSKE_ShareOneConnection

        [Test]
        [CancelAfter(60000)]
        public async Task OCPPAndNTSKE_ShareOneConnection(CancellationToken CancellationToken)
        {

            var node = await Started(made => {
                           made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing()));
                           made.AddSSHSignIns(StationsWith(("cs001", cs001Key, [ Echo, NTSKE_SSH.SubsystemName ])));
                           made.ServeNTSKEOverSSH(server!);
                       });

            await using var cs001  = await SignIn(node, "cs001", cs001Key);
            var ntsClient          = NewNTSClient();

            // The connection for OCPP, opened first and kept open, as a station keeps it for weeks.
            var ocpp               = await cs001.OpenSubsystemAsync(Echo, CancellationToken);
            var before             = await EchoOf(ocpp, "BootNotification");

            // Three key exchanges as further channels of it, e.g. a day apart. Each takes the
            // exporter of the connection (option A) with a nonce of its own, and so keys of its own.
            var first              = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);
            var second             = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);
            var third              = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);

            var after              = await EchoOf(ocpp, "Heartbeat");

            Assert.Multiple(() => {
                Assert.That(before,                    Is.EqualTo("BootNotification"));
                Assert.That(first. Success,            Is.True, first. ErrorMessage);
                Assert.That(second.Success,            Is.True, second.ErrorMessage);
                Assert.That(third. Success,            Is.True, third. ErrorMessage);
                Assert.That(SelectedMethodOf(first),   Is.EqualTo(SSHKeyBindingMethods.Exporter));
                Assert.That(SelectedMethodOf(second),  Is.EqualTo(SSHKeyBindingMethods.Exporter));
                Assert.That(SelectedMethodOf(third),   Is.EqualTo(SSHKeyBindingMethods.Exporter));
                Assert.That(second.Response!.C2SKey,   Is.Not.EqualTo(first. Response!.C2SKey), "two exchanges derived the same keys");
                Assert.That(third. Response!.C2SKey,   Is.Not.EqualTo(second.Response!.C2SKey), "two exchanges derived the same keys");
                Assert.That(third. Response!.C2SKey,   Is.Not.EqualTo(first. Response!.C2SKey), "two exchanges derived the same keys");
                Assert.That(after,                     Is.EqualTo("Heartbeat"), "the OCPP channel did not outlast the key exchanges");
            });

        }

        #endregion

        #region AnAccount_GetsNTSKE_OnlyWithThePermission

        [Test]
        [CancelAfter(60000)]
        public async Task AnAccount_GetsNTSKE_OnlyWithThePermission(CancellationToken CancellationToken)
        {

            var node = await Started(made => made.ServeNTSKEOverSSH(server!, UseNTSKE));

            await AccountIn(node, "backend", "timekeeper", backendKey);
            await AccountIn(node, "support", "support",    supportKey);

            await using var backend  = await SignIn(node, "backend", backendKey);
            await using var support  = await SignIn(node, "support", supportKey);

            var backendResult        = await NewNTSClient().GetNTSKERecordsOverSSH(backend, CancellationToken: CancellationToken);
            var supportResult        = await NewNTSClient().GetNTSKERecordsOverSSH(support, CancellationToken: CancellationToken);

            Assert.Multiple(() => {
                Assert.That(backendResult.Success,       Is.True,  backendResult.ErrorMessage);
                Assert.That(supportResult.Success,       Is.False, "served to an account without the permission");
                Assert.That(supportResult.ErrorCategory, Is.EqualTo(NTSKEErrorCategory.SSHSubsystem));
                Assert.That(Said("'support' may not use NTS-KE: that takes ntske:run"), Is.True, "the log does not say why");
            });

        }

        #endregion

        #region StoppingNTSKE_RefusesTheNextExchange

        [Test]
        [CancelAfter(60000)]
        public async Task StoppingNTSKE_RefusesTheNextExchange(CancellationToken CancellationToken)
        {

            var node = await Started(made => {
                           made.AddSSHSignIns(StationsWith(("cs001", cs001Key, [ NTSKE_SSH.SubsystemName ])));
                           made.ServeNTSKEOverSSH(server!);
                       });

            await using var cs001  = await SignIn(node, "cs001", cs001Key);
            var ntsClient          = NewNTSClient();

            var served             = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);
            var stopped            = node.StopServingNTSKEOverSSH();
            var stoppedAgain       = node.StopServingNTSKEOverSSH();
            var refused            = await ntsClient.GetNTSKERecordsOverSSH(cs001, CancellationToken: CancellationToken);

            Assert.Multiple(() => {
                Assert.That(served. Success,       Is.True, served.ErrorMessage);
                Assert.That(stopped,               Is.True);
                Assert.That(stoppedAgain,          Is.False);
                Assert.That(refused.Success,       Is.False);
                Assert.That(refused.ErrorCategory, Is.EqualTo(NTSKEErrorCategory.SSHSubsystem));
                Assert.That(() => node.ServeNTSKEOverSSH(server!), Throws.Nothing, "it can not be served again");
                Assert.That(() => node.ServeNTSKEOverSSH(server!), Throws.ArgumentException, "it was served twice");
            });

        }

        #endregion


        #region (private) Started(Prepare) / AccountIn(...) / SignIn(...) / helpers

        private String ConfigPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// A node with SSH on, root let in with a key, the role "timekeeper" that may use NTS-KE and
        /// "support" that may not - and, before it starts, what the test adds.
        /// </summary>
        private async Task<WWCPNode> Started(Action<WWCPNode> Prepare)
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                File.WriteAllText(ConfigPath,
                                  $$"""
                                  {
                                    "nts":   { "groups": { "legal": { "enabled": false } } },
                                    "ssh":   { "enabled": true, "port": {{TestPorts.Free()}} },
                                    "roles": { "timekeeper": [ "ntske:run" ], "support": [ "dns:read" ] }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        Resources:         [ "ntske" ],
                                        ConfigFile:        new WWCPConfigFile(ConfigPath),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                Prepare(made);

                nodes.Add(made);

                return made;

            });

            var added = await node.AuthorizeSSHKey(WWCPNode.DefaultAdminUser, SshPublicKey.FromHostKey(rootKey).ToAuthorizedKeyLine());
            Assert.That(added.IsAdded || added.Outcome == AddSSHKeyOutcome.AlreadyThere, Is.True, added.Reason);

            return node;

        }

        /// <summary>
        /// An account of the given name in the group of the given role, let in with the given key.
        /// </summary>
        private static async Task AccountIn(WWCPNode     Node,
                                            String       Name,
                                            String       Role,
                                            ISshHostKey  Key)
        {

            Assert.That(Node.ExtAPI.TryGetOrganization(Organization_Id.Parse(Node.Kind.Organization), out var organization) &&
                        organization is Organization, Is.True);

            await Node.ExtAPI.CreateUser(User_Id.Parse(Name),
                                         I18NString.Create(Languages.en, Name),
                                         SimpleEMailAddress.Parse($"{Name}@localhost"),
                                         User2OrganizationEdgeLabel.IsMember,
                                         (Organization) organization!,
                                         Password:                  "Not-Used-Here-1",
                                         SkipDefaultNotifications:  true,
                                         SkipNewUserEMail:          true,
                                         SkipNewUserNotifications:  true,
                                         AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                         IsAuthenticated:           true);

            Assert.That(Node.ExtAPI.TryGetUser(User_Id.Parse(Name), out var account) && account is User, Is.True);
            Assert.That(Node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group) && group is UserGroup, Is.True);

            await Node.ExtAPI.AddUserToUserGroup((User) account!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            var added = await Node.AuthorizeSSHKey(Name, SshPublicKey.FromHostKey(Key).ToAuthorizedKeyLine());
            Assert.That(added.IsAdded, Is.True, added.Reason);

        }

        /// <summary>
        /// Signed in as the given login with the given key, against the host key the node shows.
        /// </summary>
        private static ValueTask<SshClient> SignIn(WWCPNode     Node,
                                                   String       Username,
                                                   ISshHostKey  Key)

            => SshClient.ConnectAsync("127.0.0.1",
                                      Node.SSHPort!.Value.ToUInt16(),
                                      new SshClientOptions {
                                          Username       = Username,
                                          VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                          Credentials    = [ Key ]
                                      });

        private static NTSClient NewNTSClient()

            => new (
                   DomainName.Localhost,
                   NTP_Port:             ntpPort,
                   IPVersionPreference:  IPVersionPreference.IPv4Only
               );

        /// <summary>
        /// Where the keys of a key exchange came from: the exporter of the connection (option A)
        /// or the secret the server sent (option B).
        /// </summary>
        private static SSHKeyBindingMethods? SelectedMethodOf(NTSKEResult Result)

            => Result.Response?.NTSKERecords.OfType<SSHKeyBinding>().SingleOrDefault() is SSHKeyBinding keyBinding &&
               keyBinding.TryGetSelection(out var method, out _, out _)
                   ? method
                   : null;

        private static Stations StationsWith(params (String Name, ISshHostKey Key, String[] Subsystems)[] Logins)
        {

            var stations = new Stations();

            foreach (var (name, key, subsystems) in Logins)
                stations.Logins[name] = new Stations.Login(key.PublicKeyBlob, subsystems);

            return stations;

        }

        /// <summary>
        /// Serves a session by sending back what it is sent, until the channel ends.
        /// </summary>
        private static SshSubsystemHandler Echoing()

            => async (context, token) => {

                var buffer = new Byte[1024];
                Int32 read;

                while ((read = await context.Channel.Input.ReadAsync(buffer, token)) > 0)
                    await context.Channel.SendDataAsync(buffer.AsMemory(0, read), token);

            };

        /// <summary>
        /// What comes back for the given text on the given channel, within ten seconds.
        /// </summary>
        private static async Task<String> EchoOf(SshMuxChannel  Channel,
                                                 String         Text)
        {

            await Channel.SendDataAsync(Encoding.UTF8.GetBytes(Text));

            var back   = new StringBuilder();
            var buffer = new Byte[1024];

            using var within = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            try
            {
                while (back.Length < Text.Length &&
                       await Channel.Input.ReadAsync(buffer, within.Token) is var read && read > 0)
                    back.Append(Encoding.UTF8.GetString(buffer, 0, read));
            }
            catch (OperationCanceledException)
            { }

            return back.ToString();

        }

        private Boolean Said(String What)
        {
            lock (said)
                return said.Any(line => line.Contains(What, StringComparison.Ordinal));
        }

        private async Task<Boolean> SaidWithin(String What, TimeSpan Within)
        {

            var until = DateTime.UtcNow + Within;

            while (!Said(What) && DateTime.UtcNow < until)
                await Task.Delay(50);

            return Said(What);

        }

        private static IPPort FindFreeUDPPort()
        {
            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);
        }

        #endregion

    }

}
