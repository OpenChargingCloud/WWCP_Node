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

using System.Text;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

using NUnit.Framework;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a kind of node adds to its SSH server: subsystems besides the command line and SFTP, and
    /// logins besides its accounts - stations, which get the subsystems they may use and nothing else -
    /// each asked before it is served and while it lasts, and shown among the sessions.
    /// </summary>
    [TestFixture]
    public class SSHSubsystemTests
    {

        #region Data

        private const String Echo     = "echo@test.open.charging.cloud";
        private const String Other    = "other@test.open.charging.cloud";

        private static readonly Permission  UseEcho  = new ("echo", Operation.Run);

        private String                  directory    = "";
        private readonly List<WWCPNode> nodes        = [];
        private readonly List<String>   said         = [];
        private readonly ISshHostKey    rootKey      = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey    testerKey    = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey    supportKey   = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey    cs001Key     = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey    cs002Key     = SshHostKey.GenerateEd25519();

        #endregion

        #region (class) Stations

        /// <summary>
        /// The logins of a kind: stations, each with one key, the subsystems it may use, a group - and
        /// switched on or off.
        /// </summary>
        private sealed class Stations : ISSHSignIns
        {

            public sealed record Login(Byte[] Key, String[] Subsystems, String Group, Boolean Enabled = true);

            public ConcurrentDictionary<String, Login> Logins { get; } = new (StringComparer.Ordinal);

            public String PrincipalKind
                => "station";

            public Boolean Knows(String Username)
                => Logins.ContainsKey(Username);

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(Logins.TryGetValue(Request.Username, out var login) && login.Enabled && login.Key.AsSpan().SequenceEqual(Request.PublicKeyBlob));

            public IReadOnlySet<String> SubsystemsFor(String Username)
                => Logins.TryGetValue(Username, out var login)
                       ? new HashSet<String>(login.Subsystems, StringComparer.Ordinal)
                       : new HashSet<String>(StringComparer.Ordinal);

            public IReadOnlyList<String> GroupsOf(String Username)
                => Logins.TryGetValue(Username, out var login) ? [ login.Group ] : [];

            public String? WhyNoLongerIn(SshSessionInfo Session)
                => !Logins.TryGetValue(Session.Username, out var login)                                    ? $"there is no station '{Session.Username}' any more"
                 : !login.Enabled                                                                          ? $"the station '{Session.Username}' was switched off"
                 : Session.PublicKeyBlob is not Byte[] key || !key.AsSpan().SequenceEqual(login.Key)        ? $"the key is no longer the station's"
                 : null;

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-ssh-subsystems-" + Guid.NewGuid().ToString("N")[..12]);
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

        #region (private) Started(...) / SignIn(...) / helpers

        private String ConfigPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// A node with SSH and SFTP on, the given rules, root let in with a key, the role "tester" that
        /// may use Echo and "support" that may not - and, before it starts, what the test adds.
        /// </summary>
        private async Task<WWCPNode> Started(String              Rules    = "[]",
                                             Action<WWCPNode>?   Prepare  = null)
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                File.WriteAllText(ConfigPath,
                                  $$"""
                                  {
                                    "nts":   { "groups": { "legal": { "enabled": false } } },
                                    "ssh":   { "enabled": true, "port": {{TestPorts.Free()}}, "sftp": true, "accessRules": {{Rules}} },
                                    "roles": { "tester": [ "echo:run" ], "support": [ "dns:read" ] }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        Resources:         [ "echo" ],
                                        ConfigFile:        new WWCPConfigFile(ConfigPath),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                Prepare?.Invoke(made);

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

        /// <summary>
        /// Whether the given login with the given key gets in at all: refused at the door, it either
        /// can not connect or gets no session.
        /// </summary>
        private static async Task<Boolean> GetsIn(WWCPNode Node, String Username, ISshHostKey Key)
        {
            try
            {
                await using var client  = await SignIn(Node, Username, Key).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                var channel             = await client.Multiplexer.OpenChannelAsync("session").AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                await channel.CloseAsync();
                return true;
            }
            catch (Exception exception) when (exception is not TimeoutException)
            {
                return false;
            }
        }

        /// <summary>
        /// Serves a session by sending back what it is sent, until the channel ends or it is told to.
        /// </summary>
        private static SshSubsystemHandler Echoing(ConcurrentQueue<String>? Served = null)

            => async (context, token) => {

                Served?.Enqueue($"{context.Name} for {context.Session.Username}");

                var buffer = new Byte[1024];
                Int32 read;

                while ((read = await context.Channel.Input.ReadAsync(buffer, token)) > 0)
                    await context.Channel.SendDataAsync(buffer.AsMemory(0, read), token);

            };

        /// <summary>
        /// Serves a session by waiting for its channel to close - and pays no heed to its token.
        /// </summary>
        private static SshSubsystemHandler Stubborn()

            => async (context, token) => {
                await Task.Delay(Timeout.Infinite, context.Closed).ContinueWith(_ => { }, TaskScheduler.Default);
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

        /// <summary>
        /// Whether the given channel ends - reads to its end - within ten seconds.
        /// </summary>
        private static async Task<Boolean> Ends(SshMuxChannel Channel)
        {

            var buffer = new Byte[1024];

            using var within = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            try
            {
                while (await Channel.Input.ReadAsync(buffer, within.Token) > 0)
                { }
                return true;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (Exception)
            {
                return true;
            }

        }

        /// <summary>
        /// Whether the given subsystem is refused to the given client.
        /// </summary>
        private static async Task<Boolean> Refused(SshClient  Client,
                                                   String     Subsystem)
        {
            try
            {
                var channel = await Client.OpenSubsystemAsync(Subsystem).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                await channel.CloseAsync();
                return false;
            }
            catch (SshWireException)
            {
                return true;
            }
        }

        private static async Task<Boolean> Asks(SshClient Client, String Type, Byte[] Payload)
        {
            var channel = await Client.Multiplexer.OpenChannelAsync("session");
            return await channel.SendRequestAsync(Type, true, Payload);
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

        private static async Task<Boolean> GoneWithin(WWCPNode Node, Func<WWCPNode.SSHSession, Boolean> Which, TimeSpan Within)
        {

            var until = DateTime.UtcNow + Within;

            while (Node.SSHSessions.Any(Which) && DateTime.UtcNow < until)
                await Task.Delay(50);

            return !Node.SSHSessions.Any(Which);

        }

        private Stations StationsWith(params (String Name, ISshHostKey Key, String[] Subsystems, String Group)[] Logins)
        {

            var stations = new Stations();

            foreach (var (name, key, subsystems, group) in Logins)
                stations.Logins[name] = new Stations.Login(key.PublicKeyBlob, subsystems, group);

            return stations;

        }

        #endregion


        #region AnAccount_GetsASubsystem_OnlyWithThePermissionTheKindAskedFor

        [Test]
        [CancelAfter(60000)]
        public async Task AnAccount_GetsASubsystem_OnlyWithThePermissionTheKindAskedFor(CancellationToken CancellationToken)
        {

            var served = new ConcurrentQueue<String>();

            var node   = await Started(Prepare: made => {
                             made.AddSSHSubsystem(new SSHSubsystem(Echo,  "Echo",  Echoing(served), UseEcho));
                             made.AddSSHSubsystem(new SSHSubsystem(Other, "Other", Echoing(served)));
                         });

            await AccountIn(node, "tester",  "tester",  testerKey);
            await AccountIn(node, "support", "support", supportKey);

            await using var tester   = await SignIn(node, "tester",  testerKey);
            await using var support  = await SignIn(node, "support", supportKey);
            await using var root     = await SignIn(node, WWCPNode.DefaultAdminUser, rootKey);

            var echo          = await tester.OpenSubsystemAsync(Echo, CancellationToken);
            var echoed        = await EchoOf(echo, "hello");

            var supportEcho   = await Refused(support, Echo);
            var testerOther   = await Refused(tester,  Other);
            var rootOther     = await Refused(root,    Other);
            var unknown       = await Refused(tester,  "nothing@test.open.charging.cloud");

            Assert.Multiple(() => {
                Assert.That(echoed,       Is.EqualTo("hello"),  "the account with the permission was not served");
                Assert.That(served,       Is.EqualTo(new[] { $"{Echo} for tester" }));
                Assert.That(supportEcho,  Is.True,  "served to an account without the permission");
                Assert.That(testerOther,  Is.True,  "a subsystem for no account was served to an account");
                Assert.That(rootOther,    Is.True,  "a subsystem for no account was served to root");
                Assert.That(unknown,      Is.True,  "a subsystem nobody serves was served");
                Assert.That(Said("Refused Echo over SSH from"),                    Is.True);
                Assert.That(Said("'support' may not use Echo: that takes echo:run"), Is.True, "the log does not say why");
                Assert.That(Said($"Other is served to no account of this {node.Kind.Name}"), Is.True);
                Assert.That(Said("only the command line, SFTP, Echo (echo@test.open.charging.cloud) and Other (other@test.open.charging.cloud) are served"), Is.True,
                            "a subsystem nobody serves is not said with what is");
            });

        }

        #endregion

        #region AStation_SignsInWithItsKey_AndGetsItsSubsystems_AndNothingElse

        [Test]
        [CancelAfter(60000)]
        public async Task AStation_SignsInWithItsKey_AndGetsItsSubsystems_AndNothingElse(CancellationToken CancellationToken)
        {

            // It says it may have SFTP too: a station never gets it.
            var stations = StationsWith(("cs001", cs001Key, [ Echo, "sftp" ], "north"));

            var node     = await Started(Prepare: made => {
                               made.AddSSHSubsystem(new SSHSubsystem(Echo,  "Echo",  Echoing(), UseEcho));
                               made.AddSSHSubsystem(new SSHSubsystem(Other, "Other", Echoing(), UseEcho));
                               made.AddSSHSignIns(stations);
                           });

            var wrongKey = await GetsIn(node, "cs001", cs002Key);

            await using var station = await SignIn(node, "cs001", cs001Key);

            var echo     = await station.OpenSubsystemAsync(Echo, CancellationToken);
            var echoed   = await EchoOf(echo, "BootNotification");

            var other    = await Refused(station, Other);
            var shell    = await Asks(station, "shell", []);
            var exec     = await Asks(station, "exec",  SshSessionChannel.EncodeString("who"));

            Exception? sftp = null;

            try
            {
                await using var files = await station.OpenSftpClientAsync(CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken);
            }
            catch (Exception exception) when (exception is not TimeoutException)
            {
                sftp = exception;
            }

            Assert.Multiple(() => {
                Assert.That(wrongKey,  Is.False, "the station was let in with another's key");
                Assert.That(echoed,    Is.EqualTo("BootNotification"), "the station's subsystem was not served");
                Assert.That(other,     Is.True,  "a subsystem the station may not use was served");
                Assert.That(shell,     Is.False, "the station got the command line");
                Assert.That(exec,      Is.False, "the station ran a command");
                Assert.That(sftp,      Is.Not.Null, "the station got SFTP");
                Assert.That(Said("the station 'cs001' opened Echo over SSH from 127.0.0.1"), Is.True);
            });

        }

        #endregion

        #region AStation_IsConfined_WhateverTheKindSays

        /// <summary>
        /// What the door hands Hermod for a station: no terminal, no forwarding, its subsystems without
        /// SFTP - narrowed further by the kind's own entry, never widened.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task AStation_IsConfined_WhateverTheKindSays(CancellationToken CancellationToken)
        {

            var stations = StationsWith(("cs001", cs001Key, [ Echo, Other, "sftp" ], "north"));
            var node     = await Started(Prepare: made => made.AddSSHSignIns(stations));

            var door     = new NodeSSHAuthenticator(node, Passwords: true);
            var request  = new SshPublicKeyAuthRequest("cs001", "ssh-ed25519", cs001Key.PublicKeyBlob);

            var confined = await door.GetRestrictionsAsync(request, CancellationToken);
            var password = await door.AuthorizePasswordAsync("cs001", "anything", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(confined.AllowPty,             Is.False);
                Assert.That(confined.AllowPortForwarding,  Is.False);
                Assert.That(confined.PermittedSubsystems,  Is.EquivalentTo(new[] { Echo, Other }));
                Assert.That(password,                      Is.False, "a password opened a station");
            });

        }

        #endregion

        #region ANameThatIsAnAccountAndAStation_IsLetInAsNeither_AndTheStartSaysSo

        [Test]
        [CancelAfter(60000)]
        public async Task ANameThatIsAnAccountAndAStation_IsLetInAsNeither_AndTheStartSaysSo(CancellationToken CancellationToken)
        {

            // "root" is the first account of every node - and here a station's name as well.
            var stations = StationsWith((WWCPNode.DefaultAdminUser, cs001Key, [ Echo ], "north"));

            var node     = await Started(Prepare: made => {
                               made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing(), UseEcho));
                               made.AddSSHSignIns(stations);
                           });

            var asStation = await GetsIn(node, WWCPNode.DefaultAdminUser, cs001Key);
            var asAccount = await GetsIn(node, WWCPNode.DefaultAdminUser, rootKey);

            Assert.Multiple(() => {
                Assert.That(asStation, Is.False, "let in as the station");
                Assert.That(asAccount, Is.False, "let in as the account");
                Assert.That(Said($"'{WWCPNode.DefaultAdminUser}' is an account and a station of this {node.Kind.Name}, and is let in over SSH as neither"), Is.True,
                            "neither the start nor the attempt said so");
                Assert.That(node.SSHLoginOf(WWCPNode.DefaultAdminUser).Clash, Is.Not.Null);
            });

        }

        #endregion

        #region TheAccessRules_SeeAStationAsOne_WithItsGroup

        [Test]
        [CancelAfter(60000)]
        public async Task TheAccessRules_SeeAStationAsOne_WithItsGroup(CancellationToken CancellationToken)
        {

            var stations = StationsWith(("cs001", cs001Key, [ Echo ], "north"),
                                        ("cs002", cs002Key, [ Echo ], "south"));

            var node     = await Started($$"""[ "deny principal=group:south service=subsystem:{{Echo}} # not the southern ones" ]""",
                                         made => {
                                             made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing(), UseEcho));
                                             made.AddSSHSignIns(stations);
                                         });

            await using var north = await SignIn(node, "cs001", cs001Key);
            await using var south = await SignIn(node, "cs002", cs002Key);

            var northRefused = await Refused(north, Echo);
            var southRefused = await Refused(south, Echo);

            Assert.Multiple(() => {
                Assert.That(northRefused, Is.False, "a station no rule refuses was refused");
                Assert.That(southRefused, Is.True,  "the rule for the station's group did not refuse it");
                Assert.That(Said($"SSH access rule 1 (deny principal=group:south service=subsystem:{Echo} # not the southern ones) refuses station:cs002 subsystem:{Echo}"), Is.True,
                            "the log does not say which rule refused which station");
            });

        }

        #endregion

        #region AStationSwitchedOff_IsSignedOut_AtOnceWhenTheKindAsks

        /// <summary>
        /// A handler that pays no heed to its token is ended all the same: its channel is closed.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task AStationSwitchedOff_IsSignedOut_AtOnceWhenTheKindAsks(CancellationToken CancellationToken)
        {

            var stations = StationsWith(("cs001", cs001Key, [ Echo ], "north"));

            var node     = await Started(Prepare: made => {
                               made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Stubborn(), UseEcho));
                               made.AddSSHSignIns(stations);
                           });

            node.SSHSessionRecheckEvery = TimeSpan.FromMinutes(10);   // so that nothing but the kind's asking ends it

            await using var station = await SignIn(node, "cs001", cs001Key);

            var echo    = await station.OpenSubsystemAsync(Echo, CancellationToken);

            var shown   = await Task.Run(async () => {
                              for (var waited = 0; waited < 100 && !node.SSHSessions.Any(session => session.Kind == WWCPNode.SSHSession.Subsystem); waited++)
                                  await Task.Delay(50, CancellationToken);
                              return node.SSHSessions.Any(session => session.Kind == WWCPNode.SSHSession.Subsystem);
                          }, CancellationToken);

            stations.Logins["cs001"] = stations.Logins["cs001"] with { Enabled = false };

            var ended   = node.RecheckSSHSessions();
            var closed  = await Ends(echo);
            var gone    = await GoneWithin(node, session => session.Kind == WWCPNode.SSHSession.Subsystem, TimeSpan.FromSeconds(10));

            var again   = await GetsIn(node, "cs001", cs001Key);

            var signedOut = await SaidWithin("The station 'cs001' was signed out of Echo over SSH from 127.0.0.1", TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {
                Assert.That(shown,      Is.True,  "the session was never among the sessions");
                Assert.That(ended,      Is.EqualTo(1));
                Assert.That(closed,     Is.True,  "the station's channel was not closed, its handler paying no heed to its token");
                Assert.That(gone,       Is.True,  "the session is still among the sessions");
                Assert.That(again,      Is.False, "the station switched off was let in again");
                Assert.That(signedOut,  Is.True,  "the log does not say the station was signed out");
                Assert.That(Said("the station 'cs001' was switched off"), Is.True, "the log does not say why");
            });

        }

        #endregion

        #region AStationNoLongerAllowedASubsystem_IsSignedOutOfIt

        /// <summary>
        /// Its key still lets it in - but the subsystem it is at is no longer one it may use.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task AStationNoLongerAllowedASubsystem_IsSignedOutOfIt(CancellationToken CancellationToken)
        {

            var stations = StationsWith(("cs001", cs001Key, [ Echo, Other ], "north"));

            var node     = await Started(Prepare: made => {
                               made.AddSSHSubsystem(new SSHSubsystem(Echo,  "Echo",  Echoing(), UseEcho));
                               made.AddSSHSubsystem(new SSHSubsystem(Other, "Other", Echoing(), UseEcho));
                               made.AddSSHSignIns(stations);
                           });

            node.SSHSessionRecheckEvery = TimeSpan.FromMinutes(10);

            await using var station = await SignIn(node, "cs001", cs001Key);

            var echo   = await station.OpenSubsystemAsync(Echo,  CancellationToken);
            var other  = await station.OpenSubsystemAsync(Other, CancellationToken);

            Assert.That(await EchoOf(echo,  "one"), Is.EqualTo("one"));
            Assert.That(await EchoOf(other, "two"), Is.EqualTo("two"));

            stations.Logins["cs001"] = stations.Logins["cs001"] with { Subsystems = [ Other ] };

            var ended  = node.RecheckSSHSessions();
            var closed = await Ends(echo);
            var stays  = await EchoOf(other, "three");

            Assert.Multiple(() => {
                Assert.That(ended,   Is.EqualTo(1));
                Assert.That(closed,  Is.True, "the session of the subsystem the station may no longer use went on");
                Assert.That(stays,   Is.EqualTo("three"), "the session of the subsystem it still may use was ended too");
            });

            Assert.That(await SaidWithin("the station 'cs001' may not use Echo", TimeSpan.FromSeconds(10)), Is.True);

        }

        #endregion

        #region AStationsKeyTakenOut_EndsItsSession_OnTheRecheck

        [Test]
        [CancelAfter(60000)]
        public async Task AStationsKeyTakenOut_EndsItsSession_OnTheRecheck(CancellationToken CancellationToken)
        {

            var stations = StationsWith(("cs001", cs001Key, [ Echo ], "north"));

            var node     = await Started(Prepare: made => {
                               made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing(), UseEcho));
                               made.AddSSHSignIns(stations);
                               made.SSHSessionRecheckEvery = TimeSpan.FromMilliseconds(200);
                           });

            await using var station = await SignIn(node, "cs001", cs001Key);

            var echo     = await station.OpenSubsystemAsync(Echo, CancellationToken);
            var before   = await EchoOf(echo, "Heartbeat");

            stations.Logins["cs001"] = stations.Logins["cs001"] with { Key = cs002Key.PublicKeyBlob };

            var closed   = await Ends(echo);

            Assert.Multiple(() => {
                Assert.That(before,  Is.EqualTo("Heartbeat"));
                Assert.That(closed,  Is.True, "the session whose key was taken out went on");
            });

            Assert.That(await SaidWithin("the key is no longer the station's", TimeSpan.FromSeconds(10)), Is.True);

        }

        #endregion

        #region ASubsystemRemoved_EndsItsSessions_AndIsRefusedAfter

        [Test]
        [CancelAfter(60000)]
        public async Task ASubsystemRemoved_EndsItsSessions_AndIsRefusedAfter(CancellationToken CancellationToken)
        {

            var node = await Started(Prepare: made => made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing(), UseEcho)));

            node.SSHSessionRecheckEvery = TimeSpan.FromMinutes(10);

            await AccountIn(node, "tester", "tester", testerKey);

            await using var tester = await SignIn(node, "tester", testerKey);

            var echo    = await tester.OpenSubsystemAsync(Echo, CancellationToken);
            var before  = await EchoOf(echo, "hello");

            var removed = node.RemoveSSHSubsystem(Echo);
            var closed  = await Ends(echo);
            var after   = await Refused(tester, Echo);
            var twice   = node.RemoveSSHSubsystem(Echo);

            Assert.Multiple(() => {
                Assert.That(before,   Is.EqualTo("hello"));
                Assert.That(removed,  Is.True);
                Assert.That(closed,   Is.True,  "the session of the subsystem removed went on");
                Assert.That(after,    Is.True,  "the subsystem removed was served");
                Assert.That(twice,    Is.False);
                Assert.That(node.SSHSubsystems, Is.Empty);
                Assert.That(Said("Echo is no longer served over SSH: 1 session(s) ended."), Is.True);
            });

        }

        #endregion

        #region WhoAndTheSSHPage_SayWhoIsAtWhichSubsystem

        [Test]
        [CancelAfter(60000)]
        public async Task WhoAndTheSSHPage_SayWhoIsAtWhichSubsystem(CancellationToken CancellationToken)
        {

            var stations = StationsWith(("cs001", cs001Key, [ Echo ], "north"));

            var node     = await Started(Prepare: made => {
                               made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing(), UseEcho));
                               made.AddSSHSignIns(stations);
                           });

            await using var station = await SignIn(node, "cs001", cs001Key);

            var echo     = await station.OpenSubsystemAsync(Echo, CancellationToken);
            Assert.That(await EchoOf(echo, "hello"), Is.EqualTo("hello"));

            using var cli = new NodeCLI(node);

            var who       = await cli.Execute("who");
            var page      = node.SSHConfigurationJSON()["sessions"] as JArray;
            var session   = page?.OfType<JObject>().SingleOrDefault(one => one["kind"]?.Value<String>() == WWCPNode.SSHSession.Subsystem);
            var principal = node.SSHPrincipalFor(new SshSessionInfo("made-up", "cs001", "publickey", cs001Key.PublicKeyBlob, null, null, null, SshSessionRestrictions.None));

            Assert.Multiple(() => {
                Assert.That(who.Any(line => Regex.IsMatch(line, @"^cs001 \(station\)\s+with Echo from 127\.0\.0\.1:\d+, since \d\d:\d\d, key SHA256:")), Is.True,
                            String.Join(Environment.NewLine, who));
                Assert.That(session?["account"]?.  Value<String>(),  Is.EqualTo("cs001"));
                Assert.That(session?["principal"]?.Value<String>(),  Is.EqualTo("station"));
                Assert.That(session?["subsystem"]?.Value<String>(),  Is.EqualTo(Echo));
                Assert.That(session?["label"]?.    Value<String>(),  Is.EqualTo("Echo"));
                Assert.That(principal.ToString(),                    Is.EqualTo("station:cs001"));
                Assert.That(principal.Groups,                        Is.EqualTo(new[] { "north" }));
            });

        }

        #endregion

        #region SubsystemsAndLogins_ThatCannotBe_AreRefused

        [Test]
        [CancelAfter(60000)]
        public async Task SubsystemsAndLogins_ThatCannotBe_AreRefused(CancellationToken CancellationToken)
        {

            var node = await Started(Prepare: made => made.AddSSHSubsystem(new SSHSubsystem(Echo, "Echo", Echoing(), UseEcho)));

            Assert.Multiple(() => {
                Assert.That(() => node.AddSSHSubsystem(new SSHSubsystem("sftp",      "Files", Echoing())), Throws.ArgumentException, "'sftp' was taken from the node");
                Assert.That(() => node.AddSSHSubsystem(new SSHSubsystem("with space", "X",    Echoing())), Throws.ArgumentException);
                Assert.That(() => node.AddSSHSubsystem(new SSHSubsystem("",          "X",     Echoing())), Throws.ArgumentException);
                Assert.That(() => node.AddSSHSubsystem(new SSHSubsystem(Echo,        "Again", Echoing())), Throws.ArgumentException, "a subsystem was served twice");
                Assert.That(() => node.AddSSHSubsystem(new SSHSubsystem(Other,       " ",     Echoing())), Throws.ArgumentException, "a subsystem without a label");
                Assert.That(() => node.AddSSHSignIns(new AccountsAgain()),                                Throws.ArgumentException, "logins of the kind 'account'");
                Assert.That(() => { node.AddSSHSignIns(new Stations()); node.AddSSHSignIns(new Stations()); }, Throws.ArgumentException, "two kinds of logins named alike");
                Assert.That(node.SSHSubsystems.Select(subsystem => subsystem.Name), Is.EqualTo(new[] { Echo }));
            });

        }

        private sealed class AccountsAgain : ISSHSignIns
        {
            public String PrincipalKind => SSHPrincipal.Account;
            public Boolean Knows(String Username) => false;
            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default) => ValueTask.FromResult(false);
            public IReadOnlySet<String> SubsystemsFor(String Username) => new HashSet<String>();
            public IReadOnlyList<String> GroupsOf(String Username) => [];
            public String? WhyNoLongerIn(SshSessionInfo Session) => null;
        }

        #endregion

    }

}
