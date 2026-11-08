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

using System.Collections.Concurrent;

using NUnit.Framework;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The connections of each kind that signs in over SSH - the node's accounts, and the logins a kind
    /// of node lets in besides, its stations - counted apart, so that stations filling the server leave
    /// room for an account, and the other way round.
    /// </summary>
    [TestFixture]
    public class SSHConnectionLimitTests
    {

        #region Data

        private String                   directory  = "";
        private readonly List<WWCPNode>  nodes      = [];
        private readonly List<SshClient> clients    = [];
        private readonly List<String>    said       = [];
        private readonly ISshHostKey     rootKey    = SshHostKey.GenerateEd25519();
        private readonly ISshHostKey[]   keys       = [ SshHostKey.GenerateEd25519(), SshHostKey.GenerateEd25519(), SshHostKey.GenerateEd25519() ];

        private const String Full = "station connection(s) are open, as many as ssh.maxConnections lets in";

        #endregion

        #region (class) Stations / ManualClock

        /// <summary>
        /// The logins of a kind: stations cs001, cs002 and cs003, each with its key, and no subsystem -
        /// signed in is all they need to be here.
        /// </summary>
        private sealed class Stations(ISshHostKey[] Keys) : ISSHSignIns
        {

            private readonly Dictionary<String, Byte[]> logins = Enumerable.Range(0, Keys.Length).
                                                                     ToDictionary(n => $"cs00{n + 1}", n => Keys[n].PublicKeyBlob, StringComparer.Ordinal);

            public String PrincipalKind
                => "station";

            public Boolean Knows(String Username)
                => logins.ContainsKey(Username);

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(logins.TryGetValue(Request.Username, out var key) && key.AsSpan().SequenceEqual(Request.PublicKeyBlob));

            public IReadOnlySet<String> SubsystemsFor(String Username)
                => new HashSet<String>(StringComparer.Ordinal);

            public IReadOnlyList<String> GroupsOf(String Username)
                => [];

            public String? WhyNoLongerIn(SshSessionInfo Session)
                => logins.ContainsKey(Session.Username) ? null : $"there is no station '{Session.Username}' any more";

        }

        /// <summary>
        /// A clock that moves when it is told to.
        /// </summary>
        private sealed class ManualClock : TimeProvider
        {

            private Int64 ticks = DateTimeOffset.UtcNow.UtcTicks;

            public override DateTimeOffset GetUtcNow()
                => new (Interlocked.Read(ref ticks), TimeSpan.Zero);

            public void Advance(TimeSpan By)
                => Interlocked.Add(ref ticks, By.Ticks);

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-ssh-limits-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
            lock (said) said.Clear();
        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var client in clients)
            {
                try { await client.DisposeAsync(); } catch (Exception) { }
            }

            clients.Clear();

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

        #region (private) Started(...) / Held(...) / helpers

        private String ConfigPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// A node with SSH on, the given limits in its "ssh" section, the stations cs001 to cs003 let in
        /// besides its accounts, and root with a key.
        /// </summary>
        private async Task<WWCPNode> Started(String?        MaxConnections  = null,
                                             TimeProvider?  TimeProvider    = null)
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var limits = MaxConnections is not null ? $", \"maxConnections\": {MaxConnections}" : "";

                File.WriteAllText(ConfigPath,
                                  $$"""
                                  {
                                    "nts":   { "groups": { "legal": { "enabled": false } } },
                                    "ssh":   { "enabled": true, "port": {{TestPorts.Free()}}{{limits}} }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(ConfigPath),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        TimeProvider:      TimeProvider,
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                made.AddSSHSignIns(new Stations(keys));

                nodes.Add(made);

                return made;

            });

            var added = await node.AuthorizeSSHKey(WWCPNode.DefaultAdminUser, SshPublicKey.FromHostKey(rootKey).ToAuthorizedKeyLine());
            Assert.That(added.IsAdded || added.Outcome == AddSSHKeyOutcome.AlreadyThere, Is.True, added.Reason);

            return node;

        }

        /// <summary>
        /// A connection of the given login with the given key that got in, kept open - or null where it
        /// was refused at the door: it then either can not connect or gets no channel.
        /// </summary>
        private async Task<SshClient?> Held(WWCPNode     Node,
                                            String       Username,
                                            ISshHostKey  Key)
        {

            SshClient? client = null;

            try
            {

                client = await SshClient.ConnectAsync("127.0.0.1",
                                                      Node.SSHPort!.Value.ToUInt16(),
                                                      new SshClientOptions {
                                                          Username       = Username,
                                                          VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                                          Credentials    = [ Key ]
                                                      }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

                var channel = await client.Multiplexer.OpenChannelAsync("session").AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                await channel.CloseAsync();

                clients.Add(client);

                return client;

            }
            catch (Exception exception) when (exception is not TimeoutException)
            {
                if (client is not null)
                    await client.DisposeAsync();
                return null;
            }

        }

        private static JObject ByKind(WWCPNode Node, String Kind)
            => (JObject) Node.SSHConfigurationJSON()["limits"]!["byKind"]![Kind]!;

        /// <summary>
        /// Whether the node counts the given number of connections of the given kind within ten seconds.
        /// </summary>
        private static async Task<Boolean> CountsWithin(WWCPNode Node, String Kind, Int32 Connections)
        {

            var until = DateTime.UtcNow + TimeSpan.FromSeconds(10);

            while (Node.SSHConnectionsOf(Kind) != Connections && DateTime.UtcNow < until)
                await Task.Delay(50);

            return Node.SSHConnectionsOf(Kind) == Connections;

        }

        private Int32 Saids(String What)
        {
            lock (said)
                return said.Count(line => line.Contains(What, StringComparison.Ordinal));
        }

        /// <summary>
        /// How many lines say the given text, once no new one came for a third of a second.
        /// </summary>
        private async Task<Int32> SettledSaids(String What)
        {

            var until = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            var count = Saids(What);

            while (DateTime.UtcNow < until)
            {
                await Task.Delay(330);
                var now = Saids(What);
                if (now == count)
                    break;
                count = now;
            }

            return count;

        }

        private String[] Lines(String What)
        {
            lock (said)
                return [ .. said.Where(line => line.Contains(What, StringComparison.Ordinal)) ];
        }

        #endregion


        #region EachKind_HasConnectionsOfItsOwn

        /// <summary>
        /// Two stations fill what stations may have, and an account still gets in; the account fills its
        /// own, and the stations do not get it; a station that leaves makes room for the next.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task EachKind_HasConnectionsOfItsOwn(CancellationToken CancellationToken)
        {

            var node   = await Started(MaxConnections: """{ "account": 1, "station": 2 }""");

            var cs001  = await Held(node, "cs001", keys[0]);
            var cs002  = await Held(node, "cs002", keys[1]);

            await SettledSaids(", and was refused: ");

            Assert.That(cs001,                                Is.Not.Null, "the first station");
            Assert.That(cs002,                                Is.Not.Null, "the second station");
            Assert.That(await Held(node, "cs003", keys[2]),   Is.Null,     "a third station, where two may be");
            Assert.That(await Held(node, "root",  rootKey),   Is.Not.Null, "an account, beside two stations");
            Assert.That(await Held(node, "root",  rootKey),   Is.Null,     "a second connection of an account, where one may be");

            await SettledSaids(", and was refused: ");

            Assert.Multiple(() => {
                Assert.That(node.SSHConnectionsOf("account"),                      Is.EqualTo(1));
                Assert.That(node.SSHConnectionsOf("station"),                      Is.EqualTo(2));
                Assert.That(ByKind(node, "account").Value<Int32>("maxConnections"), Is.EqualTo(1));
                Assert.That(ByKind(node, "account").Value<Int32>("connections"),    Is.EqualTo(1));
                Assert.That(ByKind(node, "station").Value<Int32>("maxConnections"), Is.EqualTo(2));
                Assert.That(ByKind(node, "station").Value<Int32>("connections"),    Is.EqualTo(2));
                Assert.That(Lines(", and was refused: "),                            Has.Length.EqualTo(2), "the two refusals, said");
                Assert.That(Lines(", and was refused: ").First(),                    Does.StartWith("'cs003' signed in over SSH from ").And.EndWith($", and was refused: 2 {Full}."));
                Assert.That(Lines(", and was refused: ").Last(),                     Does.StartWith("'root' signed in over SSH from ").And.EndWith(", and was refused: 1 account connection(s) are open, as many as ssh.maxConnections lets in."));
            });

            await cs001!.DisposeAsync();

            Assert.That(await CountsWithin(node, "station", 1),  Is.True,     "the station that left, counted out");
            Assert.That(await Held(node, "cs003", keys[2]),      Is.Not.Null, "a third station, once one left");
            Assert.That(node.SSHConnectionsOf("station"),        Is.EqualTo(2));

        }

        #endregion

        #region TheServer_TakesWhatTheKindsTakeTogether

        /// <summary>
        /// The SSH server lets in at once what every kind may have, and the connections not signed in yet
        /// besides: so that no kind takes another's place before it is known who signed in.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task TheServer_TakesWhatTheKindsTakeTogether(CancellationToken CancellationToken)
        {

            var unauthenticated  = new SshServerLimits().MaxUnauthenticated;

            var byDefault        = await Started();
            var configured       = await Started(MaxConnections: """{ "account": 5, "station": 7 }""");

            Assert.Multiple(() => {

                Assert.That(byDefault.SSHMaxConnectionsOf("account"),   Is.EqualTo(SSHConfiguration.DefaultMaxConnectionsOfAccounts));
                Assert.That(byDefault.SSHMaxConnectionsOf("station"),   Is.EqualTo(SSHConfiguration.DefaultMaxConnectionsOfLogins));
                Assert.That(byDefault.SSHConfigurationJSON()["limits"]!.Value<Int32>("maxConnections"),
                            Is.EqualTo(SSHConfiguration.DefaultMaxConnectionsOfAccounts + SSHConfiguration.DefaultMaxConnectionsOfLogins + unauthenticated));

                Assert.That(configured.SSHMaxConnectionsOf("account"),  Is.EqualTo(5));
                Assert.That(configured.SSHMaxConnectionsOf("station"),  Is.EqualTo(7));
                Assert.That(configured.SSHConfigurationJSON()["limits"]!.Value<Int32>("maxConnections"),
                            Is.EqualTo(5 + 7 + unauthenticated));

            });

        }

        #endregion

        #region TheLimits_AreSaved_InEffectAtOnce_AndRefusedWhereWrong

        /// <summary>
        /// What is wrong is refused with the sentence that says so, and nothing is saved; what is right is
        /// saved in the "ssh" section and in effect at once, for the next one to sign in - the connections
        /// open stay - and where the server would let fewer in than the kinds together may have, the
        /// answer says so.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task TheLimits_AreSaved_InEffectAtOnce_AndRefusedWhereWrong(CancellationToken CancellationToken)
        {

            var node = await Started(MaxConnections: """{ "station": 2 }""");

            var wrong = new (String JSON, String Error)[] {
                ("""{ "maxConnections": 5 }""",                   "'ssh.maxConnections' must be an object"),
                ("""{ "maxConnections": { "station": 0 } }""",     "'ssh.maxConnections.station' must be between 1 and 10000."),
                ("""{ "maxConnections": { "station": 10001 } }""", "'ssh.maxConnections.station' must be between 1 and 10000."),
                ("""{ "maxConnections": { "station": "3" } }""",   "'ssh.maxConnections.station' must be a whole number."),
                ("""{ "maxConnections": { "Station": 3 } }""",     "'ssh.maxConnections' names 'Station'"),
                ("""{ "maxConnections": { "group": 3 } }""",       "'ssh.maxConnections' names 'group'")
            };

            foreach (var (json, error) in wrong)
            {
                var refused = await node.TryUpdateSSHConfiguration(JObject.Parse(json));
                Assert.That(refused.IsChanged, Is.False,               json);
                Assert.That(refused.Error,     Does.StartWith(error),  json);
            }

            Assert.That(JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["maxConnections"]!.ToString(Newtonsoft.Json.Formatting.None),
                        Is.EqualTo("""{"station":2}"""), "nothing saved");

            var cs001 = await Held(node, "cs001", keys[0]);
            var cs002 = await Held(node, "cs002", keys[1]);

            Assert.That(cs001, Is.Not.Null);
            Assert.That(cs002, Is.Not.Null);

            // Fewer than are open: they stay, and the next is refused.
            var lowered = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "maxConnections": { "account": 3, "station": 1 } }"""));

            Assert.That(lowered.IsChanged,                                                       Is.True, lowered.Error);
            Assert.That(lowered.Notice,                                                          Is.Null);
            Assert.That(node.SSHMaxConnectionsOf("station"),                                     Is.EqualTo(1));
            Assert.That(node.SSHMaxConnectionsOf("account"),                                     Is.EqualTo(3));
            Assert.That(await Held(node, "cs003", keys[2]),                                      Is.Null, "a third station, where one may be now");
            var stays = await cs001!.Multiplexer.OpenChannelAsync("session").AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await stays.CloseAsync();
            Assert.That(JToken.DeepEquals(JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["maxConnections"], JObject.Parse("""{ "account": 3, "station": 1 }""")), Is.True, "saved");

            // A kind not sent keeps what it had, in the file and in effect alike.
            var accountsOnly = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "maxConnections": { "account": 4 } }"""));

            Assert.That(accountsOnly.IsChanged,                Is.True, accountsOnly.Error);
            Assert.That(node.SSHMaxConnectionsOf("account"),  Is.EqualTo(4));
            Assert.That(node.SSHMaxConnectionsOf("station"),  Is.EqualTo(1));
            Assert.That(JToken.DeepEquals(JObject.Parse(File.ReadAllText(ConfigPath))["ssh"]!["maxConnections"], JObject.Parse("""{ "account": 4, "station": 1 }""")), Is.True, "merged");

            // More than the running server lets in: said, for until it starts again.
            var running = node.SSHConfigurationJSON()["limits"]!.Value<Int32>("maxConnections");
            var raised  = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "maxConnections": { "account": 300, "station": 400 } }"""));

            Assert.That(raised.IsChanged,  Is.True, raised.Error);
            Assert.That(raised.Notice,     Does.Contain($"The SSH server lets {running} connection(s) in at once until it starts again"));
            Assert.That(raised.Notice,     Does.Contain($"{300 + 400 + new SshServerLimits().MaxUnauthenticated} after"));
            Assert.That(node.SSHConfigurationJSON()["limits"]!.Value<Int32>("maxConnections"), Is.EqualTo(running), "the running server's");

        }

        #endregion

        #region AServerStartedAgain_TakesTheLimitsSentWithIt

        /// <summary>
        /// Limits sent with a new port, or with what starts the server again on its port, are what the new
        /// server lets in - not what the one before it did.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task AServerStartedAgain_TakesTheLimitsSentWithIt(CancellationToken CancellationToken)
        {

            var unauthenticated  = new SshServerLimits().MaxUnauthenticated;
            var node             = await Started();

            var moved = await node.TryUpdateSSHConfiguration(JObject.Parse($$"""{ "port": {{TestPorts.Free()}}, "maxConnections": { "account": 2, "station": 3 } }"""));

            Assert.That(moved.IsChanged,  Is.True, moved.Error);
            Assert.That(moved.Notice,     Is.Null);
            Assert.That(node.SSHConfigurationJSON()["limits"]!.Value<Int32>("maxConnections"), Is.EqualTo(2 + 3 + unauthenticated), "on a new port");

            var rebound = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "passwords": true, "maxConnections": { "account": 4, "station": 5 } }"""));

            Assert.That(rebound.IsChanged,  Is.True, rebound.Error);
            Assert.That(rebound.Notice,     Is.Null);
            Assert.That(node.SSHConfigurationJSON()["limits"]!.Value<Int32>("maxConnections"), Is.EqualTo(4 + 5 + unauthenticated), "on its port again");
            Assert.That(await Held(node, "cs001", keys[0]), Is.Not.Null, "the server started again lets in");

        }

        #endregion

        #region AFullKind_IsSaid_AtMostOnceAMinute

        /// <summary>
        /// Stations that knock again and again at a full server write one line a minute, and the next
        /// says how many it did not.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task AFullKind_IsSaid_AtMostOnceAMinute(CancellationToken CancellationToken)
        {

            var clock = new ManualClock();
            var node  = await Started(MaxConnections: """{ "station": 1 }""", TimeProvider: clock);

            Assert.That(await Held(node, "cs001", keys[0]), Is.Not.Null);

            Assert.That(await Held(node, "cs002", keys[1]), Is.Null);
            Assert.That(await Held(node, "cs003", keys[2]), Is.Null);
            Assert.That(await Held(node, "cs002", keys[1]), Is.Null);

            Assert.That(await SettledSaids(Full), Is.EqualTo(1), "within a minute");

            clock.Advance(TimeSpan.FromSeconds(61));

            Assert.That(await Held(node, "cs003", keys[2]), Is.Null);

            Assert.That(await SettledSaids(Full), Is.EqualTo(2), "a minute later");
            Assert.That(Lines(Full).Last(), Does.Contain("'cs003' signed in over SSH from ").
                                            And.EndsWith($"1 {Full} - and 2 more were refused since that was said last."));

        }

        #endregion

    }

}
