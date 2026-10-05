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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The command line over SSH, as far as the node is concerned: whether it
    /// is served and where, the host key it presents, who is let in with which
    /// key, what the switches say of it and what the banner shows.
    /// </summary>
    [TestFixture]
    public class SSHTests
    {

        #region Data

        private String directory = "";

        private readonly List<WWCPNode> nodes = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-ssh-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

            Configure("""{ "nts": { "enabled": false } }""");

        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var node in nodes)
            {
                try
                {
                    await node.DisposeAsync();
                }
                catch (Exception)
                { }
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

        #region (private) Configure(JSON) / Node(SSH, HTTPPort, Log)

        private void Configure(String JSON)

            => File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), JSON);

        /// <summary>
        /// A node in this test's directory, let go of after the test.
        /// </summary>
        private WWCPNode Node(SSHSettings?  SSH       = null,
                              IPPort?       HTTPPort  = null,
                              EventLog?     Log       = null)
        {

            var node = new WWCPNode(HTTPPort:          HTTPPort ?? IPPort.Parse(TestPorts.Free()),
                                    AccountsPath:      Path.Combine(directory, "accounts"),
                                    ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                    CertificatesPath:  Path.Combine(directory, "certificates"),
                                    Log:               Log,
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    SSH:               SSH);

            nodes.Add(node);

            return node;

        }

        /// <summary>
        /// A node with SSH on a port of its own, started.
        /// </summary>
        private async Task<WWCPNode> Started(EventLog? Log = null, IReadOnlyList<(String, String)>? Authorize = null)
        {

            var node = Node(new SSHSettings(Enabled: true, Port: IPPort.Parse(TestPorts.Free()), Authorize: Authorize), Log: Log);

            await node.Start();

            return node;

        }

        /// <summary>
        /// Sign in to the given node over SSH.
        /// </summary>
        private static ValueTask<SshClient> SignIn(WWCPNode     Node,
                                                   String       Account,
                                                   ISshHostKey  Key)

            => SshClient.ConnectAsync("127.0.0.1",
                                      Node.SSHPort!.Value.ToUInt16(),
                                      new SshClientOptions {
                                          Username       = Account,
                                          VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                          Credentials    = [ Key ]
                                      });

        private static String PublicKeyLine(ISshHostKey Key, String Comment = "tester")

            => SshPublicKey.FromHostKey(Key, Comment).ToAuthorizedKeyLine();

        /// <summary>
        /// An account of the given name, in the group of the given role - or in none.
        /// </summary>
        private static async Task AccountIn(WWCPNode Node, String Name, String? Role)
        {

            await Node.ExtAPI.AddUser(new User(User_Id.Parse(Name),
                                               I18NString.Create(Languages.en, Name),
                                               SimpleEMailAddress.Parse($"{Name}@localhost")),
                                      SkipDefaultNotifications:  true,
                                      SkipNewUserEMail:          true,
                                      SkipNewUserNotifications:  true);

            Assert.That(Node.ExtAPI.TryGetUser(User_Id.Parse(Name), out var stored) && stored is User, Is.True);

            if (Role is not null)
            {
                Assert.That(Node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group) && group is UserGroup, Is.True);
                Assert.That((await Node.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!)).IsSuccess, Is.True);
            }

        }

        #endregion


        #region ANodeServesSSHWhereSomethingSaysSo

        /// <summary>
        /// A node made with nothing said serves no SSH - a node in a test has no
        /// business opening a second port - and a program's default serves it
        /// twenty thousand above the web interface: 22347 beside 2347. Past the
        /// last port there is, there is none, and that is said.
        /// </summary>
        [Test]
        public void ANodeServesSSHWhereSomethingSaysSo()
        {

            var log   = new EventLog();
            var said  = new List<String>();

            log.OnLogged += entry => said.Add(entry.Message);

            Assert.Multiple(() => {

                Assert.That(Node().SSHEnabled,                                                        Is.False, "nothing said");

                var program = Node(SSHSettings.ByDefault, IPPort.Parse(2347));
                Assert.That(program.SSHEnabled,                                                       Is.True,  "the program's default");
                Assert.That(program.SSHPort,                                                          Is.EqualTo(IPPort.Parse(22347)));
                Assert.That(program.SSHURL,                                                           Is.EqualTo("ssh://127.0.0.1:22347"));

                var high = Node(SSHSettings.ByDefault, IPPort.Parse(50000), log);
                Assert.That(high.SSHEnabled,                                                          Is.False, "no port past 65535");
                Assert.That(said,                                                                     Has.Some.Contains("--ssh-port"));

            });

        }

        #endregion

        #region ASwitchWinsOverTheFileAndTheFileOverTheDefault

        /// <summary>
        /// --no-ssh wins over a file that switches SSH on, --ssh-port over the
        /// file's port, and the file over the program's default.
        /// </summary>
        [Test]
        public void ASwitchWinsOverTheFileAndTheFileOverTheDefault()
        {

            Configure("""{ "nts": { "enabled": false }, "ssh": { "enabled": true, "port": 30022, "passwords": true } }""");

            Assert.Multiple(() => {

                Assert.That(Node(new SSHSettings(Enabled: false, OnByDefault: true)).SSHEnabled,  Is.False,                       "--no-ssh");
                Assert.That(Node(new SSHSettings(Enabled: true, Port: IPPort.Parse(30023))).SSHPort,  Is.EqualTo(IPPort.Parse(30023)), "--ssh-port");

                var filed = Node();
                Assert.That(filed.SSHEnabled,     Is.True,                        "the file switches it on");
                Assert.That(filed.SSHPort,        Is.EqualTo(IPPort.Parse(30022)), "the file's port");
                Assert.That(filed.SSHPasswords,   Is.True,                        "the file's passwords");

            });

            Configure("""{ "nts": { "enabled": false }, "ssh": { "enabled": false } }""");

            Assert.That(Node(SSHSettings.ByDefault).SSHEnabled, Is.False, "the file over the program's default");

        }

        #endregion

        #region AFileThatSaysSSHWrongIsRefused

        /// <summary>
        /// An "ssh" section that is not what it should be stops the node from
        /// being made, as every other mistake in the file does.
        /// </summary>
        [TestCase("""{ "ssh": "on" }""",                   "'ssh' must be a JSON object.")]
        [TestCase("""{ "ssh": { "enabled": "yes" } }""",   "'ssh.enabled' must be true or false.")]
        [TestCase("""{ "ssh": { "port": 70000 } }""",      "'ssh.port' must be a port number between 1 and 65535.")]
        public void AFileThatSaysSSHWrongIsRefused(String JSON, String Error)
        {

            Configure(JSON);

            Assert.That(() => Node(), Throws.InvalidOperationException.With.Message.Contains(Error));

        }

        #endregion

        #region TheHostKeyIsMadeOnceAndKept

        /// <summary>
        /// The first start that serves SSH makes the host key, in the log book;
        /// every start after it presents the same one.
        /// </summary>
        [Test]
        public async Task TheHostKeyIsMadeOnceAndKept()
        {

            var first = await Started();
            var key   = first.SSHHostKey;

            await first.DisposeAsync();

            var second = await Started();

            Assert.Multiple(() => {
                Assert.That(key,                          Does.StartWith("ssh-ed25519 SHA256:"));
                Assert.That(second.SSHHostKey,            Is.EqualTo(key), "a restart presents another host key");
                Assert.That(File.Exists(second.SSHHostKeyPath),          Is.True);
                Assert.That(File.Exists(second.SSHHostKeyPath + ".pub"), Is.True);
            });

        }

        #endregion

        #region AHostKeyThatCannotBeReadStopsTheStart

        /// <summary>
        /// A host key that is there and cannot be read stops the start, rather
        /// than being replaced by another one - which would be another machine
        /// to every client that knew this one.
        /// </summary>
        [Test]
        public void AHostKeyThatCannotBeReadStopsTheStart()
        {

            var node = Node(new SSHSettings(Enabled: true, Port: IPPort.Parse(TestPorts.Free())));

            Directory.CreateDirectory(Path.GetDirectoryName(node.SSHHostKeyPath)!);
            File.WriteAllText(node.SSHHostKeyPath, "not a key at all");

            Assert.That(async () => await node.Start(), Throws.InvalidOperationException.With.Message.Contains("could not be read"));
            Assert.That(File.ReadAllText(node.SSHHostKeyPath), Is.EqualTo("not a key at all"), "the key was replaced");

        }

        #endregion

        #region AnAccountIsLetInWithItsOwnKeysOnly

        /// <summary>
        /// An account signs in with a key of its file, and with no other; under
        /// a name that is no account's, nobody signs in. Who signed in, from
        /// where and with which key, is in the log.
        /// </summary>
        [Test]
        public async Task AnAccountIsLetInWithItsOwnKeysOnly()
        {

            var log    = new EventLog();
            var said   = new List<String>();

            log.OnLogged += entry => said.Add(entry.Message);

            var node   = await Started(log);
            var key    = SshHostKey.GenerateEd25519();
            var other  = SshHostKey.GenerateEd25519();

            Assert.That(node.SSHKeys.TryAuthorize(WWCPNode.DefaultAdminUser, PublicKeyLine(key), out var added, out var refused), Is.True, refused);

            await using (await SignIn(node, WWCPNode.DefaultAdminUser, key)) { }

            Assert.That(async () => await SignIn(node, WWCPNode.DefaultAdminUser, other),  Throws.InstanceOf<SshAuthenticationException>(), "another key");
            Assert.That(async () => await SignIn(node, "nobody", key),                     Throws.InstanceOf<SshAuthenticationException>(), "no such account");

            var fingerprint = SshFingerprint.Sha256(key.PublicKeyBlob);

            Assert.Multiple(() => {
                Assert.That(added,  Is.EqualTo(new[] { fingerprint }));
                Assert.That(said,
                            Has.Some.Matches<String>(message => message is not null && message.StartsWith($"'{WWCPNode.DefaultAdminUser}' signed in over SSH from 127.0.0.1:") &&
                                                                                       message.EndsWith($"with the key {fingerprint}.")));
            });

        }

        #endregion

        #region AKeyTakenOutLetsNobodyInAtOnce

        /// <summary>
        /// A file is read at every sign-in: a key taken out of it lets nobody in
        /// from that moment on, without a restart.
        /// </summary>
        [Test]
        public async Task AKeyTakenOutLetsNobodyInAtOnce()
        {

            var node = await Started();
            var key  = SshHostKey.GenerateEd25519();

            node.SSHKeys.TryAuthorize(WWCPNode.DefaultAdminUser, PublicKeyLine(key), out _, out _);

            await using (await SignIn(node, WWCPNode.DefaultAdminUser, key)) { }

            File.Delete(node.SSHKeys.FileOf(WWCPNode.DefaultAdminUser)!);

            Assert.That(async () => await SignIn(node, WWCPNode.DefaultAdminUser, key), Throws.InstanceOf<SshAuthenticationException>());

        }

        #endregion

        #region AnAccountWithoutARoleOrSwitchedOffIsNotLetIn

        /// <summary>
        /// An account that holds none of the node's roles could do nothing, and
        /// is not let in to be refused everything; one in a role is.
        /// </summary>
        [Test]
        public async Task AnAccountWithoutARoleIsNotLetIn()
        {

            var node = await Started();
            var key  = SshHostKey.GenerateEd25519();

            await AccountIn(node, "nobodysrole", null);
            await AccountIn(node, "anadmin",     WWCPNode.AdminRole);

            node.SSHKeys.TryAuthorize("nobodysrole", PublicKeyLine(key), out _, out _);
            node.SSHKeys.TryAuthorize("anadmin",     PublicKeyLine(key), out _, out _);

            Assert.That(async () => await SignIn(node, "nobodysrole", key), Throws.InstanceOf<SshAuthenticationException>());

            await using (await SignIn(node, "anadmin", key)) { }

        }

        #endregion

        #region AKeyMayBeConfinedToWhereItComesFrom

        /// <summary>
        /// The options of a line are honoured: a key that may only come from
        /// elsewhere does not let anybody in from here.
        /// </summary>
        [Test]
        public async Task AKeyMayBeConfinedToWhereItComesFrom()
        {

            var node = await Started();
            var key  = SshHostKey.GenerateEd25519();

            Assert.That(node.SSHKeys.TryAuthorize(WWCPNode.DefaultAdminUser, $"from=\"192.0.2.0/24\" {PublicKeyLine(key)}", out _, out var refused), Is.True, refused);

            Assert.That(async () => await (await SignIn(node, WWCPNode.DefaultAdminUser, key)).OpenShellAsync(),
                        Throws.Exception);

        }

        #endregion

        #region TheKeysTheProgramBroughtAreThereBeforeAnybodyConnects

        /// <summary>
        /// --authorize-ssh-key puts the key in once the accounts are read and
        /// before a port opens - at a first start too, where the account is only
        /// made then - and an account the node does not have stops the start.
        /// </summary>
        [Test]
        public async Task TheKeysTheProgramBroughtAreThereBeforeAnybodyConnects()
        {

            var key   = SshHostKey.GenerateEd25519();
            var file  = Path.Combine(directory, "id_ed25519.pub");

            File.WriteAllText(file, PublicKeyLine(key));

            var node = await Started(Authorize: [ (WWCPNode.DefaultAdminUser, file) ]);

            Assert.That(node.SSHKeys.AccountsWithKeys(), Is.EqualTo(new[] { WWCPNode.DefaultAdminUser }));

            await using (await SignIn(node, WWCPNode.DefaultAdminUser, key)) { }

            await node.DisposeAsync();

            var refused = Node(new SSHSettings(Enabled: true, Port: IPPort.Parse(TestPorts.Free()), Authorize: [ ("somebodyelse", file) ]));

            Assert.That(async () => await refused.Start(),
                        Throws.InvalidOperationException.With.Message.Contains("has no account 'somebodyelse'"));

        }

        #endregion

        #region OnlyTheCommandLineIsServed

        /// <summary>
        /// Nothing but the shell: exec, SFTP and a tunnel are refused.
        /// </summary>
        [Test]
        public async Task OnlyTheCommandLineIsServed()
        {

            var node = await Started();
            var key  = SshHostKey.GenerateEd25519();

            node.SSHKeys.TryAuthorize(WWCPNode.DefaultAdminUser, PublicKeyLine(key), out _, out _);

            await using var client = await SignIn(node, WWCPNode.DefaultAdminUser, key);

            var exec = await client.Multiplexer.OpenChannelAsync("session");
            var sftp = await client.Multiplexer.OpenChannelAsync("session");

            Assert.Multiple(() => {
                Assert.That(exec.SendRequestAsync("exec",      true, SshSessionChannel.EncodeString("uname -a")).AsTask().Result, Is.False);
                Assert.That(sftp.SendRequestAsync("subsystem", true, SshSessionChannel.EncodeString("sftp")).AsTask().Result,     Is.False);
            });

            Assert.That(async () => await client.OpenTcpStreamAsync("127.0.0.1", node.HTTPPort.ToUInt16()), Throws.TypeOf<SshChannelOpenException>());

        }

        #endregion

        #region APortThatIsTakenIsSaidAsTheSSHServers

        /// <summary>
        /// A port the SSH server cannot have ends the start as one, naming the
        /// SSH server and --ssh-port - and the web interface's port is let go.
        /// </summary>
        [Test]
        public async Task APortThatIsTakenIsSaidAsTheSSHServers()
        {

            using var taken  = new TcpListener(System.Net.IPAddress.Loopback, 0);
            taken.Start();

            var port         = IPPort.Parse((UInt16) ((IPEndPoint) taken.LocalEndpoint).Port);
            var node         = Node(new SSHSettings(Enabled: true, Port: port));

            var problem      = (await Assert.ThrowsAsync<PortUnavailableException>(async () => await node.Start()))!;

            Assert.Multiple(() => {
                Assert.That(problem.Whose,                                Is.EqualTo(NodePort.SSH));
                Assert.That(problem.Message,                              Does.StartWith("The SSH server could not be given port"));
                Assert.That(NodeProgram.AdviceOn(node.Kind, problem, null, OnWindows: true, Program: null).Single(),
                            Does.Contain("--ssh-port <number>").And.Contain("--no-ssh"));
                Assert.That(node.HTTPServer.IsRunning,                    Is.False, "the web interface's port was kept");
            });

        }

        #endregion

        #region TheBannerSaysWhereAndWithWhichHostKey

        /// <summary>
        /// The banner says where the SSH server is and the host key to compare
        /// PuTTY's question with, which accounts have a key - root, after a first
        /// start - and how to get a key in while nobody has one, in lines of no
        /// more than 80 columns.
        /// </summary>
        [Test]
        public async Task TheBannerSaysWhereAndWithWhichHostKey()
        {

            var node   = await Started();
            var lines  = node.Banner();
            var at     = lines.ToList().FindIndex(line => line.StartsWith("  SSH "));

            Assert.That(at, Is.GreaterThan(0), String.Join("\n", lines));

            Assert.Multiple(() => {
                Assert.That(lines[at],      Does.EndWith(node.SSHURL!));
                Assert.That(lines[at + 1].Trim(),  Is.EqualTo(node.SSHHostKey));
                Assert.That(lines[at + 2].Trim(),  Is.EqualTo($"accounts with a key: {WWCPNode.DefaultAdminUser}"));
                Assert.That(lines.Take(at + 3).Skip(at), Has.All.Length.LessThanOrEqualTo(NodeUsage.Width));
            });

            File.Delete(node.SSHKeys.FileOf(WWCPNode.DefaultAdminUser)!);

            lines  = node.Banner();
            at     = lines.ToList().FindIndex(line => line.StartsWith("  SSH "));

            Assert.That(lines[at + 2].Trim(), Is.EqualTo($"no account has a key yet: --authorize-ssh-key {WWCPNode.DefaultAdminUser}=<file.pub>"));

        }

        #endregion

        #region TheKeysAreReadAsTheyAreHandedOver

        /// <summary>
        /// A key is taken as an authorized_keys line has it, with its options, or
        /// as PuTTYgen saves it (RFC 4716); a private key is refused with what to
        /// give instead, and a key already there is not written twice.
        /// </summary>
        [Test]
        public void TheKeysAreReadAsTheyAreHandedOver()
        {

            var store = new AuthorizedKeysStore(Path.Combine(directory, "keys"));
            var key   = SshHostKey.GenerateEd25519();
            var rfc   = SshPublicKey.FromHostKey(key, "from puttygen").ToRfc4716();

            Assert.Multiple(() => {

                Assert.That(store.TryAuthorize("root", rfc, out var added, out var refused), Is.True, refused);
                Assert.That(added, Has.Count.EqualTo(1));

                Assert.That(store.TryAuthorize("root", PublicKeyLine(key), out var again, out _), Is.True);
                Assert.That(again, Is.Empty, "the same key written twice");

                Assert.That(store.TryAuthorize("root", OpenSshPrivateKey.Format(key), out _, out var privateRefused), Is.False);
                Assert.That(privateRefused, Does.Contain("private key"));

                Assert.That(store.TryAuthorize("root", "hello", out _, out var garbage), Is.False);
                Assert.That(garbage, Does.Contain("no public key"));

                Assert.That(store.TryAuthorize("../root", PublicKeyLine(key), out _, out _), Is.False, "a path as an account");

                Assert.That(store.Of("root").Single().PublicKey.Sha256Fingerprint, Is.EqualTo(SshFingerprint.Sha256(key.PublicKeyBlob)));

            });

        }

        #endregion

        #region TheSwitchesSayWhatTheyShould

        /// <summary>
        /// --ssh-port, --no-ssh and --authorize-ssh-key as the node reads them,
        /// and what is refused before the node is made.
        /// </summary>
        [Test]
        public void TheSwitchesSayWhatTheyShould()
        {

            var file = Path.Combine(directory, "id.pub");
            File.WriteAllText(file, PublicKeyLine(SshHostKey.GenerateEd25519()));

            var plain   = NodeArguments.Parse([]);
            var port    = NodeArguments.Parse([ "--ssh-port", "2222" ]);
            var none    = NodeArguments.Parse([ "--no-ssh" ]);
            var keys    = NodeArguments.Parse([ "--authorize-ssh-key", $"root={file}" ]);

            Assert.Multiple(() => {

                Assert.That(plain.SSH,  Is.EqualTo(new SSHSettings(OnByDefault: true, Authorize: plain.SSHKeyAuthorizations)));
                Assert.That(port.SSH.Enabled,  Is.True);
                Assert.That(port.SSH.Port,     Is.EqualTo(IPPort.Parse(2222)));
                Assert.That(none.SSH.Enabled,  Is.False);
                Assert.That(keys.SSH.Authorize, Is.EqualTo(new[] { ("root", file) }));

                Assert.That(NodeArguments.Parse([ "--no-ssh", "--ssh-port", "2222" ]).Problem,  Is.EqualTo("--no-ssh and --ssh-port ask for opposite things!"));
                Assert.That(NodeArguments.Parse([ "--ssh-port", "0" ]).Problem,                 Is.EqualTo("Missing or invalid port number after --ssh-port!"));
                Assert.That(NodeArguments.Parse([ "--authorize-ssh-key", "root" ]).Problem,     Does.StartWith("--authorize-ssh-key wants <account>=<file>"));
                Assert.That(NodeArguments.Parse([ "--authorize-ssh-key", "../x=y" ]).Problem,   Does.Contain("cannot be the name of an account"));

            });

            var error  = new StringWriter();
            var usage  = new NodeUsage("TestNodeCLI", NodeKind.Default, IPPort.Parse(4711), "libs/x");

            Assert.That(NodeArguments.Parse([ "--authorize-ssh-key", $"root={file}.missing" ]).Refused(usage, Error: error), Is.EqualTo(2));
            Assert.That(error.ToString(), Does.StartWith("--authorize-ssh-key: there is no file"));

        }

        #endregion

        #region TheUsageSaysHowToGetIn

        /// <summary>
        /// -h has the three switches, the port beside the web interface's, and
        /// keeps to 80 columns.
        /// </summary>
        [Test]
        public void TheUsageSaysHowToGetIn()
        {

            var lines = new NodeUsage("TestNodeCLI", NodeKind.Default, IPPort.Parse(2347), "libs/x").Lines().ToArray();
            var text  = String.Join("\n", lines);

            Assert.Multiple(() => {
                Assert.That(text,   Does.Contain("--ssh-port <number>").And.Contain("--no-ssh").And.Contain("--authorize-ssh-key <account>=<file>"));
                Assert.That(text,   Does.Contain("(default: 22347,"));
                Assert.That(String.Join(" ", lines.Select(line => line.Trim())),
                                    Does.Contain($"Recommended at a first start: --authorize-ssh-key {WWCPNode.DefaultAdminUser}=<your key.pub>."));
                Assert.That(lines,  Has.All.Length.LessThanOrEqualTo(NodeUsage.Width));
            });

        }

        #endregion


        #region AFirstStartWithoutAKeyGivesRootOne

        /// <summary>
        /// A first start with SSH on and no key for root makes up an Ed25519 key
        /// pair for it: its public key is let in, its private key signs in, the
        /// log names it by its fingerprint - and the private key is in no file
        /// below the node's directory and in no entry of its log.
        /// </summary>
        [Test]
        public async Task AFirstStartWithoutAKeyGivesRootOne()
        {

            var log   = new EventLog();
            var said  = new List<String>();

            log.OnLogged += entry => said.Add(entry.Message);

            var node  = await Started(log);
            var made  = node.GeneratedSSHKey;

            Assert.That(made, Is.Not.Null, "no key was made up for root");

            var key   = SshKeyGenerator.LoadPrivateKey(made!.PrivateKey).Key;
            // The lines that hold what is secret: past the first two, which begin
            // alike in every unencrypted Ed25519 key - the host key's file has
            // them too - and hold the public key.
            var secret = made.PrivateKey.Split('\n').Select(line => line.Trim()).
                                         Where (line => line.Length > 0 && !line.StartsWith("-----")).
                                         Skip  (2).
                                         ToArray();

            var written = String.Join("\n", Directory.GetFiles(directory, "*", SearchOption.AllDirectories).
                                                      Select(path => File.ReadAllText(path)));

            Assert.Multiple(() => {
                Assert.That(made.Account,      Is.EqualTo(WWCPNode.DefaultAdminUser));
                Assert.That(made.Fingerprint,  Is.EqualTo(SshFingerprint.Sha256(key.PublicKeyBlob)));
                Assert.That(made.PrivateKey,   Does.StartWith("-----BEGIN OPENSSH PRIVATE KEY-----"));
                Assert.That(node.SSHKeys.Of(WWCPNode.DefaultAdminUser).Count,                       Is.EqualTo(1));
                Assert.That(node.SSHKeys.Find(WWCPNode.DefaultAdminUser, key.PublicKeyBlob),        Is.Not.Null, "the key made up is not let in");
                Assert.That(said,     Has.Some.Contains(made.Fingerprint), "the log does not name the key made up");
                Assert.That(secret,   Is.Not.Empty);
                Assert.That(secret,   Has.None.Matches<String>(line => said.Any(message => message.Contains(line))), "the private key is in the log");
                Assert.That(secret,   Has.None.Matches<String>(line => written.Contains(line)),                       "the private key was written to disk");
            });

            await using (await SignIn(node, WWCPNode.DefaultAdminUser, key)) { }

        }

        #endregion

        #region TheBannerShowsTheMadeUpKeyOnceAsItStands

        /// <summary>
        /// The first-start box names the key by its fingerprint and how to sign
        /// in with it; its private key follows outside the box, at the start of
        /// each line, so that the lines from BEGIN to END, copied as they stand,
        /// are the key - and then the way recommended instead.
        /// </summary>
        [Test]
        public async Task TheBannerShowsTheMadeUpKeyOnceAsItStands()
        {

            var node   = await Started();
            var lines  = node.Banner().ToList();
            var begin  = lines.IndexOf("-----BEGIN OPENSSH PRIVATE KEY-----");
            var end    = lines.IndexOf("-----END OPENSSH PRIVATE KEY-----");

            Assert.That(begin, Is.GreaterThan(0).And.LessThan(end), String.Join("\n", lines));

            var copied = String.Join("\n", lines.Skip(begin).Take(end - begin + 1));
            var key    = SshKeyGenerator.LoadPrivateKey(copied).Key;
            var after  = String.Join(" ", lines.Skip(end + 1).Select(line => line.Trim()));

            Assert.Multiple(() => {
                Assert.That(SshFingerprint.Sha256(key.PublicKeyBlob), Is.EqualTo(node.GeneratedSSHKey!.Fingerprint));
                Assert.That(lines.Take(begin), Has.Some.EqualTo($"  │  SSH key   {node.GeneratedSSHKey.Fingerprint}"));
                Assert.That(lines.Take(begin), Has.Some.EqualTo($"  │  ssh -i <file> ssh://{WWCPNode.DefaultAdminUser}@127.0.0.1:{node.SSHPort}"));
                Assert.That(after,  Does.Contain($"--authorize-ssh-key {WWCPNode.DefaultAdminUser}=<your key.pub>"));
                Assert.That(lines.Skip(lines.FindIndex(line => line.StartsWith("  ┌─ First start"))),
                                    Has.All.Length.LessThanOrEqualTo(NodeUsage.Width));
            });

        }

        #endregion

        #region NoKeyIsMadeUpWhereOneWasGivenOrNeedNotBe

        /// <summary>
        /// No key is made up where the command line brought one for root - the
        /// way recommended - nor without SSH, nor at a start after the first.
        /// </summary>
        [Test]
        public async Task NoKeyIsMadeUpWhereOneWasGivenOrNeedNotBe()
        {

            var own   = SshHostKey.GenerateEd25519();
            var file  = Path.Combine(directory, "id_ed25519.pub");

            File.WriteAllText(file, PublicKeyLine(own));

            var brought = await Started(Authorize: [ (WWCPNode.DefaultAdminUser, file) ]);

            Assert.Multiple(() => {
                Assert.That(brought.GeneratedPassword,  Is.Not.Null, "not a first start");
                Assert.That(brought.GeneratedSSHKey,    Is.Null,     "a key was made up beside the one brought");
                Assert.That(brought.SSHKeys.Of(WWCPNode.DefaultAdminUser).Count, Is.EqualTo(1));
                Assert.That(brought.Banner(), Has.None.Contains("PRIVATE KEY"));
            });

            await brought.DisposeAsync();

            // A start after the first: the accounts are there - and root has no
            // key any more, which a first start alone answers with one.
            File.Delete(brought.SSHKeys.FileOf(WWCPNode.DefaultAdminUser)!);

            var again = await Started();

            Assert.That(again.GeneratedSSHKey,             Is.Null,  "a key was made up at a start after the first");
            Assert.That(again.SSHKeys.AccountsWithKeys(),  Is.Empty);

            await again.DisposeAsync();

            // A first start without SSH.
            Directory.Delete(Path.Combine(directory, "accounts"), true);

            var noSSH = Node(new SSHSettings(Enabled: false));

            await noSSH.Start();

            Assert.Multiple(() => {
                Assert.That(noSSH.GeneratedPassword,  Is.Not.Null, "not a first start");
                Assert.That(noSSH.GeneratedSSHKey,    Is.Null,     "a key was made up without SSH");
            });

        }

        #endregion

    }

}
