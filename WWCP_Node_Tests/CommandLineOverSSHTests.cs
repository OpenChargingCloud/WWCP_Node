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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The node's command line as somebody signed in over SSH gets it: the
    /// account they signed in as, what its roles let it do, the log above the
    /// line, and an end that leaves the node running - or is the node's.
    /// </summary>
    [TestFixture]
    public class CommandLineOverSSHTests
    {

        #region Data

        private static readonly SshPty Terminal = new ("xterm", new SshWindowSize(120, 40), new Dictionary<Byte, UInt32>());

        private String               directory  = "";
        private WWCPNode?            node;
        private readonly List<String> said      = [];
        private readonly List<LogEntry> entries = [];

        #endregion

        #region (class) Screen

        /// <summary>
        /// What the shell writes, as it arrives.
        /// </summary>
        private sealed class Screen
        {

            private readonly StringBuilder  received = new ();
            private readonly Lock           padlock  = new ();

            public Screen(SshClientShell Shell)
                => _ = Task.Run(async () => {
                       var buffer = new Byte[4096];
                       try
                       {
                           Int32 read;
                           while ((read = await Shell.Output.ReadAsync(buffer)) > 0)
                               lock (padlock) { received.Append(Encoding.UTF8.GetString(buffer, 0, read)); }
                       }
                       catch { }
                   });

            public String Text
            {
                get { lock (padlock) { return received.ToString(); } }
            }

            /// <summary>
            /// Wait until the given text has been written after what was there
            /// when Since was taken.
            /// </summary>
            public async Task<String> WaitFor(String What, Int32 Since = 0, Int32 Seconds = 10)
            {

                var until = DateTime.UtcNow.AddSeconds(Seconds);

                while (DateTime.UtcNow < until)
                {
                    var text = Text;
                    if (text.IndexOf(What, Math.Min(Since, text.Length), StringComparison.Ordinal) >= 0)
                        return text[Math.Min(Since, text.Length)..];
                    await Task.Delay(20);
                }

                Assert.Fail($"Waited in vain for '{What}'. The session said:\n{Text}");
                return "";

            }

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-cli-ssh-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), """{ "nts": { "enabled": false } }""");

            var log = new EventLog();
            log.OnLogged += entry => { lock (said) { said.Add(entry.Message); entries.Add(entry); } };

            node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                AccountsPath:      Path.Combine(directory, "accounts"),
                                ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                CertificatesPath:  Path.Combine(directory, "certificates"),
                                Log:               log,
                                LogToConsole:      false,
                                BridgeDebugLog:    false,
                                SSH:               new SSHSettings(Enabled: true, Port: IPPort.Parse(TestPorts.Free())));

            await node.Start();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            said.Clear();
            entries.Clear();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion

        #region (private) SignIn(Account = root, Role = null) / Open(Client)

        /// <summary>
        /// Sign in over SSH as the given account - made, in the given role,
        /// where it is not root - with a key of its own.
        /// </summary>
        private async Task<SshClient> SignIn(String Account = WWCPNode.DefaultAdminUser, String? Role = null)
        {

            if (Account != WWCPNode.DefaultAdminUser)
            {

                await node!.ExtAPI.AddUser(new User(User_Id.Parse(Account), I18NString.Create(Languages.en, Account), SimpleEMailAddress.Parse($"{Account}@localhost")),
                                           SkipDefaultNotifications: true, SkipNewUserEMail: true, SkipNewUserNotifications: true);

                node.ExtAPI.TryGetUser(User_Id.Parse(Account), out var stored);
                node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role!), out var group);

                await node.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            }

            var key = SshHostKey.GenerateEd25519();

            Assert.That(node!.SSHKeys.TryAuthorize(Account, SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine(), out _, out var refused), Is.True, refused);

            return await SshClient.ConnectAsync("127.0.0.1",
                                                node.SSHPort!.Value.ToUInt16(),
                                                new SshClientOptions {
                                                    Username       = Account,
                                                    VerifyHostKey  = blob => node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                                    Credentials    = [ key ]
                                                });

        }

        private static async Task<(SshClientShell Shell, Screen Screen)> Open(SshClient Client, SshPty? Pty = null)
        {
            var shell  = await Client.OpenShellAsync(Pty ?? Terminal);
            var screen = new Screen(shell);
            return (shell, screen);
        }

        #endregion


        #region ASessionIsTheNodesCommandLineAsTheAccount

        /// <summary>
        /// A session is greeted with who it is and how to leave, gets the node's
        /// prompt, and runs the node's commands - Tab included.
        /// </summary>
        [Test]
        public async Task ASessionIsTheNodesCommandLineAsTheAccount()
        {

            await using var client          = await SignIn();
            var (shell, screen)             = await Open(client);

            await screen.WaitFor("WWCP node> ");

            Assert.That(screen.Text, Does.Contain($"signed in as '{WWCPNode.DefaultAdminUser}' from 127.0.0.1:").
                                      And.Contain("'quit' or Ctrl+D leaves, and the WWCP node keeps running"));

            var mark = screen.Text.Length;

            await shell.WriteAsync("sync\t");
            await screen.WaitFor("syncNTS", mark);

            await shell.WriteAsync("nowhere.example\r");

            var answer = await screen.WaitFor("is none of this WWCP node's time servers", mark);

            Assert.That(answer, Does.Contain("'nowhere.example' is none of this WWCP node's time servers"));

        }

        #endregion

        #region WhoAskedIsTheAccountAndTheTagSaysSSH

        /// <summary>
        /// syncNTS over SSH writes the line 'Sync now' writes, naming the account
        /// - and "cli" and "ssh" where the page says "web".
        /// </summary>
        [Test]
        public async Task WhoAskedIsTheAccountAndTheTagSaysSSH()
        {

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");
            await shell.WriteAsync("syncNTS\r");
            await screen.WaitFor("WWCP node> ", screen.Text.Length);

            LogEntry[] asked;
            lock (said)
                asked = [.. entries.Where(entry => entry.Message == $"'{WWCPNode.DefaultAdminUser}' at the command line over SSH asked this WWCP node to synchronise its time.")];

            Assert.That(asked,               Has.Length.EqualTo(1));
            Assert.That(asked[0].Level,      Is.EqualTo(LogLevel.Notice));
            Assert.That(asked[0].Tags,       Is.EqualTo(new[] { "nts", "test", "cli", "ssh" }));

        }

        #endregion

        #region AnAccountMayDoWhatItsRolesLetIt

        /// <summary>
        /// A viewer may look and not run: syncNTS is refused, with the roles that
        /// would do, and the refusal is in the log.
        /// </summary>
        [Test]
        public async Task AnAccountMayDoWhatItsRolesLetIt()
        {

            await using var client  = await SignIn("aviewer", Role.Viewer.Name);
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            var mark = screen.Text.Length;
            await shell.WriteAsync("syncNTS\r");

            var answer = await screen.WaitFor("may not do that here", mark);

            Assert.That(answer, Does.Contain($"needs the {WWCPNode.AdminRole}"));

            lock (said)
                Assert.That(said, Has.Some.StartsWith("'aviewer' was refused nts:run on 'syncNTS' at the command line over SSH"));

        }

        #endregion

        #region TheLogIsAboveTheLineFromALevelOfItsOwn

        /// <summary>
        /// What the node logs appears in the session as it happens; 'log off'
        /// stops it, for this session alone.
        /// </summary>
        [Test]
        public async Task TheLogIsAboveTheLineFromALevelOfItsOwn()
        {

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            node!.Log.Notice("A line for the session.", "test");
            await screen.WaitFor("A line for the session.");

            var mark = screen.Text.Length;
            await shell.WriteAsync("log off\r");
            await screen.WaitFor("shows no log now", mark);

            node.Log.Notice("A line nobody here should see.", "test");
            await shell.WriteAsync("log\r");
            await screen.WaitFor("This session shows no log.", mark);

            Assert.That(screen.Text, Does.Not.Contain("A line nobody here should see."));

        }

        #endregion

        #region QuitLeavesTheSessionAndTheNodeRuns

        /// <summary>
        /// 'quit' over SSH ends the session - exit status 0, and a line in the
        /// log - and the node goes on running.
        /// </summary>
        [Test]
        public async Task QuitLeavesTheSessionAndTheNodeRuns()
        {

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");
            await shell.WriteAsync("quit\r");

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(0));
            Assert.That(node!.HTTPServer.IsRunning, Is.True, "quit over SSH stopped the node");

            var until = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < until && !said.ToArray().Any(line => line.StartsWith($"'{WWCPNode.DefaultAdminUser}' left the command line over SSH after")))
                await Task.Delay(20);

            Assert.That(said.ToArray(), Has.Some.StartsWith($"'{WWCPNode.DefaultAdminUser}' left the command line over SSH after"));

        }

        #endregion

        #region AStoppingNodeSaysSoOnEverySession

        /// <summary>
        /// A node that stops says so on every session while its channel is still
        /// open, and ends it with exit status 0.
        /// </summary>
        [Test]
        public async Task AStoppingNodeSaysSoOnEverySession()
        {

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");
            await shell.WriteAsync("sync");

            await node!.Stop();

            await screen.WaitFor("The WWCP node is shutting down.");

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(0));

        }

        #endregion

        #region WhoSaysWhoIsHere

        /// <summary>
        /// 'who' lists the sessions open now, with their keys, and marks the
        /// asking one.
        /// </summary>
        [Test]
        public async Task WhoSaysWhoIsHere()
        {

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            var mark = screen.Text.Length;
            await shell.WriteAsync("who\r");

            var answer = await screen.WaitFor("<- this one", mark);

            Assert.That(answer, Does.Contain($"{WWCPNode.DefaultAdminUser}  from 127.0.0.1:").And.Contain("key SHA256:"));

        }

        #endregion

        #region WithoutATerminalThereIsNothingToTypeAt

        /// <summary>
        /// A session without a terminal - ssh -T - is told what it needs, and ends.
        /// </summary>
        [Test]
        public async Task WithoutATerminalThereIsNothingToTypeAt()
        {

            await using var client  = await SignIn();
            var shell               = await client.OpenShellAsync(null);
            var screen              = new Screen(shell);

            await screen.WaitFor("wants a terminal");

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(1));

        }

        #endregion

        #region AKindsCommandLineIsWhatASessionGets

        /// <summary>
        /// The program says which command line a session gets: its kind's, with
        /// the kind's own commands beside the node's.
        /// </summary>
        [Test]
        public async Task AKindsCommandLineIsWhatASessionGets()
        {

            node!.CommandLines = (terminal, caller) => new NodeCLITests.KindCLI(node, terminal, caller);

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            var mark = screen.Text.Length;
            await shell.WriteAsync("kindOnly\r");

            await screen.WaitFor("the kind's own", mark);

        }

        #endregion

    }

}
