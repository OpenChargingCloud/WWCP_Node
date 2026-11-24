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

        private const           String Prompt   = "WWCP node> ";

        private String               directory  = "";
        private WWCPNode?            node;
        // A test's own, made new in each Setup: a node of the test before may
        // still log while it goes, and that is the test before's to hold.
        private List<String>         said       = [];
        private List<LogEntry>       entries    = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-cli-ssh-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), """{ "nts": { "groups": { "legal": { "enabled": false } } } }""");

            // Made again on fresh ports where one was taken before the node
            // could bind it, with a log of its own each time.
            node = await TestPorts.StartedOnFreshPorts(() => {

                       List<String>   said     = this.said    = [];
                       List<LogEntry> entries  = this.entries = [];

                       var log = new EventLog();
                       log.OnLogged += entry => { lock (said) { said.Add(entry.Message); entries.Add(entry); } };

                       return new WWCPNode(HTTPPort:          TestPorts.Free(),
                                           AccountsPath:      Path.Combine(directory, "accounts"),
                                           ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                           CertificatesPath:  Path.Combine(directory, "certificates"),
                                           Log:               log,
                                           LogToConsole:      false,
                                           BridgeDebugLog:    false,
                                           SSH:               new SSHSettings(Enabled: true, Port: TestPorts.Free()));

                   });

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion

        #region (private) Said()

        /// <summary>
        /// What the log has said so far, taken under its lock: a copy taken
        /// while a line is added may hold a slot not yet written.
        /// </summary>
        private String[] Said()
        {
            lock (said)
                return [.. said];
        }

        #endregion

        #region (private) MakeAccount(Account, Role) / SignIn(Account = root, Role = null) / Open(Client)

        /// <summary>
        /// Make the given account, in the given role.
        /// </summary>
        private async Task<User> MakeAccount(User_Id Account, String Role)
        {

            await node!.ExtAPI.AddUser(new User(Account, I18NString.Create(Languages.en, Account.ToString()), SimpleEMailAddress.Parse($"{Account}@localhost")),
                                       SkipDefaultNotifications: true, SkipNewUserEMail: true, SkipNewUserNotifications: true);

            node.ExtAPI.TryGetUser(Account, out var stored);
            node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group);

            await node.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            return (User) stored!;

        }

        /// <summary>
        /// Sign in over SSH as the given account - made, in the given role,
        /// where it is not root - with a key of its own.
        /// </summary>
        private async Task<SSHClient> SignIn(User_Id? Login = null, String? Role = null)
        {

            var Account = Login ?? WWCPNode.DefaultAdminUser;

            if (Account != WWCPNode.DefaultAdminUser)
                await MakeAccount(Account, Role!);

            var key = SshHostKey.GenerateEd25519();

            var added = await node!.AuthorizeSSHKey(Account, SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine());

            Assert.That(added.IsAdded, Is.True, added.Reason);

            return await SSHClient.Connect("127.0.0.1",
                                                node.SSHPort!.Value,
                                                new SSHClientOptions {
                                                    Username       = Account,
                                                    VerifyHostKey  = blob => node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                                    Credentials    = [ key ]
                                                });

        }

        private static async Task<(SshClientShell Shell, SSHScreen Screen)> Open(SSHClient Client, SshPty? Pty = null)
        {
            var shell  = await Client.OpenShell(Pty ?? Terminal);
            var screen = new SSHScreen(shell, Prompt);
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
        /// syncNTS-over-SSH writes the line 'Sync now' writes, naming the account
        /// - and "cli" and "ssh" where the page says "web".
        /// </summary>
        [Test]
        public async Task WhoAskedIsTheAccountAndTheTagSaysSSH()
        {

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");
            await screen.Run("syncNTS");

            LogEntry[] asked;
            lock (said)
                asked = [.. entries.Where(entry => entry.Message == $"'{WWCPNode.DefaultAdminUser}' at the command line over SSH asked this WWCP node to synchronise its time.")];

            Assert.That(asked,               Has.Length.EqualTo(1));
            Assert.That(asked[0].Level,      Is.EqualTo(LogLevel.Notice));
            Assert.That(asked[0].Tags,       Is.EqualTo(new[] { "nts", "test", "cli", "ssh" }));

        }

        #endregion

        #region WhatANodeLogsAfterItsTestIsNotTheNextTestsToRead

        /// <summary>
        /// A node of the test before may still log while it goes - a session
        /// that leaves - after the TearDown that cleared what the test had
        /// read. That line is the test before's, and lands in what it read, not
        /// in what the next test reads: added to the same list as the next
        /// test's Clear() ran, it left that list with empty slots, and the
        /// next test failed on a null entry (Gateway CI, Windows).
        /// </summary>
        [Test]
        public async Task WhatANodeLogsAfterItsTestIsNotTheNextTestsToRead()
        {

            var before = node!.Log;

            await TearDown();
            await Setup();

            before.Notice("said by the node of the test before, after its TearDown");

            lock (said)
                Assert.That(said, Has.None.EqualTo("said by the node of the test before, after its TearDown"));

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

            await using var client  = await SignIn(User_Id.Parse("aviewer"), Role.Viewer.Name);
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

        #region EachAccountGetsItsOwnHistoryBack

        /// <summary>
        /// A session brings back with Up what its account typed in the session
        /// before - and nothing another account typed: each account's history
        /// is a file of its own below the accounts.
        /// </summary>
        [Test]
        public async Task EachAccountGetsItsOwnHistoryBack()
        {

            await using (var client = await SignIn())
            {
                var (shell, screen) = await Open(client);
                await screen.WaitFor("WWCP node> ");
                await shell.WriteAsync("syncNTS nowhere.example\r");
                await screen.WaitFor("is none of this WWCP node's time servers");
            }

            await using (var client = await SignIn(User_Id.Parse("aviewer"), Role.Viewer.Name))
            {
                var (shell, screen) = await Open(client);
                await screen.WaitFor("WWCP node> ");
                await screen.Run("help");
            }

            var history = Path.Combine(directory, "accounts", NodeCLI.HistoryDirectory);

            Assert.Multiple(() => {
                Assert.That(new HistoryFile(Path.Combine(history, WWCPNode.DefaultAdminUser.ToString())).Read(),  Is.EqualTo(new[] { "syncNTS nowhere.example" }));
                Assert.That(new HistoryFile(Path.Combine(history, "aviewer")).Read(),                  Is.EqualTo(new[] { "help" }));
                Assert.That(OwnerOnlyChecks.OthersMayGetIn(history),                                   Is.Empty, "the directory");
                Assert.That(OwnerOnlyChecks.OthersMayGetIn(Path.Combine(history, "aviewer")),          Is.Empty, "a file");
            });

            await using (var client = await SignIn())
            {

                var (shell, screen) = await Open(client);
                await screen.WaitFor("WWCP node> ");

                var mark = screen.Text.Length;
                await shell.WriteAsync("\x1b[A");

                Assert.That(await screen.WaitFor("syncNTS nowhere.example", mark), Does.Not.Contain("help"));

            }

        }

        #endregion

        #region AnAccountsHistoryGoesWithIt

        /// <summary>
        /// What an account typed is its own, and goes when it goes: deleted, it
        /// leaves no history file behind, and an account made again under its
        /// name starts with none.
        /// </summary>
        [Test]
        public async Task AnAccountsHistoryGoesWithIt()
        {

            await using (var client = await SignIn(User_Id.Parse("aviewer"), Role.Viewer.Name))
            {
                var (shell, screen) = await Open(client);
                await screen.WaitFor("WWCP node> ");
                await screen.Run("help");
            }

            var file = Path.Combine(directory, "accounts", NodeCLI.HistoryDirectory, "aviewer");

            Assert.That(new HistoryFile(file).Read(), Is.EqualTo(new[] { "help" }));

            node!.ExtAPI.TryGetUser(User_Id.Parse("aviewer"), out var account);
            var deleted = await node.ExtAPI.DeleteUser(account!, SkipUserDeletedNotifications: true);

            Assert.That(deleted.Result,  Is.EqualTo(CommandResult.Success), deleted.Description?.FirstText());
            Assert.That(File.Exists(file), Is.False, "the history of the account deleted");

            await MakeAccount(User_Id.Parse("aviewer"), Role.Viewer.Name);

            Assert.That(new HistoryFile(file).Read(), Is.Empty, "the history of the account made again");

        }

        #endregion

        #region AnAccountMadeAgainDoesNotGetTheHistoryLeftBehind

        /// <summary>
        /// A history file whose account is gone - left by a node that did not
        /// yet take it away with the account - is not the history of the next
        /// account made under that name.
        /// </summary>
        [Test]
        public async Task AnAccountMadeAgainDoesNotGetTheHistoryLeftBehind()
        {

            var file = Path.Combine(directory, "accounts", NodeCLI.HistoryDirectory, "aviewer");

            Assert.That(new HistoryFile(file).Add("syncNTS nowhere.example"), Is.True);

            await MakeAccount(User_Id.Parse("aviewer"), Role.Viewer.Name);

            Assert.That(File.Exists(file), Is.False);

        }

        #endregion

        #region ASessionOfAnAccountDeletedLeavesNoHistoryBehind

        /// <summary>
        /// An account deleted while it is signed in may still type a line before
        /// its session is ended - one that needs no role is not asked about -
        /// and that line lands in a history file the deletion already took
        /// away. Once the session is over, that file is gone as well.
        /// </summary>
        [Test]
        public async Task ASessionOfAnAccountDeletedLeavesNoHistoryBehind()
        {

            // Ended by the recheck below, not by the one every few seconds.
            node!.SSHSessionRecheckEvery = TimeSpan.FromHours(1);

            var file                = Path.Combine(directory, "accounts", NodeCLI.HistoryDirectory, "aviewer");

            await using var client  = await SignIn(User_Id.Parse("aviewer"), Role.Viewer.Name);
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            node.ExtAPI.TryGetUser(User_Id.Parse("aviewer"), out var account);
            var deleted = await node.ExtAPI.DeleteUser(account!, SkipUserDeletedNotifications: true);

            Assert.That(deleted.Result, Is.EqualTo(CommandResult.Success), deleted.Description?.FirstText());

            var mark = screen.Text.Length;
            await screen.Run("help");

            Assert.That(new HistoryFile(file).Read(), Is.EqualTo(new[] { "help" }), "the line typed after the deletion");

            Assert.That(node.RecheckSSHSessions(), Is.EqualTo(1));

            await screen.WaitFor("Signed out:", mark);

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(1));
            Assert.That(File.Exists(file), Is.False);

        }

        #endregion

        #region AnAccountManagesItsOwnKeys

        /// <summary>
        /// Signed in over SSH, an account lists, lets in and takes out its own
        /// SSH keys, and makes and takes back its own API keys - without naming
        /// itself, and in any role: the keys are its own.
        /// </summary>
        [Test]
        public async Task AnAccountManagesItsOwnKeys()
        {

            await using var client  = await SignIn(User_Id.Parse("kimberly"), Role.Viewer.Name);
            var (shell, screen)     = await Open(client);
            var kimberly                 = User_Id.Parse("kimberly");

            await screen.WaitFor("WWCP node> ");

            var own   = node!.ExtAPI.GetSSHKeys(kimberly).Single();
            var mark  = screen.Text.Length;

            await shell.WriteAsync("sshKeys\r");
            Assert.That(await screen.WaitFor(own.Fingerprint, mark), Does.Contain(own.Fingerprint));

            var other = SshHostKey.GenerateEd25519();
            var line  = SshPublicKey.FromHostKey(other, "laptop").ToAuthorizedKeyLine();

            mark = screen.Text.Length;
            await shell.WriteAsync($"sshKeys add {line}\r");
            await screen.WaitFor("signs in with the key", mark);

            var added = node.ExtAPI.FindSSHKey(kimberly, other.PublicKeyBlob, DateTimeOffset.UtcNow);

            Assert.Multiple(() => {
                Assert.That(added,             Is.Not.Null, "not let in");
                Assert.That(added?.CreatedBy,  Is.EqualTo("kimberly"), "who let the key in");
                lock (said)
                    Assert.That(said, Has.Some.EqualTo($"'kimberly' at the command line over SSH let 'kimberly' in over SSH with the key {added?.Fingerprint}."));
            });

            mark = screen.Text.Length;
            await shell.WriteAsync($"sshKeys remove {added!.Fingerprint}\r");
            await screen.WaitFor("in no more", mark);

            Assert.That(node.ExtAPI.FindSSHKey(kimberly, other.PublicKeyBlob, DateTimeOffset.UtcNow), Is.Null, "still let in");

            var made = await screen.Run("apiKeys add for a script");

            Assert.That(made, Does.Contain("has a new API key, ReadOnly:"));

            var apiKeys = node.ExtAPI.GetAPIKeysForUser(node.ExtAPI.GetUser(kimberly)!).ToArray();

            Assert.Multiple(() => {
                Assert.That(apiKeys,                                      Has.Length.EqualTo(1));
                // Shown once, as it is made, and kept as its SHA-256 alone.
                Assert.That(System.Text.RegularExpressions.Regex.Matches(made, $"[A-Za-z0-9]{{{APIKeysCommand.KeyLength}}}").
                                                                          Select(shown => APIKey_Id.Of(shown.Value)),
                                                                          Has.Member(apiKeys[0].Id), "the key made is not the key shown");
                Assert.That(apiKeys[0].Description.FirstText(),           Is.EqualTo("for a script"));
            });

        }

        #endregion

        #region AnotherAccountsKeysAreForWhoMayActForIt

        /// <summary>
        /// The keys of another account are refused - in the log too - until the
        /// account signed in may act for it in the accounts, as an admin of the
        /// admins' organization may.
        /// </summary>
        [Test]
        public async Task AnotherAccountsKeysAreForWhoMayActForIt()
        {

            var hank                = await MakeAccount(User_Id.Parse("hank"), Role.Viewer.Name);
            var hanksKey            = SshHostKey.GenerateEd25519();

            Assert.That((await node!.AuthorizeSSHKey(User_Id.Parse("hank"), SshPublicKey.FromHostKey(hanksKey).ToAuthorizedKeyLine())).IsAdded, Is.True);

            var fingerprint         = SshFingerprint.Sha256(hanksKey.PublicKeyBlob);

            await using var client  = await SignIn(User_Id.Parse("kimberly"), Role.Viewer.Name);
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            foreach (var command in new[] { "sshKeys hank", $"sshKeys hank remove {fingerprint}", "apiKeys hank", "apiKeys hank add readWrite" })
            {

                var mark = screen.Text.Length;
                await shell.WriteAsync(command + "\r");

                Assert.That(await screen.WaitFor("may not do that for 'hank'", mark), Does.Not.Contain($"{fingerprint}  "), command);

            }

            Assert.Multiple(() => {
                Assert.That(node.ExtAPI.GetSSHKeys(hank.Id),          Has.Count.EqualTo(1), "a key was taken");
                Assert.That(node.ExtAPI.GetAPIKeysForUser(hank),      Is.Empty,             "a key was made");
                lock (said)
                    Assert.That(said, Has.Some.StartsWith("'kimberly' was refused 'sshKeys' for 'hank' at the command line over SSH").
                                          And.Some.StartsWith("'kimberly' was refused 'apiKeys' for 'hank' at the command line over SSH"));
            });

            var admins = new Organization(node.ExtAPI.AdminOrganizationId, I18NString.Create("Admins"));

            Assert.That((await node.ExtAPI.AddOrganization(admins)).Result, Is.EqualTo(CommandResult.Success));
            node.ExtAPI.TryGetUser(User_Id.Parse("kimberly"), out var kimberly);
            Assert.That((await node.ExtAPI.AddUserToOrganization(kimberly!, User2OrganizationEdgeLabel.IsAdmin, admins)).IsSuccess, Is.True);

            var listed = screen.Text.Length;
            await shell.WriteAsync("sshKeys hank\r");
            await screen.WaitFor(fingerprint, listed);

            var removed = screen.Text.Length;
            await shell.WriteAsync($"sshKeys hank remove {fingerprint}\r");
            await screen.WaitFor("lets 'hank' in no more", removed);

            var made = screen.Text.Length;
            await shell.WriteAsync("apiKeys hank add\r");
            await screen.WaitFor("has a new API key, ReadOnly:", made);

            Assert.Multiple(() => {
                Assert.That(node.ExtAPI.GetSSHKeys(hank.Id),          Is.Empty);
                Assert.That(node.ExtAPI.GetAPIKeysForUser(hank),      Has.Exactly(1).Items);
                lock (said)
                    Assert.That(said, Has.Some.EqualTo($"'kimberly' at the command line over SSH took the key {fingerprint} from 'hank': it lets nobody in from now on."));
            });

        }

        #endregion

        #region ASystemAdminManagesEveryAccountsKeys

        /// <summary>
        /// An account in the systemadmin role manages the keys of every other
        /// account - with no organization of admins anywhere, and those of
        /// another systemadmin too, whom the accounts let nobody act for.
        /// </summary>
        [Test]
        public async Task ASystemAdminManagesEveryAccountsKeys()
        {

            var hank                = await MakeAccount(User_Id.Parse("hank"), Role.Viewer.Name);
            var hanksKey            = SshHostKey.GenerateEd25519();

            Assert.That((await node!.AuthorizeSSHKey(User_Id.Parse("hank"), SshPublicKey.FromHostKey(hanksKey).ToAuthorizedKeyLine())).IsAdded, Is.True);

            var fingerprint         = SshFingerprint.Sha256(hanksKey.PublicKeyBlob);
            var rootsKey            = SshHostKey.GenerateEd25519();
            var rootsFingerprint    = SshFingerprint.Sha256(rootsKey.PublicKeyBlob);

            await using var client  = await SignIn(User_Id.Parse("sally"), WWCPNode.AdminRole.ToString());
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            var listed = screen.Text.Length;
            await shell.WriteAsync("sshKeys hank\r");
            await screen.WaitFor(fingerprint, listed);

            var removed = screen.Text.Length;
            await shell.WriteAsync($"sshKeys hank remove {fingerprint}\r");
            await screen.WaitFor("lets 'hank' in no more", removed);

            var made = screen.Text.Length;
            await shell.WriteAsync("apiKeys hank add\r");
            await screen.WaitFor("has a new API key, ReadOnly:", made);

            var rootsAdded = screen.Text.Length;
            await shell.WriteAsync($"sshKeys root add {SshPublicKey.FromHostKey(rootsKey).ToAuthorizedKeyLine()}\r");
            await screen.WaitFor($"'root' signs in with the key {rootsFingerprint} now.", rootsAdded);

            node.ExtAPI.TryGetUser(User_Id.Parse("sally"), out var sally);
            node.ExtAPI.TryGetUser(User_Id.Parse("root"),  out var root);

            Assert.Multiple(() => {
                Assert.That(node.ExtAPI.CanImpersonate(sally!, hank), Is.False,             "the accounts let sally act for hank - this test would not tell the role from them");
                Assert.That(node.ExtAPI.CanImpersonate(sally!, root!),Is.False,             "the accounts let sally act for root - this test would not tell the role from them");
                Assert.That(node.ExtAPI.GetSSHKeys(hank.Id),          Is.Empty);
                Assert.That(node.ExtAPI.GetAPIKeysForUser(hank),      Has.Exactly(1).Items);
                Assert.That(node.ExtAPI.GetSSHKeys(User_Id.Parse("root")).Select(key => key.Fingerprint), Does.Contain(rootsFingerprint));
                Assert.That(screen.Text,                              Does.Not.Contain("may not do that for"));
                lock (said)
                    Assert.That(said, Has.Some.EqualTo($"'sally' at the command line over SSH took the key {fingerprint} from 'hank': it lets nobody in from now on.").
                                          And.Some.EqualTo($"'sally' at the command line over SSH let 'root' in over SSH with the key {rootsFingerprint}."));
            });

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
            while (DateTime.UtcNow < until && !Said().Any(line => line.StartsWith($"'{WWCPNode.DefaultAdminUser}' left the command line over SSH after")))
                await Task.Delay(20);

            Assert.That(Said(), Has.Some.StartsWith($"'{WWCPNode.DefaultAdminUser}' left the command line over SSH after"));

        }

        #endregion

        #region AnAccountSwitchedOffIsSignedOutAtItsNextCommand

        /// <summary>
        /// An account switched off while it is in: its next command that needs a
        /// role is not run, the session says why and ends with exit status 1,
        /// and the log says who was signed out - as its sessions on the web
        /// interface end.
        /// </summary>
        [Test]
        public async Task AnAccountSwitchedOffIsSignedOutAtItsNextCommand()
        {

            // Only the check before a command, not the one every few seconds.
            node!.SSHSessionRecheckEvery = TimeSpan.FromHours(1);

            await using var client  = await SignIn(User_Id.Parse("anadmin"), WWCPNode.AdminRole.ToString());
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            node.ExtAPI.TryGetUser(User_Id.Parse("anadmin"), out var account);
            await node.ExtAPI.UpdateUser(account!, user => user.IsDisabled = true, SkipUserUpdatedNotifications: true);

            node.ExtAPI.TryGetUser(User_Id.Parse("anadmin"), out account);
            Assert.That(account!.IsDisabled, Is.True);

            var mark = screen.Text.Length;
            await shell.WriteAsync("syncNTS\r");

            var answer = await screen.WaitFor("Signed out: the account 'anadmin' was switched off.", mark);

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(1));

            var until = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < until && !Said().Any(line => line.StartsWith("'anadmin' was signed out of the command line over SSH from 127.0.0.1:")))
                await Task.Delay(20);

            Assert.Multiple(() => {
                Assert.That(Said(), Has.Some.StartsWith("'anadmin' was signed out of the command line over SSH from 127.0.0.1:").
                                         And.Some.EndsWith(": the account 'anadmin' was switched off."));
                Assert.That(Said(), Has.None.Contains("'anadmin' at the command line over SSH asked"), "The command ran.");
                Assert.That(node.CommandLineSessions, Is.Empty);
            });

        }

        #endregion

        #region AKeyTakenOutEndsItsSessionsWithoutACommand

        /// <summary>
        /// The key a session came with taken out of its account: the session is
        /// asked again every few seconds, and ends - typing nothing, its log
        /// with it - with a sentence naming the key.
        /// </summary>
        [Test]
        public async Task AKeyTakenOutEndsItsSessionsWithoutACommand()
        {

            node!.SSHSessionRecheckEvery = TimeSpan.FromMilliseconds(100);

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");

            var root = User_Id.Parse(WWCPNode.DefaultAdminUser.ToString());
            var key  = node.CommandLineSessions.Single().Key;

            Assert.That(await node.ExtAPI.RemoveSSHKey(root, key!), Is.True);

            await screen.WaitFor($"Signed out: the key {key} is no longer one '{WWCPNode.DefaultAdminUser}' signs in with - taken out, switched off or expired.");

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(1));

        }

        #endregion

        #region AnAccountThatMayStayInStaysIn

        /// <summary>
        /// Asked again and again, a session whose account and key are as they
        /// were goes on as it was.
        /// </summary>
        [Test]
        public async Task AnAccountThatMayStayInStaysIn()
        {

            node!.SSHSessionRecheckEvery = TimeSpan.FromMilliseconds(50);

            await using var client  = await SignIn();
            var (shell, screen)     = await Open(client);

            await screen.WaitFor("WWCP node> ");
            await Task.Delay(500);

            var mark = screen.Text.Length;
            await shell.WriteAsync("syncNTS nowhere.example\r");

            await screen.WaitFor("is none of this WWCP node's time servers", mark);

            Assert.That(screen.Text, Does.Not.Contain("Signed out"));

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
            var shell               = await client.OpenShell(null);
            var screen              = new SSHScreen(shell, Prompt);

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
