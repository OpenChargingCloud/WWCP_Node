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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
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
    /// The SSH access rules on a node: who may sign in from where and to where, and use what - asked at
    /// the door, before the command line and SFTP, and again of every session open when they change;
    /// saved in the "ssh" section, and changed at the command line.
    /// </summary>
    [TestFixture]
    public class SSHAccessTests
    {

        #region Data

        private static readonly SshPty  Terminal  = new ("xterm", new SshWindowSize(120, 40), new Dictionary<Byte, UInt32>());

        private String                  directory = "";
        private readonly List<WWCPNode> nodes     = [];
        private readonly List<String>   said      = [];
        private readonly ISshHostKey    rootKey   = SshHostKey.GenerateEd25519();

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-ssh-access-" + Guid.NewGuid().ToString("N")[..12]);
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

        #region (private) Started(Rules, Listen) / SignIn(Node, Address) / Said(What)

        private String ConfigPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// A node with SSH and SFTP on, the given rules in its file, root let in with a key.
        /// </summary>
        private async Task<WWCPNode> Started(String Rules = "[]", IIPAddress? Listen = null)
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                File.WriteAllText(ConfigPath,
                                  $$"""
                                  {
                                    "nts": { "groups": { "legal": { "enabled": false } } },
                                    "ssh": { "enabled": true, "port": {{TestPorts.Free()}}, "sftp": true, "accessRules": {{Rules}} }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        HTTPHostname:      Listen,
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(ConfigPath),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                nodes.Add(made);

                return made;

            });

            var added = await node.AuthorizeSSHKey(WWCPNode.DefaultAdminUser, SshPublicKey.FromHostKey(rootKey).ToAuthorizedKeyLine());

            // Started again in the same directory, the account has the key already.
            Assert.That(added.IsAdded || added.Outcome == AddSSHKeyOutcome.AlreadyThere, Is.True, added.Reason);

            return node;

        }

        private ValueTask<SshClient> SignIn(WWCPNode Node, String Address = "127.0.0.1")

            => SshClient.ConnectAsync(Address,
                                      Node.SSHPort!.Value.ToUInt16(),
                                      new SshClientOptions {
                                          Username       = WWCPNode.DefaultAdminUser,
                                          VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                          Credentials    = [ rootKey ]
                                      });

        private Boolean Said(String What)
        {
            lock (said)
                return said.Any(line => line.Contains(What, StringComparison.Ordinal));
        }

        /// <summary>
        /// Whether a signed-in client gets a session at all: a node that refused it at the door has
        /// disconnected it, and opening anything fails.
        /// </summary>
        private static async Task<Boolean> GetsASession(SshClient Client)
        {
            try
            {
                var channel = await Client.Multiplexer.OpenChannelAsync("session").AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                await channel.CloseAsync();
                return true;
            }
            catch (Exception exception) when (exception is not TimeoutException)
            {
                return false;
            }
        }

        /// <summary>
        /// The command line's first words, or its refusal, and its exit status.
        /// </summary>
        private static async Task<(String Text, Int32? Exit)> ShellOf(SshClient Client)
        {

            await using var shell = await Client.OpenShellAsync(Terminal);

            var text   = new StringBuilder();
            var buffer = new Byte[4096];

            using var within = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            try
            {
                while (!text.ToString().Contains("signed in as", StringComparison.Ordinal) &&
                       await shell.Output.ReadAsync(buffer, within.Token) is var read && read > 0)
                    text.Append(Encoding.UTF8.GetString(buffer, 0, read));
            }
            catch (OperationCanceledException)
            { }

            Int32? exit = null;

            try
            {
                exit = await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (TimeoutException)
            { }

            return (text.ToString(), exit);

        }

        #endregion


        #region ARuleWithoutAService_RefusesAtTheDoor_AndTheLogSaysWhich

        [Test]
        [CancelAfter(60000)]
        public async Task ARuleWithoutAService_RefusesAtTheDoor_AndTheLogSaysWhich(CancellationToken CancellationToken)
        {

            var node = await Started("""[ "allow principal=account:nobody", "deny principal=account:root local=127.0.0.1 # not from here" ]""");

            await using var client = await SignIn(node);

            var session = await GetsASession(client);

            Assert.Multiple(() => {
                Assert.That(session,                               Is.False, "refused at the door, it got a session");
                Assert.That(Said("rule 2 (deny principal=account:root local=127.0.0.1 # not from here) refuses account:root from 127.0.0.1 on 127.0.0.1"),
                            Is.True, "the log does not say which rule refused whom");
            });

        }

        #endregion

        #region ARuleForAService_RefusesThatService_AndNotTheOthers

        [Test]
        [CancelAfter(60000)]
        public async Task ARuleForAService_RefusesThatService_AndNotTheOthers(CancellationToken CancellationToken)
        {

            var node = await Started("""[ "deny principal=account:root service=shell" ]""");

            await using var client = await SignIn(node);

            var (text, exit) = await ShellOf(client);

            await using var sftp = await client.OpenSftpClientAsync(CancellationToken);
            var listed           = await sftp.ListDirectoryAsync("/", CancellationToken);   // served: it does not throw

            Assert.Multiple(() => {
                Assert.That(text,    Does.Contain("not permitted").And.Not.Contain("signed in as"), "the command line was served");
                Assert.That(exit,    Is.EqualTo(1));
                Assert.That(listed,  Is.Not.Null, "SFTP, which no rule refuses, was not served");
                Assert.That(Said("was refused the command line over SSH: SSH access rule 1"), Is.True);
            });

        }

        #endregion

        #region RulesChanged_EndTheSessionsTheyNowRefuse_AtOnce

        [Test]
        [CancelAfter(60000)]
        public async Task RulesChanged_EndTheSessionsTheyNowRefuse_AtOnce(CancellationToken CancellationToken)
        {

            var node = await Started();
            node.SSHSessionRecheckEvery = TimeSpan.FromMinutes(10);   // so that nothing but the change can end it

            await using var client = await SignIn(node);
            await using var sftp   = await client.OpenSftpClientAsync(CancellationToken);

            Assert.That(await sftp.ListDirectoryAsync("/", CancellationToken), Is.Not.Null, "SFTP was not served before the rules changed");

            Assert.That(SSHAccessRule.TryParseLine("deny service=sftp # no files over SSH any more", out var rule, out var error), Is.True, error);

            var change = await node.TryUpdateSSHAccessRules(new SSHAccessRules([ rule! ]));

            // Ended by the change itself - not by the client's next request, which an SFTP session is
            // asked about as well, and not by the recheck every few seconds, which is ten minutes off.
            var endedByTheChange = false;

            for (var waited = 0; waited < 50 && !endedByTheChange; waited++)
            {
                endedByTheChange = !node.SSHSessions.Any(session => session.Kind == WWCPNode.SSHSession.SFTP);
                if (!endedByTheChange)
                    await Task.Delay(100, CancellationToken);
            }

            Exception? ended = null;

            try
            {
                await sftp.ListDirectoryAsync("/", CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken);
            }
            catch (Exception exception) when (exception is not TimeoutException)
            {
                ended = exception;
            }

            // And asked for anew, on the same connection, it is refused.
            Exception? refusedAnew = null;

            try
            {
                await using var again = await client.OpenSftpClientAsync(CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken);
            }
            catch (Exception exception) when (exception is not TimeoutException)
            {
                refusedAnew = exception;
            }

            Assert.Multiple(() => {
                Assert.That(change.IsChanged,  Is.True, change.Error);
                Assert.That(endedByTheChange,  Is.True, "the SFTP session the new rules refuse was not ended by the change, within 5 s");
                Assert.That(ended,             Is.Not.Null, "the SFTP session the new rules refuse went on");
                Assert.That(refusedAnew,       Is.Not.Null, "SFTP asked for anew was served, though the rules refuse it");
                Assert.That(Said("The SSH access rules changed: 1 rule(s)"), Is.True);
                Assert.That(node.SSHSessions.Where(session => session.Kind == WWCPNode.SSHSession.SFTP), Is.Empty);
            });

        }

        #endregion

        #region ALocalAddressRule_TellsTheNetworksApart

        /// <summary>
        /// A node on every address: the same account, the same key - let in on one of the node's addresses
        /// and refused on another.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task ALocalAddressRule_TellsTheNetworksApart(CancellationToken CancellationToken)
        {

            var node = await Started("""[ "deny principal=account:* local=127.0.0.2 # the device network" ]""", IPv4Address.Any);

            await using var here     = await SignIn(node, "127.0.0.1");
            await using var there    = await SignIn(node, "127.0.0.2");

            var hereGets  = await GetsASession(here);
            var thereGets = await GetsASession(there);

            Assert.Multiple(() => {
                Assert.That(hereGets,   Is.True,  "refused on an address no rule names");
                Assert.That(thereGets,  Is.False, "let in on the address a rule refuses");
            });

        }

        #endregion

        #region TheRulesAreAsked_WithWhereTheClientCameFrom_AndWhereItCameTo

        /// <summary>
        /// Over loopback a client comes from the address it connects to; a session from 192.0.2.7 to
        /// 10.10.0.1 tells "source" and "local" apart.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task TheRulesAreAsked_WithWhereTheClientCameFrom_AndWhereItCameTo(CancellationToken CancellationToken)
        {

            var node    = await Started("""[ "deny principal=account:root local=10.10.0.1 service=shell", "deny principal=account:root source=10.10.0.1 service=sftp" ]""");

            var session = new SshSessionInfo("42",
                                             WWCPNode.DefaultAdminUser,
                                             "publickey",
                                             rootKey.PublicKeyBlob,
                                             IPSocket.Parse("192.0.2.7:50000"),
                                             IPSocket.Parse("10.10.0.1:22"),
                                             null,
                                             SshSessionRestrictions.None);

            Assert.Multiple(() => {
                Assert.That(node.SSHAccessFor(session, "shell").Number, Is.EqualTo(1),  "the rule for this node's address did not match the address the client came to");
                Assert.That(node.SSHAccessFor(session, "sftp"). Number, Is.Null,        "the rule for the client's address matched the address the client came to");
                Assert.That(node.SSHAccessRefusal(session, "shell"),    Does.Contain("from 192.0.2.7 on 10.10.0.1"));
            });

        }

        #endregion

        #region RulesThatCannotBeRead_AreNotSaved_AndTheOldOnesStay

        [Test]
        [CancelAfter(60000)]
        public async Task RulesThatCannotBeRead_AreNotSaved_AndTheOldOnesStay(CancellationToken CancellationToken)
        {

            var node   = await Started("""[ "deny principal=account:nobody" ]""");
            var before = File.ReadAllText(ConfigPath);

            var change = await node.TryUpdateSSHConfiguration(JObject.Parse("""{ "accessRules": [ { "action": "deny", "sourse": [ "10.0.0.0/8" ] } ] }"""));

            Assert.Multiple(() => {
                Assert.That(change.IsChanged,                                          Is.False);
                Assert.That(change.Error,                                              Does.Contain("ssh.accessRules[0]").And.Contain("sourse"));
                Assert.That(node.SSHAccessRules.Rules.Select(rule => rule.ToString()), Is.EqualTo(new[] { "deny principal=account:nobody" }));
                Assert.That(File.ReadAllText(ConfigPath),                              Is.EqualTo(before));
            });

        }

        #endregion

        #region RulesSaved_AreInTheFile_OnTheServersPage_AndAtTheNextStart

        [Test]
        [CancelAfter(60000)]
        public async Task RulesSaved_AreInTheFile_OnTheServersPage_AndAtTheNextStart(CancellationToken CancellationToken)
        {

            var node = await Started();

            Assert.That(SSHAccessRules.TryParse(JArray.Parse("""[ "deny principal=group:viewer service=sftp # read on the web", "allow" ]"""), "rules", out var rules, out var error), Is.True, error);

            var change = await node.TryUpdateSSHAccessRules(rules!);
            var page   = node.SSHConfigurationJSON();
            var file   = JObject.Parse(File.ReadAllText(ConfigPath));

            await node.DisposeAsync();
            nodes.Remove(node);

            var again  = await Started((file["ssh"]?["accessRules"] ?? new JArray()).ToString());

            Assert.Multiple(() => {
                Assert.That(change.IsChanged,                                                         Is.True, change.Error);
                Assert.That(file["ssh"]?["accessRules"]?.ToString(),                                  Is.EqualTo(rules!.ToJSON().ToString()));
                Assert.That(page["accessRules"]?.ToString(),                                          Is.EqualTo(rules!.ToJSON().ToString()));
                Assert.That(again.SSHAccessRules.Rules.Select(rule => rule.ToString()),               Is.EqualTo(new[] { "deny principal=group:viewer service=sftp # read on the web", "allow" }));
            });

        }

        #endregion


        #region TheCommandLine_AddsListsMovesTestsAndRemovesRules

        [Test]
        [CancelAfter(60000)]
        public async Task TheCommandLine_AddsListsMovesTestsAndRemovesRules(CancellationToken CancellationToken)
        {

            var node = await Started();

            using var cli = new NodeCLI(node);

            var none      = await cli.Execute("sshAccessRules");
            var first     = await cli.Execute("sshAccessRules add deny principal=account:* service=shell local=10.10.0.1 # the device network");
            var second    = await cli.Execute("sshAccessRules add at 1 allow principal=account:root");
            var testRoot  = await cli.Execute("sshAccessRules test account:root service=shell local=10.10.0.1");
            var testBob   = await cli.Execute("sshAccessRules test account:bob service=shell local=10.10.0.1");
            var testDoor  = await cli.Execute("sshAccessRules test account:bob local=10.10.0.1");
            var moved     = await cli.Execute("sshAccessRules move 2 1");
            var testAgain = await cli.Execute("sshAccessRules test account:root service=shell local=10.10.0.1");
            var removed   = await cli.Execute("sshAccessRules remove 1");
            var bad       = await cli.Execute("sshAccessRules add deny service=telnet");
            var nowhere   = await cli.Execute("sshAccessRules remove 7");

            Assert.Multiple(() => {

                Assert.That(none,      Has.Some.Contains("No SSH access rules"));
                Assert.That(first,     Has.Some.Contains("added SSH access rule 1").IgnoreCase);
                Assert.That(second,    Has.Some.EqualTo("1  allow principal=account:root"));
                Assert.That(second,    Has.Some.EqualTo("2  deny principal=account:* service=shell local=10.10.0.1 # the device network"));

                Assert.That(testRoot,  Has.Some.StartsWith("rule 1 (allow principal=account:root) lets on account:root shell"));
                Assert.That(testBob,   Has.Some.StartsWith("rule 2 (deny principal=account:* service=shell local=10.10.0.1 # the device network) refuses account:bob shell"));
                Assert.That(testDoor,  Has.Some.StartsWith("Let in at sign-in"));

                Assert.That(moved,     Has.Some.EqualTo("1  deny principal=account:* service=shell local=10.10.0.1 # the device network"));
                Assert.That(testAgain, Has.Some.StartsWith("rule 1 (deny").And.Some.Contains("refuses account:root shell"));

                Assert.That(removed,   Has.Some.EqualTo("1  allow principal=account:root"));
                Assert.That(bad,       Has.Some.Contains("telnet"));
                Assert.That(nowhere,   Has.Some.Contains("numbered 1 to 1"));

                Assert.That(node.SSHAccessRules.Rules.Select(rule => rule.ToString()), Is.EqualTo(new[] { "allow principal=account:root" }));
                Assert.That(Said("the console took out SSH access rule 1") || Said("took out SSH access rule 1"), Is.True, "the change is not in the log");

            });

        }

        #endregion

    }

}
