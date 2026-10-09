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
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The SSH server as its page shows it, and its settings changed from
    /// there - saved, and made at once: a server moved answers on its new port
    /// and on its old one no more, a port that is taken leaves it where it was,
    /// and a switch on the command line wins and is said to.
    /// </summary>
    public class SSHConfigurationTests
    {

        #region Data

        private          String          directory  = "";
        private readonly List<WWCPNode>  nodes      = [];
        private readonly List<PageAPI>   apis       = [];

        /// <summary>
        /// The JSON API every node has, as a kind of node brings it.
        /// </summary>
        private sealed class PageAPI(WWCPNode TheNode)
            : NodeHTTPAPI(TheNode.HTTPServer, TheNode, TheNode.ExtAPI, TheNode.Log);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-ssh-page-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
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


        #region (helpers) Started(Port, CommandLine) / Client(Node) / Send(...) / Listens(Port) / SignIn(Node, Key)

        private String ConfigFile
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// A node whose SSH server the file puts on the given port - or the
        /// command line, where it says so - started.
        /// </summary>
        private async Task<WWCPNode> Started(UInt16 Port, Boolean CommandLine = false)
        {

            File.WriteAllText(ConfigFile, CommandLine
                                              ? """{ "nts": { "enabled": false } }"""
                                              : $$"""{ "nts": { "enabled": false }, "ssh": { "enabled": true, "port": {{Port}} } }""");

            var node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                    AccountsPath:      Path.Combine(directory, "accounts"),
                                    ConfigFile:        new WWCPConfigFile(ConfigFile),
                                    CertificatesPath:  Path.Combine(directory, "certificates"),
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    SSH:               CommandLine
                                                           ? new SSHSettings(Enabled: true, Port: IPPort.Parse(Port))
                                                           : new SSHSettings(OnByDefault: false));

            nodes.Add(node);
            apis. Add(new PageAPI(node));

            await node.Start();

            return node;

        }

        private static HttpClient Client(WWCPNode Node, String Login = "root", String? Password = null)
        {

            var client = new HttpClient { BaseAddress = new Uri(Node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                             "Basic",
                                                             Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Login}:{Password ?? Node.GeneratedPassword}"))
                                                         );

            return client;

        }

        private static async Task<(HttpStatusCode Status, JObject JSON)> Send(HttpClient  HTTP,
                                                                             HttpMethod  Method,
                                                                             JObject?    JSON = null)
        {

            using var request   = new HttpRequestMessage(Method, "api/v1/configuration/ssh");

            if (JSON is not null)
                request.Content = new StringContent(JSON.ToString(), Encoding.UTF8, "application/json");

            using var response  = await HTTP.SendAsync(request);
            var text            = await response.Content.ReadAsStringAsync();

            return (response.StatusCode, text.Length > 0 ? JObject.Parse(text) : new JObject());

        }

        /// <summary>
        /// Whether something accepts a connection on the given port of this machine.
        /// </summary>
        private static async Task<Boolean> Listens(UInt16 Port)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(System.Net.IPAddress.Loopback, Port).WaitAsync(TimeSpan.FromSeconds(5));
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Sign in to the node over SSH as root, with the given key, on the
        /// port it serves SSH on now, believing nothing but its own host key.
        /// </summary>
        private static ValueTask<SshClient> SignIn(WWCPNode Node, ISshHostKey Key)

            => SshClient.ConnectAsync("127.0.0.1",
                                      Node.SSHPort!.Value.ToUInt16(),
                                      new SshClientOptions {
                                          Username       = "root",
                                          VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                          Credentials    = [ Key ]
                                      });

        private static JObject Section(String File)
            => (JObject) JObject.Parse(System.IO.File.ReadAllText(File))["ssh"]!;

        #endregion


        #region TheSSHServerIsShownAsItRuns()

        /// <summary>
        /// Whether it runs and where, what the file says, its host key as a
        /// client compares it and as known_hosts takes it, what it allows and
        /// offers, who is connected, and the keys every account signs in with.
        /// </summary>
        [Test]
        public async Task TheSSHServerIsShownAsItRuns()
        {

            var port     = TestPorts.Free();
            var node     = await Started(port);
            var key      = SshHostKey.GenerateEd25519();

            Assert.That((await node.AuthorizeSSHKey("root", SshPublicKey.FromHostKey(key, "tester").ToAuthorizedKeyLine())).IsAdded, Is.True);

            await using var client = await SignIn(node, key);
            await using var shell  = await client.OpenShellAsync(new SshPty("xterm", new SshWindowSize(80, 24), new Dictionary<Byte, UInt32>()));

            for (var waited = 0; node.CommandLineSessions.Count == 0 && waited < 100; waited++)
                await Task.Delay(50);

            using var http      = Client(node);
            var (status, ssh)   = await Send(http, HttpMethod.Get);
            var hostKey         = ssh["hostKeys"]![0]!;
            var root            = ssh["accounts"]!.Children<JObject>().Single(account => account.Value<String>("account") == "root");

            Assert.Multiple(() => {

                Assert.That(status,                                                Is.EqualTo(HttpStatusCode.OK), ssh.ToString());
                Assert.That(ssh.Value<Boolean>("enabled"),                         Is.True);
                Assert.That(ssh.Value<UInt16>("port"),                             Is.EqualTo(port));
                Assert.That(ssh.Value<String>("url"),                              Is.EqualTo(node.SSHURL));
                Assert.That(ssh["configured"]!.Value<UInt16>("port"),              Is.EqualTo(port), "what the file says");
                Assert.That(ssh["commandLine"]!.Children().Any(),                  Is.False, "a switch said something");

                Assert.That($"{hostKey.Value<String>("algorithm")} {hostKey.Value<String>("fingerprint")}",
                                                                                   Is.EqualTo(node.SSHHostKey), "the host key a client is shown");
                Assert.That(hostKey.Value<String>("knownHosts"),                   Does.StartWith($"[127.0.0.1]:{port} ssh-ed25519 AAAA"));
                Assert.That(hostKey.Value<String>("publicKey"),                    Does.StartWith("ssh-ed25519 AAAA"));

                Assert.That(ssh["algorithms"]!["keyExchange"]!.Values<String>(),   Does.Contain("curve25519-sha256").And.Contain("mlkem768x25519-sha256"));
                Assert.That(ssh["algorithms"]!["hostKey"]!.Values<String>(),       Is.EqualTo(new[] { "ssh-ed25519" }));
                Assert.That(ssh["algorithms"]!["cipher"]!.Values<String>(),        Does.Contain("chacha20-poly1305@openssh.com"));
                Assert.That(ssh["limits"]!.Value<Int32>("loginGraceTime"),         Is.EqualTo(30));
                Assert.That(ssh["limits"]!.Value<Int32>("maxSessions"),            Is.EqualTo(4));

                Assert.That(ssh.Value<Int32>("connections"),                       Is.Positive);
                Assert.That(ssh["sessions"]!.Select(session => session.Value<String>("account")),
                                                                                   Is.EqualTo(new[] { "root" }), "who is connected");
                Assert.That(ssh["sessions"]![0]!.Value<String>("key"),             Is.EqualTo(SshFingerprint.Sha256(key.PublicKeyBlob)));
                Assert.That(root["keys"]!.Select(one => one.Value<String>("fingerprint")),
                                                                                   Does.Contain(SshFingerprint.Sha256(key.PublicKeyBlob)), "the keys an account signs in with");
                Assert.That(root["keys"]!.Single(one => one.Value<String>("fingerprint") == SshFingerprint.Sha256(key.PublicKeyBlob)).Value<String>("comment"),
                                                                                   Is.EqualTo("tester"));

            });

        }

        #endregion

        #region AServerMovedAnswersOnItsNewPortAndOnItsOldNoMore()

        /// <summary>
        /// Moved, it is saved in the file, answers on the new port - with the
        /// same host key - and no longer on the old one.
        /// </summary>
        [Test]
        public async Task AServerMovedAnswersOnItsNewPortAndOnItsOldNoMore()
        {

            var before  = TestPorts.Free();
            var after   = TestPorts.Free();
            var node    = await Started(before);
            var hostKey = node.SSHHostKey;

            using var http      = Client(node);
            var (status, ssh)   = await Send(http, HttpMethod.Put, new JObject(new JProperty("enabled", true), new JProperty("port", after)));

            Assert.Multiple(async () => {
                Assert.That(status,                               Is.EqualTo(HttpStatusCode.OK), ssh.ToString());
                Assert.That(ssh.Value<UInt16>("port"),            Is.EqualTo(after));
                Assert.That(node.SSHPort?.ToUInt16(),             Is.EqualTo(after));
                Assert.That(Section(ConfigFile).Value<UInt16>("port"), Is.EqualTo(after), "saved in the file");
                Assert.That(await Listens(after),                 Is.True,  "nothing answers on the new port");
                Assert.That(await Listens(before),                Is.False, "the old port still answers");
                Assert.That(node.SSHHostKey,                      Is.EqualTo(hostKey), "moved, it is another machine to its clients");
            });

            var key = SshHostKey.GenerateEd25519();
            Assert.That((await node.AuthorizeSSHKey("root", SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine())).IsAdded, Is.True);

            await using var client = await SignIn(node, key);

            Assert.That(client, Is.Not.Null, "signing in on the new port");

        }

        #endregion

        #region APortThatIsTakenLeavesTheServerWhereItWas()

        /// <summary>
        /// A port another program listens on is a 409: nothing is saved, and the
        /// server goes on on the port it had.
        /// </summary>
        [Test]
        public async Task APortThatIsTakenLeavesTheServerWhereItWas()
        {

            var before    = TestPorts.Free();
            var node      = await Started(before);

            // On the address the node listens on: on Windows, one on 0.0.0.0
            // leaves 127.0.0.1 to be bound all the same.
            using var squatter = new TcpListener(System.Net.IPAddress.Loopback, 0);
            squatter.Start();
            var taken     = (UInt16) ((IPEndPoint) squatter.LocalEndpoint).Port;

            using var http      = Client(node);
            var (status, said)  = await Send(http, HttpMethod.Put, new JObject(new JProperty("enabled", true), new JProperty("port", taken)));

            Assert.Multiple(async () => {
                Assert.That(status,                                    Is.EqualTo(HttpStatusCode.Conflict), said.ToString());
                Assert.That(said.Value<String>("error"),               Does.Contain($"Port {taken} is taken").And.Contain($"goes on on port {before}"));
                Assert.That(node.SSHPort?.ToUInt16(),                  Is.EqualTo(before));
                Assert.That(Section(ConfigFile).Value<UInt16>("port"), Is.EqualTo(before), "saved although it did not happen");
                Assert.That(await Listens(before),                     Is.True, "the server stopped where it was");
            });

        }

        #endregion

        #region SwitchedOffItListensNowhereAndPasswordsAreToldAtOnce()

        /// <summary>
        /// Switched off it listens nowhere; switched on again it listens where
        /// it did; and told that passwords open it - on the port it has, which
        /// it binds again once the old server let go - it says so.
        /// </summary>
        [Test]
        public async Task SwitchedOffItListensNowhereAndPasswordsAreToldAtOnce()
        {

            var port   = TestPorts.Free();
            var node   = await Started(port);

            using var http   = Client(node);

            var (off, offJSON)   = await Send(http, HttpMethod.Put, new JObject(new JProperty("enabled", false)));

            Assert.Multiple(async () => {
                Assert.That(off,                                Is.EqualTo(HttpStatusCode.OK), offJSON.ToString());
                Assert.That(offJSON.Value<Boolean>("enabled"),  Is.False);
                Assert.That(node.SSHEnabled,                    Is.False);
                Assert.That(await Listens(port),                Is.False, "switched off, it still listens");
            });

            var (on, onJSON)     = await Send(http, HttpMethod.Put, new JObject(new JProperty("enabled", true)));

            Assert.Multiple(async () => {
                Assert.That(on,                                 Is.EqualTo(HttpStatusCode.OK), onJSON.ToString());
                Assert.That(await Listens(port),                Is.True, "switched on again, it does not listen where it did");
            });

            var (told, toldJSON) = await Send(http, HttpMethod.Put, new JObject(new JProperty("passwords", true)));

            Assert.Multiple(async () => {
                Assert.That(told,                                       Is.EqualTo(HttpStatusCode.OK), toldJSON.ToString());
                Assert.That(toldJSON.Value<Boolean>("passwords"),       Is.True);
                Assert.That(node.SSHPasswords,                          Is.True);
                Assert.That(Section(ConfigFile).Value<Boolean>("passwords"), Is.True);
                Assert.That(await Listens(port),                        Is.True, "the server did not come back on its port");
            });

        }

        #endregion

        #region TheCommandLineWinsAndIsSaidSo()

        /// <summary>
        /// A port given with --ssh-port wins over the file, as at a start: what
        /// was sent is saved for a start without the switch, and that is said.
        /// </summary>
        [Test]
        public async Task TheCommandLineWinsAndIsSaidSo()
        {

            var port    = TestPorts.Free();
            var asked   = TestPorts.Free();
            var node    = await Started(port, CommandLine: true);

            using var http      = Client(node);
            var (status, ssh)   = await Send(http, HttpMethod.Put, new JObject(new JProperty("port", asked)));

            Assert.Multiple(async () => {
                Assert.That(status,                                    Is.EqualTo(HttpStatusCode.OK), ssh.ToString());
                Assert.That(ssh.Value<String>("notice"),               Does.Contain($"--ssh-port {port}"));
                Assert.That(ssh["commandLine"]!.Value<UInt16>("port"), Is.EqualTo(port));
                Assert.That(node.SSHPort?.ToUInt16(),                  Is.EqualTo(port), "the switch lost");
                Assert.That(Section(ConfigFile).Value<UInt16>("port"), Is.EqualTo(asked), "what was sent was not saved");
                Assert.That(await Listens(port),                       Is.True);
                Assert.That(await Listens(asked),                      Is.False);
            });

        }

        #endregion

        #region AViewerSeesItAndChangesNothing()

        /// <summary>
        /// Somebody who may read everything sees the SSH server, and may not
        /// change it: a 403, and the server where it was.
        /// </summary>
        [Test]
        public async Task AViewerSeesItAndChangesNothing()
        {

            var port      = TestPorts.Free();
            var node      = await Started(port);
            var password  = "a viewer's password, 1234";

            Assert.That(node.ExtAPI.TryGetOrganization(Organization_Id.Parse(node.Kind.Organization), out var organization) && organization is Organization, Is.True);

            await node.ExtAPI.CreateUser(User_Id.Parse("viewer1"),
                                         I18NString.Create(Languages.en, "viewer1"),
                                         SimpleEMailAddress.Parse("viewer1@localhost"),
                                         User2OrganizationEdgeLabel.IsMember,
                                         (Organization) organization!,
                                         Password:                  password,
                                         SkipDefaultNotifications:  true,
                                         SkipNewUserEMail:          true,
                                         SkipNewUserNotifications:  true,
                                         AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                         IsAuthenticated:           true);

            Assert.That(node.ExtAPI.TryGetUser(User_Id.Parse("viewer1"), out var viewer) && viewer is User, Is.True);
            Assert.That(node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse("viewer"), out var group) && group is UserGroup, Is.True);

            await node.ExtAPI.AddUserToUserGroup((User) viewer!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            using var http         = Client(node, "viewer1", password);
            var (read,  shown)     = await Send(http, HttpMethod.Get);
            var (moved, refused)   = await Send(http, HttpMethod.Put, new JObject(new JProperty("enabled", false)));

            Assert.Multiple(async () => {
                Assert.That(read,                Is.EqualTo(HttpStatusCode.OK), shown.ToString());
                Assert.That(moved,               Is.EqualTo(HttpStatusCode.Forbidden), refused.ToString());
                Assert.That(node.SSHEnabled,     Is.True);
                Assert.That(await Listens(port), Is.True);
            });

        }

        #endregion

    }

}
