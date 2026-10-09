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
    /// What the account page asks of a node, asked of a running one through
    /// the HTTPExt API below /ext, in the shapes the page sends: the account's
    /// details changed and saved whole, still signing in, with its roles, after
    /// a restart too; an API key made as the page makes one, opening the door
    /// until it is switched off or removed; an SSH key switched off letting
    /// nobody in until it is switched on; and nobody at another account.
    /// </summary>
    public class AccountPageTests
    {

        #region Data

        private const    String          Kim        = "kimberly";
        private const    String          KimsWord   = "Correct-Horse-1";

        private          String          directory  = "";
        private          String          password   = "";
        private readonly List<WWCPNode>  nodes      = [];

        /// <summary>
        /// The JSON API every node has, as a kind of node brings it: /api/v1/auth/me.
        /// </summary>
        private sealed class PageAPI(WWCPNode TheNode)
            : NodeHTTPAPI(TheNode.HTTPServer, TheNode, TheNode.ExtAPI, TheNode.Log);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-account-page-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helpers) Started(SSHPort) / Client(Node, Login, Password) / Send(...) / SignIn(Node, Key)

        /// <summary>
        /// A node on this test's directory - the first start, or the next -
        /// with its JSON API, and its SSH server where a port is given.
        /// </summary>
        private async Task<WWCPNode> Started(UInt16? SSHPort = null)
        {

            var configFile = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configFile, """{ "nts": { "enabled": false } }""");

            var node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                    AccountsPath:      Path.Combine(directory, "accounts"),
                                    ConfigFile:        new WWCPConfigFile(configFile),
                                    CertificatesPath:  Path.Combine(directory, "certificates"),
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    SSH:               SSHPort.HasValue
                                                           ? new SSHSettings(Enabled: true, Port: IPPort.Parse(SSHPort.Value))
                                                           : new SSHSettings(OnByDefault: false));

            nodes.Add(node);
            _ = new PageAPI(node);

            await node.Start();

            if (node.GeneratedPassword is String generated)
                password = generated;

            return node;

        }

        /// <summary>
        /// A client of the node signed in as the given account, with HTTP Basic
        /// Auth, which the routes below /ext take as they take the page's session.
        /// </summary>
        private HttpClient Client(WWCPNode Node, String Login = WWCPNode.DefaultAdminUser, String? Password = null)
        {

            var client = new HttpClient { BaseAddress = new Uri(Node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                             "Basic",
                                                             Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Login}:{Password ?? password}"))
                                                         );

            return client;

        }

        private static async Task<(HttpStatusCode Status, JToken? JSON, String Text)> Send(HttpClient  HTTP,
                                                                                         String      Method,
                                                                                         String      Path,
                                                                                         JToken?     JSON    = null,
                                                                                         String?     APIKey  = null)
        {

            using var request   = new HttpRequestMessage(new HttpMethod(Method), Path);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (APIKey is not null)
            {
                request.Headers.Authorization = null;
                request.Headers.Add("API-Key", APIKey);
            }

            if (JSON is not null)
                request.Content = new StringContent(JSON.ToString(), Encoding.UTF8, "application/json");

            using var response  = await HTTP.SendAsync(request);
            var text            = await response.Content.ReadAsStringAsync();

            JToken? json = null;

            try
            {
                json = text.Length > 0 ? JToken.Parse(text) : null;
            }
            catch (Exception)
            { }

            return (response.StatusCode, json, text);

        }

        /// <summary>
        /// Sign in to the node over SSH as root, with the given key.
        /// </summary>
        private static ValueTask<SshClient> SignIn(WWCPNode Node, ISshHostKey Key)

            => SshClient.ConnectAsync("127.0.0.1",
                                      Node.SSHPort!.Value.ToUInt16(),
                                      new SshClientOptions {
                                          Username       = WWCPNode.DefaultAdminUser,
                                          VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                          Credentials    = [ Key ]
                                      });

        /// <summary>
        /// Whether the key signs in over SSH.
        /// </summary>
        private static async Task<Boolean> SignsIn(WWCPNode Node, ISshHostKey Key)
        {
            try
            {
                await using var client = await SignIn(Node, Key);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion


        #region AnAccountSavedWholeStillSignsInWithItsRoles_AfterARestartToo()

        /// <summary>
        /// The page reads the account, changes what its form shows and sends
        /// the whole of it back with SET: the change is there, after a restart
        /// too, and the account signs in with its password and holds its roles
        /// as before - a SET that lost the account's groups or password would
        /// leave nobody able to manage the node.
        /// </summary>
        [Test]
        public async Task AnAccountSavedWholeStillSignsInWithItsRoles_AfterARestartToo()
        {

            var node = await Started();

            using (var http = Client(node))
            {

                var (status, read, text) = await Send(http, "GET", "ext/users/root");

                Assert.That(status, Is.EqualTo(HttpStatusCode.OK), text);

                var account = (JObject) read!;
                account.Remove("youCanEdit");
                account["name"]         = new JObject(new JProperty("en", "Root of all"));
                account["email"]        = "root@example.test";
                account["mobilePhone"]  = "+49 170 1234567";
                account["description"]  = new JObject(new JProperty("en", "Looks after this node"));

                var saved = await Send(http, "SET", "ext/users/root", account);

                Assert.That(saved.Status, Is.EqualTo(HttpStatusCode.OK), saved.Text);

                var me = await Send(http, "GET", "api/v1/auth/me");

                Assert.Multiple(() => {
                    Assert.That(me.Status,                                          Is.EqualTo(HttpStatusCode.OK), "the account saved no longer signs in: " + me.Text);
                    Assert.That(me.JSON?["roles"]?.Values<String>(),                Does.Contain("systemadmin"),   "the account saved lost its role");
                });

            }

            await node.DisposeAsync();
            nodes.Remove(node);

            var again = await Started();

            using (var http = Client(again))
            {

                var (status, read, text) = await Send(http, "GET", "ext/users/root");
                var me                   = await Send(http, "GET", "api/v1/auth/me");

                Assert.Multiple(() => {
                    Assert.That(status,                                             Is.EqualTo(HttpStatusCode.OK), "after a restart the account no longer signs in: " + text);
                    Assert.That(read?["name"]?["en"]?.Value<String>(),              Is.EqualTo("Root of all"));
                    Assert.That(read?["email"]?.Value<String>(),                    Is.EqualTo("root@example.test"));
                    Assert.That(read?["mobilePhone"]?.Value<String>(),              Does.Contain("170"));
                    Assert.That(read?["description"]?["en"]?.Value<String>(),       Is.EqualTo("Looks after this node"));
                    Assert.That(me.JSON?["roles"]?.Values<String>(),                Does.Contain("systemadmin"),   "after a restart the account lost its role");
                });

            }

        }

        #endregion

        #region AnAPIKeyMadeAsThePageMakesItOpensUntilSwitchedOffOrRemoved()

        /// <summary>
        /// An API key sent as the page sends one - its "@id" made in the
        /// browser, "readOnly", a description in English, when it was made and
        /// until when it is valid - is taken, listed, and opens the node's API;
        /// switched off it opens nothing, switched on it opens again, and
        /// removed it opens nothing.
        /// </summary>
        [Test]
        public async Task AnAPIKeyMadeAsThePageMakesItOpensUntilSwitchedOffOrRemoved()
        {

            var node   = await Started();
            var key    = "Page0made0key0" + Guid.NewGuid().ToString("N");
            var path   = $"ext/users/root/APIKeys/{key}";

            using var http    = Client(node);
            using var anybody = new HttpClient { BaseAddress = new Uri(node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            var added = await Send(http, "ADD", "ext/users/root/APIKeys", new JObject(
                                                                             new JProperty("@id",           key),
                                                                             new JProperty("@context",      "https://opendata.social/contexts/UsersAPI/APIKey"),
                                                                             new JProperty("userId",        "root"),
                                                                             new JProperty("description",   new JObject(new JProperty("en", "monitoring"))),
                                                                             new JProperty("accessRights",  "readOnly"),
                                                                             new JProperty("created",       DateTime.UtcNow.ToString("o")),
                                                                             new JProperty("notAfter",      DateTime.UtcNow.AddYears(1).ToString("o"))
                                                                         ));

            Assert.That(added.Status, Is.EqualTo(HttpStatusCode.OK), "the key as the page sends it was refused: " + added.Text);

            var listed   = await Send(http,    "GET", "ext/users/root/APIKeys");
            var opens    = await Send(anybody, "GET", "api/v1/auth/me", APIKey: key);

            var off      = await Send(http,    "SET", path, new JObject(new JProperty("isDisabled", true)));
            var offOpens = await Send(anybody, "GET", "api/v1/auth/me", APIKey: key);

            var on       = await Send(http,    "SET", path, new JObject(new JProperty("isDisabled", false)));
            var onOpens  = await Send(anybody, "GET", "api/v1/auth/me", APIKey: key);

            var removed  = await Send(http,    "DELETE", path);
            var goneOpens= await Send(anybody, "GET", "api/v1/auth/me", APIKey: key);

            Assert.Multiple(() => {
                Assert.That(listed.JSON?.Select(one => one["description"]?["en"]?.Value<String>()), Does.Contain("monitoring"));
                Assert.That(opens.Status,      Is.EqualTo(HttpStatusCode.OK),            "the key made opens nothing: " + opens.Text);
                Assert.That(opens.JSON?["username"]?.Value<String>(), Is.EqualTo("root"));
                Assert.That(off.Status,        Is.EqualTo(HttpStatusCode.OK),            off.Text);
                Assert.That(offOpens.Status,   Is.EqualTo(HttpStatusCode.Unauthorized),  "switched off, and the key opens the door");
                Assert.That(on.Status,         Is.EqualTo(HttpStatusCode.OK),            on.Text);
                Assert.That(onOpens.Status,    Is.EqualTo(HttpStatusCode.OK),            "switched on, and the key opens nothing");
                Assert.That(removed.Status,    Is.EqualTo(HttpStatusCode.OK),            removed.Text);
                Assert.That(goneOpens.Status,  Is.EqualTo(HttpStatusCode.Unauthorized),  "removed, and the key opens the door");
            });

        }

        #endregion

        #region AnSSHKeySwitchedOffLetsNobodyInUntilSwitchedOn()

        /// <summary>
        /// An SSH key added, as the page adds one, signs in to the command
        /// line; switched off it lets nobody in, and the SSH server's page says
        /// it is off; switched on it signs in again.
        /// </summary>
        [Test]
        public async Task AnSSHKeySwitchedOffLetsNobodyInUntilSwitchedOn()
        {

            var node   = await Started(TestPorts.Free());
            var key    = SshHostKey.GenerateEd25519();
            var path   = $"ext/users/root/SSHKeys/{UserSSHKey.FingerprintInURL(SshFingerprint.Sha256(key.PublicKeyBlob))}";

            using var http = Client(node);

            var added  = await Send(http, "ADD", "ext/users/root/SSHKeys", new JObject(
                                                                              new JProperty("line",   SshPublicKey.FromHostKey(key, "tester").ToAuthorizedKeyLine()),
                                                                              new JProperty("label",  "laptop")
                                                                          ));

            Assert.That(added.Status, Is.EqualTo(HttpStatusCode.OK), added.Text);
            Assert.That(await SignsIn(node, key), Is.True, "the key added does not sign in");

            var off    = await Send(http, "SET", path, new JObject(new JProperty("isDisabled", true)));
            var offIn  = await SignsIn(node, key);
            var page   = await Send(http, "GET", "api/v1/configuration/ssh");

            var on     = await Send(http, "SET", path, new JObject(new JProperty("isDisabled", false)));
            var onIn   = await SignsIn(node, key);

            // Root has the key its first start made as well.
            var shown  = page.JSON?["accounts"]?.Children<JObject>().Single(account => account.Value<String>("account") == "root")["keys"]?.
                             Single(one => one.Value<String>("fingerprint") == SshFingerprint.Sha256(key.PublicKeyBlob));

            Assert.Multiple(() => {
                Assert.That(off.Status,                              Is.EqualTo(HttpStatusCode.OK), off.Text);
                Assert.That(offIn,                                   Is.False, "switched off, and the key signs in");
                Assert.That(shown?["isDisabled"]?.Value<Boolean>(),  Is.True,  "the SSH server's page does not say the key is off");
                Assert.That(on.Status,                               Is.EqualTo(HttpStatusCode.OK), on.Text);
                Assert.That(onIn,                                    Is.True,  "switched on, and the key does not sign in");
            });

        }

        #endregion

        #region NobodyIsAtAnotherAccount()

        /// <summary>
        /// The page is the account's own: another account signed in gets 403
        /// for reading or saving it, and for its API keys and SSH keys - the
        /// system administrator's included.
        /// </summary>
        [Test]
        public async Task NobodyIsAtAnotherAccount()
        {

            var node          = await Started();
            var organization  = node.ExtAPI.GetOrganization(Organization_Id.Parse(node.Kind.Organization));

            Assert.That(organization, Is.Not.Null);

            var kim = await node.ExtAPI.CreateUser(
                                User_Id.Parse(Kim),
                                I18NString.Create(Kim),
                                SimpleEMailAddress.Parse($"{Kim}@example.test"),
                                KimsWord,
                                SkipDefaultNotifications:  true,
                                SkipNewUserEMail:          true,
                                SkipNewUserNotifications:  true,
                                AcceptedEULA:              DateTimeOffset.UtcNow.AddDays(-1),
                                IsAuthenticated:           true
                            );

            Assert.That(kim, Is.Not.Null);
            Assert.That((await node.ExtAPI.AddUserToOrganization(kim!, User2OrganizationEdgeLabel.IsMember, organization!)).IsSuccess, Is.True);

            using var asKim = Client(node, Kim, KimsWord);

            var own      = await Send(asKim, "GET", $"ext/users/{Kim}");
            var read     = await Send(asKim, "GET", "ext/users/root");
            var saved    = await Send(asKim, "SET", "ext/users/root", new JObject(
                                                                         new JProperty("@id",       "root"),
                                                                         new JProperty("@context",  "https://opendata.social/contexts/UsersAPI/user"),
                                                                         new JProperty("name",      new JObject(new JProperty("en", "Kim was here"))),
                                                                         new JProperty("email",     "kim@example.test")
                                                                     ));
            var apiKeys  = await Send(asKim, "GET", "ext/users/root/APIKeys");
            var sshKeys  = await Send(asKim, "GET", "ext/users/root/SSHKeys");

            using var asRoot = Client(node);

            var rootAtKims = await Send(asRoot, "GET", $"ext/users/{Kim}/APIKeys");

            Assert.Multiple(() => {
                Assert.That(own.Status,         Is.EqualTo(HttpStatusCode.OK),         "kim may not read kim: " + own.Text);
                // Hermod's GET of another account says 401 where its SET says 403: refused either way.
                Assert.That(read.Status,        Is.AnyOf(HttpStatusCode.Forbidden, HttpStatusCode.Unauthorized), read.Text);
                Assert.That(read.Text,          Does.Not.Contain("root@"),             "kim was shown root's account");
                Assert.That(saved.Status,       Is.EqualTo(HttpStatusCode.Forbidden),  saved.Text);
                Assert.That(apiKeys.Status,     Is.EqualTo(HttpStatusCode.Forbidden),  apiKeys.Text);
                Assert.That(sshKeys.Status,     Is.EqualTo(HttpStatusCode.Forbidden),  sshKeys.Text);
                Assert.That(rootAtKims.Status,  Is.EqualTo(HttpStatusCode.Forbidden),  "the system administrator is at kim's keys: " + rootAtKims.Text);
                Assert.That(node.ExtAPI.TryGetUser(User_Id.Parse("root"), out var root) ? root?.Name.FirstText() : null,
                                                Is.Not.EqualTo("Kim was here"));
            });

        }

        #endregion

    }

}
