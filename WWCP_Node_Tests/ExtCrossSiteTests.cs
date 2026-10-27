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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What another site makes a browser send to the HTTPExt API at "/ext"
    /// (POI3-ISSUES.md S23): every request that is not a read is refused with
    /// 403 where the browser says it is another site's - by Sec-Fetch-Site, or
    /// by an Origin that is neither the node's own nor the name a trusted proxy
    /// says - as the JSON API refuses it; reads, the node's own pages and
    /// programs that are no browsers are let through.
    /// </summary>
    [TestFixture]
    public class ExtCrossSiteTests
    {

        #region Data

        private          String          directory  = "";
        private readonly List<WWCPNode>  nodes      = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-ext-cross-site-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helpers) Started(Web) / Send(Node, Method, Path, Headers, Body) / SignIn(Node, Headers)

        /// <summary>
        /// A node with the JSON API every node has, whose file says the given
        /// "web" section, started on fresh ports.
        /// </summary>
        private async Task<WWCPNode> Started(String Web = "{}")
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var home        = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
                var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

                File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": {{Web}} }""");

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(home, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(configFile),
                                        CertificatesPath:  Path.Combine(home, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false,
                                        SSH:               new SSHSettings(OnByDefault: false));

                _ = new NodeHTTPAPI(made.HTTPServer, made, made.ExtAPI, made.Log);

                return made;

            });

            nodes.Add(node);

            return node;

        }

        /// <summary>
        /// One request to the node, with the given header fields, on a
        /// connection of its own and without a cookie jar.
        /// </summary>
        private static async Task<HttpResponseMessage> Send(WWCPNode                       Node,
                                                            HttpMethod                     Method,
                                                            String                         Path,
                                                            IEnumerable<(String, String)>  Headers,
                                                            HttpContent?                   Body   = null)
        {

            using var handler  = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
            using var client   = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var request  = new HttpRequestMessage(Method, $"http://127.0.0.1:{Node.HTTPPort}/{Path}") { Content = Body };

            foreach (var (name, value) in Headers)
                Assert.That(request.Headers.TryAddWithoutValidation(name, value), Is.True, $"{name}: {value}");

            var response = await client.SendAsync(request);

            await response.Content.LoadIntoBufferAsync();

            return response;

        }

        /// <summary>
        /// The administrator's sign-in at ext/login, as a form sends it, with the
        /// given header fields.
        /// </summary>
        private static Task<HttpResponseMessage> SignIn(WWCPNode                   Node,
                                                        params (String, String)[]  Headers)

            => Send(Node,
                    HttpMethod.Post,
                    "ext/login",
                    Headers,
                    new FormUrlEncodedContent([
                        new KeyValuePair<String, String>("login",     WWCPNode.DefaultAdminUser),
                        new KeyValuePair<String, String>("password",  Node.GeneratedPassword!)
                    ]));

        private static async Task<String?> DescriptionOf(HttpResponseMessage Response)
        {
            try
            {
                return JObject.Parse(await Response.Content.ReadAsStringAsync())["description"]?.Value<String>();
            }
            catch
            {
                return null;
            }
        }

        #endregion


        #region TheSignInRefusesAnotherSitesForm()

        /// <summary>
        /// A form of another site that posts to the sign-in is refused, as the
        /// browser says it by Sec-Fetch-Site or by its Origin; the node's own
        /// page, and a program that says neither, sign in.
        /// </summary>
        [Test]
        public async Task TheSignInRefusesAnotherSitesForm()
        {

            var node = await Started();
            var own  = $"http://127.0.0.1:{node.HTTPPort}";

            using var byOrigin    = await SignIn(node, ("Origin",          "https://evil.example"));
            using var bySite      = await SignIn(node, ("Sec-Fetch-Site",  "cross-site"));
            using var sameSite    = await SignIn(node, ("Sec-Fetch-Site",  "same-site"));
            using var otherPort   = await SignIn(node, ("Origin",          $"http://127.0.0.1:{node.HTTPPort.ToUInt16() + 1}"));
            using var ownPage     = await SignIn(node, ("Origin",          own), ("Sec-Fetch-Site", "same-origin"));
            using var program     = await SignIn(node);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(byOrigin. StatusCode,               Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(await DescriptionOf(byOrigin),      Is.EqualTo("Cross-site requests are refused."));
                Assert.That(bySite.   StatusCode,               Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(sameSite. StatusCode,               Is.EqualTo(HttpStatusCode.Forbidden), "another origin of the same site");
                Assert.That(otherPort.StatusCode,               Is.EqualTo(HttpStatusCode.Forbidden), "another port of the same host");
                Assert.That((Int32) ownPage.StatusCode,         Is.InRange(200, 399), "the node's own page");
                Assert.That((Int32) program.StatusCode,         Is.InRange(200, 399), "a program");
            }

        }

        #endregion

        #region AnotherSitesTextPlainReachesNoAccountRoute()

        /// <summary>
        /// A body of "text/plain" that reads as JSON - what another site's form
        /// may send without asking - reaches none of the account's routes from
        /// another site's page: not the password, not a new API key.
        /// </summary>
        [Test]
        public async Task AnotherSitesTextPlainReachesNoAccountRoute()
        {

            var node      = await Started();

            using var signedIn  = await SignIn(node);

            var session   = signedIn.Headers.GetValues("Set-Cookie").
                                             First(cookie => cookie.StartsWith($"{node.ExtAPI.SessionCookieName}=", StringComparison.Ordinal)).
                                             Split(';')[0];

            using var password  = await Send(node,
                                             new HttpMethod("SET"),
                                             $"ext/users/{WWCPNode.DefaultAdminUser}/password",
                                             [ ("Cookie", session), ("Origin", "https://evil.example") ],
                                             new StringContent("""{ "currentPassword": "x", "newPassword": "Correct-Horse-Battery-Staple-9!" }""", Encoding.UTF8, "text/plain"));

            using var apiKey    = await Send(node,
                                             new HttpMethod("ADD"),
                                             $"ext/users/{WWCPNode.DefaultAdminUser}/APIKeys",
                                             [ ("Cookie", session), ("Sec-Fetch-Site", "cross-site") ],
                                             new StringContent("""{ "description": "mine now" }""", Encoding.UTF8, "text/plain"));

            using var read      = await Send(node,
                                             HttpMethod.Get,
                                             $"ext/users/{WWCPNode.DefaultAdminUser}",
                                             [ ("Cookie", session), ("Origin", "https://evil.example"), ("Accept", "application/json") ]);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(password.StatusCode,             Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(apiKey.  StatusCode,             Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(read.    StatusCode,             Is.Not.EqualTo(HttpStatusCode.Forbidden), "a read is no change");
                Assert.That(node.ExtAPI.VerifyPassword(User_Id.Parse(WWCPNode.DefaultAdminUser), node.GeneratedPassword!),  Is.True);
            }

        }

        #endregion

        #region BehindATrustedProxyTheNameItSaysIsTheNodesOwn()

        /// <summary>
        /// Behind a trusted proxy that does not pass the browser's Host on, a
        /// page of the name the proxy says is the node's own - at "/ext" and at
        /// the JSON API alike; where the proxy is not trusted, it is another
        /// site's.
        /// </summary>
        [Test]
        public async Task BehindATrustedProxyTheNameItSaysIsTheNodesOwn()
        {

            var trusted    = await Started("""{ "trustedProxies": [ "127.0.0.1" ] }""");
            var untrusted  = await Started("""{ "trustedProxies": [ "10.0.0.0/8" ] }""");

            (String, String)[] fromTheProxy = [ ("Origin", "https://hub.example.org"), ("X-Forwarded-Host", "hub.example.org"), ("X-Forwarded-Proto", "https") ];

            using var signIn         = await SignIn(trusted,   fromTheProxy);
            using var logout         = await Send  (trusted,   HttpMethod.Post, "api/v1/auth/logout", fromTheProxy);
            using var signInElse     = await SignIn(untrusted, fromTheProxy);
            using var logoutElse     = await Send  (untrusted, HttpMethod.Post, "api/v1/auth/logout", fromTheProxy);

            using (Assert.EnterMultipleScope())
            {
                Assert.That((Int32) signIn.StatusCode,  Is.InRange(200, 399));
                Assert.That(logout.    StatusCode,      Is.EqualTo(HttpStatusCode.NoContent));
                Assert.That(signInElse.StatusCode,      Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(logoutElse.StatusCode,      Is.EqualTo(HttpStatusCode.Forbidden));
            }

        }

        #endregion

    }

}
