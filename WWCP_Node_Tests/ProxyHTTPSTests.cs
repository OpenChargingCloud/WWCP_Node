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

using NUnit.Framework;

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
    /// A node behind a reverse proxy that does the HTTPS: what the trusted
    /// proxy says of the browser's leg - HTTPS or not - decides the secure
    /// session cookie and HSTS, request by request; who it says the client is
    /// goes into the log and into the count of password guesses; and what
    /// anybody else says is not believed, and said at debug level.
    /// </summary>
    /// <remarks>
    /// The node listens on 127.0.0.1, so every request here comes from
    /// 127.0.0.1: a proxy, where the file trusts that address, and a client
    /// where it does not.
    /// </remarks>
    public class ProxyHTTPSTests
    {

        #region Data

        private          String          directory  = "";
        private readonly List<WWCPNode>  nodes      = [];
        private readonly List<String>    said       = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-proxy-https-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);
            Directory.CreateDirectory(Path.Combine(directory, "frontend"));

            File.WriteAllText(Path.Combine(directory, "frontend", WWCPNode.IndexFile), "<!doctype html><title>{{NodeName}}</title>");

            lock (said)
                said.Clear();

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


        #region (helpers) Started(Web) / Send(Node, Method, Path, Headers, Body) / SessionCookieOf(Node, Response)

        /// <summary>
        /// A node with a web interface of one page and the JSON API every node
        /// has, whose file says the given "web" section, started on fresh ports -
        /// with its log, debug lines and all, kept in <see cref="said"/>.
        /// </summary>
        private async Task<WWCPNode> Started(String Web)
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var home        = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
                var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

                File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": {{Web}} }""");

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(home, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(configFile),
                                        Frontend:          new FileSystemContentSource(Path.Combine(directory, "frontend")),
                                        CertificatesPath:  Path.Combine(home, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false,
                                        SSH:               new SSHSettings(OnByDefault: false));

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                _ = new NodeHTTPAPI(made.HTTPServer, made, made.ExtAPI, made.Log);

                return made;

            });

            nodes.Add(node);

            return node;

        }

        /// <summary>
        /// One request to the node over plain HTTP, with the given header fields
        /// written as given, on a connection of its own and without a cookie jar.
        /// </summary>
        private static async Task<HttpResponseMessage> Send(WWCPNode                          Node,
                                                            HttpMethod                        Method,
                                                            String                            Path,
                                                            IEnumerable<(String, String)>     Headers,
                                                            HttpContent?                      Body   = null)
        {

            using var handler  = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
            using var client   = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
            using var request  = new HttpRequestMessage(Method, $"http://127.0.0.1:{Node.HTTPPort}/{Path}") { Content = Body };

            foreach (var (name, value) in Headers)
                Assert.That(request.Headers.TryAddWithoutValidation(name, value), Is.True, $"{name}: {value}");

            var response = await client.SendAsync(request);

            await response.Content.LoadIntoBufferAsync();

            return response;

        }

        /// <summary>
        /// A sign-in with the given password, from behind whatever the header
        /// fields say.
        /// </summary>
        private static Task<HttpResponseMessage> SignIn(WWCPNode                       Node,
                                                        String                         Password,
                                                        params (String, String)[]      Headers)

            => Send(Node,
                    HttpMethod.Post,
                    "ext/login",
                    Headers,
                    new FormUrlEncodedContent([
                        new KeyValuePair<String, String>("login",     WWCPNode.DefaultAdminUser),
                        new KeyValuePair<String, String>("password",  Password)
                    ]));

        /// <summary>
        /// The session cookie an answer sets, as it was written, or null.
        /// </summary>
        private static String? SessionCookieOf(WWCPNode             Node,
                                               HttpResponseMessage  Response)

            => Response.Headers.TryGetValues("Set-Cookie", out var cookies)
                   ? cookies.FirstOrDefault(cookie => cookie.StartsWith($"{Node.ExtAPI.SessionCookieName}=", StringComparison.Ordinal))
                   : null;

        #endregion


        #region HTTPSAsTheTrustedProxySaysIt_MakesTheCookieSecureAndSendsHSTS()

        /// <summary>
        /// From a trusted proxy that says the browser's leg was HTTPS, the
        /// session cookie of a sign-in is a secure one and the pages carry HSTS;
        /// from the same proxy saying it was plain HTTP, neither - request by
        /// request, on one node.
        /// </summary>
        [Test]
        public async Task HTTPSAsTheTrustedProxySaysIt_MakesTheCookieSecureAndSendsHSTS()
        {

            var node = await Started("""{ "trustedProxies": [ "127.0.0.1" ] }""");

            using var overHTTPS     = await SignIn(node, node.GeneratedPassword!, ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "https"));
            using var overHTTP      = await SignIn(node, node.GeneratedPassword!, ("X-Forwarded-For", "192.0.2.8"), ("X-Forwarded-Proto", "http"));
            using var pageHTTPS     = await Send(node, HttpMethod.Get, "", [ ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "https") ]);
            using var pageHTTP      = await Send(node, HttpMethod.Get, "", [ ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "http") ]);
            using var pageForwarded = await Send(node, HttpMethod.Get, "", [ ("Forwarded", "for=192.0.2.7;proto=https") ]);

            Assert.Multiple(() => {

                Assert.That(overHTTPS.IsSuccessStatusCode,                           Is.True, $"{(Int32) overHTTPS.StatusCode}");
                Assert.That(SessionCookieOf(node, overHTTPS),                        Does.Contain("secure").IgnoreCase);
                Assert.That(SessionCookieOf(node, overHTTP),                         Is.Not.Null.And.Not.Contain("secure").IgnoreCase,
                            "a secure cookie over a leg of plain HTTP is one the browser drops");

                Assert.That(pageHTTPS.Headers.TryGetValues("Strict-Transport-Security", out var hsts) ? hsts.Single() : null,
                                                                                     Is.EqualTo("max-age=31536000"));
                Assert.That(pageHTTP.     Headers.Contains("Strict-Transport-Security"),  Is.False);
                Assert.That(pageForwarded.Headers.Contains("Strict-Transport-Security"),  Is.False,
                            "Forwarded is not the header this node was told its proxies write");

                Assert.That(node.HTTPS,                                              Is.False);
                Assert.That(node.ExtAPI.UseSecureCookies,                            Is.False);
                Assert.That(node.PlainHTTPWarning,                                   Is.Null);

            });

        }

        #endregion

        #region ForwardedSaysTheProtoOfTheHopItsClientWasFoundAt()

        /// <summary>
        /// Where the proxies write "Forwarded", its "proto" is read - of the
        /// element the client was found at, reading from the right - and
        /// X-Forwarded-Proto is not.
        /// </summary>
        [Test]
        public async Task ForwardedSaysTheProtoOfTheHopItsClientWasFoundAt()
        {

            var node = await Started("""{ "trustedProxies": [ "127.0.0.1", "10.0.0.0/8" ], "clientAddressHeader": "Forwarded" }""");

            using var https      = await Send(node, HttpMethod.Get, "", [ ("Forwarded", "for=192.0.2.7;proto=https, for=10.1.2.3;proto=http") ]);
            using var http       = await Send(node, HttpMethod.Get, "", [ ("Forwarded", "for=192.0.2.7;proto=http, for=10.1.2.3;proto=https") ]);
            using var xfp        = await Send(node, HttpMethod.Get, "", [ ("Forwarded", "for=192.0.2.7"), ("X-Forwarded-Proto", "https") ]);

            Assert.Multiple(() => {
                Assert.That(https.Headers.Contains("Strict-Transport-Security"),  Is.True,  "the client's hop was HTTPS");
                Assert.That(http. Headers.Contains("Strict-Transport-Security"),  Is.False, "the client's hop was plain HTTP, whatever the hop after it was");
                Assert.That(xfp.  Headers.Contains("Strict-Transport-Security"),  Is.False, "X-Forwarded-Proto is not read beside Forwarded");
            });

        }

        #endregion

        #region FromAnUntrustedPeerTheHeadersAreIgnored_AndSaidAtDebugLevel()

        /// <summary>
        /// From a peer that is no trusted proxy, what it says of HTTPS and of the
        /// client is not believed: the cookie is not secure, no HSTS is sent, the
        /// log names the TCP peer - and says at debug level what was not believed.
        /// </summary>
        [Test]
        public async Task FromAnUntrustedPeerTheHeadersAreIgnored_AndSaidAtDebugLevel()
        {

            var node = await Started("""{ "trustedProxies": [ "10.0.0.0/8" ] }""");

            using var signIn  = await SignIn(node, node.GeneratedPassword!, ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "https"));
            using var page    = await Send(node, HttpMethod.Get, "", [ ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "https") ]);

            Assert.Multiple(() => {

                Assert.That(signIn.IsSuccessStatusCode,                          Is.True);
                Assert.That(SessionCookieOf(node, signIn),                       Is.Not.Null.And.Not.Contain("secure").IgnoreCase);
                Assert.That(page.Headers.Contains("Strict-Transport-Security"),  Is.False);

                lock (said)
                {
                    Assert.That(said.Where(line => line.StartsWith("X-Forwarded-For, X-Forwarded-Proto from 127.0.0.1:", StringComparison.Ordinal)),
                                Has.Some.EndsWith("not believed: it is no trusted proxy."));
                    Assert.That(said, Has.Some.StartsWith("GET / from 127.0.0.1:"));
                    Assert.That(said, Has.None.Contains("192.0.2.7"));
                }

            });

        }

        #endregion

        #region TheLogNamesTheClientTheTrustedProxyNames()

        /// <summary>
        /// Every request in the log names the client a trusted proxy names, and
        /// the proxy beside it.
        /// </summary>
        [Test]
        public async Task TheLogNamesTheClientTheTrustedProxyNames()
        {

            var node = await Started("""{ "trustedProxies": [ "127.0.0.1" ] }""");

            using var page = await Send(node, HttpMethod.Get, "", [ ("X-Forwarded-For", "203.0.113.9, 192.0.2.7"), ("X-Forwarded-Proto", "https") ]);

            lock (said)
                Assert.That(said, Has.Some.StartsWith("GET / from 192.0.2.7 (via 127.0.0.1:"),
                            "the client is the first address from the right that is no trusted proxy, and what stands left of it the client's own word");

        }

        #endregion

        #region PasswordGuessesAreCountedPerClientTheTrustedProxyNames()

        /// <summary>
        /// Behind a trusted proxy, the sign-in's ration of guesses is counted
        /// against the client the proxy names: one client that guessed ten times
        /// waits, and another behind the same proxy signs in at once. Without the
        /// proxies trusted, both are the proxy, and both wait.
        /// </summary>
        [Test]
        public async Task PasswordGuessesAreCountedPerClientTheTrustedProxyNames()
        {

            async Task<(HttpStatusCode Guesser, HttpStatusCode Other)> AfterTenGuesses(WWCPNode Node)
            {

                // Another account for the guesses, so that only the client's
                // ration is used up and not root's.
                for (var guess = 1; guess <= 10; guess++)
                {
                    using var wrong = await Send(Node, HttpMethod.Post, "ext/login", [ ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "https") ],
                                                 new FormUrlEncodedContent([
                                                     new KeyValuePair<String, String>("login",     "nobody"),
                                                     new KeyValuePair<String, String>("password",  $"Not-The-Password-{guess}")
                                                 ]));
                }

                using var guesser = await SignIn(Node, Node.GeneratedPassword!, ("X-Forwarded-For", "192.0.2.7"), ("X-Forwarded-Proto", "https"));
                using var other   = await SignIn(Node, Node.GeneratedPassword!, ("X-Forwarded-For", "198.51.100.4"), ("X-Forwarded-Proto", "https"));

                return (guesser.StatusCode, other.StatusCode);

            }

            var trusted    = await AfterTenGuesses(await Started("""{ "trustedProxies": [ "127.0.0.1" ] }"""));
            var untrusted  = await AfterTenGuesses(await Started("""{ "trustedProxies": [ "10.0.0.0/8" ] }"""));

            Assert.Multiple(() => {
                Assert.That(trusted.Guesser,    Is.EqualTo(HttpStatusCode.TooManyRequests), "the client who guessed waits");
                Assert.That((Int32) trusted.Other,  Is.InRange(200, 399),               "another client behind the same proxy signs in");
                Assert.That(untrusted.Guesser,  Is.EqualTo(HttpStatusCode.TooManyRequests));
                Assert.That(untrusted.Other,    Is.EqualTo(HttpStatusCode.TooManyRequests), "without the proxy trusted, every client is the proxy");
            });

        }

        #endregion

        #region TheNameTheBrowserAskedByIsTheProxys()

        /// <summary>
        /// The name the browser asked by - for what a page writes for somebody to
        /// type somewhere else - is X-Forwarded-Host where a trusted proxy says
        /// it, without its port, and the request's own Host otherwise.
        /// </summary>
        [Test]
        public async Task TheNameTheBrowserAskedByIsTheProxys()
        {

            var node = await Started("""{ "trustedProxies": [ "127.0.0.1" ] }""");

            String? host       = null;
            String? untrusted  = null;

            node.HTTPServer.OnHTTPRequest += (server, request, token) => {
                if (request.Path.ToString().EndsWith("/host", StringComparison.Ordinal))
                    host = node.HostOf(request);
                return Task.CompletedTask;
            };

            using (await Send(node, HttpMethod.Get, "api/v1/host", [ ("X-Forwarded-Host", "hub.example.org:443") ])) { }

            var plain = await Started("{}");

            plain.HTTPServer.OnHTTPRequest += (server, request, token) => {
                if (request.Path.ToString().EndsWith("/host", StringComparison.Ordinal))
                    untrusted = plain.HostOf(request);
                return Task.CompletedTask;
            };

            using (await Send(plain, HttpMethod.Get, "api/v1/host", [ ("X-Forwarded-Host", "hub.example.org") ])) { }

            Assert.Multiple(() => {
                Assert.That(host,       Is.EqualTo("hub.example.org"));
                Assert.That(untrusted,  Is.EqualTo("127.0.0.1"));
            });

        }

        #endregion

        #region BehindAProxyNoWarningIsSaid()

        /// <summary>
        /// A node that trusts a proxy in front says no warning about plain HTTP,
        /// says in the log whom it believes, and says on the Configuration page
        /// which proxies those are.
        /// </summary>
        [Test]
        public async Task BehindAProxyNoWarningIsSaid()
        {

            var node = await Started("""{ "trustedProxies": [ "127.0.0.1", "::1" ] }""");
            var http = node.ConfigurationJSON()["http"];

            Assert.Multiple(() => {
                Assert.That(node.PlainHTTPWarning,                                          Is.Null);
                Assert.That(http?["trustedProxies"]?.Values<String>(),                      Is.EqualTo(new[] { "127.0.0.1", "::1" }));
                Assert.That(http?.Value<String>("clientAddressHeader"),                     Is.EqualTo("X-Forwarded-For"));
                Assert.That(http?.Value<String>("hsts"),                                    Is.EqualTo("max-age=31536000"));
                Assert.That(http?["tls"]?.Type,                                             Is.EqualTo(Newtonsoft.Json.Linq.JTokenType.Null));
            });

            lock (said)
                Assert.That(said, Has.Some.StartsWith("Behind 127.0.0.1, ::1: the client X-Forwarded-For names"));

        }

        #endregion

    }

}
