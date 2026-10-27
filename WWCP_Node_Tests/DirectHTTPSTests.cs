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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A node serving its web interface over TLS of its own, as the "web"
    /// section asks it: with the store's identity for "web", with PEM files
    /// read again when they change - and the one before kept where the new ones
    /// do not read - with HSTS on its pages and a secure session cookie, a port
    /// of plain HTTP that only redirects, and nothing at all where there is no
    /// certificate to show.
    /// </summary>
    public class DirectHTTPSTests
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

            directory = Path.Combine(Path.GetTempPath(), "node-direct-https-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helpers) SelfSigned(Name) / WritePEM(Certificate, FullChain, PrivateKey) / Started(Web, Prepare) / Get(...)

        /// <summary>
        /// A certificate for 127.0.0.1 with its key, the given name in its
        /// subject, as a server can use it on every platform: through a PKCS#12,
        /// because a key that only ever lived in memory is one Windows' TLS will
        /// not sign with.
        /// </summary>
        private static X509Certificate2 SelfSigned(String Name)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request   = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);
            var names     = new SubjectAlternativeNameBuilder();

            names.AddIpAddress(System.Net.IPAddress.Loopback);
            names.AddDnsName("localhost");

            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));

            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);

        }

        /// <summary>
        /// The certificate as certbot writes it: fullchain.pem, and privkey.pem
        /// beside it.
        /// </summary>
        private static void WritePEM(X509Certificate2  Certificate,
                                     String            FullChain,
                                     String            PrivateKey)
        {

            using var key = Certificate.GetECDsaPrivateKey()!;

            File.WriteAllText(FullChain,   Certificate.ExportCertificatePem());
            File.WriteAllText(PrivateKey,  key.ExportPkcs8PrivateKeyPem());

        }

        /// <summary>
        /// A node with a web interface of one page, whose file says the given
        /// "web" section, made on fresh ports and started - the given work done
        /// to it before it starts - with what it logs kept in <see cref="said"/>.
        /// </summary>
        private async Task<WWCPNode> Started(Func<String, String>  Web,
                                             Action<WWCPNode>?     Prepare  = null)
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var home        = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
                var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);
                var redirect    = TestPorts.Free().ToString();

                File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": {{Web(redirect)}} }""");

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

                Prepare?.Invoke(made);

                return made;

            });

            nodes.Add(node);

            return node;

        }

        /// <summary>
        /// A GET over HTTPS, on a connection of its own, that believes whatever
        /// certificate it is shown and says which it was.
        /// </summary>
        private static async Task<(HttpResponseMessage Response, String? Shown)> Get(String  URL,
                                                                                    Boolean AllowRedirects = false)
        {

            String? shown = null;

            var handler = new HttpClientHandler {
                              AllowAutoRedirect                          = AllowRedirects,
                              UseCookies                                 = false,
                              ServerCertificateCustomValidationCallback  = (message, served, chain, errors) => {
                                                                               shown = served is null ? null : CertificateEntry.ThumbprintOf(served);
                                                                               return true;
                                                                           }
                          };

            using var client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(15) };

            var response = await client.GetAsync(URL);

            await response.Content.LoadIntoBufferAsync();

            return (response, shown);

        }

        /// <summary>
        /// The certificate shown at a new connection, asked until it is the
        /// given one or the time is up.
        /// </summary>
        private static async Task<String?> ShownOnceItIs(String    URL,
                                                         String    Expected,
                                                         TimeSpan  Within)
        {

            var until  = DateTime.UtcNow + Within;
            String? shown;

            do
            {

                (var response, shown) = await Get(URL);
                response.Dispose();

                if (shown == Expected)
                    return shown;

                await Task.Delay(500);

            }
            while (DateTime.UtcNow < until);

            return shown;

        }

        #endregion


        #region TheStoresIdentityForTheWebIsShownWithHSTS()

        /// <summary>
        /// "certificate": "store" shows the store's TLS server identity, for
        /// "web" or told no listener, at every handshake: one put in after the
        /// node was made is shown, the pages carry HSTS, the node names itself by
        /// https URLs and the Configuration page says which certificate it is.
        /// </summary>
        [Test]
        public async Task TheStoresIdentityForTheWebIsShownWithHSTS()
        {

            using var certificate  = SelfSigned("node web interface from the store");

            var node = await Started(_ => """{ "tls": { "certificate": "store" } }""",
                                     made => Assert.That(made.Certificates.Import(certificate.Export(X509ContentType.Pkcs12),
                                                                                  CertificateKind.TLSServerIdentity,
                                                                                  null,
                                                                                  "web",
                                                                                  out _,
                                                                                  out var refused),
                                                         Is.True, refused));

            var (response, shown) = await Get($"https://127.0.0.1:{node.HTTPPort}/");
            var http              = node.ConfigurationJSON()["http"] as JObject;

            using (response)
                Assert.Multiple(() => {
                    Assert.That(shown,                                                   Is.EqualTo(CertificateEntry.ThumbprintOf(certificate)));
                    Assert.That(response.StatusCode,                                     Is.EqualTo(HttpStatusCode.OK));
                    Assert.That(response.Headers.TryGetValues("Strict-Transport-Security", out var hsts) ? hsts.Single() : null,
                                                                                         Is.EqualTo("max-age=31536000"));
                    Assert.That(node.HTTPS,                                              Is.True);
                    Assert.That(node.WebInterfaceURL.ToString(),                         Does.StartWith("https://"));
                    Assert.That(node.ExtAPI.UseSecureCookies,                            Is.True);
                    Assert.That(node.PlainHTTPWarning,                                   Is.Null);
                    Assert.That(http?["tls"]?.Value<String>("certificate"),              Is.EqualTo("store"));
                    Assert.That(http?["tls"]?.Value<String>("label"),                    Is.EqualTo("web"));
                    Assert.That(http?["tls"]?.Value<String>("thumbprint"),               Is.EqualTo(CertificateEntry.ThumbprintOf(certificate)));
                    Assert.That(http?.Value<String>("hsts"),                             Is.EqualTo("max-age=31536000"));
                });

            lock (said)
                Assert.That(said, Has.Some.Contains($"The web interface shows CN=node web interface from the store ({CertificateEntry.ThumbprintOf(certificate)})"));

        }

        #endregion

        #region PEMFilesAreReadAgainWhenTheyChange_AndTheOldOneKeptWhereTheNewOnesDoNotRead()

        /// <summary>
        /// certbot's fullchain.pem and privkey.pem: shown at once, a renewal that
        /// went half-way - the certificate copied, the key not yet - leaves the
        /// one before shown and is said in the log, and the renewal completed is
        /// shown from a handshake a few seconds later, without a restart.
        /// </summary>
        [Test]
        public async Task PEMFilesAreReadAgainWhenTheyChange_AndTheOldOneKeptWhereTheNewOnesDoNotRead()
        {

            using var first    = SelfSigned("node web interface first");
            using var renewed  = SelfSigned("node web interface renewed");

            var fullchain      = Path.Combine(directory, "fullchain.pem");
            var privkey        = Path.Combine(directory, "privkey.pem");

            WritePEM(first, fullchain, privkey);

            var node           = await Started(_ => new JObject(
                                                        new JProperty("tls", new JObject(
                                                            new JProperty("certificate", new JObject(
                                                                new JProperty("fullchain",   fullchain),
                                                                new JProperty("privateKey",  privkey)
                                                            ))
                                                        ))
                                                    ).ToString());

            var url            = $"https://127.0.0.1:{node.HTTPPort}/";

            var (response, shown) = await Get(url);

            using (response)
                Assert.Multiple(() => {
                    Assert.That(shown,                                                   Is.EqualTo(CertificateEntry.ThumbprintOf(first)));
                    Assert.That(response.Headers.Contains("Strict-Transport-Security"),  Is.True);
                });

            // Half of a renewal: the new certificate, the old key.
            File.WriteAllText(fullchain, renewed.ExportCertificatePem());

            await Task.Delay(ServerCertificateFile.DefaultCheckInterval + TimeSpan.FromSeconds(1));

            (response, shown) = await Get(url);
            response.Dispose();

            Assert.That(shown, Is.EqualTo(CertificateEntry.ThumbprintOf(first)), "the certificate before is shown while the new files do not read");

            lock (said)
                Assert.That(said.Where(line => line.StartsWith("The certificate of the web interface was not taken from", StringComparison.Ordinal)),
                            Has.Some.EndsWith("The one before is shown still."));

            // The renewal completed.
            WritePEM(renewed, fullchain, privkey);

            Assert.That(await ShownOnceItIs(url, CertificateEntry.ThumbprintOf(renewed), ServerCertificateFile.DefaultCheckInterval + TimeSpan.FromSeconds(10)),
                        Is.EqualTo(CertificateEntry.ThumbprintOf(renewed)));

            lock (said)
                Assert.That(said, Has.Some.Contains("The web interface shows CN=node web interface renewed"));

        }

        #endregion

        #region TheSessionCookieOfASignInOverHTTPSIsSecure()

        /// <summary>
        /// The sign-in over HTTPS of the node's own sets a secure session cookie,
        /// which a browser sends over TLS only.
        /// </summary>
        [Test]
        public async Task TheSessionCookieOfASignInOverHTTPSIsSecure()
        {

            using var certificate = SelfSigned("node web interface signing in");

            var node = await Started(_ => """{ "tls": { "certificate": "store" } }""",
                                     made => made.Certificates.Import(certificate.Export(X509ContentType.Pkcs12), CertificateKind.TLSServerIdentity, null, "web", out _, out _));

            using var handler  = new HttpClientHandler {
                                     AllowAutoRedirect                          = false,
                                     UseCookies                                 = false,
                                     ServerCertificateCustomValidationCallback  = (message, served, chain, errors) => true
                                 };

            using var client   = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            using var response = await client.PostAsync($"https://127.0.0.1:{node.HTTPPort}/ext/login",
                                                        new FormUrlEncodedContent([
                                                            new KeyValuePair<String, String>("login",     WWCPNode.DefaultAdminUser),
                                                            new KeyValuePair<String, String>("password",  node.GeneratedPassword!)
                                                        ]));

            var session = response.Headers.TryGetValues("Set-Cookie", out var cookies)
                              ? cookies.FirstOrDefault(cookie => cookie.StartsWith($"{node.ExtAPI.SessionCookieName}=", StringComparison.Ordinal))
                              : null;

            Assert.Multiple(() => {
                Assert.That(response.IsSuccessStatusCode,  Is.True, $"{(Int32) response.StatusCode}");
                Assert.That(session,                       Is.Not.Null, "no session cookie was set");
                Assert.That(session,                       Does.Contain("secure").IgnoreCase);
                Assert.That(session,                       Does.Contain("HttpOnly"));
            });

        }

        #endregion

        #region WithNothingToShowEveryConnectionIsRefused_NotServedInTheClear()

        /// <summary>
        /// HTTPS asked for, and nothing in the store to show: a connection is
        /// refused - over TLS and over plain HTTP alike - rather than served
        /// without TLS, which Hermod does where it is handed no certificate; the
        /// log says so once.
        /// </summary>
        [Test]
        public async Task WithNothingToShowEveryConnectionIsRefused_NotServedInTheClear()
        {

            var node = await Started(_ => """{ "tls": { "certificate": "store" } }""");

            await Assert.ThrowsAsync<HttpRequestException>(async () => (await Get($"https://127.0.0.1:{node.HTTPPort}/")).Response.Dispose());

            using var plain = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };

            HttpStatusCode? answered = null;

            try
            {
                using var response = await plain.GetAsync($"http://127.0.0.1:{node.HTTPPort}/");
                answered = response.StatusCode;
            }
            catch (HttpRequestException)
            { }
            catch (TaskCanceledException)
            { }

            Assert.That(answered, Is.Null, "a request over plain HTTP was answered on the port of HTTPS");

            lock (said)
                Assert.That(said.Count(line => line.StartsWith("The web interface has no certificate to show", StringComparison.Ordinal)), Is.EqualTo(1));

        }

        #endregion

        #region ThePortOfPlainHTTPSendsEveryBrowserToHTTPS()

        /// <summary>
        /// "redirectPort" answers every request - a page, the JSON API, a POST -
        /// with a 308 to the same path and query over HTTPS on the node's port,
        /// at the name it was asked by, and with nothing else.
        /// </summary>
        [Test]
        public async Task ThePortOfPlainHTTPSendsEveryBrowserToHTTPS()
        {

            using var certificate = SelfSigned("node web interface redirected to");

            var node = await Started(redirect => $$"""{ "tls": { "certificate": "store", "redirectPort": {{redirect}} } }""",
                                     made => made.Certificates.Import(certificate.Export(X509ContentType.Pkcs12), CertificateKind.TLSServerIdentity, null, "web", out _, out _));

            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
            using var plain   = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

            using var page    = await plain.GetAsync ($"http://127.0.0.1:{node.RedirectPort}/logs?level=warning");
            using var api     = await plain.PostAsync($"http://localhost:{node.RedirectPort}/api/v1/auth/logout", new StringContent(""));
            var       body    = await page.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(node.RedirectPort,                      Is.Not.Null);
                Assert.That(page.StatusCode,                        Is.EqualTo(HttpStatusCode.PermanentRedirect));
                Assert.That(page.Headers.Location?.ToString(),      Is.EqualTo($"https://127.0.0.1:{node.HTTPPort}/logs?level=warning"));
                Assert.That(body,                                   Does.Not.Contain("<title>"), "the redirect served a page");
                Assert.That(page.Headers.Contains("Set-Cookie"),    Is.False);
                Assert.That(api.StatusCode,                         Is.EqualTo(HttpStatusCode.PermanentRedirect));
                Assert.That(api.Headers.Location?.ToString(),       Is.EqualTo($"https://localhost:{node.HTTPPort}/api/v1/auth/logout"));
                Assert.That((node.ConfigurationJSON()["http"]?["tls"] as JObject)?.Value<Int32>("redirectPort"),  Is.EqualTo(node.RedirectPort?.ToUInt16()));
            });

            var (followed, shown) = await Get($"http://127.0.0.1:{node.RedirectPort}/", AllowRedirects: true);

            using (followed)
                Assert.Multiple(() => {
                    Assert.That(followed.StatusCode,  Is.EqualTo(HttpStatusCode.OK));
                    Assert.That(shown,                Is.EqualTo(CertificateEntry.ThumbprintOf(certificate)));
                });

        }

        #endregion

        #region APlainNodeSendsNoHSTS()

        /// <summary>
        /// A node over plain HTTP, with no proxy in front, sends no HSTS: there
        /// is no HTTPS to hold a browser to.
        /// </summary>
        [Test]
        public async Task APlainNodeSendsNoHSTS()
        {

            var node = await Started(_ => "{}");

            using var plain     = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            using var response  = await plain.GetAsync($"http://127.0.0.1:{node.HTTPPort}/");

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                                     Is.EqualTo(HttpStatusCode.OK));
                Assert.That(response.Headers.Contains("Strict-Transport-Security"),  Is.False);
                Assert.That(node.StrictTransportSecurity,                            Is.Null);
                Assert.That(node.WebCertificate,                                     Is.Null);
            });

        }

        #endregion

    }

}
