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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A node that serves its web interface over TLS: what it shows, what it
    /// calls itself, and what its session cookie is.
    /// </summary>
    /// <remarks>
    /// The secure cookie is the part that matters most and shows least: a
    /// browser drops a secure cookie over plain HTTP, so a node that set one
    /// without TLS would be a node nobody can stay signed in to - and one that
    /// did not set one with TLS would send its session in the clear the moment
    /// somebody typed http:// by mistake.
    /// </remarks>
    public class NodeHTTPSTests
    {

        #region Data

        private String            directory    = "";
        private X509Certificate2  certificate  = default!;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory    = Path.Combine(Path.GetTempPath(), "node-https-" + Guid.NewGuid().ToString("N")[..12]);
            certificate  = SelfSigned();

            Directory.CreateDirectory(directory);

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), """{ "nts": { "enabled": false } }""");

        }

        [TearDown]
        public void TearDown()
        {

            certificate.Dispose();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (helpers) SelfSigned() / FreePort() / Node(...)

        /// <summary>
        /// A certificate for 127.0.0.1 with its key, as a server can use it on
        /// every platform: through a PKCS#12, because a key that only ever
        /// lived in memory is one Windows' TLS will not sign with.
        /// </summary>
        private static X509Certificate2 SelfSigned()
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request   = new CertificateRequest("CN=node web interface", key, HashAlgorithmName.SHA256);
            var names     = new SubjectAlternativeNameBuilder();

            names.AddIpAddress(System.Net.IPAddress.Loopback);
            names.AddDnsName("localhost");

            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));

            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);

        }

        private static IPPort FreePort()
        {

            var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();

            var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();

            return IPPort.Parse((UInt16) port);

        }

        private WWCPNode Node(IPPort?                            Port                        = null,
                              HTTPServer?                        Server                      = null,
                              ServerCertificateSelectorDelegate?  ServerCertificateSelector   = null)

            => new (
                   HTTPPort:                   Port,
                   HTTPServer:                 Server,
                   ServerCertificateSelector:  ServerCertificateSelector,
                   AccountsPath:               Path.Combine(directory, "accounts"),
                   ConfigFile:                 new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                   CertificatesPath:           Path.Combine(directory, "certificates"),
                   LogToConsole:               false,
                   BridgeDebugLog:             false
               );

        #endregion


        #region ANodeGivenACertificateSpeaksTLSAndSaysSo()

        /// <summary>
        /// A node given a certificate shows it at every handshake, names itself
        /// by https URLs, and sets a secure session cookie.
        /// </summary>
        [Test]
        public async Task ANodeGivenACertificateSpeaksTLSAndSaysSo()
        {

            var port = FreePort();

            await using var node = Node(port, ServerCertificateSelector: (server, client) => certificate);

            await node.Start();

            String? shown = null;

            using var handler = new HttpClientHandler {
                                    ServerCertificateCustomValidationCallback = (message, served, chain, errors) => {
                                        shown = served is null ? null : CertificateEntry.ThumbprintOf(served);
                                        return true;
                                    }
                                };

            using var client   = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            using var response = await client.GetAsync($"https://127.0.0.1:{port}/");

            Assert.Multiple(() => {
                Assert.That(shown,                                                   Is.EqualTo(CertificateEntry.ThumbprintOf(certificate)),  "another certificate was shown, or none");
                Assert.That(node.HTTPS,                                              Is.True);
                Assert.That(node.WebInterfaceURL.ToString(),                         Does.StartWith("https://"));
                Assert.That(node.APIURL.ToString(),                                  Does.StartWith("https://"));
                Assert.That(node.ExtAPI.UseSecureCookies,                            Is.True,  "a session over TLS would be sent in the clear over plain HTTP");
                Assert.That(node.ConfigurationJSON()["http"]?.Value<Boolean>("https"),  Is.True);
            });

        }

        #endregion

        #region ANodeWithoutOneSpeaksPlainHTTPAndItsCookieIsNotSecure()

        /// <summary>
        /// A node given no certificate is what a node always was: plain HTTP,
        /// http URLs, and a cookie a browser keeps over plain HTTP.
        /// </summary>
        [Test]
        public async Task ANodeWithoutOneSpeaksPlainHTTPAndItsCookieIsNotSecure()
        {

            await using var node = Node();

            Assert.Multiple(() => {
                Assert.That(node.HTTPS,                        Is.False);
                Assert.That(node.WebInterfaceURL.ToString(),   Does.StartWith("http://"));
                Assert.That(node.APIURL.ToString(),            Does.StartWith("http://"));
                Assert.That(node.ExtAPI.UseSecureCookies,      Is.False,  "nobody could stay signed in to a node reached over plain HTTP");
            });

        }

        #endregion

        #region AServerThatIsHandedInKeepsItsOwnTLS()

        /// <summary>
        /// A server handed in speaks whatever it was made to speak, and the node
        /// goes by that - and a certificate given for it here is refused, since
        /// it would never be shown.
        /// </summary>
        [Test]
        public async Task AServerThatIsHandedInKeepsItsOwnTLS()
        {

            var withTLS    = new HTTPServer(IPAddress: IPv4Address.Localhost, TCPPort: FreePort(), ServerCertificateSelector: (server, client) => certificate);
            var withoutTLS = new HTTPServer(IPAddress: IPv4Address.Localhost, TCPPort: FreePort());

            await using (var node = Node(Server: withTLS))
                Assert.Multiple(() => {
                    Assert.That(node.HTTPS,                    Is.True);
                    Assert.That(node.ExtAPI.UseSecureCookies,  Is.True);
                });

            await using (var node = Node(Server: withoutTLS))
                Assert.Multiple(() => {
                    Assert.That(node.HTTPS,                    Is.False);
                    Assert.That(node.ExtAPI.UseSecureCookies,  Is.False);
                });

            Assert.Throws<ArgumentException>(() => Node(Server: withoutTLS, ServerCertificateSelector: (server, client) => certificate));

        }

        #endregion

        #region CertificatesBesideItNeedACertificate()

        /// <summary>
        /// The certificates sent beside a server's own are refused without one:
        /// they would be sent beside nothing.
        /// </summary>
        [Test]
        public void CertificatesBesideItNeedACertificate()
        {

            Assert.Throws<ArgumentException>(() => new WWCPNode(
                                                       AccountsPath:                    Path.Combine(directory, "accounts"),
                                                       ConfigFile:                      new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                                       ServerCertificateChainSelector:  (server, client) => null,
                                                       LogToConsole:                    false,
                                                       BridgeDebugLog:                  false
                                                   ));

        }

        #endregion

    }

}
