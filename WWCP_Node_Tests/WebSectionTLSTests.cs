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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the "web" section says of HTTPS - "tls" and "hsts" beside the
    /// trusted proxies - read, written back and refused; the switches that say
    /// the same on the command line, and how the two are put together; and a
    /// program that does not pass the switches on.
    /// </summary>
    public class WebSectionTLSTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-web-tls-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void TearDown()
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }
        }

        #endregion


        #region (helpers) Parsed(JSON) / Refusal(JSON) / Node(Web, Section)

        /// <summary>
        /// The "web" section as the file says it.
        /// </summary>
        private static WebConfiguration Parsed(String JSON)
        {

            Assert.That(WebConfiguration.TryParse(JObject.Parse(JSON), out var web, out var error), Is.True, error);

            return web!;

        }

        /// <summary>
        /// Why the "web" section is refused, or null where it is not.
        /// </summary>
        private static String? Refusal(String JSON)

            => WebConfiguration.TryParse(JObject.Parse(JSON), out _, out var error)
                   ? null
                   : error;

        /// <summary>
        /// A node, not started, whose file says the given "web" section, handed
        /// what the given switches say.
        /// </summary>
        private WWCPNode Node(WebConfiguration?  Web      = null,
                              String?            Section  = null)
        {

            var configFile = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }{{(Section is not null ? $", \"web\": {Section}" : "")}} }""");

            return new WWCPNode(HTTPPort:          IPPort.Parse(TestKit.TestPorts.Free()),
                                AccountsPath:      Path.Combine(directory, "accounts"),
                                ConfigFile:        new WWCPConfigFile(configFile),
                                CertificatesPath:  Path.Combine(directory, "certificates"),
                                LogToConsole:      false,
                                BridgeDebugLog:    false,
                                SSH:               new SSHSettings(OnByDefault: false),
                                Web:               Web);

        }

        #endregion


        #region TheStoreTheRedirectAndHSTSAreReadAndWrittenBack()

        /// <summary>
        /// "tls" with the store and a redirect, and "hsts" with an age and the
        /// names below: read as said, and written back as read.
        /// </summary>
        [Test]
        public void TheStoreTheRedirectAndHSTSAreReadAndWrittenBack()
        {

            var json = JObject.Parse("""
                                     { "tls":            { "certificate": "store", "redirectPort": 80 },
                                       "hsts":           { "maxAge": 600, "includeSubDomains": true },
                                       "trustedProxies": [ "127.0.0.1" ] }
                                     """);

            var web  = Parsed(json.ToString());

            Assert.Multiple(() => {
                Assert.That(web.TLS?.Certificate?.IsStore,       Is.True);
                Assert.That(web.TLS?.RedirectPort,               Is.EqualTo(IPPort.Parse(80)));
                Assert.That(web.HSTS?.HeaderValue,               Is.EqualTo("max-age=600; includeSubDomains"));
                Assert.That(JToken.DeepEquals(web.ToJSON(), json), Is.True, web.ToJSON().ToString());
                Assert.That(web.ToString(),                      Does.Contain("HTTPS with a certificate from the certificate store, redirected to from port 80"));
            });

        }

        #endregion

        #region FilesAndNoHSTSAreReadAndWrittenBack()

        /// <summary>
        /// "tls" with PEM files - the key in a file of its own, and in the first
        /// - and "hsts": false: read as said, and written back as read.
        /// </summary>
        [Test]
        public void FilesAndNoHSTSAreReadAndWrittenBack()
        {

            var both  = JObject.Parse("""{ "tls": { "certificate": { "fullchain": "live/fullchain.pem", "privateKey": "live/privkey.pem" } }, "hsts": false }""");
            var one   = JObject.Parse("""{ "tls": { "certificate": { "fullchain": "live/both.pem" } } }""");

            var web   = Parsed(both.ToString());
            var alone = Parsed(one.ToString());

            Assert.Multiple(() => {
                Assert.That(web.TLS?.Certificate,                    Is.EqualTo(new WebCertificateSource("live/fullchain.pem", "live/privkey.pem")));
                Assert.That(web.HSTS?.Enabled,                       Is.False);
                Assert.That(web.HSTS?.HeaderValue,                   Is.Null);
                Assert.That(JToken.DeepEquals(web.  ToJSON(), both), Is.True, web.  ToJSON().ToString());
                Assert.That(alone.TLS?.Certificate?.PrivateKey,      Is.Null);
                Assert.That(JToken.DeepEquals(alone.ToJSON(), one),  Is.True, alone.ToJSON().ToString());
                Assert.That(Parsed("""{ "hsts": {} }""").HSTS?.HeaderValue,  Is.EqualTo($"max-age={HSTSConfiguration.DefaultMaxAge}"));
                Assert.That(Parsed("""{ "tls": {} }""").TLS?.Certificate,   Is.Null, "said nothing of the certificate, which the node takes for the store");
            });

        }

        #endregion

        #region WhatIsWrongIsRefusedSayingWhere(Section, Says)

        /// <summary>
        /// A "tls" or an "hsts" that says something wrong, or something it may
        /// not say at all, stops the start with a sentence that says where.
        /// </summary>
        [TestCase("""{ "tls": "store" }""",                                                       "'web.tls' must be a JSON object")]
        [TestCase("""{ "tls": { "certificate": "letsencrypt" } }""",                              "'web.tls.certificate' is 'letsencrypt', and may be \"store\"")]
        [TestCase("""{ "tls": { "certificate": 42 } }""",                                         "'web.tls.certificate' may be \"store\"")]
        [TestCase("""{ "tls": { "certificate": { "privateKey": "privkey.pem" } } }""",            "'web.tls.certificate.fullchain' is missing")]
        [TestCase("""{ "tls": { "certificate": { "fullchain": "a.pem", "privatekey": "b" } } }""","'web.tls.certificate' says 'privatekey', and may say nothing but 'fullchain', 'privateKey'")]
        [TestCase("""{ "tls": { "certificate": "store", "redirect": 80 } }""",                    "'web.tls' says 'redirect'")]
        [TestCase("""{ "tls": { "redirectPort": 0 } }""",                                         "'web.tls.redirectPort' must be a port number between 1 and 65535")]
        [TestCase("""{ "tls": { "redirectPort": "80" } }""",                                      "'web.tls.redirectPort' must be a port number")]
        [TestCase("""{ "hsts": "yes" }""",                                                        "'web.hsts' must be false, or")]
        [TestCase("""{ "hsts": { "maxAge": 63072001 } }""",                                       "'web.hsts.maxAge' must be between 0 and 63072000")]
        [TestCase("""{ "hsts": { "maxAge": 600, "preload": true } }""",                           "'web.hsts' says 'preload'")]
        public void WhatIsWrongIsRefusedSayingWhere(String Section,
                                                    String Says)
        {

            Assert.That(Refusal(Section), Does.Contain(Says));

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), $$"""{ "web": {{Section}} }""");

            var refused = Assert.Throws<InvalidOperationException>(() => new WWCPNode(AccountsPath:      Path.Combine(directory, "accounts"),
                                                                                      ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                                                                      CertificatesPath:  Path.Combine(directory, "certificates"),
                                                                                      LogToConsole:      false,
                                                                                      BridgeDebugLog:    false));

            Assert.That(refused!.Message, Does.Contain(Says));

        }

        #endregion

        #region TheSwitchesWinOverTheFileEachWhereItSaysSomething()

        /// <summary>
        /// What the command line says over what the file says: the certificate
        /// and the redirect each on its own, the proxies as a whole, and what the
        /// command line does not say - the header, HSTS - the file's.
        /// </summary>
        [Test]
        public void TheSwitchesWinOverTheFileEachWhereItSaysSomething()
        {

            var file      = Parsed("""
                                   { "tls":                 { "certificate": "store", "redirectPort": 8080 },
                                     "hsts":                { "maxAge": 600 },
                                     "trustedProxies":      [ "127.0.0.1", "::1" ],
                                     "clientAddressHeader": "Forwarded" }
                                   """);

            var switches  = new WebConfiguration(TrustedProxies:  [ System.Net.IPNetwork.Parse("10.0.0.0/8") ],
                                                 TLS:             new WebTLSConfiguration(new WebCertificateSource("/etc/fullchain.pem", "/etc/privkey.pem")));

            var both      = switches.Over(file);
            var redirect  = new WebConfiguration(TLS: new WebTLSConfiguration(RedirectPort: IPPort.Parse(80))).Over(file);

            Assert.Multiple(() => {
                Assert.That(both.TLS?.Certificate,                         Is.EqualTo(new WebCertificateSource("/etc/fullchain.pem", "/etc/privkey.pem")));
                Assert.That(both.TLS?.RedirectPort,                        Is.EqualTo(IPPort.Parse(8080)), "the file's redirect, which no switch said otherwise");
                Assert.That(both.TrustedProxies!.Select(WebConfiguration.TextOf),  Is.EqualTo(new[] { "10.0.0.0/8" }), "the proxies of the command line, and none of the file's beside them");
                Assert.That(both.Header,                                   Is.EqualTo(ClientAddressHeader.Forwarded));
                Assert.That(both.HSTS?.MaxAge,                             Is.EqualTo(600));
                Assert.That(redirect.TLS?.Certificate?.IsStore,            Is.True, "the file's certificate, which --redirect-port keeps");
                Assert.That(redirect.TLS?.RedirectPort,                    Is.EqualTo(IPPort.Parse(80)));
                Assert.That(file.Over(null),                               Is.EqualTo(file));
            });

        }

        #endregion

        #region TheFilesOfTheFileAreMeasuredFromIt()

        /// <summary>
        /// Relative paths of PEM files in the file are measured from the file,
        /// as the store's own directory is - not from wherever the process was
        /// started - and those of the command line are taken as they come.
        /// </summary>
        [Test]
        public async Task TheFilesOfTheFileAreMeasuredFromIt()
        {

            await using (var node = Node(Section: """{ "tls": { "certificate": { "fullchain": "live/fullchain.pem", "privateKey": "live/privkey.pem" } } }"""))
                Assert.Multiple(() => {
                    Assert.That(node.WebCertificate?.Source.FullChain,   Is.EqualTo(Path.GetFullPath(Path.Combine(directory, "live", "fullchain.pem"))));
                    Assert.That(node.WebCertificate?.Source.PrivateKey,  Is.EqualTo(Path.GetFullPath(Path.Combine(directory, "live", "privkey.pem"))));
                    Assert.That(node.HTTPS,                              Is.True);
                    Assert.That(node.WebInterfaceURL.ToString(),         Does.StartWith("https://"));
                });

            var elsewhere = Path.Combine(Path.GetTempPath(), "elsewhere", "fullchain.pem");

            await using (var node = Node(Web:      new WebConfiguration(TLS: new WebTLSConfiguration(new WebCertificateSource(elsewhere))),
                                         Section:  """{ "tls": { "certificate": "store" } }"""))
                Assert.That(node.WebCertificate?.Source.FullChain,  Is.EqualTo(elsewhere));

        }

        #endregion

        #region TheSwitchesSayWhatTheSectionSays()

        /// <summary>
        /// --https, --https-cert with --https-key, --redirect-port and
        /// --trusted-proxy, given several times: what they say, in the words of
        /// the "web" section, with the files measured from where the node is
        /// started - and nothing where none of them is given.
        /// </summary>
        [Test]
        public void TheSwitchesSayWhatTheSectionSays()
        {

            var fullchain  = Path.Combine(directory, "fullchain.pem");
            var privkey    = Path.Combine(directory, "privkey.pem");

            File.WriteAllText(fullchain, "");
            File.WriteAllText(privkey,   "");

            var store      = NodeArguments.Parse([ "--https", "--redirect-port", "8080" ]);
            var files      = NodeArguments.Parse([ "--https-cert", fullchain, "--https-key", privkey,
                                                   "--trusted-proxy", "127.0.0.1", "--trusted-proxy", "10.0.0.0/8", "--trusted-proxy", "127.0.0.1" ]);
            var proxies    = NodeArguments.Parse([ "--trusted-proxy", "::1" ]);

            Assert.Multiple(() => {

                Assert.That(store.Problem,                                     Is.Null);
                Assert.That(store.Web?.TLS?.Certificate?.IsStore,              Is.True);
                Assert.That(store.Web?.TLS?.RedirectPort,                      Is.EqualTo(IPPort.Parse(8080)));
                Assert.That(store.Web?.TrustedProxies,                         Is.Null);

                Assert.That(files.Problem,                                     Is.Null);
                Assert.That(files.Web?.TLS?.Certificate,                       Is.EqualTo(new WebCertificateSource(Path.GetFullPath(fullchain), Path.GetFullPath(privkey))));
                Assert.That(files.Web?.TrustedProxies!.Select(WebConfiguration.TextOf),  Is.EqualTo(new[] { "127.0.0.1", "10.0.0.0/8" }), "each proxy once, in the order given");

                Assert.That(proxies.Web?.TLS,                                  Is.Null, "proxies alone ask for no TLS of the node's own");
                Assert.That(proxies.Rest,                                      Is.Empty);

                Assert.That(NodeArguments.Parse([ "--port", "8080" ]).Web,     Is.Null);

            });

        }

        #endregion

        #region WhatTheSwitchesCannotMeanIsRefused(Arguments, Says)

        /// <summary>
        /// Switches that contradict each other, want one beside them, or name
        /// what is not there are refused before anything is made.
        /// </summary>
        [TestCase(new[] { "--https", "--https-cert", "@fullchain" },     "--https shows the certificate store's identity and --https-cert the one in a file")]
        [TestCase(new[] { "--https-key", "@privkey" },                   "--https-key is the key of the certificate --https-cert names")]
        [TestCase(new[] { "--redirect-port", "80" },                     "--redirect-port sends browsers to HTTPS: give it with --https or --https-cert")]
        [TestCase(new[] { "--https", "--redirect-port", "0" },           "Missing or invalid port number after --redirect-port")]
        [TestCase(new[] { "--https", "--port", "8443", "--redirect-port", "8443" },  "--redirect-port and --port name the same port")]
        [TestCase(new[] { "--https-cert", "no-such-fullchain.pem" },     "--https-cert: there is no file 'no-such-fullchain.pem'")]
        [TestCase(new[] { "--https-cert" },                              "Missing PEM file after --https-cert")]
        [TestCase(new[] { "--https-cert", "@fullchain" },                "holds no private key. Give the file of its key with --https-key.")]
        [TestCase(new[] { "--trusted-proxy", "proxy.example.org" },      "--trusted-proxy: 'proxy.example.org' is neither an IP address nor a network")]
        [TestCase(new[] { "--trusted-proxy", "10.0.0.1/8" },             "--trusted-proxy: '10.0.0.1/8' is neither an IP address nor a network")]
        [TestCase(new[] { "--trusted-proxy" },                           "Missing address or network after --trusted-proxy")]
        public void WhatTheSwitchesCannotMeanIsRefused(String[] Arguments,
                                                       String   Says)
        {

            File.WriteAllText(Path.Combine(directory, "fullchain.pem"), "");
            File.WriteAllText(Path.Combine(directory, "privkey.pem"),   "");

            var arguments = Arguments.Select(argument => argument.StartsWith('@')
                                                             ? Path.Combine(directory, argument[1..] + ".pem")
                                                             : argument).
                                      ToArray();

            Assert.That(NodeArguments.Parse(arguments).Problem, Does.Contain(Says));

        }

        #endregion

        #region ACertificateWithItsKeyInOneFileIsTakenAlone()

        /// <summary>
        /// --https-cert alone, where its file holds the key as well, is taken:
        /// only a file without a key wants --https-key beside it.
        /// </summary>
        [Test]
        public void ACertificateWithItsKeyInOneFileIsTakenAlone()
        {

            var combined = Path.Combine(directory, "combined.pem");

            File.WriteAllText(combined, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
                                        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n");

            var arguments = NodeArguments.Parse([ "--https-cert", combined ]);

            Assert.Multiple(() => {
                Assert.That(arguments.Problem,                    Is.Null);
                Assert.That(arguments.Web?.TLS?.Certificate,      Is.EqualTo(new WebCertificateSource(Path.GetFullPath(combined))));
            });

        }

        #endregion

        #region AProgramThatDoesNotPassTheSwitchesOnIsStopped()

        /// <summary>
        /// A program whose kind of node does not hand NodeArguments.Web on is
        /// stopped before it starts - 2, saying where else it can be said -
        /// rather than starting over plain HTTP with --https on its command
        /// line; one that does is not.
        /// </summary>
        [Test]
        public async Task AProgramThatDoesNotPassTheSwitchesOnIsStopped()
        {

            var arguments = NodeArguments.Parse([ "--https" ]);

            await using (var node = Node())
            {

                var said = new StringWriter();

                Assert.Multiple(() => {
                    Assert.That(node.ImportCertificates(arguments, out _, new StringWriter(), said),  Is.EqualTo(2));
                    Assert.That(said.ToString(),  Does.Contain("--https, --https-cert, --redirect-port and --trusted-proxy are not passed on"));
                    Assert.That(said.ToString(),  Does.Contain("\"web\" section"));
                });

            }

            await using (var node = Node(Web: arguments.Web))
                Assert.Multiple(() => {
                    Assert.That(node.ImportCertificates(arguments, out _, new StringWriter(), new StringWriter()),  Is.Null);
                    Assert.That(node.HTTPS,  Is.True);
                });

            await using (var node = Node())
                Assert.That(node.ImportCertificates(NodeArguments.Parse([ "--port", "8080" ]), out _, new StringWriter(), new StringWriter()),  Is.Null,
                            "a command line that says nothing of HTTPS stops nothing");

        }

        #endregion

        #region ThePortOfTheRedirectIsNotThePortOfHTTPS()

        /// <summary>
        /// A redirect to HTTPS on the port HTTPS is on itself stops the start,
        /// saying where it was said.
        /// </summary>
        [Test]
        public void ThePortOfTheRedirectIsNotThePortOfHTTPS()
        {

            var port      = TestKit.TestPorts.Free();
            var file      = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(file, $$"""{ "web": { "tls": { "certificate": "store", "redirectPort": {{port}} } } }""");

            var refused   = Assert.Throws<InvalidOperationException>(() => new WWCPNode(HTTPPort:          IPPort.Parse(port),
                                                                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                                                                        ConfigFile:        new WWCPConfigFile(file),
                                                                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                                                                        LogToConsole:      false,
                                                                                        BridgeDebugLog:    false));

            Assert.That(refused!.Message, Does.Contain($"The redirect to HTTPS is to be on port {port}, which HTTPS is served on itself"));

        }

        #endregion

        #region ATLSOfItsOwnIsNotUsedBesideACertificateOrAServerHandedIn()

        /// <summary>
        /// A kind of node that hands in a certificate of its own - the meter's -
        /// or a server, keeps it: the file's "tls" is not used, and the log says
        /// so.
        /// </summary>
        [Test]
        public async Task ATLSOfItsOwnIsNotUsedBesideACertificateOrAServerHandedIn()
        {

            var file    = Path.Combine(directory, WWCPConfigFile.DefaultFileName);
            var said    = new List<String>();

            File.WriteAllText(file, """{ "web": { "tls": { "certificate": "store", "redirectPort": 1 } } }""");

            var handed  = new HTTPServer(IPAddress: IPv4Address.Localhost, TCPPort: IPPort.Parse(TestKit.TestPorts.Free()));

            var log     = new Logging.EventLog();
            log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

            await using (var node = new WWCPNode(HTTPServer:        handed,
                                                 AccountsPath:      Path.Combine(directory, "accounts"),
                                                 ConfigFile:        new WWCPConfigFile(file),
                                                 CertificatesPath:  Path.Combine(directory, "certificates"),
                                                 Log:               log,
                                                 LogToConsole:      false,
                                                 BridgeDebugLog:    false))
                Assert.Multiple(() => {
                    Assert.That(node.WebCertificate,  Is.Null);
                    Assert.That(node.RedirectServer,  Is.Null);
                    Assert.That(node.HTTPS,           Is.False);
                });

            await using (var node = new WWCPNode(HTTPPort:                   IPPort.Parse(TestKit.TestPorts.Free()),
                                                 ServerCertificateSelector:  (server, client) => throw new InvalidOperationException("never asked here"),
                                                 AccountsPath:               Path.Combine(directory, "accounts"),
                                                 ConfigFile:                 new WWCPConfigFile(file),
                                                 CertificatesPath:           Path.Combine(directory, "certificates"),
                                                 Log:                        log,
                                                 LogToConsole:               false,
                                                 BridgeDebugLog:             false))
                Assert.Multiple(() => {
                    Assert.That(node.WebCertificate,  Is.Null);
                    Assert.That(node.RedirectServer,  Is.Null);
                    Assert.That(node.HTTPS,           Is.True, "the kind's own certificate");
                });

            Assert.Multiple(() => {
                Assert.That(said, Has.Some.Contains("'web.tls' is not used: the HTTP server was handed in"));
                Assert.That(said, Has.Some.Contains($"'web.tls' is not used: this {NodeKind.Default.Name} shows a certificate of its own"));
            });

        }

        #endregion

    }

}
