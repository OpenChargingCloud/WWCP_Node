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

using System.Net.Http.Headers;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The warning a node says where it serves its web interface, its JSON API
    /// and its sign-in over plain HTTP beyond its machine, with neither TLS nor
    /// a trusted proxy: in the log at the start, in a box below the banner, on
    /// the Configuration page, and to its administrators above every page - and
    /// nowhere on the loopback alone.
    /// </summary>
    /// <remarks>
    /// Beyond the loopback without a socket on it: a test that listened on
    /// every address would ask a desktop's firewall whether it may. A server
    /// that is handed in is not started by the node, and says where it would
    /// listen all the same - which is what the warning is about.
    /// </remarks>
    public class PlainHTTPWarningTests
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

            directory = Path.Combine(Path.GetTempPath(), "node-plain-http-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

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


        #region (helpers) Node(Address, Web)

        /// <summary>
        /// A node whose file says the given "web" section, on a server handed in
        /// that would listen on the given address - not started by the node -
        /// with what it logs kept in <see cref="said"/>.
        /// </summary>
        private WWCPNode Node(IIPAddress  Address,
                              String      Web = "{}")
        {

            var home        = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
            var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": {{Web}} }""");

            var node = new WWCPNode(HTTPServer:        new HTTPServer(IPAddress: Address, TCPPort: IPPort.Parse(TestPorts.Free())),
                                    AccountsPath:      Path.Combine(home, "accounts"),
                                    ConfigFile:        new WWCPConfigFile(configFile),
                                    CertificatesPath:  Path.Combine(home, "certificates"),
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    SSH:               new SSHSettings(OnByDefault: false));

            node.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

            nodes.Add(node);

            return node;

        }

        #endregion


        #region BeyondTheLoopbackOverPlainHTTP_TheWarningIsSaidEverywhere()

        /// <summary>
        /// On every address, over plain HTTP and with no trusted proxy: the
        /// warning in the log at the start, in a box below the banner - before
        /// the box of a first start - on the Configuration page, and to an
        /// administrator above every page, to nobody else.
        /// </summary>
        [Test]
        public async Task BeyondTheLoopbackOverPlainHTTP_TheWarningIsSaidEverywhere()
        {

            var node    = Node(IPvXAddress.Any);

            await node.Start();

            var banner  = node.Banner().ToList();
            var box     = banner.FindIndex(line => line.StartsWith("  ┌─ Warning: plain HTTP beyond this machine", StringComparison.Ordinal));
            var first   = banner.FindIndex(line => line.StartsWith("  ┌─ First start",                             StringComparison.Ordinal));

            Assert.Multiple(() => {

                Assert.That(node.ListensBeyondLoopback,  Is.True);
                Assert.That(node.PlainHTTPWarning,       Does.StartWith($"The web interface, the JSON API and the sign-in of this {node.Kind.Name} are served over plain HTTP on every address of this machine, port {node.HTTPServer.TCPPort}"));
                Assert.That(node.PlainHTTPWarning,       Does.Contain("passwords, API keys and session cookies cross the network in clear text"));
                Assert.That(node.PlainHTTPWarning,       Does.Contain("--https").And.Contain("--trusted-proxy").And.Contain("\"trustedProxies\""));

                lock (said)
                    Assert.That(said,                    Has.Some.EqualTo(node.PlainHTTPWarning));

                Assert.That(box,                         Is.GreaterThan(0), "no box below the banner");
                Assert.That(first,                       Is.GreaterThan(box), "the box of a first start comes after the warning");
                Assert.That(banner.Skip(box).TakeWhile(line => !line.StartsWith("  └", StringComparison.Ordinal)),
                                                         Has.All.Length.LessThanOrEqualTo(NodeUsage.Width));
                Assert.That(String.Join(" ", banner.Skip(box + 1).TakeWhile(line => line.StartsWith("  │", StringComparison.Ordinal)).Select(line => line[5..])),
                                                         Is.EqualTo(node.PlainHTTPWarning));

                Assert.That(node.ConfigurationJSON()["http"]?.Value<String>("warning"),  Is.EqualTo(node.PlainHTTPWarning));

                Assert.That(node.NoticesFor([ WWCPNode.AdminRole ]),  Is.EqualTo(new[] { node.PlainHTTPWarning }));
                Assert.That(node.NoticesFor([ "viewer" ]),            Is.Empty, "nothing a viewer could do about it");

            });

        }

        #endregion

        #region OnTheLoopbackNothingIsSaid()

        /// <summary>
        /// On the loopback alone, over plain HTTP, nothing is said: whoever
        /// reaches it is on the machine already. And /api/v1/auth/me answers no
        /// notice to the administrator either.
        /// </summary>
        [Test]
        public async Task OnTheLoopbackNothingIsSaid()
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var home        = Directory.CreateDirectory(Path.Combine(directory, "loopback" + nodes.Count)).FullName;
                var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

                File.WriteAllText(configFile, """{ "nts": { "groups": { "legal": { "enabled": false } } } }""");

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(home, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(configFile),
                                        CertificatesPath:  Path.Combine(home, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false,
                                        SSH:               new SSHSettings(OnByDefault: false));

                made.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

                _ = new NodeHTTPAPI(made.HTTPServer, made, made.ExtAPI, made.Log);

                return made;

            });

            nodes.Add(node);

            using var http = new HttpClient { BaseAddress = new Uri(node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{WWCPNode.DefaultAdminUser}:{node.GeneratedPassword}")));

            var me = JObject.Parse(await http.GetStringAsync("api/v1/auth/me"));

            Assert.Multiple(() => {
                Assert.That(node.ListensBeyondLoopback,                     Is.False);
                Assert.That(node.PlainHTTPWarning,                          Is.Null);
                Assert.That(node.Banner(),                                  Has.None.Contains("plain HTTP"));
                Assert.That(me["notices"],                                  Is.Null, "a notice where there is nothing to say");
                Assert.That(me["roles"]?.Values<String>(),                  Does.Contain(WWCPNode.AdminRole));
                Assert.That(node.ConfigurationJSON()["http"]?["warning"]?.Type,  Is.EqualTo(JTokenType.Null));
            });

            lock (said)
                Assert.That(said, Has.None.Contains("plain HTTP"));

        }

        #endregion

        #region BehindATrustedProxyOrOverTLSNothingIsSaid()

        /// <summary>
        /// On every address, but behind a trusted proxy, or over TLS of the
        /// node's own: nothing is said, since neither crosses the network in the
        /// clear.
        /// </summary>
        [Test]
        public async Task BehindATrustedProxyOrOverTLSNothingIsSaid()
        {

            var behind  = Node(IPvXAddress.Any, """{ "trustedProxies": [ "10.0.0.1" ] }""");

            await behind.Start();

            var overTLS = new WWCPNode(HTTPHostname:      IPvXAddress.Any,
                                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                       AccountsPath:      Path.Combine(directory, "tls", "accounts"),
                                       ConfigFile:        new WWCPConfigFile(Path.Combine(directory, "tls", WWCPConfigFile.DefaultFileName)),
                                       CertificatesPath:  Path.Combine(directory, "tls", "certificates"),
                                       LogToConsole:      false,
                                       BridgeDebugLog:    false,
                                       Web:               new WebConfiguration(TLS: new WebTLSConfiguration(WebCertificateSource.Store)));

            nodes.Add(overTLS);

            Assert.Multiple(() => {
                Assert.That(behind. ListensBeyondLoopback,  Is.True);
                Assert.That(behind. PlainHTTPWarning,       Is.Null);
                Assert.That(behind. Banner(),               Has.None.Contains("plain HTTP"));
                Assert.That(overTLS.ListensBeyondLoopback,  Is.True);
                Assert.That(overTLS.PlainHTTPWarning,       Is.Null);
            });

            lock (said)
                Assert.That(said, Has.None.Contains("plain HTTP"));

        }

        #endregion

    }

}
