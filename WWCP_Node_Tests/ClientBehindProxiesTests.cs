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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Who the client of a request is behind a reverse proxy, as an API key
    /// bound to addresses asks it: the "web" section's trusted proxies are
    /// believed in the one header it names, read from the right, and nobody
    /// else is - and the section itself, read and refused.
    /// </summary>
    /// <remarks>
    /// The node listens on 127.0.0.1, so every request here comes from
    /// 127.0.0.1: a proxy, where the file trusts that address, and a client
    /// where it does not.
    /// </remarks>
    public class ClientBehindProxiesTests
    {

        #region Data

        private const    String          AtTheClient    = "Bound0to0the0client0192";
        private const    String          AtTheProxy     = "Bound0to0the0proxy0127";
        private const    String          AtTheIPv6Host  = "Bound0to0an0IPv60host";
        private const    String          AtAShortOne    = "Bound0to0the0short0one0192.0.0.7";
        private const    String          AtANeighbour   = "Bound0to0the0neighbour0127.0.0.2";

        private          String          directory      = "";
        private          String          password       = "";
        private readonly List<WWCPNode>  nodes          = [];

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
            directory = Path.Combine(Path.GetTempPath(), "node-proxies-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helpers) Started(Web) / Status(Node, Key, Headers)

        /// <summary>
        /// A node whose file says the given "web" section, or none, with API
        /// keys of root: one bound to the client 192.0.2.7, one to the proxy
        /// 127.0.0.1, one to 2001:db8::7, one to 192.0.0.7 - what "192.7" would
        /// be read as - and one to 127.0.0.2, a host beside the proxy. Each in
        /// a directory of its own, so that a second one makes its keys anew.
        /// </summary>
        private async Task<WWCPNode> Started(JObject? Web)
        {

            var home          = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
            var configFile    = Path.Combine(home, WWCPConfigFile.DefaultFileName);
            var configuration = JObject.Parse("""{ "nts": { "groups": { "legal": { "enabled": false } } } }""");

            if (Web is not null)
                configuration.Add(WebConfiguration.SectionName, Web);

            File.WriteAllText(configFile, configuration.ToString());

            var node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                    AccountsPath:      Path.Combine(home, "accounts"),
                                    ConfigFile:        new WWCPConfigFile(configFile),
                                    CertificatesPath:  Path.Combine(home, "certificates"),
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    SSH:               new SSHSettings(OnByDefault: false));

            nodes.Add(node);
            _ = new PageAPI(node);

            await node.Start();

            if (node.GeneratedPassword is String generated)
                password = generated;

            using var http = new HttpClient { BaseAddress = new Uri(node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                           "Basic",
                                                           Convert.ToBase64String(Encoding.UTF8.GetBytes($"{WWCPNode.DefaultAdminUser}:{password}"))
                                                       );

            foreach (var (key, address) in new[] { (AtTheClient, "192.0.2.7"), (AtTheProxy, "127.0.0.1"), (AtTheIPv6Host, "2001:db8::7"), (AtAShortOne, "192.0.0.7"), (AtANeighbour, "127.0.0.2") })
            {

                using var request = new HttpRequestMessage(new HttpMethod("ADD"), "ext/users/root/APIKeys");

                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Content = new StringContent(new JObject(
                                                        new JProperty("@id",                     key),
                                                        new JProperty("@context",                "https://opendata.social/contexts/UsersAPI/APIKey"),
                                                        new JProperty("userId",                  "root"),
                                                        new JProperty("description",             new JObject(new JProperty("en", "bound to " + address))),
                                                        new JProperty("accessRights",            "readOnly"),
                                                        new JProperty("validRemoteIPAddresses",  new JArray(address)),
                                                        new JProperty("created",                 DateTime.UtcNow.ToString("o")),
                                                        new JProperty("notAfter",                DateTime.UtcNow.AddYears(1).ToString("o"))
                                                    ).ToString(), Encoding.UTF8, "application/json");

                using var response = await http.SendAsync(request);

                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), $"the key bound to {address} was refused: " + await response.Content.ReadAsStringAsync());

            }

            return node;

        }

        /// <summary>
        /// What /api/v1/auth/me answers to the given key with the given header
        /// fields, each written as given.
        /// </summary>
        private static async Task<HttpStatusCode> Status(WWCPNode Node, String Key, params (String Name, String Value)[] Headers)
        {

            using var http    = new HttpClient { BaseAddress = new Uri(Node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };
            using var request = new HttpRequestMessage(HttpMethod.Get, "api/v1/auth/me");

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("API-Key", Key);

            foreach (var (name, value) in Headers)
                Assert.That(request.Headers.TryAddWithoutValidation(name, value), Is.True, $"{name}: {value}");

            using var response = await http.SendAsync(request);

            return response.StatusCode;

        }

        private static (String, String) XFF      (String Value) => ("X-Forwarded-For", Value);
        private static (String, String) Forwarded(String Value) => ("Forwarded",       Value);
        private static (String, String) XRealIP  (String Value) => ("X-Real-IP",       Value);

        #endregion


        #region WithoutTheSection_TheClientIsTheTCPPeer_WhateverItsHeadersSay()

        /// <summary>
        /// A file that names no proxy: 127.0.0.1 is the client, and a header
        /// naming another changes nothing.
        /// </summary>
        [Test]
        public async Task WithoutTheSection_TheClientIsTheTCPPeer_WhateverItsHeadersSay()
        {

            var node = await Started(null);

            var bare        = await Status(node, AtTheProxy);
            var claimed     = await Status(node, AtTheClient, XFF("192.0.2.7"));
            var claimedAway = await Status(node, AtTheProxy,  XFF("198.51.100.9"));

            Assert.Multiple(() => {
                Assert.That(bare,         Is.EqualTo(HttpStatusCode.OK),            "the key bound to 127.0.0.1 is refused from 127.0.0.1");
                Assert.That(claimed,      Is.EqualTo(HttpStatusCode.Unauthorized),  "with no proxy trusted, X-Forwarded-For made the client 192.0.2.7");
                Assert.That(claimedAway,  Is.EqualTo(HttpStatusCode.OK),            "with no proxy trusted, X-Forwarded-For made the client somebody else");
            });

        }

        #endregion

        #region BehindATrustedProxy_TheClientIsTheFirstUntrustedHopFromTheRight()

        /// <summary>
        /// 127.0.0.1 trusted, X-Forwarded-For as the default: the client is the
        /// first address from the right that is no trusted proxy - not what
        /// the client wrote further left, and not the proxy itself unless the
        /// header names nobody else; an entry that is no address ends the
        /// search, and Forwarded or X-Real-IP is not read at all.
        /// </summary>
        [Test]
        public async Task BehindATrustedProxy_TheClientIsTheFirstUntrustedHopFromTheRight()
        {

            var node = await Started(new JObject(new JProperty("trustedProxies", new JArray("127.0.0.1"))));

            var named             = await Status(node, AtTheClient,   XFF("192.0.2.7"));
            var notNamed          = await Status(node, AtTheClient);
            var writtenByClient   = await Status(node, AtTheClient,   XFF("192.0.2.7, 198.51.100.9"));
            var behindTwo         = await Status(node, AtTheClient,   XFF("198.51.100.9, 192.0.2.7, 127.0.0.1"));
            var garbageLeft       = await Status(node, AtTheClient,   XFF("unknown, 192.0.2.7"));
            var garbageRight      = await Status(node, AtTheClient,   XFF("192.0.2.7, unknown"));
            var withPort          = await Status(node, AtTheClient,   XFF("192.0.2.7:4711"));
            var mapped            = await Status(node, AtTheClient,   XFF("::ffff:192.0.2.7"));
            var mappedProxy       = await Status(node, AtTheClient,   XFF("192.0.2.7, ::ffff:127.0.0.1"));
            var ipv6WithPort      = await Status(node, AtTheIPv6Host, XFF("[2001:db8::7]:4711"));
            var shortIPv4         = await Status(node, AtAShortOne,   XFF("192.7"));
            var proxyForOther     = await Status(node, AtTheProxy,    XFF("198.51.100.9"));
            var proxyForItself    = await Status(node, AtTheProxy,    XFF("127.0.0.1"));
            var otherHeader       = await Status(node, AtTheClient,   Forwarded("for=192.0.2.7"));
            var realIP            = await Status(node, AtTheClient,   XRealIP("192.0.2.7"));

            Assert.Multiple(() => {
                Assert.That(named,           Is.EqualTo(HttpStatusCode.OK),            "the client the trusted proxy names is refused");
                Assert.That(notNamed,        Is.EqualTo(HttpStatusCode.Unauthorized),  "with no header the client was 192.0.2.7, and not the proxy");
                Assert.That(writtenByClient, Is.EqualTo(HttpStatusCode.Unauthorized),  "what the client wrote left of the proxy's entry was believed");
                Assert.That(behindTwo,       Is.EqualTo(HttpStatusCode.OK),            "a trusted hop on the right was not skipped");
                Assert.That(garbageLeft,     Is.EqualTo(HttpStatusCode.OK),            "an entry left of the client stopped the search");
                Assert.That(garbageRight,    Is.EqualTo(HttpStatusCode.Unauthorized),  "an entry that is no address was skipped, and what is left of it believed");
                Assert.That(withPort,        Is.EqualTo(HttpStatusCode.OK),            "an address with a port is not read as the address");
                Assert.That(mapped,          Is.EqualTo(HttpStatusCode.OK),            "an IPv4 address mapped into IPv6 is not the IPv4 address it is");
                Assert.That(mappedProxy,     Is.EqualTo(HttpStatusCode.OK),            "the trusted proxy written as ::ffff:127.0.0.1 was not skipped");
                Assert.That(ipv6WithPort,    Is.EqualTo(HttpStatusCode.OK),            "an IPv6 address in brackets with a port is not read as the address");
                Assert.That(shortIPv4,       Is.EqualTo(HttpStatusCode.Unauthorized),  "'192.7' was read as an address");
                Assert.That(proxyForOther,   Is.EqualTo(HttpStatusCode.Unauthorized),  "the key bound to the proxy opened the door for the client it names");
                Assert.That(proxyForItself,  Is.EqualTo(HttpStatusCode.OK),            "a header naming nobody but trusted proxies left no client");
                Assert.That(otherHeader,     Is.EqualTo(HttpStatusCode.Unauthorized),  "Forwarded was read, where X-Forwarded-For is the header");
                Assert.That(realIP,          Is.EqualTo(HttpStatusCode.Unauthorized),  "X-Real-IP was read, where X-Forwarded-For is the header");
            });

        }

        #endregion

        #region BehindTrustedProxiesOnly_TheClientIsTheFarthestOfThem()

        /// <summary>
        /// A network trusted, and a header naming nobody outside it: the client
        /// is the hop farthest from the node, 127.0.0.2, and not the proxy that
        /// the request came from.
        /// </summary>
        [Test]
        public async Task BehindTrustedProxiesOnly_TheClientIsTheFarthestOfThem()
        {

            var node = await Started(new JObject(new JProperty("trustedProxies", new JArray("127.0.0.0/8"))));

            var neighbour = await Status(node, AtANeighbour, XFF("127.0.0.2, 127.0.0.1"));
            var proxy     = await Status(node, AtTheProxy,   XFF("127.0.0.2, 127.0.0.1"));

            Assert.Multiple(() => {
                Assert.That(neighbour,  Is.EqualTo(HttpStatusCode.OK),            "the farthest of the trusted hops was not the client");
                Assert.That(proxy,      Is.EqualTo(HttpStatusCode.Unauthorized),  "the proxy the request came from was the client");
            });

        }

        #endregion

        #region FromAnUntrustedPeer_NoHeaderIsBelieved()

        /// <summary>
        /// A network trusted that 127.0.0.1 is not in: its X-Forwarded-For is
        /// the client's own word, and the client is 127.0.0.1.
        /// </summary>
        [Test]
        public async Task FromAnUntrustedPeer_NoHeaderIsBelieved()
        {

            var node = await Started(new JObject(new JProperty("trustedProxies", new JArray("10.0.0.0/8", "fd00::/8"))));

            var claimed = await Status(node, AtTheClient, XFF("192.0.2.7"));
            var itself  = await Status(node, AtTheProxy,  XFF("192.0.2.7"));

            Assert.Multiple(() => {
                Assert.That(claimed,  Is.EqualTo(HttpStatusCode.Unauthorized),  "an untrusted peer's X-Forwarded-For was believed");
                Assert.That(itself,   Is.EqualTo(HttpStatusCode.OK),            "an untrusted peer is not its own client");
            });

        }

        #endregion

        #region TheHeaderNamed_IsTheOneRead()

        /// <summary>
        /// Forwarded named: its "for" is read, from the right, and
        /// X-Forwarded-For is not; X-Real-IP named: its one address is read,
        /// and the others are not.
        /// </summary>
        [Test]
        public async Task TheHeaderNamed_IsTheOneRead()
        {

            var forwarded = await Started(new JObject(new JProperty("trustedProxies", new JArray("127.0.0.1")),
                                                      new JProperty("clientAddressHeader", "Forwarded")));

            var named        = await Status(forwarded, AtTheClient,   Forwarded("for=192.0.2.7;proto=https"));
            var twoHops      = await Status(forwarded, AtTheClient,   Forwarded("for=198.51.100.9, for=192.0.2.7, for=127.0.0.1"));
            var ipv6         = await Status(forwarded, AtTheIPv6Host, Forwarded("for=\"[2001:db8::7]:4711\""));
            var unknownRight = await Status(forwarded, AtTheClient,   Forwarded("for=192.0.2.7, for=unknown"));
            var xffThere     = await Status(forwarded, AtTheClient,   XFF("192.0.2.7"));

            var realIP       = await Started(new JObject(new JProperty("trustedProxies", new JArray("127.0.0.1")),
                                                         new JProperty("clientAddressHeader", "X-Real-IP")));

            var realNamed    = await Status(realIP, AtTheClient, XRealIP("192.0.2.7"));
            var realList     = await Status(realIP, AtTheClient, XRealIP("198.51.100.9, 192.0.2.7"));
            var realXFF      = await Status(realIP, AtTheClient, XFF("192.0.2.7"));

            Assert.Multiple(() => {
                Assert.That(named,        Is.EqualTo(HttpStatusCode.OK),            "the client Forwarded names is refused");
                Assert.That(twoHops,      Is.EqualTo(HttpStatusCode.OK),            "Forwarded was not read from the right");
                Assert.That(ipv6,         Is.EqualTo(HttpStatusCode.OK),            "an IPv6 'for' with a port is not read as the address");
                Assert.That(unknownRight, Is.EqualTo(HttpStatusCode.Unauthorized),  "'for=unknown' was skipped, and what is left of it believed");
                Assert.That(xffThere,     Is.EqualTo(HttpStatusCode.Unauthorized),  "X-Forwarded-For was read, where Forwarded is the header");
                Assert.That(realNamed,    Is.EqualTo(HttpStatusCode.OK),            "the client X-Real-IP names is refused");
                Assert.That(realList,     Is.EqualTo(HttpStatusCode.Unauthorized),  "X-Real-IP with two addresses was read as one of them");
                Assert.That(realXFF,      Is.EqualTo(HttpStatusCode.Unauthorized),  "X-Forwarded-For was read, where X-Real-IP is the header");
            });

        }

        #endregion


        #region OnAnAPIThatWasHandedIn_ItsOwnersProxiesAreBelieved()

        /// <summary>
        /// A second node on the first one's server and accounts, whose file
        /// trusts other proxies: who the client is stays the first node's to
        /// say, whose API it is.
        /// </summary>
        [Test]
        public async Task OnAnAPIThatWasHandedIn_ItsOwnersProxiesAreBelieved()
        {

            var owner      = await Started(new JObject(new JProperty("trustedProxies", new JArray("127.0.0.1"))));

            var home       = Directory.CreateDirectory(Path.Combine(directory, "second")).FullName;
            var configFile = Path.Combine(home, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configFile, """{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": { "trustedProxies": [ "10.0.0.0/8" ], "clientAddressHeader": "X-Real-IP" } }""");

            var second     = new WWCPNode(HTTPServer:        owner.HTTPServer,
                                          ExtAPI:            owner.ExtAPI,
                                          BasePath:          HTTPPath.Parse("/second"),
                                          AccountsPath:      Path.Combine(home, "accounts"),
                                          ConfigFile:        new WWCPConfigFile(configFile),
                                          CertificatesPath:  Path.Combine(home, "certificates"),
                                          LogToConsole:      false,
                                          BridgeDebugLog:    false,
                                          SSH:               new SSHSettings(OnByDefault: false));

            nodes.Add(second);

            var named = await Status(owner, AtTheClient, XFF("192.0.2.7"));

            Assert.That(named, Is.EqualTo(HttpStatusCode.OK), "the node the API was handed to said who the client is, and not its owner");

        }

        #endregion


        #region TheSection_NamesProxiesByAddressAndNetwork_AndIsWrittenAsItWasMeant()

        /// <summary>
        /// Addresses, networks, an IPv4 address mapped into IPv6 and the header
        /// in any case are read; written back, an address is an address, a
        /// network a network, and the header as it is spelled.
        /// </summary>
        [Test]
        public void TheSection_NamesProxiesByAddressAndNetwork_AndIsWrittenAsItWasMeant()
        {

            var json = JObject.Parse("""{ "trustedProxies": [ "127.0.0.1", "::1", "10.0.0.0/8", "fd00::/8", "::ffff:192.0.2.1", " " ], "clientAddressHeader": "forwarded" }""");

            Assert.That(WebConfiguration.TryParse(json, out var web, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(web!.TrustedProxies!.Select(network => network.ToString()),  Is.EqualTo(new[] { "127.0.0.1/32", "::1/128", "10.0.0.0/8", "fd00::/8", "192.0.2.1/32" }));
                Assert.That(web.Header,                                                   Is.EqualTo(ClientAddressHeader.Forwarded));
                Assert.That(web.ToJSON().ToString(Newtonsoft.Json.Formatting.None),       Is.EqualTo("""{"trustedProxies":["127.0.0.1","::1","10.0.0.0/8","fd00::/8","192.0.2.1"],"clientAddressHeader":"Forwarded"}"""));
                Assert.That(new WebConfiguration().ToJSON().Count,                        Is.EqualTo(0));
            });

        }

        #endregion

        #region TheSection_RefusesWhatIsNoProxyOrNoHeader_AndTheNodeDoesNotStart()

        /// <summary>
        /// A name that is no address, a network with bits set past its prefix,
        /// a header it does not read and a section that is no object are each
        /// refused, saying where; a node with such a file does not start.
        /// </summary>
        [TestCase("""{ "trustedProxies": [ "proxy.example" ] }""",               "'web.trustedProxies' names 'proxy.example'")]
        [TestCase("""{ "trustedProxies": [ "10.0.0.1/8" ] }""",                  "'web.trustedProxies' names '10.0.0.1/8'")]
        [TestCase("""{ "trustedProxies": [ "10.0.0.0/33" ] }""",                 "'web.trustedProxies' names '10.0.0.0/33'")]
        [TestCase("""{ "trustedProxies": "127.0.0.1" }""",                       "'web.trustedProxies' must be an array.")]
        [TestCase("""{ "clientAddressHeader": "Via" }""",                        "'web.clientAddressHeader' is 'Via', and may be 'X-Forwarded-For', 'Forwarded' or 'X-Real-IP'.")]
        public void TheSection_RefusesWhatIsNoProxyOrNoHeader_AndTheNodeDoesNotStart(String Section, String Expected)
        {

            Assert.That(WebConfiguration.TryParse(JObject.Parse(Section), out var web, out var error), Is.False);
            Assert.That(error, Does.Contain(Expected));

            var configFile = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": {{Section}} }""");

            var refused = Assert.Throws<InvalidOperationException>(() => new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                                                                       AccountsPath:      Path.Combine(directory, "accounts"),
                                                                                       ConfigFile:        new WWCPConfigFile(configFile),
                                                                                       CertificatesPath:  Path.Combine(directory, "certificates"),
                                                                                       LogToConsole:      false,
                                                                                       BridgeDebugLog:    false,
                                                                                       SSH:               new SSHSettings(OnByDefault: false)));

            Assert.That(refused!.Message, Does.Contain(Expected));

        }

        [Test]
        public void TheSection_IsAnObject()
        {

            Assert.That(WWCPConfiguration.TryParse(JObject.Parse("""{ "web": [ "127.0.0.1" ] }"""), out _, out var error), Is.False);
            Assert.That(error, Is.EqualTo("'web' must be a JSON object."));

        }

        #endregion

    }

}
