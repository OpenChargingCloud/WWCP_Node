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

using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// How the web interface, the JSON API and the sign-in of a node are
    /// reached safely: over TLS of its own, or through reverse proxies in front
    /// of it that do the TLS - and the loud warning where neither is the case
    /// and the node listens beyond this machine all the same.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Directly</b>, with "tls" in the "web" section of the configuration
    /// file or <c>--https</c>: the web interface's port speaks HTTPS, with the
    /// store's TLS server identity for "web" or with PEM files that are read
    /// again when they change - see <see cref="WebServerCertificate"/> - the
    /// session cookie is a secure one, the pages are sent with HSTS, and a port
    /// of plain HTTP beside it may send every browser there.
    /// </para>
    /// <para>
    /// <b>Behind proxies</b>, with "trustedProxies": what they say about who
    /// the client is and whether the browser's leg was HTTPS is believed from
    /// them and from nobody else. Who the client is goes into the log and into
    /// the count of password guesses, and is what an API key bound to addresses
    /// is compared with; HTTPS makes the session cookie a secure one and has
    /// HSTS sent - on the answers to such a request, and on no others.
    /// </para>
    /// <para>
    /// <b>Neither</b>, on an address beyond the loopback: allowed, because a
    /// node on a bench in a closed network is reached that way, and said as
    /// loudly as a node says anything - in the log at the start, in a box below
    /// the banner, and above every page of the web interface to whoever may
    /// administer it. On the loopback alone nothing is said: whoever reaches
    /// that is on the machine already.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// Who the client of a request is, behind the trusted proxies; null
        /// where none are named.
        /// </summary>
        private readonly ClientBehindProxies?  clientBehindProxies;

        #endregion

        #region Properties

        /// <summary>
        /// What is in effect of TLS and of the proxies in front: what the
        /// program said - see NodeArguments.Web - over the "web" section of the
        /// configuration file; empty where neither says anything.
        /// </summary>
        public WebConfiguration       WebSettings              { get; }

        /// <summary>
        /// What the program said of TLS and of the proxies in front, before the
        /// file was asked - NodeArguments.Web, as the kind of node handed it on -
        /// or null where it said nothing.
        /// </summary>
        public WebConfiguration?      WebSwitches              { get; }

        /// <summary>
        /// The certificate the web interface shows, where the node serves it
        /// over TLS of its own making; null for plain HTTP, and where the kind
        /// of node or the HTTP server it was handed brings its own.
        /// </summary>
        public WebServerCertificate?  WebCertificate           { get; }

        /// <summary>
        /// The port of plain HTTP that sends every browser to HTTPS, and does
        /// nothing else; null where there is none.
        /// </summary>
        public HTTPServer?            RedirectServer           { get; }

        /// <summary>
        /// The port of <see cref="RedirectServer"/>, or null.
        /// </summary>
        public IPPort?                RedirectPort             { get; }

        /// <summary>
        /// The Strict-Transport-Security the pages of the web interface are
        /// sent with where they reached a browser over HTTPS - "max-age=..." -
        /// or null where none is sent.
        /// </summary>
        public String?                StrictTransportSecurity  { get; }

        /// <summary>
        /// Whether the web interface listens beyond the loopback: on every
        /// address with --any, or on one of this machine's others.
        /// </summary>
        public Boolean                ListensBeyondLoopback    { get; }

        /// <summary>
        /// What is said where the web interface, the JSON API and the sign-in
        /// are served over plain HTTP beyond this machine, with neither TLS nor
        /// a trusted proxy - or null where they are not.
        /// </summary>
        public String?                PlainHTTPWarning         { get; }

        #endregion


        #region ClientAddressOf(Request)

        /// <summary>
        /// The client of the given request as a trusted proxy in front of this
        /// node names it, or null where it is the TCP peer - there being no
        /// trusted proxy, or no word from one.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        public System.Net.IPAddress? ClientAddressOf(HTTPRequest Request)

            => clientBehindProxies?.AddressOf(Request);

        #endregion

        #region ClientOf(Request)

        /// <summary>
        /// Who sent the given request, as the log says it: the TCP peer - or,
        /// behind a trusted proxy, the client the proxy names, and the proxy
        /// beside it: "192.0.2.7 (via 127.0.0.1:51234)".
        /// </summary>
        /// <remarks>
        /// Wherever this node says who did something over HTTP. Behind nginx
        /// every line said "127.0.0.1", and the one thing somebody reading the
        /// log after an attack wanted to know was the one thing it did not say.
        /// </remarks>
        /// <param name="Request">An HTTP request.</param>
        public String ClientOf(HTTPRequest Request)

            => ClientAddressOf(Request) is System.Net.IPAddress client
                   ? $"{client} (via {Request.RemoteSocket})"
                   : Request.RemoteSocket.ToString();

        #endregion

        #region ReachedOverHTTPS(Request)

        /// <summary>
        /// Whether the browser's own leg of the given request was HTTPS: over TLS
        /// of this node's own, or as a trusted proxy in front of it says.
        /// </summary>
        /// <remarks>
        /// What decides whether the session cookie set in the answer is a secure
        /// one, and whether the answer carries HSTS.
        /// </remarks>
        /// <param name="Request">An HTTP request.</param>
        public Boolean ReachedOverHTTPS(HTTPRequest Request)

            => HTTPS ||
               clientBehindProxies?.IsHTTPS(Request) == true;

        #endregion

        #region HostOf(Request)

        /// <summary>
        /// The name the browser asked for: what a trusted proxy in front of this
        /// node says it was, or the request's own Host - without its port - or
        /// null where neither says one.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        public String? HostOf(HTTPRequest Request)
        {

            var forwarded = clientBehindProxies?.HostOf(Request);

            if (forwarded is not null)
                return HTTPHostname.TryParse(forwarded) is HTTPHostname named && named.Name is { Length: > 0 } name
                           ? name
                           : forwarded;

            return Request.Host.Name is { Length: > 0 } host
                       ? host
                       : null;

        }

        #endregion

        #region ProxyHostOf(Request)

        /// <summary>
        /// The name the browser asked for as a trusted proxy in front of this
        /// node says it - "host" of "Forwarded", or X-Forwarded-Host, with its
        /// port where it names one - or null where no trusted proxy says one.
        /// </summary>
        /// <remarks>
        /// What a page of the node's own may be called besides the request's
        /// Host: a request another site made a browser send is refused, and
        /// behind a proxy that does not pass the browser's Host on, the node's
        /// own pages would otherwise be another site to it.
        /// </remarks>
        /// <param name="Request">An HTTP request.</param>
        public String? ProxyHostOf(HTTPRequest Request)

            => clientBehindProxies?.HostOf(Request);

        #endregion

        #region NoticesFor(Roles)

        /// <summary>
        /// What the web interface says above every page to somebody who holds the
        /// given roles: the warning about plain HTTP, to an administrator, and
        /// nothing to anybody else - there is nothing they could do about it.
        /// </summary>
        /// <param name="Roles">The roles of whoever is signed in.</param>
        public IReadOnlyList<String> NoticesFor(IEnumerable<String> Roles)

            => PlainHTTPWarning is String warning &&
               Roles.Contains(AdminRole, StringComparer.OrdinalIgnoreCase)
                   ? [ warning ]
                   : [];

        #endregion


        #region (private) WebSettingsOf(Program, File)

        /// <summary>
        /// What the program said, over what the file said - the paths of the
        /// file's certificate measured from the file, as every path in it is.
        /// </summary>
        private WebConfiguration WebSettingsOf(WebConfiguration?  Program,
                                               WebConfiguration?  File)
        {

            var file = File?.TLS?.Certificate is WebCertificateSource source && !source.IsStore
                           ? File with { TLS = File.TLS with { Certificate = source.Beside(ConfigFile.Path) } }
                           : File;

            return Program?.Over(file) ?? file ?? new WebConfiguration();

        }

        #endregion

        #region (private) PlainHTTPWarningFor(Address, Port)

        /// <summary>
        /// The warning about plain HTTP beyond this machine, or null where the
        /// node speaks TLS, stands behind trusted proxies, or listens on the
        /// loopback alone.
        /// </summary>
        private String? PlainHTTPWarningFor(IIPAddress  Address,
                                            IPPort      Port)

            => HTTPS || clientBehindProxies is not null || !ListensBeyondLoopback
                   ? null
                   : $"The web interface, the JSON API and the sign-in of this {Kind.Name} are served over plain HTTP on " +
                     (Address.IsAny
                          ? $"every address of this machine, port {Port}"
                          : $"{Address}, port {Port}") +
                     ": passwords, API keys and session cookies cross the network in clear text. " +
                      "Serve it over HTTPS (--https, --https-cert, or \"tls\" in the \"web\" section of the configuration file), " +
                      "or put a reverse proxy that does HTTPS in front of it and name the proxy in \"trustedProxies\" there (--trusted-proxy).";

        #endregion

        #region (private static) IsBeyondLoopback(Address)

        /// <summary>
        /// Whether an address to listen on reaches beyond this machine: every
        /// address does, and every one that is not 127.0.0.0/8 or ::1.
        /// </summary>
        private static Boolean IsBeyondLoopback(IIPAddress Address)

            => Address.IsAny ||
               !System.Net.IPAddress.TryParse(Address.ToString().Trim('[', ']'), out var address) ||
               !System.Net.IPAddress.IsLoopback(address);

        #endregion

        #region (private) NewRedirectServer(Address, RedirectPort, HTTPSPort, Product)

        /// <summary>
        /// The port of plain HTTP beside HTTPS: every request, whatever its
        /// method and path, is answered with a permanent redirect to the same
        /// path and query over HTTPS, at the name the browser asked for.
        /// </summary>
        /// <remarks>
        /// <para>
        /// 308 and not 301: a browser keeps the method and the body of a 308, and
        /// a form sent there by mistake is sent on rather than turned into a GET.
        /// Nothing else is served here - no page, no API, no sign-in: whatever
        /// came over plain HTTP has crossed the network in the clear already, and
        /// the answer to it says nothing but where to go.
        /// </para>
        /// <para>
        /// The name is the request's Host, as nginx's "return 301 https://$host"
        /// takes it: a browser is sent where it was going, and anybody who sends
        /// another name is sent to that one. A request without one is told so -
        /// there is nowhere to send it that it asked for.
        /// </para>
        /// </remarks>
        private HTTPServer NewRedirectServer(IIPAddress  Address,
                                             IPPort      RedirectPort,
                                             IPPort      HTTPSPort,
                                             String      Product)
        {

            var server = new HTTPServer(
                             IPAddress:       Address,
                             TCPPort:         RedirectPort,
                             HTTPServerName:  Product,
                             DNSClient:       dnsClient
                         );

            var api    = server.AddHTTPAPI(HTTPPath.Root);

            Task<HTTPResponse> Redirect(HTTPRequest Request)
            {

                if (Request.Host.Name is not { Length: > 0 } host)
                    return Task.FromResult(
                               new HTTPResponse.Builder(Request) {
                                   HTTPStatusCode  = HTTPStatusCode.BadRequest,
                                   Server          = Product,
                                   ContentType     = HTTPContentType.Text.PLAIN,
                                   Content         = System.Text.Encoding.UTF8.GetBytes("This port only sends browsers to HTTPS, and a request without a Host has nowhere to be sent."),
                                   Connection      = ConnectionType.Close
                               }.AsImmutable
                           );

                var name    = host.Contains(':') && !host.StartsWith('[')
                                  ? $"[{host}]"
                                  : host;

                var target  = Request.RequestTarget is { Length: > 0 } requested && requested.StartsWith('/')
                                  ? requested
                                  : "/";

                return Task.FromResult(
                           new HTTPResponse.Builder(Request) {
                               HTTPStatusCode  = HTTPStatusCode.PermanentRedirect,
                               Server          = Product,
                               Location        = Location.Parse($"https://{name}{(HTTPSPort.ToUInt16() == 443 ? "" : $":{HTTPSPort}")}{target}"),
                               CacheControl    = "no-store",
                               Connection      = ConnectionType.Close
                           }.AsImmutable
                       );

            }

            foreach (var method in new[] { HTTPMethod.GET, HTTPMethod.HEAD, HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE })
            {
                api.AddHandler(HTTPPath.Root,                    Redirect, method);
                api.AddHandler(HTTPPath.Root + "{path..}",       Redirect, method);
            }

            return server;

        }

        #endregion

        #region (private) StartRedirectServer() / StopRedirectServer()

        /// <summary>
        /// Open the port of plain HTTP that redirects to HTTPS, where there is
        /// one: after the node's own port, and said as the node's own is where it
        /// cannot be had.
        /// </summary>
        private async Task StartRedirectServer()
        {

            if (RedirectServer is null)
                return;

            try
            {
                await RedirectServer.Start();
            }
            catch (SocketException problem)
            {
                throw new PortUnavailableException(RedirectPort!.Value, problem, NodePort.HTTPSRedirect);
            }

            Log.Notice($"Port {RedirectPort} sends every browser to HTTPS on port {HTTPPort}.", "web", "http", "tls");

        }

        /// <summary>
        /// Close it again.
        /// </summary>
        private async Task StopRedirectServer()
        {
            if (RedirectServer is not null)
                await RedirectServer.Stop();
        }

        #endregion

        #region (private) SayHowItIsReached()

        /// <summary>
        /// What the log says at the start about how the web interface is reached:
        /// the certificate it shows, the proxies it believes - or the warning
        /// about plain HTTP.
        /// </summary>
        private void SayHowItIsReached()
        {

            // Asked once, which says in the log what is shown - or that nothing
            // is, and every connection refused until there is something.
            _ = WebCertificate?.Current;

            if (clientBehindProxies is not null)
                Log.Notice($"Behind {String.Join(", ", WebSettings.TrustedProxies!.Select(WebConfiguration.TextOf))}: the client " +
                           $"{WebConfiguration.TextOf(WebSettings.Header ?? ClientAddressHeader.XForwardedFor)} names, " +
                           $"and HTTPS where {(WebSettings.Header == ClientAddressHeader.Forwarded ? "its proto" : "X-Forwarded-Proto")} says so, are believed from them and from nobody else.",
                           "web", "http", "security");

            if (PlainHTTPWarning is String warning)
                Log.Warning(warning, "web", "http", "security");

        }

        #endregion

        #region (private) SayWhatWasForwardedInVain(Request)

        /// <summary>
        /// Say at debug level that a request named a client or a protocol on its
        /// way and was not believed, because it did not come from a trusted proxy.
        /// </summary>
        /// <remarks>
        /// Anybody can write those headers, so this is no alarm - but it is the
        /// first thing to look for where a node behind a proxy counts every
        /// password guess against the proxy: the proxy is then not among the
        /// trusted ones, or not as the node sees it.
        /// </remarks>
        private void SayWhatWasForwardedInVain(HTTPRequest Request)
        {

            if (clientBehindProxies?.IsFromATrustedProxy(Request) == true)
                return;

            var headers = ClientBehindProxies.SaysWhoForwarded(Request);

            if (headers.Count > 0)
                Log.Debug($"{String.Join(", ", headers)} from {Request.RemoteSocket} not believed: " +
                          (clientBehindProxies is null
                               ? $"'{WebConfiguration.SectionName}.trustedProxies' names no proxy."
                               : "it is no trusted proxy."),
                          "http", "security");

        }

        #endregion

        #region (private) WebJSON()

        /// <summary>
        /// How the web interface is reached, as the Configuration page says it,
        /// beside what "http" said of it before.
        /// </summary>
        private IEnumerable<JProperty> WebJSON()
        {

            var tls = WebCertificate?.ToJSON();

            if (tls is not null && RedirectPort is IPPort redirect)
                tls.Add("redirectPort", redirect.ToUInt16());

            return [
                new JProperty("tls",                  tls),
                new JProperty("hsts",                 StrictTransportSecurity),
                new JProperty("trustedProxies",       WebSettings.HasTrustedProxies
                                                          ? new JArray(WebSettings.TrustedProxies!.Select(WebConfiguration.TextOf))
                                                          : null),
                new JProperty("clientAddressHeader",  WebSettings.HasTrustedProxies
                                                          ? WebConfiguration.TextOf(WebSettings.Header ?? ClientAddressHeader.XForwardedFor)
                                                          : null),
                new JProperty("warning",              PlainHTTPWarning)
            ];

        }

        #endregion

    }

}
