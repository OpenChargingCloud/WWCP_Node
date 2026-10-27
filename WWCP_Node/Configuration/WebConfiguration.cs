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

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The header a reverse proxy in front of the node names the client in.
    /// </summary>
    public enum ClientAddressHeader
    {

        /// <summary>
        /// X-Forwarded-For: client, proxy1, proxy2 - what nginx writes with
        /// $proxy_add_x_forwarded_for, and the default.
        /// </summary>
        XForwardedFor,

        /// <summary>
        /// Forwarded: for=client, for=proxy1 (RFC 7239).
        /// </summary>
        Forwarded,

        /// <summary>
        /// X-Real-IP: client - one address, from the one proxy in front.
        /// </summary>
        XRealIP

    }


    /// <summary>
    /// The "web" section of the configuration file: how the web interface,
    /// its JSON API and its sign-in are reached safely - over TLS of the
    /// node's own, with which certificate and with HSTS, or through reverse
    /// proxies in front of it that do the TLS, which of them are believed when
    /// they say who the client is and whether it came over HTTPS, and in which
    /// header they say it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Behind a proxy every request comes from the proxy. Who the client is
    /// matters twice - an API key bound to addresses opens the door only from
    /// them, and password guesses are counted per client - and only the proxy
    /// knows it. But a header is something anybody can write: it is believed
    /// only from a proxy named here, and only the one header named here is
    /// read, because a proxy that writes one of them passes the others on as
    /// the client wrote them. Whether the browser came over HTTPS is read from
    /// the same proxies and nobody else - from "Forwarded" where that is the
    /// header, from X-Forwarded-Proto otherwise - and decides whether the
    /// session cookie is a secure one and whether HSTS is sent.
    /// </para>
    /// <para>
    /// Read when the node starts. Without trusted proxies nothing is read, and
    /// the client is the TCP peer, as before; without "tls" the node speaks
    /// plain HTTP, as before. A switch on the command line wins over what is
    /// said here: <c>--https</c> and <c>--https-cert</c> over "tls.certificate",
    /// <c>--redirect-port</c> over "tls.redirectPort", and <c>--trusted-proxy</c>
    /// over the whole of "trustedProxies".
    /// </para>
    /// </remarks>
    /// <param name="TrustedProxies">The proxies believed, by address or network (CIDR); none where absent.</param>
    /// <param name="Header">The header they name the client in; X-Forwarded-For where absent.</param>
    /// <param name="TLS">The web interface over TLS of the node's own, and with which certificate; plain HTTP where absent.</param>
    /// <param name="HSTS">Whether, and for how long, an answer that reached a browser over HTTPS tells it to come back over HTTPS only; for a year where absent.</param>
    public sealed record WebConfiguration(IReadOnlyList<IPNetwork>?  TrustedProxies  = null,
                                          ClientAddressHeader?       Header          = null,
                                          WebTLSConfiguration?       TLS             = null,
                                          HSTSConfiguration?         HSTS            = null)
    {

        #region Data

        /// <summary>
        /// The name of this section in the configuration file.
        /// </summary>
        public const String  SectionName        = "web";

        /// <summary>
        /// How many proxies may be named.
        /// </summary>
        public const Int32   MaxTrustedProxies  = 64;

        #endregion

        #region Properties

        /// <summary>
        /// Whether reverse proxies are named whose word is believed.
        /// </summary>
        public Boolean HasTrustedProxies
            => TrustedProxies is { Count: > 0 };

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The "web" section, or the one sentence that says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JObject                                    JSON,
                                       [NotNullWhen(true)]  out WebConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?            Error)
        {

            Configuration = null;

            if (!ConfigurationReader.TryReadStrings(JSON, "trustedProxies",       SectionName, MaxTrustedProxies, 64, out var proxies, out Error) ||
                !ConfigurationReader.TryReadString (JSON, "clientAddressHeader",  SectionName, 32,                    out var header,  out Error))
                return false;

            List<IPNetwork>? networks = null;

            if (proxies is not null)
            {

                networks = [];

                foreach (var proxy in proxies)
                {

                    if (!TryParseNetwork(proxy, out var network))
                    {
                        Error = $"'{SectionName}.trustedProxies' names '{proxy}', which is neither an IP address nor a network such as 10.0.0.0/8 with no bits set past its prefix.";
                        return false;
                    }

                    networks.Add(network);

                }

            }

            ClientAddressHeader? clientAddressHeader = null;

            if (header is not null)
            {

                clientAddressHeader = header.ToLowerInvariant() switch {
                                          "x-forwarded-for"  => ClientAddressHeader.XForwardedFor,
                                          "forwarded"        => ClientAddressHeader.Forwarded,
                                          "x-real-ip"        => ClientAddressHeader.XRealIP,
                                          _                  => null
                                      };

                if (clientAddressHeader is null)
                {
                    Error = $"'{SectionName}.clientAddressHeader' is '{header}', and may be 'X-Forwarded-For', 'Forwarded' or 'X-Real-IP'.";
                    return false;
                }

            }

            WebTLSConfiguration? tls = null;

            if (JSON[WebTLSConfiguration.Name] is JToken tlsToken && tlsToken.Type != JTokenType.Null)
            {

                if (tlsToken is not JObject tlsJSON)
                {
                    Error = $"'{SectionName}.{WebTLSConfiguration.Name}' must be a JSON object: {{ \"certificate\": \"{WebTLSConfiguration.StoreText}\" }}, say.";
                    return false;
                }

                if (!WebTLSConfiguration.TryParse(tlsJSON, $"{SectionName}.{WebTLSConfiguration.Name}", out tls, out Error))
                    return false;

            }

            HSTSConfiguration? hsts = null;

            if (JSON[HSTSConfiguration.Name] is JToken hstsToken && hstsToken.Type != JTokenType.Null &&
                !HSTSConfiguration.TryParse(hstsToken, $"{SectionName}.{HSTSConfiguration.Name}", out hsts, out Error))
                return false;

            Configuration = new WebConfiguration(networks, clientAddressHeader, tls, hsts);

            return true;

        }

        #endregion

        #region (static) TryParseNetwork(Text, out Network)

        /// <summary>
        /// An address, as the network of just that address, or a network in
        /// CIDR notation. An IPv4 address mapped into IPv6 is the IPv4 address
        /// it is, as the client's address is compared.
        /// </summary>
        public static Boolean TryParseNetwork(String Text, out IPNetwork Network)
        {

            Network = default;

            if (!Text.Contains('/'))
            {

                if (!IPAddress.TryParse(Text, out var address))
                    return false;

                if (address.IsIPv4MappedToIPv6)
                    address = address.MapToIPv4();

                Network = new IPNetwork(address, address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
                return true;

            }

            // IPNetwork takes "10.0.0.1/8" for 10.0.0.0/8 and says nothing; somebody
            // who wrote it may have meant the one host, and is told instead.
            return IPNetwork.TryParse(Text, out Network) &&
                   IPAddress.TryParse(Text[..Text.IndexOf('/')], out var written) &&
                   written.Equals(Network.BaseAddress);

        }

        #endregion

        #region (static) TextOf(Header)

        /// <summary>
        /// The header's name, as the file and the request write it.
        /// </summary>
        public static String TextOf(ClientAddressHeader Header)

            => Header switch {
                   ClientAddressHeader.Forwarded  => "Forwarded",
                   ClientAddressHeader.XRealIP    => "X-Real-IP",
                   _                              => "X-Forwarded-For"
               };

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as it is written to the file: an address as an address,
        /// a network as a network.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (TLS is not null)
                json.Add(WebTLSConfiguration.Name,  TLS.ToJSON());

            if (HSTS is not null)
                json.Add(HSTSConfiguration.Name,    HSTS.ToJSON());

            if (TrustedProxies is not null)
                json.Add("trustedProxies",       new JArray(TrustedProxies.Select(TextOf)));

            if (Header is not null)
                json.Add("clientAddressHeader",  TextOf(Header.Value));

            return json;

        }

        #endregion

        #region (static) TextOf(Network)

        /// <summary>
        /// A proxy as the file writes it: an address as an address, a network
        /// as a network.
        /// </summary>
        public static String TextOf(IPNetwork Network)

            => Network.PrefixLength == (Network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)
                   ? Network.BaseAddress.ToString()
                   : Network.ToString();

        #endregion

        #region Over(Below)

        /// <summary>
        /// This, where it says something, and what the given one says where it
        /// does not: what the switches of the command line say, over what the
        /// configuration file says.
        /// </summary>
        /// <remarks>
        /// "trustedProxies" as a whole: proxies named on the command line are
        /// the proxies, and not more of them beside the file's - a list that
        /// grew from two places would be one nobody could read off either.
        /// The certificate and the redirect port each on its own, so that
        /// <c>--redirect-port 80</c> keeps the certificate the file names.
        /// </remarks>
        /// <param name="Below">What the configuration file says, or null.</param>
        public WebConfiguration Over(WebConfiguration? Below)

            => new (TrustedProxies  ?? Below?.TrustedProxies,
                    Header          ?? Below?.Header,
                    TLS is not null
                        ? TLS.Over(Below?.TLS)
                        : Below?.TLS,
                    HSTS            ?? Below?.HSTS);

        #endregion

        #region (override) ToString()

        public override String ToString()

            => String.Join(", ",
                   new[] {
                       TLS?.ToString(),
                       TLS is not null || HasTrustedProxies
                           ? HSTS?.ToString()
                           : null,
                       HasTrustedProxies
                           ? $"the client named in {TextOf(Header ?? ClientAddressHeader.XForwardedFor)} by {String.Join(", ", TrustedProxies!.Select(TextOf))}"
                           : "the client is the TCP peer"
                   }.Where(part => part is not null));

        #endregion

    }

}
