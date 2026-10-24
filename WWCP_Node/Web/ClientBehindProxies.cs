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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// Who the client of a request is, where trusted reverse proxies stand
    /// between it and the node: what HTTPExtAPI.ClientAddressOf asks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A request from anybody but a trusted proxy is its TCP peer's, whatever
    /// its headers say. From a trusted proxy the one header configured is read
    /// from its right end, the hop nearest the node: every proxy appends whom
    /// it got the request from, so the entries a trusted proxy wrote are on the
    /// right, and whatever the client wrote itself is further left. The first
    /// address from the right that is not a trusted proxy is the client; an
    /// entry that is no address - "unknown", an obfuscated name, a typo - ends
    /// the search there, because nothing to the left of it was vouched for.
    /// </para>
    /// <para>
    /// Null, which is the TCP peer to Hermod, wherever the client can not be
    /// told: not from a trusted proxy, no header, or an entry that is no
    /// address before an untrusted one. That is the proxy's address, which no
    /// API key bound to a client's address matches.
    /// </para>
    /// </remarks>
    public sealed class ClientBehindProxies
    {

        #region Data

        private readonly IReadOnlyList<IPNetwork>  trustedProxies;
        private readonly ClientAddressHeader       header;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Who the client is, behind the given proxies naming it in the given header.
        /// </summary>
        public ClientBehindProxies(IReadOnlyList<IPNetwork>  TrustedProxies,
                                   ClientAddressHeader       Header)
        {
            this.trustedProxies  = TrustedProxies;
            this.header          = Header;
        }

        #endregion


        #region AddressOf(Request)

        /// <summary>
        /// The client of the given request, or null for its TCP peer.
        /// </summary>
        public IPAddress? AddressOf(HTTPRequest Request)
        {

            if (!IPAddress.TryParse(Request.RemoteSocket.IPAddress.ToString(), out var peer) ||
                !IsTrusted(peer))
                return null;

            var hops = HopsOf(Request);

            if (hops is null || hops.Count == 0)
                return null;

            for (var i = hops.Count - 1; i >= 0; i--)
            {

                var hop = hops[i];

                if (hop is null)
                    return null;

                if (!IsTrusted(hop) || i == 0)
                    return hop;

            }

            return null;

        }

        #endregion

        #region (private) IsTrusted(Address)

        /// <summary>
        /// Whether the address is a trusted proxy's - an IPv4 address mapped into
        /// IPv6 as the IPv4 address it is, which IPNetwork.Contains sees to.
        /// </summary>
        private Boolean IsTrusted(IPAddress Address)
        {

            foreach (var network in trustedProxies)
                if (network.Contains(Address))
                    return true;

            return false;

        }

        #endregion

        #region (private) HopsOf(Request)

        /// <summary>
        /// The addresses the configured header names, nearest the client first;
        /// null for an entry that is no address. Null when the header is absent,
        /// or not to be read as a list at all.
        /// </summary>
        private List<IPAddress?>? HopsOf(HTTPRequest Request)
        {

            // A field sent on several lines is one list (RFC 9110, 5.3), however
            // the lines were kept.
            var text = Request.TryGetHeaderField(WebConfiguration.TextOf(header), out var value)
                           ? value switch {
                                 String   one   => one,
                                 String[] many  => String.Join(", ", many),
                                 _              => null
                             }
                           : null;

            if (String.IsNullOrWhiteSpace(text))
                return null;

            switch (header)
            {

                // One address, from the one proxy in front: on several lines it
                // is no longer one, and no address either.
                case ClientAddressHeader.XRealIP:
                    return [ AddressIn(text.Trim()) ];

                case ClientAddressHeader.Forwarded:

                    // A field that does not parse is no chain at all - see
                    // ForwardedElement.TryParseAll.
                    if (!ForwardedElement.TryParseAll(text, out var elements))
                        return null;

                    return elements.Select(element => element.For?.IPAddress is { } address &&
                                                      IPAddress.TryParse(address.ToString(), out var parsed)
                                                          ? parsed
                                                          : null).
                                    ToList();

                default:
                    return text.Split(',').
                                Select(entry => AddressIn(entry.Trim())).
                                ToList();

            }

        }

        #endregion

        #region (private static) AddressIn(Entry)

        /// <summary>
        /// The address in one entry of X-Forwarded-For or X-Real-IP: an address,
        /// or one with a port, as some proxies write it ("192.0.2.7:4711",
        /// "[2001:db8::7]:4711"); null for anything else.
        /// </summary>
        /// <remarks>
        /// An IPv4 address in its four parts only: IPAddress.TryParse also takes
        /// "7" for 0.0.0.7 and "192.7" for 192.0.0.7, which no proxy writes.
        /// </remarks>
        private static IPAddress? AddressIn(String Entry)
        {

            var text = Entry;

            if (text.StartsWith('[') && text.LastIndexOf(']') is var close && close > 0)
            {
                var rest = text[(close + 1)..];
                if (rest.Length > 0 && !(rest[0] == ':' && UInt16.TryParse(rest[1..], out _)))
                    return null;
                text = text[1..close];
            }
            else if (text.Count(c => c == ':') == 1)
            {
                var colon = text.IndexOf(':');
                if (!UInt16.TryParse(text[(colon + 1)..], out _))
                    return null;
                text = text[..colon];
            }

            if (!IPAddress.TryParse(text, out var address))
                return null;

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                text.Split('.').Length != 4)
                return null;

            return address;

        }

        #endregion

    }

}
