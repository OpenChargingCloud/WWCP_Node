/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// How a node asks for the link-local names of Multicast DNS (RFC 6762) -
    /// "lc1.local" and the like: the object "multicast" of its "dns" section.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off unless the file says otherwise (mDNS-Concept.md, decision 1): a
    /// node that never asked for it opens no socket on port 5353 and sends
    /// nothing to the multicast groups of the link. A name under ".local" is
    /// then answered NXDOMAIN, as RFC 6762 section 22.1 asks of a client that
    /// may not send such a name to its unicast name servers.
    /// </para>
    /// <para>
    /// Which network interfaces take part is the file's to say (decision 2),
    /// by their names as the operating system gives them; none named is every
    /// interface that is up and can multicast, the loopback interface left
    /// out. A name this machine does not have is kept, so that a file can be
    /// taken to another machine, and simply asks nothing there.
    /// </para>
    /// <para>
    /// As everywhere in a section, null is "the file does not say": what is
    /// missing keeps what was in effect.
    /// </para>
    /// </remarks>
    /// <param name="Enabled">Whether names under ".local" are asked for by Multicast DNS.</param>
    /// <param name="Interfaces">The network interfaces asked on, by name; an empty list is all of them.</param>
    /// <param name="IPv4">Whether the IPv4 group 224.0.0.251 is asked.</param>
    /// <param name="IPv6">Whether the IPv6 group ff02::fb is asked.</param>
    public sealed record MulticastDNSConfiguration(Boolean?                Enabled     = null,
                                                   IReadOnlyList<String>?  Interfaces  = null,
                                                   Boolean?                IPv4        = null,
                                                   Boolean?                IPv6        = null)
    {

        #region Data

        /// <summary>
        /// The name of this object in the "dns" section.
        /// </summary>
        public const String  Key            = "multicast";

        /// <summary>
        /// The most network interfaces one node may name.
        /// </summary>
        public const Int32   MaxInterfaces  = 32;

        /// <summary>
        /// The longest name of a network interface accepted - Windows gives
        /// them long ones, such as "vEthernet (Default Switch)".
        /// </summary>
        public const Int32   MaxInterfaceNameLength  = 128;

        private const String Path           = "dns.multicast";

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The object "multicast" of a "dns" section, or the one sentence that
        /// says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JToken                                                JSON,
                                       [NotNullWhen(true)]  out MulticastDNSConfiguration?   Configuration,
                                       [NotNullWhen(false)] out String?                      Error)
        {

            Configuration = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object.";
                return false;
            }

            if (!ConfigurationReader.TryReadBoolean(json, "enabled",     Path, out var enabled, out Error) ||
                !ConfigurationReader.TryReadBoolean(json, "ipv4",        Path, out var ipv4,    out Error) ||
                !ConfigurationReader.TryReadBoolean(json, "ipv6",        Path, out var ipv6,    out Error) ||
                !ConfigurationReader.TryReadStrings(json, "interfaces",  Path, MaxInterfaces, MaxInterfaceNameLength, out var interfaces, out Error))
            {
                return false;
            }

            // Both said, and both false: a multicast DNS asked on no group at
            // all, which is "off" said in a way nobody would find again.
            if (ipv4 == false && ipv6 == false)
            {
                Error = $"'{Path}' must keep IPv4 or IPv6; to ask neither, set 'enabled' to false.";
                return false;
            }

            Configuration = new MulticastDNSConfiguration(
                                enabled,
                                interfaces?.Distinct(StringComparer.Ordinal).ToArray(),
                                ipv4,
                                ipv6
                            );

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The object as it is written to the file: what was not said is not
        /// written.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Enabled.HasValue)       json.Add("enabled",     Enabled.Value);
            if (Interfaces is not null) json.Add("interfaces",  new JArray(Interfaces));
            if (IPv4.HasValue)          json.Add("ipv4",        IPv4.Value);
            if (IPv6.HasValue)          json.Add("ipv6",        IPv6.Value);

            return json;

        }

        #endregion

    }

}
