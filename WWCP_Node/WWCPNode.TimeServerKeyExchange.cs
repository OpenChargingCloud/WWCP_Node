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

using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Which key exchange server each time server's keys and cookies come
    /// from, where it is another than the time server itself: the
    /// NTSKEServerURL of the Secure Time Synchronization white paper.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The time server is asked for as the NTP server, by an NTPv4 Server
    /// Negotiation record; the NTP server is still the one the response names,
    /// or the key exchange server where it names none (RFC 8915 § 4.1.7). The
    /// certificate seen is the key exchange server's, and TLS compares it with
    /// that name; what it is held to, and what it was believed with, are kept
    /// under the time server's name, as everything else about the server is.
    /// </para>
    /// <para>
    /// By the time server's name across every group, as its AEAD algorithm is:
    /// its key exchange is kept by that name, and the first entry that names a
    /// key exchange server decides. A server whose key exchange server changes
    /// lets go of its key exchange.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) KeyExchangeHosts() / KeyExchangeHostOf(Hostname)

        /// <summary>
        /// The key exchange server of each time server that has one of its own:
        /// the first entry naming one across every group.
        /// </summary>
        private Dictionary<DomainName, DomainName> KeyExchangeHosts()
        {

            var hosts = new Dictionary<DomainName, DomainName>();

            foreach (var server in ntsGroups.SelectMany(group => group.Settings?.Servers ?? []))
                if (server.NTSKEHostname is DomainName keyExchange)
                    hosts.TryAdd(server.Hostname, keyExchange);

            return hosts;

        }

        /// <summary>
        /// The key exchange server of the given time server, where it has one of
        /// its own.
        /// </summary>
        private DomainName? KeyExchangeHostOf(DomainName Hostname)

            => KeyExchangeHosts().TryGetValue(Hostname, out var keyExchange)
                   ? keyExchange
                   : null;

        #endregion

        #region (private) PutKeyExchangeHosts()

        /// <summary>
        /// Put each time server's key exchange server on every group's servers.
        /// </summary>
        private void PutKeyExchangeHosts()
        {

            var hosts = KeyExchangeHosts();

            foreach (var source in ntsGroups.SelectMany(group => group.Sources.Sources))
                source.NTSKEHost = hosts.TryGetValue(source.Hostname, out var keyExchange)
                                       ? keyExchange
                                       : null;

        }

        #endregion

        #region (private) KeyExchangeHostChanges(Was)

        /// <summary>
        /// What changed about the time servers' key exchange servers since the
        /// given state, as the log line says it - and each server whose key
        /// exchange server changed lets go of its key exchange.
        /// </summary>
        /// <param name="Was">The key exchange servers before, by <see cref="KeyExchangeHosts"/>.</param>
        private IEnumerable<String> KeyExchangeHostChanges(Dictionary<DomainName, DomainName> Was)
        {

            var now      = KeyExchangeHosts();
            var changes  = new List<String>();

            foreach (var server in Was.Keys.Union(now.Keys).ToArray())
            {

                var before = Was.TryGetValue(server, out var wasHost) ? wasHost : null;
                var after  = now.TryGetValue(server, out var nowHost) ? nowHost : null;

                if (Equals(before, after))
                    continue;

                timeEngine.ForgetKeyExchange(server);

                changes.Add(after is DomainName keyExchange
                                ? $"{server.Trimmed}'s keys from {keyExchange.Trimmed}"
                                : $"{server.Trimmed}'s keys from itself");

            }

            return changes;

        }

        #endregion

    }

}
