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

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// When the key exchange with each time server is made again: at a random
    /// time between the MinRefresh and the MaxRefresh of the Secure Time
    /// Synchronization white paper after the last one - what its entry sets,
    /// or 12 to 24 hours.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By the server's name across every group, as its AEAD algorithm is: a
    /// server is one server, whichever group asks it, and its key exchange is
    /// kept by its name and reused by every group that asks it. The first
    /// entry that sets a refresh decides.
    /// </para>
    /// <para>
    /// A server whose refresh changes lets go of its key exchange, and the
    /// next round makes a new one, due by what was set: one kept would be due
    /// by what was set before, a day away where an hour was just set.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) Refreshes()

        /// <summary>
        /// When the key exchange with each time server is made again, for the
        /// servers an entry sets it for: the first such entry across every group.
        /// </summary>
        private Dictionary<DomainName, (TimeSpan Min, TimeSpan Max)> Refreshes()
        {

            var refreshes = new Dictionary<DomainName, (TimeSpan Min, TimeSpan Max)>();

            foreach (var server in ntsGroups.SelectMany(group => group.Settings?.Servers ?? []))
                if (NTSServerConfiguration.SetsRefresh(server))
                    refreshes.TryAdd(server.Hostname, NTSServerConfiguration.RefreshOf(server));

            return refreshes;

        }

        #endregion

        #region (private) PutRefreshes()

        /// <summary>
        /// Put when each time server's key exchange is made again on every
        /// group's servers.
        /// </summary>
        /// <remarks>
        /// Every group and not only the one that changed, because the change of
        /// one group can change the refresh of a server another one asks.
        /// </remarks>
        private void PutRefreshes()
        {

            var refreshes = Refreshes();

            foreach (var source in ntsGroups.SelectMany(group => group.Sources.Sources))
            {

                var (min, max) = refreshes.TryGetValue(source.Hostname, out var refresh)
                                     ? refresh
                                     : NTSServerConfiguration.RefreshOf(null);

                source.MinRefresh = min;
                source.MaxRefresh = max;

            }

        }

        #endregion

        #region (private) RefreshChanges(Was)

        /// <summary>
        /// What changed about when the time servers' key exchanges are made
        /// again since the given state, as the log line says it - and each server
        /// whose refresh changed lets go of its key exchange.
        /// </summary>
        /// <param name="Was">When each server's key exchange was made again before, by <see cref="Refreshes"/>.</param>
        private IEnumerable<String> RefreshChanges(Dictionary<DomainName, (TimeSpan Min, TimeSpan Max)> Was)
        {

            var now      = Refreshes();
            var changes  = new List<String>();

            foreach (var server in Was.Keys.Union(now.Keys).ToArray())
            {

                var before = Was.TryGetValue(server, out var wasRefresh) ? wasRefresh : NTSServerConfiguration.RefreshOf(null);
                var after  = now.TryGetValue(server, out var nowRefresh) ? nowRefresh : NTSServerConfiguration.RefreshOf(null);

                if (before == after)
                    continue;

                timeEngine.ForgetKeyExchange(server);

                changes.Add($"{server.Trimmed} makes its key exchange again after {NTSServerConfiguration.RefreshText(after)}");

            }

            return changes;

        }

        #endregion

    }

}
