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
    /// Which versions of NTP each time server is asked in: the Versions of the
    /// Secure Time Synchronization white paper (section 3.2.4), NTPv4 alone
    /// unless an entry says otherwise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By the server's name across every group, as its AEAD algorithm is: a
    /// server is one server, whichever group asks it, and its key exchange is
    /// kept by its name and reused by every group that asks it. The first entry
    /// that names versions decides, so a group that lists the same server
    /// without a word about it does not undo what another group said.
    /// </para>
    /// <para>
    /// A server whose versions change gets a new key exchange at its next
    /// measurement, offering the new ones: the time library does not reuse one
    /// that offered other next protocols.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) NTPVersionsOfServers()

        /// <summary>
        /// The versions each time server is asked in, for the servers an entry
        /// names versions for: the first such entry across every group.
        /// </summary>
        private Dictionary<DomainName, IReadOnlyList<Byte>> NTPVersionsOfServers()
        {

            var versions = new Dictionary<DomainName, IReadOnlyList<Byte>>();

            foreach (var server in ntsGroups.SelectMany(group => group.Settings?.Servers ?? []))
                if (server.Versions is { } named)
                    versions.TryAdd(server.Hostname, named);

            return versions;

        }

        #endregion

        #region (private) PutNTPVersions()

        /// <summary>
        /// Put the versions each time server is asked in on every group's servers.
        /// </summary>
        private void PutNTPVersions()
        {

            var versions = NTPVersionsOfServers();

            foreach (var source in ntsGroups.SelectMany(group => group.Sources.Sources))
                source.NTPVersions = versions.TryGetValue(source.Hostname, out var named)
                                         ? named
                                         : NTSServerConfiguration.DefaultVersions;

        }

        #endregion

        #region (private) NTPVersionChanges(Was)

        /// <summary>
        /// What changed about the versions the time servers are asked in since the
        /// given state, as the log line says it.
        /// </summary>
        private IEnumerable<String> NTPVersionChanges(Dictionary<DomainName, IReadOnlyList<Byte>> Was)
        {

            var now      = NTPVersionsOfServers();
            var changes  = new List<String>();

            foreach (var server in Was.Keys.Union(now.Keys).ToArray())
            {

                var before  = Was.TryGetValue(server, out var was)    ? was    : NTSServerConfiguration.DefaultVersions;
                var after   = now.TryGetValue(server, out var isNow)  ? isNow  : NTSServerConfiguration.DefaultVersions;

                if (before.SequenceEqual(after))
                    continue;

                changes.Add($"{server.Trimmed} asked in {NTSServerConfiguration.VersionsText(after)}");

            }

            return changes;

        }

        #endregion

    }

}
