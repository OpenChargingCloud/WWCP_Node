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
    /// How the offsets measured with each time server are corrected for what
    /// is known about the path to it: the DelayAsymmetry and DelayVarAsymmetry
    /// of the Secure Time Synchronization white paper, chrony's "offset" and
    /// "asymmetry".
    /// </summary>
    /// <remarks>
    /// By the server's name across every group, as its AEAD algorithm and its
    /// refresh are: the path to a server is the same whichever group asks it.
    /// The first entry that sets either decides both. A change takes effect
    /// with the next measurement; nothing measured before is corrected anew.
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) Corrections()

        /// <summary>
        /// How the offsets measured with each time server are corrected, for the
        /// servers an entry corrects them for: the first such entry across every
        /// group.
        /// </summary>
        private Dictionary<DomainName, (TimeSpan? DelayAsymmetry, Double? DelayVarAsymmetry)> Corrections()
        {

            var corrections = new Dictionary<DomainName, (TimeSpan?, Double?)>();

            foreach (var server in ntsGroups.SelectMany(group => group.Settings?.Servers ?? []))
                if (NTSServerConfiguration.SetsCorrection(server))
                    corrections.TryAdd(server.Hostname, (server.DelayAsymmetry, server.DelayVarAsymmetry));

            return corrections;

        }

        #endregion

        #region (private) PutCorrections()

        /// <summary>
        /// Put how each time server's offsets are corrected on every group's
        /// servers.
        /// </summary>
        private void PutCorrections()
        {

            var corrections = Corrections();

            foreach (var source in ntsGroups.SelectMany(group => group.Sources.Sources))
            {

                var (delayAsymmetry, delayVarAsymmetry) = corrections.TryGetValue(source.Hostname, out var correction)
                                                              ? correction
                                                              : (null, null);

                source.DelayAsymmetry     = delayAsymmetry;
                source.DelayVarAsymmetry  = delayVarAsymmetry;

            }

        }

        #endregion

        #region (private) CorrectionChanges(Was)

        /// <summary>
        /// What changed about how the time servers' offsets are corrected since
        /// the given state, as the log line says it.
        /// </summary>
        /// <param name="Was">How each server's offsets were corrected before, by <see cref="Corrections"/>.</param>
        private IEnumerable<String> CorrectionChanges(Dictionary<DomainName, (TimeSpan? DelayAsymmetry, Double? DelayVarAsymmetry)> Was)
        {

            var now      = Corrections();
            var changes  = new List<String>();

            foreach (var server in Was.Keys.Union(now.Keys).ToArray())
            {

                var before = Was.TryGetValue(server, out var wasCorrection) ? wasCorrection : (null, null);
                var after  = now.TryGetValue(server, out var nowCorrection) ? nowCorrection : (null, null);

                if (before == after)
                    continue;

                changes.Add($"{server.Trimmed}'s offsets corrected {NTSServerConfiguration.CorrectionText(after.DelayAsymmetry, after.DelayVarAsymmetry)}");

            }

            return changes;

        }

        #endregion

    }

}
