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
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Which AEAD algorithms the key exchange with each time server offers:
    /// the one its entry names, or every one the time library offers, the
    /// server choosing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By the server's name across every group, as what it is held to is: a
    /// server is one server, whichever group asks it, and its key exchange is
    /// kept by its name and reused by every group that asks it. The first
    /// entry that names an algorithm decides, so a group that lists the same
    /// server without a word about it - its own list of the PTB's servers, say
    /// - does not undo what another group said.
    /// </para>
    /// <para>
    /// A server whose algorithm changes lets go of its key exchange: its
    /// cookies and keys are of the algorithm agreed on before, and the next
    /// round makes a new one.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) AEADs()

        /// <summary>
        /// The one AEAD algorithm each time server is offered, for the servers
        /// an entry names one for: the first such entry across every group.
        /// </summary>
        private Dictionary<DomainName, AEADAlgorithms> AEADs()
        {

            var aeads = new Dictionary<DomainName, AEADAlgorithms>();

            foreach (var server in ntsGroups.SelectMany(group => group.Settings?.Servers ?? []))
                if (server.AEAD is { } aead)
                    aeads.TryAdd(server.Hostname, aead);

            return aeads;

        }

        #endregion

        #region (private) AEADOffer(Hostname)

        /// <summary>
        /// What the key exchange with the given time server offers: the one
        /// algorithm an entry names for it, or null for every one the time
        /// library offers.
        /// </summary>
        private AEADAlgorithms[]? AEADOffer(DomainName Hostname)

            => AEADs().TryGetValue(Hostname, out var aead)
                   ? [ aead ]
                   : null;

        #endregion

        #region (private static) Offers(Client, Offer)

        /// <summary>
        /// Whether a client offers what it should: the one algorithm given, or
        /// where none is given, every one the time library offers.
        /// </summary>
        private static Boolean Offers(NTSClient           Client,
                                      AEADAlgorithms[]?  Offer)

            => Client.OfferedAEADAlgorithms.SequenceEqual(Offer ?? NTSServerConfiguration.AEADAlgorithmsOffered.Where(NTSAEAD.IsSupported));

        #endregion

        #region (private) OfferAEAD()

        /// <summary>
        /// Put what each time server is to be offered on every group's servers,
        /// and on the client each group's detailed test starts from.
        /// </summary>
        /// <remarks>
        /// Every group and not only the one that changed, because the change of
        /// one group can change what a server of another is offered. A client
        /// cannot be told to offer something else, so one that offers the wrong
        /// thing is made anew, with what it had besides; its cookies go with it.
        /// </remarks>
        private void OfferAEAD()
        {

            var aeads = AEADs();

            foreach (var group in ntsGroups)
            {

                foreach (var source in group.Sources.Sources)
                    source.OfferedAEADAlgorithms = aeads.TryGetValue(source.Hostname, out var aead)
                                                       ? [ aead ]
                                                       : null;

                if (group.Client is NTSClient client)
                {

                    var offer = aeads.TryGetValue(client.Hostname, out var clientAEAD)
                                    ? new[] { clientAEAD }
                                    : null;

                    if (!Offers(client, offer))
                        group.Client = new NTSClient(
                                           client.Hostname,
                                           NTSKE_Port:                  client.NTSKE_Port,
                                           NTP_Port:                    client.NTP_Port,
                                           RemoteCertificateValidator:  TimeServerValidator(client.Hostname),
                                           IPVersionPreference:         client.IPVersionPreference,
                                           Timeout:                     client.Timeout,
                                           DNSClient:                   dnsClient,
                                           CookiePoolPolicy:            client.CookiePoolPolicy,
                                           OfferedAEADAlgorithms:       offer,
                                           TimeProvider:                TimeProvider
                                       );

                }

            }

        }

        #endregion

        #region (private) AEADChanges(Was)

        /// <summary>
        /// What changed about what the time servers are offered since the given
        /// state, as the log line says it - and each server whose offer changed
        /// lets go of its key exchange.
        /// </summary>
        /// <param name="Was">What each server was offered before, by <see cref="AEADs"/>.</param>
        private IEnumerable<String> AEADChanges(Dictionary<DomainName, AEADAlgorithms> Was)
        {

            var now     = AEADs();
            var changes = new List<String>();

            foreach (var server in Was.Keys.Union(now.Keys).ToArray())
            {

                AEADAlgorithms? before = Was.TryGetValue(server, out var wasAEAD) ? wasAEAD : null;
                AEADAlgorithms? after  = now.TryGetValue(server, out var nowAEAD) ? nowAEAD : null;

                if (before == after)
                    continue;

                timeEngine.ForgetKeyExchange(server);

                changes.Add(after is { } aead
                                ? $"{server.Trimmed} offered {NTSServerConfiguration.AEADNameOf(aead)} alone"
                                : $"{server.Trimmed} offered {String.Join(" and ", NTSServerConfiguration.AEADAlgorithmsOffered.Select(NTSServerConfiguration.AEADNameOf))}");

            }

            return changes;

        }

        #endregion

    }

}
