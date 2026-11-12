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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Which time servers are asked for a digitally signed response after every
    /// measurement, and what becomes of it: the SignedResponses of the Secure
    /// Time Synchronization white paper.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every signed response goes into the metrological log, with whether its
    /// signature is the server's and the response itself, signature included -
    /// Achim's decision of 2026-11-07, whatever the correction: the proof that
    /// the server said what it said, which an attacker holding the symmetric
    /// keys of NTS could otherwise have said for it. A signature that is not the
    /// server's is a security event of its own.
    /// </para>
    /// <para>
    /// By the server's name across every group: a server is asked for one where
    /// any entry for it asks. A server whose asking changes lets go of its key
    /// exchange, which has to fetch the public keys a signature is checked
    /// against.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) SignedResponseServers()

        /// <summary>
        /// The time servers asked for signed responses: those an entry of any
        /// group asks for one.
        /// </summary>
        private HashSet<DomainName> SignedResponseServers()

            => [ .. ntsGroups.SelectMany(group => group.Settings?.Servers ?? []).
                              Where     (server => server.SignedResponses).
                              Select    (server => server.Hostname) ];

        #endregion

        #region (private) PutSignedResponses()

        /// <summary>
        /// Put whether each time server is asked for signed responses on every
        /// group's servers.
        /// </summary>
        private void PutSignedResponses()
        {

            var asked = SignedResponseServers();

            foreach (var source in ntsGroups.SelectMany(group => group.Sources.Sources))
                source.SignedResponses = asked.Contains(source.Hostname);

        }

        #endregion

        #region (private) SignedResponseChanges(Was)

        /// <summary>
        /// What changed about which time servers are asked for signed responses
        /// since the given state, as the log line says it - and each server whose
        /// asking changed lets go of its key exchange.
        /// </summary>
        private IEnumerable<String> SignedResponseChanges(HashSet<DomainName> Was)
        {

            var now      = SignedResponseServers();
            var changes  = new List<String>();

            foreach (var server in Was.Union(now).ToArray())
            {

                if (Was.Contains(server) == now.Contains(server))
                    continue;

                timeEngine.ForgetKeyExchange(server);

                changes.Add(now.Contains(server)
                                ? $"{server.Trimmed} asked for signed responses"
                                : $"{server.Trimmed} no longer asked for signed responses");

            }

            return changes;

        }

        #endregion

        #region (private) WriteDownSignedResponses(Results)

        /// <summary>
        /// Write every signed response of a round into the metrological log.
        /// </summary>
        private void WriteDownSignedResponses(IEnumerable<NTSMeasurementResult> Results)
        {

            foreach (var result in Results)
            {

                if (result.SignedResponse is not SignedResponseResult signed)
                    continue;

                var server = result.ServerHostname.Trimmed;

                var data   = new JObject(
                                 new JProperty("server",    server),
                                 new JProperty("keyId",     signed.KeyId),
                                 new JProperty("verified",  signed.Verified),
                                 new JProperty("response",  signed.Packet is Byte[] packet ? Convert.ToBase64String(packet) : null),
                                 new JProperty("error",     signed.ErrorMessage)
                             );

                if (!signed.Success)
                    Log.Metrological(LogLevel.Warning,
                                     $"NTS: {server} sent no signed response: {signed.ErrorMessage}.",
                                     data, "nts", "signed");

                else if (signed.Verified == true)
                    Log.Metrological(LogLevel.Info,
                                     $"NTS: {server} signed its response with its key {signed.KeyId}.",
                                     data, "nts", "signed");

                else if (signed.Verified == false)
                    Log.Metrological(LogLevel.Critical,
                                     $"NTS: the signature of {server}'s response is not that of its key {signed.KeyId}.",
                                     data, "nts", "signed", "security");

                // Signed, and not with a key the signature could be held to: one the key
                // exchange did not name, or another than the one that was asked for. The
                // time library says which, and both leave the signature unchecked.
                else
                    Log.Metrological(LogLevel.Warning,
                                     $"NTS: the signature of {server}'s response with its key {signed.KeyId} is unchecked: {signed.ErrorMessage ?? "its key exchange did not name that key"}.",
                                     data, "nts", "signed");

            }

        }

        #endregion

    }

}
