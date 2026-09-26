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

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Which certificates of its time servers a node believes: the usual, a
    /// root of its own where the machine knows none, and the fingerprints a
    /// server is held to - judged as every server's certificate is, see
    /// <see cref="JudgeServer"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A time server's certificate is only seen at a key exchange, and that is
    /// where this is asked - for every server of the group, and for the one the
    /// detailed test asks. A key exchange is reused for as long as its cookies
    /// last, up to half an hour, so what this refuses is refused from the next
    /// key exchange on; a change to what a server is held to forgets the key
    /// exchange it has, so that its next round makes a new one.
    /// </para>
    /// <para>
    /// A time server bears on the time this node keeps, so what is news about
    /// one is written into the metrological log whatever its pins say - a
    /// mismatch, a server held to what it was first believed with, a server
    /// believed with another certificate than before.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region LastJudgementOf(Hostname)

        /// <summary>
        /// What this node made of the certificate the given time server showed
        /// at its last key exchange, or null before it had one.
        /// </summary>
        public ServerJudgement? LastJudgementOf(DomainName Hostname)

            => LastJudgementOf(CertificateUsages.NTS, Hostname.Trimmed);

        #endregion

        #region JudgeTimeServer(Hostname, Certificate, Chain, PolicyErrors)

        /// <summary>
        /// Whether to go ahead with a key exchange with a time server that showed
        /// this certificate - see <see cref="JudgeServer"/>.
        /// </summary>
        /// <param name="Hostname">The time server.</param>
        /// <param name="Certificate">The certificate it showed.</param>
        /// <param name="Chain">The chain the machine built for it, with the certificates the server sent beside it.</param>
        /// <param name="PolicyErrors">What building that chain, and comparing the name, found.</param>
        public ServerJudgement JudgeTimeServer(DomainName         Hostname,
                                               X509Certificate2?  Certificate,
                                               X509Chain?         Chain,
                                               SslPolicyErrors    PolicyErrors)

            => JudgeServer(CertificateUsages.NTS,
                           Hostname.Trimmed,
                           PinsOf(Hostname)?.Pins,
                           Certificate,
                           Chain,
                           PolicyErrors,
                           Evidence:  true,
                           Learn:     (what, fingerprint) => LearnTimeServerPin(Hostname, what, fingerprint));

        #endregion


        #region (private) TimeServerValidator(Hostname)

        /// <summary>
        /// What a key exchange with the given time server asks about its
        /// certificate - see <see cref="JudgeTimeServer"/>.
        /// </summary>
        /// <remarks>
        /// The server's pins are looked up when it is asked, and not when this
        /// is made: what the configuration says at the handshake is what counts.
        /// </remarks>
        private RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient> TimeServerValidator(DomainName Hostname)

            => (sender, certificate, chain, client, policyErrors) => {

                   var judgement = JudgeTimeServer(Hostname, certificate, chain, policyErrors);

                   return judgement.Accepted
                              ? TLSValidationResult.Success()
                              : TLSValidationResult.Failed(judgement.Steps.LastOrDefault(step => step.Level == "error").Text
                                                               ?? $"The certificate of {Hostname.Trimmed} was refused.");

               };

        #endregion

        #region (private) AttachValidators(Group)

        /// <summary>
        /// Make every server of a group ask this node about its certificate at
        /// its key exchanges.
        /// </summary>
        /// <remarks>
        /// Every server and not only the pinned ones: a TLS root of this node's
        /// store for the time servers is a root for every one of them, every
        /// server is remembered with the certificate it was believed with, and a
        /// server whose certificate is refused should say why somewhere. Where a
        /// server was given a validator of its own by whoever made the group,
        /// that one stays.
        /// </remarks>
        private void AttachValidators(TimeSourceGroup Group)
        {

            foreach (var source in Group.Sources)
                source.RemoteCertificateValidator ??= TimeServerValidator(source.Hostname);

        }

        #endregion

        #region (private) PinsOf(Hostname) / Pins()

        /// <summary>
        /// The configuration of the given time server, where the configuration
        /// names it in its list.
        /// </summary>
        private NTSServerConfiguration? PinsOf(DomainName Hostname)

            => ntsSettings?.Servers?.FirstOrDefault(server => server.Hostname.Equals(Hostname));

        /// <summary>
        /// What each server of the configuration is held to, or learns, by its
        /// name.
        /// </summary>
        private Dictionary<DomainName, ServerPins> Pins()
        {

            var pins = new Dictionary<DomainName, ServerPins>();

            foreach (var server in ntsSettings?.Servers ?? [])
                if (server.Pins is { SaysAnything: true } held)
                    pins.TryAdd(server.Hostname, held);

            return pins;

        }

        #endregion

        #region (private) LearnTimeServerPin(Hostname, What, Fingerprint)

        /// <summary>
        /// Hold a time server to the fingerprint it was first believed with,
        /// from now on: written into its entry of the configuration file, as a
        /// pin somebody typed would be.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Asked from inside the key exchange that believed it, so the key
        /// exchange is not forgotten, as it is when somebody changes a pin: it
        /// is the one that showed what the server is held to now.
        /// </para>
        /// <para>
        /// Waits a moment for a reconfiguration somebody else is in the middle
        /// of, and leaves the lesson to the next key exchange where that takes
        /// longer - a key exchange held up by a page's save would be a time
        /// server that timed out.
        /// </para>
        /// </remarks>
        /// <returns>Whether the server is held to it now.</returns>
        private Boolean LearnTimeServerPin(DomainName       Hostname,
                                           TrustOnFirstUse  What,
                                           String           Fingerprint)
        {

            if (!reconfigureLock.Wait(LearningWait))
                return false;

            try
            {

                var servers  = ntsSettings?.Servers?.ToList();
                var index    = servers?.FindIndex(server => server.Hostname.Equals(Hostname)) ?? -1;

                if (servers is null || index < 0)
                    return false;

                var pins     = servers[index].Pins ?? ServerPins.None;

                // Learned already - by another key exchange, or by somebody's
                // hand in between: there is nothing to learn, and the pin that is
                // there is the one that counts.
                if ((What == TrustOnFirstUse.Root ? pins.Roots : pins.Certificates).Count > 0)
                    return true;

                servers[index] = servers[index] with { Pins = pins.Learning(What, Fingerprint) };

                var update   = new NTSConfiguration(Servers: servers);

                if (!ConfigFile.TryMergeSection(NTSConfiguration.SectionName, update.ToJSON(), update.RemovedKeys, out var error))
                {
                    Log.Error($"NTS: what {Hostname.Trimmed} is held to from now on could not be written into '{ConfigFile.Path}': {error}",
                              CertificateUsages.NTS, "certificates", "security");
                    return false;
                }

                ntsSettings = ntsSettings!.OverriddenBy(update);

                return true;

            }
            finally
            {
                reconfigureLock.Release();
            }

        }

        #endregion

    }

}
