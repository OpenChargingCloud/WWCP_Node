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
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Which certificates of its name servers a node believes, where it
    /// reaches them over TLS or HTTPS: judged as every server's certificate is
    /// - see <see cref="JudgeServer"/> - by the TLS roots for "dns" and by what
    /// each server is held to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Asked by the node's DNS client at every handshake with an encrypted name
    /// server, and by the client a test of one server makes for itself. A
    /// connection is kept open between queries, so a change to what a server
    /// is held to closes the one it has, and the pin counts from the next.
    /// </para>
    /// <para>
    /// A name server does not bear on the time a node keeps, so what is news
    /// about one goes into the log tagged "security" and into the metrological
    /// log only where its entry says "record".
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What each configured name server is held to, where it is held to
        /// anything.
        /// </summary>
        private IReadOnlyDictionary<DNSServerConfig, ServerPins> dnsPins = new Dictionary<DNSServerConfig, ServerPins>();

        #endregion


        #region (static) NameOf(Server)

        /// <summary>
        /// A name server as the log and the memory of known servers name it:
        /// "tls://1.1.1.1:853" - its transport, its address and its port, and
        /// not its timeout, which says how long to wait for a server rather
        /// than which one.
        /// </summary>
        /// <remarks>
        /// An IPv6 address comes spelled out, as Hermod's ToString() has always
        /// written it, although the page shows the short form: what a node
        /// knows of a server is kept under this name, and a name written anew
        /// would find nothing it knew of an IPv6 name server.
        /// </remarks>
        public static String NameOf(DNSServerConfig Server)

            => $"{Server.Transport.ToString().ToLowerInvariant()}://{Server.IPAddress?.ToString() ?? Server.DomainName?.Trimmed}:{Server.Port}";

        #endregion

        #region PinsOf(Server)

        /// <summary>
        /// What the given name server is held to, or null for nothing.
        /// </summary>
        public ServerPins? PinsOf(DNSServerConfig Server)

            => dnsPins.GetValueOrDefault(Server);

        #endregion

        #region LastJudgementOf(Server)

        /// <summary>
        /// What this node made of the certificate the given name server showed
        /// at its last handshake, or null before it had one.
        /// </summary>
        public ServerJudgement? LastJudgementOf(DNSServerConfig Server)

            => LastJudgementOf(CertificateUsages.DNS, NameOf(Server));

        #endregion

        #region JudgeNameServer(Server, Certificate, Chain, PolicyErrors)

        /// <summary>
        /// Whether to go ahead with a connection to a name server that showed
        /// this certificate - see <see cref="JudgeServer"/>.
        /// </summary>
        /// <param name="Server">The name server.</param>
        /// <param name="Certificate">The certificate it showed.</param>
        /// <param name="Chain">The chain the machine built for it, with the certificates the server sent beside it.</param>
        /// <param name="PolicyErrors">What building that chain, and comparing the name, found.</param>
        public ServerJudgement JudgeNameServer(DNSServerConfig    Server,
                                               X509Certificate2?  Certificate,
                                               X509Chain?         Chain,
                                               SslPolicyErrors    PolicyErrors)

            => JudgeServer(CertificateUsages.DNS,
                           NameOf(Server),
                           PinsOf(Server),
                           Certificate,
                           Chain,
                           PolicyErrors,
                           Evidence:  false,
                           Learn:     (what, fingerprint) => LearnNameServerPin(Server, what, fingerprint));

        #endregion


        #region (private) NameServerValidator(Server, Certificate, Chain, PolicyErrors)

        /// <summary>
        /// What the DNS client asks about a name server's certificate at a
        /// handshake - see <see cref="JudgeNameServer"/>.
        /// </summary>
        /// <remarks>
        /// What the server is held to is looked up when it is asked, and not
        /// when the client was made: what the configuration says at the
        /// handshake is what counts.
        /// </remarks>
        private TLSValidationResult NameServerValidator(DNSServerConfig    Server,
                                                        X509Certificate2?  Certificate,
                                                        X509Chain?         Chain,
                                                        SslPolicyErrors    PolicyErrors)
        {

            var judgement = JudgeNameServer(Server, Certificate, Chain, PolicyErrors);

            return judgement.Accepted
                       ? TLSValidationResult.Success()
                       : TLSValidationResult.Failed(judgement.Steps.LastOrDefault(step => step.Level == "error").Text
                                                        ?? $"The certificate of the name server {NameOf(Server)} was refused.");

        }

        #endregion

        #region (private) TryPinsAfterAPageSaved(Update, AsShown, out Saved, out Error)

        /// <summary>
        /// The name servers a page sends, each held to what it is held to now
        /// with what was changed on the page - where the page says what it
        /// showed, and this node has that server; see
        /// <see cref="ServerPins.TryAfterAPageSaved"/>.
        /// </summary>
        /// <remarks>
        /// Asked under the reconfiguration lock, which is the one trust on first
        /// use writes under. The same server is the same transport to the same
        /// address and port: one switched to another transport on the page is
        /// another server, held to what the page sends.
        /// </remarks>
        /// <param name="Update">The section as the page sent it.</param>
        /// <param name="AsShown">What the page showed each server held to, by its place in the list.</param>
        private Boolean TryPinsAfterAPageSaved(DNSConfiguration                           Update,
                                               IReadOnlyDictionary<Int32, ServerPins?>    AsShown,
                                               out DNSConfiguration                       Saved,
                                               [NotNullWhen(false)] out String?           Error)
        {

            Saved  = Update;
            Error  = null;

            if (Update.Servers is null || AsShown.Count == 0)
                return true;

            var pins = new Dictionary<DNSServerConfig, ServerPins>(Update.Pins ?? new Dictionary<DNSServerConfig, ServerPins>());

            for (var index = 0; index < Update.Servers.Count; index++)
            {

                var server = Update.Servers[index];

                if (!AsShown.TryGetValue(index, out var shown) ||
                    !configuredDNSServers.Contains(server))
                {
                    continue;
                }

                if (!ServerPins.TryAfterAPageSaved(PinsOf(server), shown, Update.Pins?.GetValueOrDefault(server), $"{DNSConfiguration.SectionName}.servers[{index}]", out var held, out Error))
                    return false;

                if (held is null)
                    pins.Remove(server);
                else
                    pins[server] = held;

            }

            Saved = Update with { Pins = pins };

            return true;

        }

        #endregion

        #region (private) LearnNameServerPin(Server, What, Fingerprint)

        /// <summary>
        /// Hold a name server to the fingerprint it was first believed with,
        /// from now on: written into its entry of the configuration file, as a
        /// pin somebody typed would be.
        /// </summary>
        /// <remarks>
        /// Asked from inside the handshake that believed it, so the connection
        /// is kept, as it is not when somebody changes a pin: it is the one that
        /// showed what the server is held to now. Waits a moment for a
        /// reconfiguration somebody else is in the middle of, and leaves the
        /// lesson to the next handshake where that takes longer.
        /// </remarks>
        /// <returns>Whether the server is held to it now.</returns>
        private Boolean LearnNameServerPin(DNSServerConfig  Server,
                                           TrustOnFirstUse  What,
                                           String           Fingerprint)
        {

            if (!reconfigureLock.Wait(LearningWait))
                return false;

            try
            {

                var pins = dnsPins.GetValueOrDefault(Server) ?? ServerPins.None;

                // Learned already - by another handshake, or by somebody's hand
                // in between: there is nothing to learn.
                if ((What == TrustOnFirstUse.Root ? pins.Roots : pins.Certificates).Count > 0)
                    return true;

                if (!configuredDNSServers.Contains(Server))
                    return false;

                var learned  = new Dictionary<DNSServerConfig, ServerPins>(dnsPins) {
                                   [Server] = pins.Learning(What, Fingerprint)
                               };

                var update   = new DNSConfiguration(Servers: configuredDNSServers, Pins: learned);

                if (!ConfigFile.TryMergeSection(DNSConfiguration.SectionName, update.ToJSON(), out var error))
                {
                    Log.Error($"DNS: what {NameOf(Server)} is held to from now on could not be written into '{ConfigFile.Path}': {error}",
                              CertificateUsages.DNS, "certificates", "security");
                    return false;
                }

                dnsPins = learned;

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
