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

using System.Collections.Concurrent;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a configuration of name resolution would resolve, asked without
    /// putting it into effect - see <see cref="WWCPNode.ResolveWithAsync"/>.
    /// </summary>
    /// <param name="Resolved">Every name asked, and whether it resolved to an address.</param>
    /// <param name="Judgements">What was made of the certificates of the name servers asked over TLS or HTTPS, in the order they were asked.</param>
    /// <param name="Error">Why the configuration could not be asked at all: the one sentence a save of it would have been refused with.</param>
    public sealed record DNSPreflight(IReadOnlyDictionary<String, Boolean>  Resolved,
                                      IReadOnlyList<ServerJudgement>        Judgements,
                                      String?                               Error   = null)
    {

        /// <summary>
        /// Whether the given name resolved.
        /// </summary>
        /// <param name="Name">A name that was asked, in any case.</param>
        public Boolean Resolves(String Name)

            => Resolved.Any(name => String.Equals(name.Key, Name, StringComparison.OrdinalIgnoreCase) && name.Value);

    }


    /// <summary>
    /// A dry run of a configuration of name resolution: whether names would
    /// resolve with it, before anybody puts it into effect.
    /// </summary>
    /// <remarks>
    /// For a change that could cut a node off from what it must reach - its
    /// back end, say - when nothing would show it before the next connection,
    /// days later.
    /// </remarks>
    public partial class WWCPNode
    {

        #region ResolveWithAsync(Section, Names, Within, CancellationToken = default, WithoutRoots = null)

        /// <summary>
        /// Resolve the given names as this node would with the given "dns"
        /// section saved, without saving it or putting any of it into effect.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The section is read as <see cref="TryUpdateDNSConfiguration(JObject, out String?)"/>
        /// reads it: what it does not mention is as it is now, so an empty one
        /// asks the configuration in effect. A client of its own asks, without a
        /// cache, because an answer remembered from before says nothing about
        /// the servers that would be asked.
        /// </para>
        /// <para>
        /// A certificate is judged as at every handshake, against what the
        /// section holds its server to - but nothing about it is news: no line
        /// in the log, no pin learned on first use, nothing kept as the
        /// server's last judgement or as what it was believed with. A
        /// configuration that is not in effect has nothing to report.
        /// </para>
        /// </remarks>
        /// <param name="Section">A change of the "dns" section, in the shape of the configuration file.</param>
        /// <param name="Names">The names to resolve.</param>
        /// <param name="Within">How long all of them may take together.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        /// <param name="WithoutRoots">The fingerprints of roots of this node's store to resolve without, as if they were deleted: whether the names would still resolve after a deletion of them.</param>
        public async Task<DNSPreflight> ResolveWithAsync(JObject                       Section,
                                                         IEnumerable<String>           Names,
                                                         TimeSpan                      Within,
                                                         CancellationToken             CancellationToken   = default,
                                                         IReadOnlyCollection<String>?  WithoutRoots        = null)
        {

            var names = Names.Select   (name => name.Trim().TrimEnd('.')).
                              Where    (name => name.Length > 0).
                              Distinct (StringComparer.OrdinalIgnoreCase).
                              ToArray  ();

            if (!DNSConfiguration.TryParse(Section, out var candidate, out var error))
                return new DNSPreflight(new Dictionary<String, Boolean>(), [], error);

            var enabled  = candidate.Enabled ?? DNSEnabled;
            var servers  = candidate.Servers ?? configuredDNSServers;
            var pins     = candidate.Servers is not null
                               ? candidate.Pins ?? new Dictionary<DNSServerConfig, ServerPins>()
                               : dnsPins;

            if (!enabled || servers.Count == 0)
                return new DNSPreflight(names.ToDictionary(name => name, _ => false, StringComparer.OrdinalIgnoreCase), []);

            var judged   = new ConcurrentQueue<ServerJudgement>();

            using var client = new DNSClient(servers,
                                             QueryTimeout:   candidate.QueryTimeout ?? dnsClient.QueryTimeout,
                                             UseQueryCache:  false) {

                                   RecursionDesired            = candidate.RemovesRecursionDesired
                                                                     ? null
                                                                     : candidate.RecursionDesired ?? dnsClient.RecursionDesired,
                                   DnssecOK                    = candidate.DnssecOK        ?? dnsClient.DnssecOK,
                                   FollowCNAMEs                = candidate.FollowCNAMEs    ?? dnsClient.FollowCNAMEs,
                                   MaxCNAMEFollows             = candidate.MaxCNAMEFollows ?? dnsClient.MaxCNAMEFollows,
                                   MaxRetries                  = candidate.MaxRetries      ?? dnsClient.MaxRetries,

                                   RemoteCertificateValidator  = (server, certificate, chain, policyErrors) => {

                                       var judgement = JudgeServer(CertificateUsages.DNS,
                                                                   NameOf(server),
                                                                   pins.GetValueOrDefault(server),
                                                                   certificate,
                                                                   chain,
                                                                   policyErrors,
                                                                   Evidence:      false,
                                                                   Learn:         null,
                                                                   Remember:      false,
                                                                   WithoutRoots:  WithoutRoots);

                                       judged.Enqueue(judgement);

                                       return judgement.Accepted
                                                  ? TLSValidationResult.Success()
                                                  : TLSValidationResult.Failed(judgement.Steps.LastOrDefault(step => step.Level == "error").Text
                                                                                   ?? $"The certificate of the name server {NameOf(server)} was refused.");

                                   }

                               };

            using var within = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            within.CancelAfter(Within);

            async Task<(String Name, Boolean Resolved)> Resolve(String Name)
            {

                if (!DNSServiceName.TryParse(Name, out var serviceName, out _))
                    return (Name, false);

                try
                {

                    var answer = await client.Query(serviceName,
                                                    [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                                    ForceUpdate:        true,
                                                    CancellationToken:  within.Token).ConfigureAwait(false);

                    return (Name, answer.ResponseCode == DNSResponseCodes.NoError &&
                                  answer.Answers.Any(record => record.Type is DNSResourceRecordTypes.A or DNSResourceRecordTypes.AAAA));

                }
                catch
                {
                    // Not answered in time, or not at all: either way it did
                    // not resolve, and the judgements say why where a
                    // certificate was the reason.
                    return (Name, false);
                }

            }

            var resolved = await Task.WhenAll(names.Select(Resolve)).ConfigureAwait(false);

            return new DNSPreflight(resolved.ToDictionary(name => name.Name, name => name.Resolved, StringComparer.OrdinalIgnoreCase),
                                    [.. judged]);

        }

        #endregion

    }

}
