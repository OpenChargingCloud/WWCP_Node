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
using System.Diagnostics.CodeAnalysis;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a node made of the certificate a time server showed at a key
    /// exchange.
    /// </summary>
    /// <param name="Hostname">The time server.</param>
    /// <param name="At">When.</param>
    /// <param name="Accepted">Whether the key exchange went ahead.</param>
    /// <param name="Outcome">In one word: "accepted"; "recorded", where a fingerprint did not match and the server is used all the same; "pinMismatch", where it did not and the server was refused for it; "untrusted", "wrongName" or "noCertificate", where it was refused before any fingerprint was asked.</param>
    /// <param name="CertificateFingerprint">The SHA-256 fingerprint of the certificate it showed, or null when it showed none.</param>
    /// <param name="RootFingerprint">The SHA-256 fingerprint of the root its chain ends at, or null when it ends at none this node trusts.</param>
    /// <param name="AnchoredBy">The label of the root of this node's own store the chain ends at, where the machine did not know that root; null otherwise.</param>
    /// <param name="HeldToCertificate">The fingerprint its own certificate is held to, or null.</param>
    /// <param name="HeldToRoot">The fingerprint its root is held to, or null.</param>
    /// <param name="Steps">What the judgement went through, as a detailed test shows it.</param>
    public sealed record TimeServerJudgement(DomainName                                   Hostname,
                                             DateTimeOffset                               At,
                                             Boolean                                      Accepted,
                                             String                                       Outcome,
                                             String?                                      CertificateFingerprint,
                                             String?                                      RootFingerprint,
                                             String?                                      AnchoredBy,
                                             String?                                      HeldToCertificate,
                                             String?                                      HeldToRoot,
                                             IReadOnlyList<(String Level, String Text)>  Steps)
    {

        /// <summary>
        /// The judgement as the NTS page and the metrological log read it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("server",       Hostname.Trimmed),
                   new JProperty("at",           At.ToString("o")),
                   new JProperty("accepted",     Accepted),
                   new JProperty("outcome",      Outcome),
                   new JProperty("certificate",  CertificateFingerprint),
                   new JProperty("root",         RootFingerprint),
                   new JProperty("anchoredBy",   AnchoredBy),
                   new JProperty("heldTo",       HeldToCertificate is null && HeldToRoot is null
                                                     ? null
                                                     : new JObject(
                                                           new JProperty("certificate",  HeldToCertificate),
                                                           new JProperty("root",         HeldToRoot)
                                                       ))
               );

    }


    /// <summary>
    /// Which certificates of its time servers a node believes: the usual, a
    /// root of its own where the machine knows none, and a fingerprint where
    /// the configuration holds a server to one.
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
    /// A pin narrows what is believed and never widens it: a server held to a
    /// fingerprint still has to show a certificate issued for its name whose
    /// chain ends at a root this node trusts. A certificate that matches its
    /// pin and chains to nothing is refused - somebody who means to believe it
    /// imports it, or its root, as a TLS root, which says the same thing on
    /// purpose.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// The last judgement of every time server that has had a key exchange.
        /// </summary>
        private readonly ConcurrentDictionary<DomainName, TimeServerJudgement> judgements = new();

        #endregion


        #region LastJudgementOf(Hostname)

        /// <summary>
        /// What this node made of the certificate the given time server showed
        /// at its last key exchange, or null before it had one.
        /// </summary>
        public TimeServerJudgement? LastJudgementOf(DomainName Hostname)

            => judgements.GetValueOrDefault(Hostname);

        #endregion

        #region JudgeTimeServer(Hostname, Certificate, Chain, PolicyErrors)

        /// <summary>
        /// Whether to go ahead with a key exchange with a time server that showed
        /// this certificate: what a key exchange asks, and what can be asked
        /// without one.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Three questions, in this order, and a no to any of them ends it. Is
        /// the certificate issued for the server's name? Does its chain end at a
        /// root this machine trusts - or, where it does not, at a TLS root of
        /// this node's own store, or at the root this server is held to where
        /// the store has it? And is it the certificate, and the root, the
        /// server is held to, where its configuration holds it to one?
        /// </para>
        /// <para>
        /// What is news is written into the metrological log: a server refused,
        /// or used although a fingerprint did not match, the first time or
        /// differently from the last time - and a server believed again after
        /// that. The same verdict at every round is said once there, and at the
        /// rounds after it only in the ordinary log: a server refused for a
        /// fortnight would otherwise fill the log book with one line a quarter
        /// of an hour.
        /// </para>
        /// </remarks>
        /// <param name="Hostname">The time server.</param>
        /// <param name="Certificate">The certificate it showed.</param>
        /// <param name="Chain">The chain the machine built for it, with the certificates the server sent beside it.</param>
        /// <param name="PolicyErrors">What building that chain, and comparing the name, found.</param>
        public TimeServerJudgement JudgeTimeServer(DomainName         Hostname,
                                                   X509Certificate2?  Certificate,
                                                   X509Chain?         Chain,
                                                   SslPolicyErrors    PolicyErrors)
        {

            var name                    = Hostname.Trimmed;
            var pins                    = PinsOf(Hostname);
            var steps                   = new List<(String Level, String Text)>();

            String?  certificateFingerprint  = null;
            String?  rootFingerprint         = null;
            String?  anchoredBy              = null;
            String   outcome;
            Boolean  accepted;

            if (Certificate is null)
            {
                outcome   = "noCertificate";
                accepted  = false;
                steps.Add(("error", $"Refused: {name} showed no certificate."));
            }

            else
            {

                certificateFingerprint = CertificateEntry.ThumbprintOf(Certificate);

                // The name first, and never forgiven: a certificate issued for
                // another host is a certificate for another host, whatever it
                // chains to and whatever it is pinned as.
                if (PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                {
                    outcome   = "wrongName";
                    accepted  = false;
                    steps.Add(("error", $"Refused: the certificate is not issued for {name}."));
                }

                else
                {

                    // The chain as the machine built it, where it could; and
                    // where it could not, against this node's own roots.
                    if (!PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) &&
                        !PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable) &&
                        Chain is not null && Chain.ChainElements.Count > 0)
                    {
                        rootFingerprint = CertificateEntry.ThumbprintOf(Chain.ChainElements[Chain.ChainElements.Count - 1].Certificate);
                    }

                    else if (TryAnchor(Certificate, Chain, pins, out var anchoredRoot, out var label))
                    {
                        rootFingerprint  = anchoredRoot;
                        anchoredBy       = label;
                        steps.Add(("notice", $"Validated by this {Kind.Name}'s own root '{label}', which the machine does not know."));
                    }

                    if (rootFingerprint is null)
                    {
                        outcome   = "untrusted";
                        accepted  = false;
                        steps.Add(("error", $"Refused: its chain ends at no root this machine or this {Kind.Name} trusts."));
                    }

                    else if (pins is { IsPinned: true })
                    {

                        var certificateMatches  = pins.CertificateFingerprint is null || pins.CertificateFingerprint == certificateFingerprint;
                        var rootMatches         = pins.RootFingerprint        is null || pins.RootFingerprint        == rootFingerprint;
                        var mismatchLevel       = pins.OnMismatch == PinMismatch.Refuse ? "error" : "warning";

                        if (pins.CertificateFingerprint is not null)
                            steps.Add(certificateMatches
                                          ? ("notice",       $"Held to certificate {pins.CertificateFingerprint}: it is the one it showed.")
                                          : (mismatchLevel,  $"Held to certificate {pins.CertificateFingerprint}, and it showed {certificateFingerprint}."));

                        if (pins.RootFingerprint is not null)
                            steps.Add(rootMatches
                                          ? ("notice",       $"Held to root {pins.RootFingerprint}: its chain ends there.")
                                          : (mismatchLevel,  $"Held to root {pins.RootFingerprint}, and its chain ends at {rootFingerprint}."));

                        if (certificateMatches && rootMatches)
                        {
                            outcome   = "accepted";
                            accepted  = true;
                        }

                        else if (pins.OnMismatch == PinMismatch.Record)
                        {
                            outcome   = "recorded";
                            accepted  = true;
                            steps.Add(("warning", "Used all the same, as its configuration says, and written into the metrological log."));
                        }

                        else
                        {
                            outcome   = "pinMismatch";
                            accepted  = false;
                            steps.Add(("error", "Refused, as its configuration says, and written into the metrological log."));
                        }

                    }

                    else
                    {
                        outcome   = "accepted";
                        accepted  = true;
                    }

                }

            }

            var judgement = new TimeServerJudgement(
                                Hostname,
                                TimeProvider.GetUtcNow(),
                                accepted,
                                outcome,
                                certificateFingerprint,
                                rootFingerprint,
                                anchoredBy,
                                pins?.CertificateFingerprint,
                                pins?.RootFingerprint,
                                steps
                            );

            WriteDown(judgement, judgements.GetValueOrDefault(Hostname), pins);

            judgements[Hostname] = judgement;

            return judgement;

        }

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
                              : TLSValidationResult.Failed(judgement.Steps.Count > 0
                                                               ? judgement.Steps[^1].Text
                                                               : $"The certificate of {Hostname.Trimmed} was refused.");

               };

        #endregion

        #region (private) AttachValidators(Group)

        /// <summary>
        /// Make every server of a group ask this node about its certificate at
        /// its key exchanges.
        /// </summary>
        /// <remarks>
        /// Every server and not only the pinned ones: a TLS root of this node's
        /// store is a root for every server it connects to, and a server whose
        /// certificate is refused should say why somewhere. Where a server was
        /// given a validator of its own by whoever made the group, that one
        /// stays.
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
        /// What each pinned server of the configuration is held to, by its name.
        /// </summary>
        private Dictionary<DomainName, (String? Certificate, String? Root, PinMismatch OnMismatch)> Pins()
        {

            var pins = new Dictionary<DomainName, (String?, String?, PinMismatch)>();

            foreach (var server in ntsSettings?.Servers ?? [])
                if (server.IsPinned)
                    pins.TryAdd(server.Hostname, (server.CertificateFingerprint, server.RootFingerprint, server.OnMismatch));

            return pins;

        }

        #endregion

        #region (private) TryAnchor(Certificate, Chain, Pins, out RootFingerprint, out Label)

        /// <summary>
        /// Build the certificate's chain against this node's own roots: every
        /// TLS root of its store that is switched on and valid, and the root the
        /// server is held to, where the store has it as whatever kind of
        /// certificate.
        /// </summary>
        /// <remarks>
        /// Revocation is asked where there is somebody to ask, and what cannot be
        /// asked is not held against the certificate: a root of one's own is
        /// often a CA without a revocation list, and one that is on a list is
        /// still refused.
        /// </remarks>
        private Boolean TryAnchor(X509Certificate2                            Certificate,
                                  X509Chain?                                  Chain,
                                  NTSServerConfiguration?                     Pins,
                                  [NotNullWhen(true)] out String?             RootFingerprint,
                                  [NotNullWhen(true)] out String?             Label)
        {

            RootFingerprint  = null;
            Label            = null;

            var anchors      = new List<(X509Certificate2 Certificate, String Label)>();

            try
            {

                foreach (var entry in Certificates.UsableByKind(CertificateKind.TLSRoot))
                    if (Certificates.TryLoad(entry, out var root, out _))
                        anchors.Add((root, entry.Label));

                if (Pins?.RootFingerprint is String pinned                 &&
                    Certificates.ByFingerprint(pinned) is CertificateEntry held &&
                    held.IsUsable                                           &&
                    held.Kind != CertificateKind.TLSRoot                    &&
                    Certificates.TryLoad(held, out var heldRoot, out _))
                {
                    anchors.Add((heldRoot, held.Label));
                }

                if (anchors.Count == 0)
                    return false;

                using var chain = new X509Chain();

                chain.ChainPolicy.TrustMode          = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.RevocationMode     = X509RevocationMode.Online;
                chain.ChainPolicy.VerificationFlags  = X509VerificationFlags.IgnoreEndRevocationUnknown                 |
                                                       X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                                       X509VerificationFlags.IgnoreRootRevocationUnknown;

                foreach (var anchor in anchors)
                    chain.ChainPolicy.CustomTrustStore.Add(anchor.Certificate);

                // The certificates the server sent beside its own, which is what
                // the machine's chain was built with as well.
                if (Chain is not null)
                    chain.ChainPolicy.ExtraStore.AddRange(Chain.ChainPolicy.ExtraStore);

                var built = chain.Build(Certificate) ||
                            chain.ChainStatus.All(status => status.Status is X509ChainStatusFlags.NoError
                                                                          or X509ChainStatusFlags.RevocationStatusUnknown
                                                                          or X509ChainStatusFlags.OfflineRevocation);

                if (!built || chain.ChainElements.Count == 0)
                    return false;

                var end          = CertificateEntry.ThumbprintOf(chain.ChainElements[chain.ChainElements.Count - 1].Certificate);

                RootFingerprint  = end;
                Label            = anchors.FirstOrDefault(anchor => CertificateEntry.ThumbprintOf(anchor.Certificate) == end).Label ?? end;

                return true;

            }
            catch
            {
                // A chain that cannot even be built is a chain that does not
                // validate, which is the answer either way.
                return false;
            }
            finally
            {
                foreach (var anchor in anchors)
                    anchor.Certificate.Dispose();
            }

        }

        #endregion

        #region (private) WriteDown(Judgement, Previous, Pins)

        /// <summary>
        /// Say what a judgement found, where it is news in the metrological log
        /// and otherwise in the ordinary one - see <see cref="JudgeTimeServer"/>.
        /// </summary>
        private void WriteDown(TimeServerJudgement      Judgement,
                               TimeServerJudgement?     Previous,
                               NTSServerConfiguration?  Pins)
        {

            var name         = Judgement.Hostname.Trimmed;
            var certificate  = Judgement.CertificateFingerprint ?? "none";
            var root         = Judgement.RootFingerprint        ?? "no root this node trusts";

            if (Judgement.Outcome == "accepted")
            {

                // Believed again after it was not: the end of a gap in what the
                // time rests on is as much news as its beginning.
                if (Previous is not null && Previous.Outcome != "accepted")
                    Log.Metrological(LogLevel.Notice,
                                     $"NTS: the certificate of {name} is believed again: {certificate}, with root {root}.",
                                     Judgement.ToJSON(),
                                     "nts", "certificates");

                return;

            }

            var sentence     = Judgement.Outcome switch {
                                   "noCertificate"  => $"NTS: the key exchange with {name} was refused: it showed no certificate.",
                                   "wrongName"      => $"NTS: the key exchange with {name} was refused: its certificate {certificate} is not issued for that name.",
                                   "untrusted"      => $"NTS: the key exchange with {name} was refused: its certificate {certificate} chains to no root this {Kind.Name} trusts.",
                                   "pinMismatch"    => $"NTS: the key exchange with {name} was refused: it showed certificate {certificate} with root {root}, and is held to {Pins?.PinsText}.",
                                   _                => $"NTS: {name} showed certificate {certificate} with root {root}, and is held to {Pins?.PinsText} - used all the same, as its configuration says."
                               };

            var same         = Previous is not null                                              &&
                               Previous.Outcome                == Judgement.Outcome                &&
                               Previous.CertificateFingerprint == Judgement.CertificateFingerprint &&
                               Previous.RootFingerprint        == Judgement.RootFingerprint;

            if (same)
                Log.Debug(sentence, "nts", "certificates");

            else
                Log.Metrological(Judgement.Accepted ? LogLevel.Warning : LogLevel.Error,
                                 sentence,
                                 Judgement.ToJSON(),
                                 "nts", "certificates");

        }

        #endregion

    }

}
