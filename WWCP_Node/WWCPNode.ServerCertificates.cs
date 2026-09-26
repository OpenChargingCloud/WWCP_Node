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

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a node made of the certificate a server showed when it connected.
    /// </summary>
    /// <param name="Service">What the server is to the node: "nts", "dns" - see <see cref="CertificateUsages"/>.</param>
    /// <param name="Server">Its name or its address, as the node asks it.</param>
    /// <param name="At">When.</param>
    /// <param name="Accepted">Whether the connection went ahead.</param>
    /// <param name="Outcome">In one word: "accepted"; "recorded" or "tolerated", where a fingerprint did not match and the server is used all the same; "pinMismatch", where it did not and the server was refused for it; "untrusted", "wrongName" or "noCertificate", where it was refused before any fingerprint was asked.</param>
    /// <param name="CertificateFingerprint">The SHA-256 fingerprint of the certificate it showed, or null when it showed none.</param>
    /// <param name="RootFingerprint">The SHA-256 fingerprint of the root its chain ends at, or null when it ends at none this node trusts.</param>
    /// <param name="AnchoredBy">The label of the root of this node's own store the chain ends at, where the machine did not know that root; null otherwise.</param>
    /// <param name="HeldTo">What the server is held to, or null for nothing.</param>
    /// <param name="Learned">What this judgement taught the node to hold the server to from now on, trusted on first use.</param>
    /// <param name="Previously">What the server was believed with before, where it showed another certificate now; null otherwise.</param>
    /// <param name="FirstSeen">Whether this is the first certificate the server is believed with here.</param>
    /// <param name="Steps">What the judgement went through, as a detailed test shows it.</param>
    public sealed record ServerJudgement(String                                       Service,
                                         String                                       Server,
                                         DateTimeOffset                               At,
                                         Boolean                                      Accepted,
                                         String                                       Outcome,
                                         String?                                      CertificateFingerprint,
                                         String?                                      RootFingerprint,
                                         String?                                      AnchoredBy,
                                         ServerPins?                                  HeldTo,
                                         TrustOnFirstUse                              Learned,
                                         KnownServer?                                 Previously,
                                         Boolean                                      FirstSeen,
                                         IReadOnlyList<(String Level, String Text)>  Steps)
    {

        #region Properties

        /// <summary>
        /// The first certificate the server is held to, or null.
        /// </summary>
        public String?  HeldToCertificate
            => HeldTo?.Certificates.FirstOrDefault();

        /// <summary>
        /// The first root the server is held to, or null.
        /// </summary>
        public String?  HeldToRoot
            => HeldTo?.Roots.FirstOrDefault();

        /// <summary>
        /// Whether the server showed another certificate than it was believed
        /// with before.
        /// </summary>
        public Boolean  Changed
            => Previously is not null;

        #endregion

        #region ToJSON()

        /// <summary>
        /// The judgement as a page and the metrological log read it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("server",       Server),
                   new JProperty("service",      Service),
                   new JProperty("at",           At.ToString("o")),
                   new JProperty("accepted",     Accepted),
                   new JProperty("outcome",      Outcome),
                   new JProperty("certificate",  CertificateFingerprint),
                   new JProperty("root",         RootFingerprint),
                   new JProperty("anchoredBy",   AnchoredBy),
                   new JProperty("heldTo",       HeldTo is { IsPinned: true } pins
                                                     ? new JObject(
                                                           new JProperty("certificate",   pins.Certificates.FirstOrDefault()),
                                                           new JProperty("root",          pins.Roots.       FirstOrDefault()),
                                                           new JProperty("certificates",  new JArray(pins.Certificates)),
                                                           new JProperty("roots",         new JArray(pins.Roots))
                                                       )
                                                     : null),
                   new JProperty("learned",      Learned.AsText()),
                   new JProperty("previously",   Previously is null
                                                     ? null
                                                     : new JObject(
                                                           new JProperty("certificate",  Previously.Certificate),
                                                           new JProperty("root",         Previously.Root),
                                                           new JProperty("since",        Previously.Since.ToString("o"))
                                                       ))
               );

        #endregion

    }


    /// <summary>
    /// Which certificates of the servers it connects to a node believes: the
    /// same questions for a time server and a name server, and the same
    /// answers written into the same log.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A certificate is judged when a connection is made - a key exchange, a
    /// TLS handshake - and that is where this is asked. What it refuses is
    /// refused from the next connection on, what it believes is remembered
    /// between starts, and a server believed with another certificate than
    /// before is said, whether or not anything holds it to one.
    /// </para>
    /// <para>
    /// Everything here that bears on trust is written into the log tagged
    /// "security". What bears on the time a node keeps - a time server - is
    /// written into the metrological log as well, as evidence; for other
    /// servers that is what "record" is for.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// The last judgement of every server that has had a connection, by
        /// service and name.
        /// </summary>
        private readonly ConcurrentDictionary<(String Service, String Server), ServerJudgement> judgements = new ();

        /// <summary>
        /// How long a lesson of trust on first use waits for a reconfiguration
        /// somebody else is in the middle of, before it is left to the next
        /// connection.
        /// </summary>
        private static readonly TimeSpan  LearningWait = TimeSpan.FromSeconds(5);

        #endregion

        #region Properties

        /// <summary>
        /// What every server this node connects to was last believed with,
        /// kept between starts - see <see cref="Certificates.KnownServers"/>.
        /// </summary>
        public KnownServers  KnownServers    { get; }

        #endregion


        #region LastJudgementOf(Service, Server)

        /// <summary>
        /// What this node made of the certificate the given server showed at its
        /// last connection, or null before it had one.
        /// </summary>
        public ServerJudgement? LastJudgementOf(String  Service,
                                                String  Server)

            => judgements.GetValueOrDefault((Service, Server.TrimEnd('.').ToLowerInvariant()));

        #endregion

        #region JudgeServer(Service, Server, Pins, Certificate, Chain, PolicyErrors, Evidence, Learn)

        /// <summary>
        /// Whether to go ahead with a connection to a server that showed this
        /// certificate.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Three questions, in this order, and a no to any of them ends it. Is
        /// the certificate issued for the server's name? Does its chain end at a
        /// root this machine trusts - or, where it does not, at a TLS root of
        /// this node's own store for this service, or at a root the server is
        /// held to where the store has it? And is it a certificate, and a root,
        /// the server is held to, where it is held to any?
        /// </para>
        /// <para>
        /// Then, where it went ahead: what trust on first use learns from it, and
        /// whether it is the certificate the server was believed with before.
        /// </para>
        /// </remarks>
        /// <param name="Service">What the server is to the node: "nts", "dns".</param>
        /// <param name="Server">Its name or its address, as the node asks it.</param>
        /// <param name="Pins">What it is held to, or null for nothing.</param>
        /// <param name="Certificate">The certificate it showed.</param>
        /// <param name="Chain">The chain the machine built for it, with the certificates the server sent beside it.</param>
        /// <param name="PolicyErrors">What building that chain, and comparing the name, found.</param>
        /// <param name="Evidence">Whether what is news here is written into the metrological log as well, whatever the pins say: for a time server.</param>
        /// <param name="Learn">Writes down a fingerprint the server is held to from now on, answering whether it could; null where nothing may be learned.</param>
        public ServerJudgement JudgeServer(String                                   Service,
                                           String                                   Server,
                                           ServerPins?                              Pins,
                                           X509Certificate2?                        Certificate,
                                           X509Chain?                               Chain,
                                           SslPolicyErrors                          PolicyErrors,
                                           Boolean                                  Evidence,
                                           Func<TrustOnFirstUse, String, Boolean>?  Learn   = null)
        {

            var name                    = Server.TrimEnd('.');
            var key                     = (Service, name.ToLowerInvariant());
            var pins                    = Pins ?? ServerPins.None;
            var steps                   = new List<(String Level, String Text)>();
            var now                     = TimeProvider.GetUtcNow();

            String?       certificateFingerprint  = null;
            String?       rootFingerprint         = null;
            String?       anchoredBy              = null;
            String        outcome;
            Boolean       accepted;
            var           learned                 = TrustOnFirstUse.None;
            KnownServer?  previously              = null;
            var           firstSeen               = false;

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

                    else if (TryAnchor(Service, Certificate, Chain, pins, out var anchoredRoot, out var label))
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

                    else
                    {

                        var certificateMatches  = pins.HoldsCertificate(certificateFingerprint);
                        var rootMatches         = pins.HoldsRoot(rootFingerprint);
                        var mismatchLevel       = pins.OnMismatch == PinMismatch.Refuse ? "error" : "warning";

                        if (pins.Certificates.Count > 0)
                            steps.Add(certificateMatches
                                          ? ("notice",       $"Held to certificate {String.Join(" or ", pins.Certificates)}: it is {(pins.Certificates.Count == 1 ? "the one" : "one")} it showed.")
                                          : (mismatchLevel,  $"Held to certificate {String.Join(" or ", pins.Certificates)}, and it showed {certificateFingerprint}."));

                        if (pins.Roots.Count > 0)
                            steps.Add(rootMatches
                                          ? ("notice",       $"Held to root {String.Join(" or ", pins.Roots)}: its chain ends there.")
                                          : (mismatchLevel,  $"Held to root {String.Join(" or ", pins.Roots)}, and its chain ends at {rootFingerprint}."));

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

                        else if (pins.OnMismatch == PinMismatch.Accept)
                        {
                            outcome   = "tolerated";
                            accepted  = true;
                            steps.Add(("warning", Evidence
                                                      ? "Used all the same, as its configuration says, and written into the metrological log."
                                                      : "Used all the same, as its configuration says, and written into the log."));
                        }

                        else
                        {
                            outcome   = "pinMismatch";
                            accepted  = false;
                            steps.Add(("error", Evidence
                                                    ? "Refused, as its configuration says, and written into the metrological log."
                                                    : "Refused, as its configuration says, and written into the log."));
                        }

                        #region Trust on first use

                        // Only from a certificate believed without a mismatch:
                        // learning from one that is merely tolerated would hold
                        // the server to exactly what its pins said it must not
                        // show.
                        var toLearn = pins.TrustOnFirstUse switch {
                                          TrustOnFirstUse.Root         when pins.Roots.       Count == 0  => rootFingerprint,
                                          TrustOnFirstUse.Certificate  when pins.Certificates.Count == 0  => certificateFingerprint,
                                          _                                                             => null
                                      };

                        if (outcome == "accepted" && toLearn is not null && Learn is not null)
                        {

                            var what = pins.TrustOnFirstUse.AsText();

                            if (Learn(pins.TrustOnFirstUse, toLearn))
                            {
                                learned = pins.TrustOnFirstUse;
                                steps.Add(("notice", $"Held to its {what} {toLearn} from now on: the first one it was believed with, trusted on first use."));
                            }

                            else
                                steps.Add(("warning", $"Its {what} {toLearn} could not be written down as the one to hold it to, and is tried again at the next connection."));

                        }

                        #endregion

                    }

                }

            }

            #region Whether it is what the server was believed with before

            if (accepted && certificateFingerprint is not null)
            {

                var before = KnownServers.Observe(Service, name, certificateFingerprint, rootFingerprint, now);

                if (before is null)
                {
                    firstSeen = true;
                    steps.Add(("info", "The first certificate it is believed with here: remembered from now on, so that another one is noticed."));
                }

                else if (!String.Equals(before.Certificate, certificateFingerprint, StringComparison.OrdinalIgnoreCase) ||
                         !String.Equals(before.Root,        rootFingerprint,        StringComparison.OrdinalIgnoreCase))
                {
                    previously = before;
                    steps.Add(("warning", $"Another certificate than it was believed with since {before.Since.UtcDateTime:yyyy-MM-dd}: " +
                                          $"{before.Certificate}, with root {before.Root ?? "unknown"}."));
                }

            }

            #endregion

            var judgement = new ServerJudgement(
                                Service,
                                name,
                                now,
                                accepted,
                                outcome,
                                certificateFingerprint,
                                rootFingerprint,
                                anchoredBy,
                                pins.IsPinned ? pins : null,
                                learned,
                                previously,
                                firstSeen,
                                steps
                            );

            WriteDown(judgement, judgements.GetValueOrDefault(key), pins, Evidence);

            judgements[key] = judgement;

            return judgement;

        }

        #endregion


        #region (private) TryAnchor(Service, Certificate, Chain, Pins, out RootFingerprint, out Label)

        /// <summary>
        /// Build the certificate's chain against this node's own roots: every
        /// TLS root of its store that is switched on, valid and for this
        /// service, and every root the server is held to, where the store has
        /// it as whatever kind of certificate.
        /// </summary>
        /// <remarks>
        /// For this service, which is what a root never told what it is for is
        /// as well: a root kept for the name servers alone vouches for no time.
        /// A root a server is held to is believed whatever it is kept as,
        /// because naming it in the server's configuration says the same thing,
        /// and more narrowly.
        ///
        /// Revocation is asked where there is somebody to ask, and what cannot be
        /// asked is not held against the certificate: a root of one's own is
        /// often a CA without a revocation list, and one that is on a list is
        /// still refused.
        /// </remarks>
        private Boolean TryAnchor(String                                      Service,
                                  X509Certificate2                            Certificate,
                                  X509Chain?                                  Chain,
                                  ServerPins                                  Pins,
                                  [NotNullWhen(true)] out String?             RootFingerprint,
                                  [NotNullWhen(true)] out String?             Label)
        {

            RootFingerprint  = null;
            Label            = null;

            var anchors      = new List<(X509Certificate2 Certificate, String Fingerprint, String Label)>();

            try
            {

                foreach (var entry in Certificates.UsableFor(CertificateKind.TLSRoot, Service))
                    if (Certificates.TryLoad(entry, out var root, out _))
                        anchors.Add((root, entry.Thumbprint, entry.Label));

                foreach (var pinned in Pins.Roots)
                {

                    if (anchors.Any(anchor => String.Equals(anchor.Fingerprint, pinned, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    if (Certificates.ByFingerprint(pinned) is CertificateEntry held &&
                        held.IsUsable                                               &&
                        Certificates.TryLoad(held, out var heldRoot, out _))
                    {
                        anchors.Add((heldRoot, held.Thumbprint, held.Label));
                    }

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
                Label            = anchors.FirstOrDefault(anchor => anchor.Fingerprint == end).Label ?? end;

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

        #region (private) WriteDown(Judgement, Previous, Pins, Evidence)

        /// <summary>
        /// Say what a judgement found: what is news where it is evidence or a
        /// matter of security, and the same verdict again only in passing.
        /// </summary>
        /// <remarks>
        /// <para>
        /// What is news: a server refused, or used although a fingerprint did
        /// not match, the first time or differently from the last time - and a
        /// server believed again after that; a server held to what it was first
        /// believed with; a server believed with another certificate than
        /// before. The same verdict at every round is said once, and at the
        /// rounds after it only in passing: a server refused for a fortnight
        /// would otherwise fill the log book with one line a quarter of an hour.
        /// </para>
        /// <para>
        /// Every line is tagged "security". The metrological log gets what is
        /// news where the judgement is evidence - a time server's - and a
        /// mismatch recorded because the configuration says so.
        /// </para>
        /// </remarks>
        private void WriteDown(ServerJudgement   Judgement,
                               ServerJudgement?  Previous,
                               ServerPins        Pins,
                               Boolean           Evidence)
        {

            var service      = Judgement.Service.ToUpperInvariant();
            var name         = Judgement.Server;
            var connection   = Judgement.Service == CertificateUsages.NTS ? "key exchange" : "connection";
            var certificate  = Judgement.CertificateFingerprint ?? "none";
            var root         = Judgement.RootFingerprint        ?? "no root this node trusts";
            String[] tags    = [ Judgement.Service, "certificates", "security" ];

            void Say(LogLevel Level, String Sentence, Boolean AsEvidence)
            {
                if (AsEvidence)
                    Log.Metrological(Level, Sentence, Judgement.ToJSON(), tags);
                else
                    Log.Log(Level, Sentence, tags);
            }

            #region What it learned, and whether it changed

            if (Judgement.Learned != TrustOnFirstUse.None)
                Say(LogLevel.Notice,
                    $"{service}: {name} is held to its {Judgement.Learned.AsText()} " +
                    $"{(Judgement.Learned == TrustOnFirstUse.Root ? Judgement.RootFingerprint : Judgement.CertificateFingerprint)} from now on - " +
                     "the first one it was believed with, trusted on first use.",
                    Evidence);

            if (Judgement.Previously is KnownServer before)
                Say(LogLevel.Warning,
                    $"{service}: {name} showed another certificate than it was believed with before: {certificate} with root {root}, " +
                    $"where it showed {before.Certificate} with root {before.Root ?? "unknown"} since {before.Since.UtcDateTime:yyyy-MM-dd}.",
                    Evidence);

            else if (Judgement.FirstSeen)
                Log.Info($"{service}: {name} is believed with certificate {certificate}, with root {root} - remembered from now on.", tags);

            #endregion

            if (Judgement.Outcome == "accepted")
            {

                // Believed again after it was not: the end of a gap in what the
                // service rests on is as much news as its beginning.
                if (Previous is not null && Previous.Outcome != "accepted")
                    Say(LogLevel.Notice,
                        $"{service}: the certificate of {name} is believed again: {certificate}, with root {root}.",
                        Evidence);

                return;

            }

            var sentence     = Judgement.Outcome switch {
                                   "noCertificate"  => $"{service}: the {connection} with {name} was refused: it showed no certificate.",
                                   "wrongName"      => $"{service}: the {connection} with {name} was refused: its certificate {certificate} is not issued for that name.",
                                   "untrusted"      => $"{service}: the {connection} with {name} was refused: its certificate {certificate} chains to no root this {Kind.Name} trusts.",
                                   "pinMismatch"    => $"{service}: the {connection} with {name} was refused: it showed certificate {certificate} with root {root}, and is held to {Pins.Text}.",
                                   _                => $"{service}: {name} showed certificate {certificate} with root {root}, and is held to {Pins.Text} - used all the same, as its configuration says."
                               };

            var same         = Previous is not null                                              &&
                               Previous.Outcome                == Judgement.Outcome                &&
                               Previous.CertificateFingerprint == Judgement.CertificateFingerprint &&
                               Previous.RootFingerprint        == Judgement.RootFingerprint;

            if (same)
                Log.Debug(sentence, tags);

            else
                Say(Judgement.Accepted ? LogLevel.Warning : LogLevel.Error,
                    sentence,
                    Evidence || Judgement.Outcome == "recorded");

        }

        #endregion

    }

}
