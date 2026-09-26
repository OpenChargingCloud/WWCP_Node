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

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// What one server this node connects to is held to, beside what every
    /// server is held to: the certificates it may show, the roots its chain
    /// may end at, what a mismatch comes to, and what is learned from the
    /// first time it is believed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same for a time server and a name server, because the question is
    /// the same: a server that has to be this one, and not merely one that a
    /// certificate authority would vouch for.
    /// </para>
    /// <para>
    /// Any number of each, and the server is held to any one of them: two
    /// certificates are a renewal that has been announced, two roots a CA
    /// moving to a new one - written down before it happens, so that the day
    /// it does is not a day without the server. Each by its SHA-256
    /// fingerprint, which is what a configuration file can carry and a
    /// certificate authority, a browser and openssl write down.
    /// </para>
    /// <para>
    /// A pin narrows what is believed and never widens it: a server held to a
    /// fingerprint still has to show a certificate issued for its name, whose
    /// chain ends at a root this node trusts. A certificate that matches its
    /// pin and chains to nothing is refused.
    /// </para>
    /// </remarks>
    /// <param name="Certificates">The fingerprints of the certificates it may show, any of them; none to hold it to no certificate.</param>
    /// <param name="Roots">The fingerprints of the roots its chain may end at, any of them; none to hold it to no root.</param>
    /// <param name="OnMismatch">What a connection comes to whose certificate is not one of those.</param>
    /// <param name="TrustOnFirstUse">What it is held to from the first time it is believed, where it is held to nothing of that kind yet.</param>
    public sealed record ServerPins(IReadOnlyList<String>  Certificates,
                                    IReadOnlyList<String>  Roots,
                                    PinMismatch            OnMismatch       = PinMismatch.Refuse,
                                    TrustOnFirstUse        TrustOnFirstUse  = TrustOnFirstUse.None)
    {

        #region Data

        /// <summary>
        /// The most fingerprints of one kind one server may be held to.
        /// </summary>
        public const Int32  MaxPins         = 16;

        /// <summary>
        /// The longest a fingerprint may be written, colons and all.
        /// </summary>
        public const Int32  MaxPinLength    = 200;

        /// <summary>
        /// Held to nothing beyond the usual.
        /// </summary>
        public static readonly ServerPins  None = new ([], []);

        #endregion

        #region Properties

        /// <summary>
        /// Whether the server is held to a certificate or to a root.
        /// </summary>
        public Boolean  IsPinned
            => Certificates.Count > 0 || Roots.Count > 0;

        /// <summary>
        /// Whether this says anything at all: a pin, or something to learn.
        /// </summary>
        public Boolean  SaysAnything
            => IsPinned || TrustOnFirstUse != TrustOnFirstUse.None;

        /// <summary>
        /// What the server is held to, as a sentence names it - "certificate A
        /// or B and root C, refused otherwise" - or null where it is held to
        /// nothing yet.
        /// </summary>
        public String?  Text
            => IsPinned
                   ? String.Join(" and ", new[] {
                         Certificates.Count > 0 ? $"certificate {String.Join(" or ", Certificates)}" : null,
                         Roots.       Count > 0 ? $"root {String.Join(" or ", Roots)}"               : null
                     }.Where(pin => pin is not null)) +
                     OnMismatch switch {
                         PinMismatch.Record  => ", recorded otherwise",
                         PinMismatch.Accept  => ", accepted otherwise",
                         _                   => ", refused otherwise"
                     }
                   : null;

        #endregion


        #region HoldsCertificate(Fingerprint) / HoldsRoot(Fingerprint)

        /// <summary>
        /// Whether a certificate of this fingerprint is one the server may show:
        /// one of its pins, or any where it is held to none.
        /// </summary>
        public Boolean HoldsCertificate(String? Fingerprint)

            => Certificates.Count == 0 ||
               Fingerprint is not null && Certificates.Contains(Fingerprint, StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Whether a root of this fingerprint is one the server's chain may end
        /// at: one of its pins, or any where it is held to none.
        /// </summary>
        public Boolean HoldsRoot(String? Fingerprint)

            => Roots.Count == 0 ||
               Fingerprint is not null && Roots.Contains(Fingerprint, StringComparer.OrdinalIgnoreCase);

        #endregion

        #region Learning(What, Fingerprint)

        /// <summary>
        /// The same, held to the given fingerprint as well - what trust on first
        /// use makes of it.
        /// </summary>
        public ServerPins Learning(TrustOnFirstUse  What,
                                   String           Fingerprint)

            => What switch {
                   TrustOnFirstUse.Certificate  => this with { Certificates = [.. Certificates, Fingerprint] },
                   TrustOnFirstUse.Root         => this with { Roots        = [.. Roots,        Fingerprint] },
                   _                            => this
               };

        #endregion

        #region SameAs(Other)

        /// <summary>
        /// Whether the other holds a server to the same, in whatever order it
        /// lists it. Null is held to nothing.
        /// </summary>
        public Boolean SameAs(ServerPins? Other)
        {

            var other = Other ?? None;

            return OnMismatch      == other.OnMismatch      &&
                   TrustOnFirstUse == other.TrustOnFirstUse &&
                   Certificates.Count == other.Certificates.Count && !Certificates.Except(other.Certificates, StringComparer.OrdinalIgnoreCase).Any() &&
                   Roots.       Count == other.Roots.       Count && !Roots.       Except(other.Roots,        StringComparer.OrdinalIgnoreCase).Any();

        }

        #endregion


        #region (static) TryParse(JSON, Path, out Pins, out Error)

        /// <summary>
        /// What the entry of a server says it is held to, or null where it says
        /// nothing about it - or the one sentence that says what is wrong.
        /// </summary>
        /// <remarks>
        /// One pin of a kind is written "certificateFingerprint" or
        /// "rootFingerprint", which is what a file said before a server could
        /// be held to several; several are written as a list under
        /// "certificateFingerprints" or "rootFingerprints". Both may be there,
        /// and they add up.
        /// </remarks>
        /// <param name="JSON">The entry of the server.</param>
        /// <param name="Path">Where it is in the file, to say which entry is wrong: "nts.servers[2]".</param>
        public static Boolean TryParse(JObject                                JSON,
                                       String                                 Path,
                                       out ServerPins?                        Pins,
                                       [NotNullWhen(false)] out String?       Error)
        {

            Pins   = null;
            Error  = null;

            if (!ConfigurationReader.TryReadString (JSON, "certificateFingerprint",  Path,          MaxPinLength, out var certificatePin,   out Error) ||
                !ConfigurationReader.TryReadStrings(JSON, "certificateFingerprints", Path, MaxPins, MaxPinLength, out var certificatePins,  out Error) ||
                !ConfigurationReader.TryReadString (JSON, "rootFingerprint",         Path,          MaxPinLength, out var rootPin,          out Error) ||
                !ConfigurationReader.TryReadStrings(JSON, "rootFingerprints",        Path, MaxPins, MaxPinLength, out var rootPins,         out Error) ||
                !ConfigurationReader.TryReadString (JSON, "onMismatch",              Path,                    20, out var onMismatchText,   out Error) ||
                !ConfigurationReader.TryReadString (JSON, "trustOnFirstUse",         Path,                    20, out var learnText,        out Error))
            {
                return false;
            }

            if (!TryFingerprints(certificatePin, certificatePins, $"{Path}.certificateFingerprint", out var certificates, out Error) ||
                !TryFingerprints(rootPin,        rootPins,        $"{Path}.rootFingerprint",        out var roots,        out Error))
            {
                return false;
            }

            var learn = TrustOnFirstUse.None;

            if (learnText is not null && !TrustOnFirstUseExtensions.TryParse(learnText, out learn))
            {
                Error = $"'{Path}.trustOnFirstUse' is '{learnText}', and has to be 'root' or 'certificate'.";
                return false;
            }

            var onMismatch = PinMismatch.Refuse;

            if (onMismatchText is not null)
            {

                if (!PinMismatchExtensions.TryParse(onMismatchText, out onMismatch))
                {
                    Error = $"'{Path}.onMismatch' is '{onMismatchText}', and has to be 'refuse', 'record' or 'accept'.";
                    return false;
                }

                // Refused rather than kept: it says what a fingerprint that does
                // not match comes to, so somebody meant to write one down - and a
                // server they believe to be held to something is held to nothing.
                if (certificates.Count == 0 && roots.Count == 0 && learn == TrustOnFirstUse.None)
                {
                    Error = $"'{Path}.onMismatch' says what a fingerprint that does not match comes to, and this server is held to none.";
                    return false;
                }

            }

            if (certificates.Count == 0 && roots.Count == 0 && learn == TrustOnFirstUse.None)
                return true;

            Pins = new ServerPins(certificates, roots, onMismatch, learn);
            return true;

        }

        #endregion

        #region WriteInto(JSON)

        /// <summary>
        /// Write this into the entry of the server: a pin of a kind the way a
        /// file said it before there could be several, and a list where there
        /// are; a mismatch only where it is not what a pin means anyway.
        /// </summary>
        public void WriteInto(JObject JSON)
        {

            if      (Certificates.Count == 1)  JSON["certificateFingerprint"]   = Certificates[0];
            else if (Certificates.Count >  1)  JSON["certificateFingerprints"]  = new JArray(Certificates);

            if      (Roots.Count == 1)         JSON["rootFingerprint"]          = Roots[0];
            else if (Roots.Count >  1)         JSON["rootFingerprints"]         = new JArray(Roots);

            if (OnMismatch != PinMismatch.Refuse)
                JSON["onMismatch"]       = OnMismatch.AsText();

            if (TrustOnFirstUse != TrustOnFirstUse.None)
                JSON["trustOnFirstUse"]  = TrustOnFirstUse.AsText();

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// What the server is held to, as a page reads it: the first certificate
        /// and the first root as they always were, and all of them beside.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("certificate",      Certificates.FirstOrDefault()),
                   new JProperty("root",             Roots.       FirstOrDefault()),
                   new JProperty("certificates",     new JArray(Certificates)),
                   new JProperty("roots",            new JArray(Roots)),
                   new JProperty("onMismatch",       OnMismatch.AsText()),
                   new JProperty("trustOnFirstUse",  TrustOnFirstUse.AsText())
               );

        #endregion


        #region (private static) TryFingerprints(One, Several, Where, out Fingerprints, out Error)

        /// <summary>
        /// The fingerprints of one kind, however many ways they were written,
        /// each once and in the form the store keeps them.
        /// </summary>
        private static Boolean TryFingerprints(String?                           One,
                                               IReadOnlyList<String>?            Several,
                                               String                            Where,
                                               out IReadOnlyList<String>         Fingerprints,
                                               [NotNullWhen(false)] out String?  Error)
        {

            var fingerprints  = new List<String>();

            Fingerprints      = fingerprints;
            Error             = null;

            var written       = new List<String>();

            if (One is not null)
                written.Add(One);

            written.AddRange(Several ?? []);

            foreach (var text in written)
            {

                if (!CertificateEntry.TryParseFingerprint(text, out var fingerprint))
                {
                    Error = $"'{Where}' holds '{text}', which is not a SHA-256 fingerprint: 64 hexadecimal digits, with or without colons between them.";
                    return false;
                }

                if (!fingerprints.Contains(fingerprint))
                    fingerprints.Add(fingerprint);

            }

            if (fingerprints.Count > MaxPins)
            {
                Error = $"'{Where}' holds more than {MaxPins} fingerprints.";
                return false;
            }

            return true;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Text ?? (TrustOnFirstUse != TrustOnFirstUse.None
                            ? $"its {TrustOnFirstUse.AsText()}, once it is first believed"
                            : "nothing");

        #endregion

    }

}
