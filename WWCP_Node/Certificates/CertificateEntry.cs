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
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// One certificate in this node's store: what it is, what is in it, and
    /// whether this node is currently using it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything here but <see cref="Label"/>, <see cref="IsActive"/> and
    /// <see cref="Usages"/> is read out of the certificate itself and is
    /// therefore not somebody's opinion: a store whose index disagrees with
    /// its files is a store that has to be believed about the wrong one. Those
    /// three are the only fields the index is the authority on, and they are
    /// the reason the index exists rather than the directory listing being the
    /// whole truth.
    /// </para>
    /// <para>
    /// <see cref="Id"/> and <see cref="Thumbprint"/> are not the same thing and
    /// are not used for the same thing. The thumbprint is the certificate's
    /// SHA-256 fingerprint in full, which is what somebody compares against
    /// what a certificate authority told them. The id is the first 16 hex
    /// digits of it, which is what a configuration file and a URL carry - short
    /// enough to read out loud, and checked for collision at import so that two
    /// entries can never answer to one handle. A truncated fingerprint is a
    /// handle and never evidence, which is why both are kept.
    /// </para>
    /// </remarks>
    /// <param name="Id">The short handle this entry is addressed by.</param>
    /// <param name="Kind">What this certificate is for.</param>
    /// <param name="FileName">Where it is kept, relative to the store.</param>
    /// <param name="Label">What somebody calls it; the common name unless they said otherwise.</param>
    /// <param name="Subject">Who it is about.</param>
    /// <param name="Issuer">Who signed it.</param>
    /// <param name="SerialNumber">Its serial, as the issuer assigned it.</param>
    /// <param name="Thumbprint">Its SHA-256 fingerprint, in full.</param>
    /// <param name="NotBefore">When it starts being valid.</param>
    /// <param name="NotAfter">When it stops.</param>
    /// <param name="KeyAlgorithm">What kind of key it carries, e.g. "ECDSA P-521".</param>
    /// <param name="HasPrivateKey">Whether the stored file carries the private key as well.</param>
    /// <param name="ChainLength">How many further certificates travel with it, e.g. its sub-CAs.</param>
    /// <param name="IsActive">Whether this node is currently using it.</param>
    /// <param name="ImportedAt">When it was put here.</param>
    /// <param name="Usages">What it may be used for, where its kind is kept for some uses and not others; null for every use - see <see cref="CertificateUsages"/>.</param>
    public sealed record CertificateEntry(String           Id,
                                          CertificateKind  Kind,
                                          String           FileName,
                                          String           Label,
                                          String           Subject,
                                          String           Issuer,
                                          String           SerialNumber,
                                          String           Thumbprint,
                                          DateTimeOffset   NotBefore,
                                          DateTimeOffset   NotAfter,
                                          String           KeyAlgorithm,
                                          Boolean          HasPrivateKey,
                                          Int32            ChainLength,
                                          Boolean          IsActive,
                                          DateTimeOffset   ImportedAt,
                                          IReadOnlyList<CertificateUsage>?  Usages = null)
    {

        #region Data

        /// <summary>
        /// How many hex digits of the fingerprint an id is.
        /// </summary>
        /// <remarks>
        /// Sixteen, which is 64 bits: far too many for two certificates in one
        /// node's store to collide by accident, and short enough to appear
        /// in a configuration file without wrapping. Import checks anyway - see
        /// <see cref="CertificateStore"/> - because "by accident" is not the
        /// only way two things collide.
        /// </remarks>
        public const Int32  IdLength    = 16;

        /// <summary>
        /// The longest a label may be written.
        /// </summary>
        public const Int32  MaxLabelLength  = 120;

        #endregion

        #region Properties

        /// <summary>
        /// The key pin of the key in this certificate: SHA-256 over its
        /// SubjectPublicKeyInfo - the same for every certificate ever issued
        /// for the same key, and the one thing a server key's carrier and the
        /// certificate an authority issued for that key have in common.
        /// </summary>
        /// <remarks>
        /// Read out of the certificate like everything else here but the
        /// three fields the index is the authority on, and written into the
        /// index only so that whoever reads it can see which entries are one
        /// key. Null only for an entry read from an index that did not say
        /// it, of a kind this node does not keep: every entry of the store is
        /// read again from its file, and has one.
        /// </remarks>
        public KeyPin?  KeyPin    { get; init; }

        /// <summary>
        /// Whether this certificate's validity has not started yet, by the
        /// system's clock.
        /// </summary>
        /// <remarks>
        /// By the system's clock, because an entry has no other: whoever has a
        /// clock of their own - the store has its node's - asks
        /// <see cref="IsNotYetValidAt"/>.
        /// </remarks>
        public Boolean IsNotYetValid
            => IsNotYetValidAt(DateTimeOffset.UtcNow);

        /// <summary>
        /// Whether this certificate has expired, by the system's clock - see
        /// <see cref="IsExpiredAt"/>.
        /// </summary>
        public Boolean IsExpired
            => IsExpiredAt(DateTimeOffset.UtcNow);

        /// <summary>
        /// Whether this certificate could be used right now, by the system's
        /// clock: active, and within its own validity - see
        /// <see cref="IsUsableAt"/>.
        /// </summary>
        /// <remarks>
        /// Active and usable are kept apart on purpose. Somebody switches a
        /// certificate on; time switches it off. A page that showed only the
        /// one would have to explain why an active certificate did nothing.
        /// </remarks>
        public Boolean IsUsable
            => IsUsableAt(DateTimeOffset.UtcNow);

        #endregion


        #region IsNotYetValidAt(Now) / IsExpiredAt(Now) / IsUsableAt(Now)

        /// <summary>
        /// Whether this certificate's validity has not started yet at the
        /// given moment.
        /// </summary>
        /// <remarks>
        /// The moment is handed in rather than read, so that whoever judges a
        /// certificate judges it by the clock it keeps everything else by: a
        /// node whose clock is not the system's - a test's that is a year
        /// ahead, or one somebody set - would otherwise call a certificate
        /// usable that its own log calls expired.
        /// </remarks>
        /// <param name="Now">What time it is, by the clock of whoever asks.</param>
        public Boolean IsNotYetValidAt(DateTimeOffset Now)
            => NotBefore > Now;

        /// <summary>
        /// Whether this certificate has expired at the given moment.
        /// </summary>
        /// <param name="Now">What time it is, by the clock of whoever asks.</param>
        public Boolean IsExpiredAt(DateTimeOffset Now)
            => NotAfter < Now;

        /// <summary>
        /// Whether this certificate could be used at the given moment: active,
        /// and within its own validity.
        /// </summary>
        /// <param name="Now">What time it is, by the clock of whoever asks.</param>
        public Boolean IsUsableAt(DateTimeOffset Now)
            => IsActive && !IsExpiredAt(Now) && !IsNotYetValidAt(Now);

        #endregion


        #region IsFor(Usage)

        /// <summary>
        /// Whether this certificate may be used for the given usage: it is of a
        /// kind kept for some uses and not others, and this is one of its own -
        /// or it was never told which, and is for every use.
        /// </summary>
        /// <remarks>
        /// Every use for a certificate never told, because that is what every
        /// TLS root was before there were usages, and a store written then
        /// should mean tomorrow what it meant yesterday.
        /// </remarks>
        public Boolean IsFor(CertificateUsage Usage)

            => Kind.HasUsages() &&
               (Usages is null || Usages.Contains(Usage));

        #endregion


        #region (static) From(Certificate, Kind, FileName, Label, ChainLength, IsActive, ImportedAt = null, Usages = null)

        /// <summary>
        /// An entry describing a certificate that has just been read.
        /// </summary>
        public static CertificateEntry From(X509Certificate2        Certificate,
                                            CertificateKind         Kind,
                                            String                  FileName,
                                            String?                 Label,
                                            Int32                   ChainLength,
                                            Boolean                 IsActive,
                                            DateTimeOffset?         ImportedAt   = null,
                                            IEnumerable<CertificateUsage>?  Usages  = null)
        {

            var thumbprint             = ThumbprintOf(Certificate);
            var (notBefore, notAfter)  = ValidityOf(Certificate);

            return new CertificateEntry(
                       thumbprint[..IdLength],
                       Kind,
                       FileName,
                       Label?.Trim() is { Length: > 0 } given
                           ? given
                           : CommonNameOf(Certificate),
                       Certificate.Subject,
                       Certificate.Issuer,
                       Certificate.SerialNumber,
                       thumbprint,
                       notBefore,
                       notAfter,
                       KeyAlgorithmOf(Certificate),
                       Certificate.HasPrivateKey,
                       ChainLength,
                       IsActive,
                       ImportedAt ?? DateTimeOffset.UtcNow,
                       Kind.HasUsages() && Usages is not null
                           ? [.. Usages]
                           : null
                   ) {
                       KeyPin = KeyPinOf(Certificate)
                   };

        }

        #endregion

        #region (static) KeyPinOf(Certificate)

        /// <summary>
        /// The key pin of the key in a certificate, or null where this runtime
        /// cannot write its public key out - which it can for every kind of key
        /// it reads at all, so null is a key nobody here could use anyway.
        /// </summary>
        public static KeyPin? KeyPinOf(X509Certificate2 Certificate)
        {
            try
            {
                return KeyPin.FromCertificate(Certificate);
            }
            catch (Exception)
            {
                return null;
            }
        }

        #endregion

        #region (static) ValidityOf(Certificate)

        /// <summary>
        /// When a certificate starts and stops being valid, in UTC, as it is
        /// written in the certificate.
        /// </summary>
        /// <remarks>
        /// Read from the certificate's own bytes rather than from
        /// <see cref="X509Certificate2.NotAfter"/>, which hands a moment back
        /// in the local time of the machine and cannot hold the last second of
        /// 9999 east of Greenwich: it is cut off at the end of the year in local
        /// time, and turned back to UTC an hour short or more. That is the end
        /// RFC 5280 4.1.2.5 gives a certificate without a well-defined one -
        /// a server key's carrier, see <see cref="CertificateStore.CarrierNotAfter"/> -
        /// and a store that wrote it down an hour short would write a different
        /// index in Berlin than in London. Where the bytes cannot be read this
        /// way, what the runtime says is taken after all.
        /// </remarks>
        public static (DateTimeOffset NotBefore, DateTimeOffset NotAfter) ValidityOf(X509Certificate2 Certificate)
        {

            try
            {

                // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {
                //     [0] version OPTIONAL, serialNumber, signature, issuer,
                //     validity SEQUENCE { notBefore, notAfter }, ... } ... }
                var certificate  = new AsnReader(Certificate.RawData, AsnEncodingRules.DER).ReadSequence();
                var tbs          = certificate.ReadSequence();

                if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    tbs.ReadEncodedValue();

                tbs.ReadEncodedValue();   // serialNumber
                tbs.ReadEncodedValue();   // signature
                tbs.ReadEncodedValue();   // issuer

                var validity     = tbs.ReadSequence();

                static DateTimeOffset Time(AsnReader Reader)

                    => Reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime)
                           ? Reader.ReadUtcTime().ToUniversalTime()
                           : Reader.ReadGeneralizedTime().ToUniversalTime();

                var notBefore    = Time(validity);
                var notAfter     = Time(validity);

                return (notBefore, notAfter);

            }
            catch (Exception)
            {
                return (Certificate.NotBefore.ToUniversalTime(),
                        Certificate.NotAfter. ToUniversalTime());
            }

        }

        #endregion

        #region (static) ThumbprintOf(Certificate)

        /// <summary>
        /// A certificate's SHA-256 fingerprint, in lower-case hexadecimal.
        /// </summary>
        /// <remarks>
        /// SHA-256 rather than <see cref="X509Certificate2.Thumbprint"/>, which
        /// is SHA-1 and has no business identifying anything in 2026.
        /// </remarks>
        public static String ThumbprintOf(X509Certificate2 Certificate)

            => Convert.ToHexString(SHA256.HashData(Certificate.RawData)).ToLowerInvariant();

        #endregion

        #region (static) TryParseFingerprint(Text, out Fingerprint)

        /// <summary>
        /// A SHA-256 fingerprint as somebody wrote it, in the form this store
        /// keeps it: 64 hexadecimal digits in lower case.
        /// </summary>
        /// <remarks>
        /// In upper or lower case, and with colons, spaces or dashes between
        /// the bytes or nothing at all - the ways a certificate authority, a
        /// browser and openssl write one - and never shorter than the whole of
        /// it: a truncated fingerprint is a handle, not evidence, and a
        /// certificate held to one would be held to 2^64 others as well.
        /// </remarks>
        /// <param name="Text">The fingerprint as written.</param>
        /// <param name="Fingerprint">The same, as the store keeps it.</param>
        public static Boolean TryParseFingerprint(String?                           Text,
                                                  [NotNullWhen(true)] out String?  Fingerprint)
        {

            Fingerprint = null;

            if (Text is null)
                return false;

            var digits = new System.Text.StringBuilder(64);

            foreach (var character in Text.Trim())
            {

                if (Uri.IsHexDigit(character))
                    digits.Append(Char.ToLowerInvariant(character));

                else if (character is not (':' or ' ' or '-'))
                    return false;

            }

            if (digits.Length != 64)
                return false;

            Fingerprint = digits.ToString();
            return true;

        }

        #endregion

        #region (static) CommonNameOf(Certificate)

        /// <summary>
        /// What to call a certificate nobody has named: its common name, or its
        /// whole subject where it has none.
        /// </summary>
        public static String CommonNameOf(X509Certificate2 Certificate)
        {

            var common = Certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            return common is { Length: > 0 }
                       ? common
                       : Certificate.Subject;

        }

        #endregion

        #region (static) KeyAlgorithmOf(Certificate)

        /// <summary>
        /// What kind of key a certificate carries, written the way somebody
        /// comparing it against a specification would write it.
        /// </summary>
        /// <remarks>
        /// The curve is named rather than only the size, because ISO 15118-20's
        /// requirement is a curve - secp521r1 - and "521-bit EC" is one
        /// reasonable reading away from it.
        /// </remarks>
        public static String KeyAlgorithmOf(X509Certificate2 Certificate)
        {

            using var ecdsa = Certificate.GetECDsaPublicKey();

            if (ecdsa is not null)
            {

                var curve = ecdsa.KeySize switch {
                                256  => "P-256",
                                384  => "P-384",
                                521  => "P-521",
                                _    => $"{ecdsa.KeySize}-bit"
                            };

                return $"ECDSA {curve}";

            }

            using var rsa = Certificate.GetRSAPublicKey();

            return rsa is not null
                       ? $"RSA {rsa.KeySize}-bit"
                       : Certificate.PublicKey.Oid.FriendlyName ?? Certificate.PublicKey.Oid.Value ?? "unknown";

        }

        #endregion


        #region (static) TryParse(JSON, out Entry, out Error)

        /// <summary>
        /// One entry as the index file holds it, or the one sentence that says
        /// what is wrong with it.
        /// </summary>
        /// <remarks>
        /// Only <see cref="Label"/>, <see cref="IsActive"/> and
        /// <see cref="Usages"/> are actually taken from here by
        /// <see cref="CertificateStore"/>; the rest is read again from the file
        /// it names. It is all parsed anyway so that a damaged index is refused
        /// as a whole rather than half-believed.
        ///
        /// Usages missing or null are every use, which is what an index written
        /// before there were usages says about every certificate in it. A usage
        /// that is not a usage name at all is a damaged entry.
        /// </remarks>
        public static Boolean TryParse(JObject                                     JSON,
                                       [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                       [NotNullWhen(false)] out String?            Error)

            => TryParse(JSON, [], out Entry, out Error);

        /// <summary>
        /// One entry as the index file holds it, its kind one of the given ones
        /// where it is - a kind of node's own, which its store was made with -
        /// or one defined in code, or else made up, of the group the index
        /// says.
        /// </summary>
        /// <param name="JSON">The entry as the index holds it.</param>
        /// <param name="Known">The kinds the store keeps.</param>
        /// <param name="Entry">The entry.</param>
        /// <param name="Error">What is wrong with it.</param>
        public static Boolean TryParse(JObject                                     JSON,
                                       IEnumerable<CertificateKind>                Known,
                                       [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                       [NotNullWhen(false)] out String?            Error)
        {

            Entry  = null;
            Error  = null;

            var id = JSON.Value<String>("id")?.Trim();

            if (id is null or { Length: 0 })
            {
                Error = "a certificate entry without an 'id'.";
                return false;
            }

            var kindName = JSON.Value<String>("kind")?.Trim();
            var group    = CertificateKind.TryParseGroup(JSON.Value<String>("group"), out var said) ? said : (CertificateGroup?) null;

            CertificateKind kind;

            if (Known.FirstOrDefault(known => String.Equals(known.AsText(), kindName, StringComparison.OrdinalIgnoreCase)) is { IsNotNullOrEmpty: true } keptKind)
                kind = keptKind;

            else if (CertificateKind.TryParse(kindName, group, out var parsed))
                kind = parsed.Value;

            else
            {
                Error = $"the certificate '{id}' has an unknown 'kind'.";
                return false;
            }

            var fileName = JSON.Value<String>("fileName")?.Trim();

            if (fileName is null or { Length: 0 })
            {
                Error = $"the certificate '{id}' has no 'fileName'.";
                return false;
            }

            IReadOnlyList<CertificateUsage>? usages = null;

            if (JSON.TryGetValue("usages", out var usagesToken) && usagesToken.Type != JTokenType.Null)
            {

                if (usagesToken is not JArray usagesArray ||
                    usagesArray.Any(usage => usage.Type != JTokenType.String ||
                                             !CertificateUsages.IsUsageName(usage.Value<String>())))
                {
                    Error = $"the certificate '{id}' has 'usages' that are not a list of usages.";
                    return false;
                }

                usages = [.. usagesArray.Select(usage => CertificateUsage.Parse(usage.Value<String>()!)).Distinct()];

            }

            Entry = new CertificateEntry(
                        id,
                        kind,
                        fileName,
                        JSON.Value<String>("label")        ?? "",
                        JSON.Value<String>("subject")      ?? "",
                        JSON.Value<String>("issuer")       ?? "",
                        JSON.Value<String>("serialNumber") ?? "",
                        JSON.Value<String>("thumbprint")   ?? "",
                        Moment(JSON, "notBefore") ?? DateTimeOffset.MinValue,
                        Moment(JSON, "notAfter")  ?? DateTimeOffset.MaxValue,
                        JSON.Value<String>("keyAlgorithm") ?? "",
                        JSON.Value<Boolean?>("hasPrivateKey") ?? false,
                        JSON.Value<Int32?>("chainLength")     ?? 0,
                        JSON.Value<Boolean?>("active")        ?? true,
                        Moment(JSON, "importedAt") ?? DateTimeOffset.UtcNow,
                        kind.HasUsages() ? usages : null
                    ) {
                        KeyPin = KeyPin.TryParse(JSON.Value<String>("keyPin"), out var keyPin) ? keyPin : null
                    };

            return true;

        }

        #endregion

        #region (private static) Moment(JSON, Name)

        /// <summary>
        /// One moment out of the index, whichever way the JSON reader handled it.
        /// </summary>
        /// <remarks>
        /// Newtonsoft turns an ISO 8601 string into a <see cref="DateTime"/> token while it is parsing, and
        /// asking that token for a <see cref="DateTimeOffset"/> throws rather than converting - which lost a
        /// whole index, and with it every label and every on/off, to one cast. So the token is taken as what
        /// it is and turned here, and a date this cannot read is absent rather than fatal.
        /// </remarks>
        private static DateTimeOffset? Moment(JObject  JSON,
                                              String   Name)
        {

            if (!JSON.TryGetValue(Name, out var token) || token.Type == JTokenType.Null)
                return null;

            if (token.Type == JTokenType.Date)
            {

                var value = token.ToObject<Object>();

                return value switch {
                           DateTime       moment  => new DateTimeOffset(moment.ToUniversalTime(), TimeSpan.Zero),
                           DateTimeOffset moment  => moment,
                           _                      => null
                       };

            }

            return DateTimeOffset.TryParse(token.Value<String>(),
                                           System.Globalization.CultureInfo.InvariantCulture,
                                           System.Globalization.DateTimeStyles.AdjustToUniversal |
                                           System.Globalization.DateTimeStyles.AssumeUniversal,
                                           out var parsed)
                       ? parsed
                       : null;

        }

        #endregion

        #region ToJSON(WithDiagnostics = false, Now = null)

        /// <summary>
        /// This entry as the index file holds it, and as the JSON API hands it
        /// out.
        /// </summary>
        /// <param name="WithDiagnostics">
        /// Also say what follows from the clock - expired, not yet valid,
        /// usable. Written for a page and not for the file, because a stored
        /// document that says "valid" is wrong the day after it is written.
        /// </param>
        /// <param name="Now">What time it is by the clock of whoever asks, for the diagnostics; the system's where it is not given.</param>
        public JObject ToJSON(Boolean          WithDiagnostics   = false,
                              DateTimeOffset?  Now               = null)
        {

            var json = new JObject(
                           new JProperty("id",            Id),
                           new JProperty("kind",          Kind.AsText()),
                           // Written for every kind, so that a kind of node's own
                           // read before it is defined, or a kind somebody made
                           // up, comes back in the group it was in.
                           new JProperty("group",         CertificateKind.AsText(Kind.Group)),
                           new JProperty("fileName",      FileName),
                           new JProperty("label",         Label),
                           new JProperty("subject",       Subject),
                           new JProperty("issuer",        Issuer),
                           new JProperty("serialNumber",  SerialNumber),
                           new JProperty("thumbprint",    Thumbprint),
                           new JProperty("notBefore",     NotBefore.UtcDateTime),
                           new JProperty("notAfter",      NotAfter. UtcDateTime),
                           new JProperty("keyAlgorithm",  KeyAlgorithm),
                           new JProperty("hasPrivateKey", HasPrivateKey),
                           new JProperty("chainLength",   ChainLength),
                           new JProperty("active",        IsActive),
                           new JProperty("importedAt",    ImportedAt.UtcDateTime)
                       );

            if (KeyPin is not null)
                json.Add("keyPin", KeyPin.ToHex());

            // Only where the kind has usages at all, and null there for every
            // use: a V2G root that said "usages" would be asked which, and has
            // no answer.
            if (Kind.HasUsages())
                json.Add("usages", Usages is null
                                       ? JValue.CreateNull()
                                       : new JArray(Usages.Select(usage => usage.ToString())));

            if (WithDiagnostics)
            {
                var now = Now ?? DateTimeOffset.UtcNow;

                json.Add("expired",      IsExpiredAt    (now));
                json.Add("notYetValid",  IsNotYetValidAt(now));
                json.Add("usable",       IsUsableAt     (now));
                json.Add("description",  Kind.Describe());
                json.Add("custom",       Kind.IsCustom);
            }

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"{Label} ({Kind.AsText()}, {Id}){(Kind.HasUsages() && Usages is not null ? ", " + CertificateUsages.Describe(Usages) : "")}{(IsActive ? "" : ", inactive")}{(IsExpired ? ", expired" : "")}";

        #endregion

    }

}
