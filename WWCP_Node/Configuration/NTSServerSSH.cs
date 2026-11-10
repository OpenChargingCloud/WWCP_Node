/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// How the key exchange with a time server goes over SSH instead of TLS:
    /// the subsystem "ntske/1@open.charging.cloud" of the white paper "NTS Key
    /// Establishment over SSH", on the server's SSH port, signed in under a
    /// user name with this node's own key, and the server held to its host key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "ssh" in the entry of a server: { "port", "user", "hostKeyPins",
    /// "hostCAs", "onMismatch" }, every one of them optional. Its mode is
    /// NTSv4SSH in the OCPP Device Model (section 7 of the white paper).
    /// </para>
    /// <para>
    /// There is no certificate, so a server is believed by its host key alone:
    /// a SHA-256 fingerprint it is pinned to - of the key itself, as ssh-keygen
    /// -l shows it, "SHA256:..." - or an SSH CA whose host certificate for its
    /// name it shows. Neither is the same as a certificate pin, which hashes a
    /// whole certificate. A server held to none of them is believed by nobody,
    /// unless its mismatches are recorded or accepted.
    /// </para>
    /// </remarks>
    /// <param name="Port">Its SSH port, or null for <see cref="DefaultPort"/>.</param>
    /// <param name="User">The user name to sign in under, or null for <see cref="DefaultUser"/>.</param>
    /// <param name="HostKeyPins">The SHA-256 fingerprints of the host keys it may show.</param>
    /// <param name="HostCAs">The SHA-256 fingerprints of the SSH CA keys that may sign its host certificate.</param>
    /// <param name="OnMismatch">What a host key comes to that is none of them.</param>
    public sealed record NTSServerSSH(UInt16?                 Port         = null,
                                      String?                 User         = null,
                                      IReadOnlyList<String>?  HostKeyPins  = null,
                                      IReadOnlyList<String>?  HostCAs      = null,
                                      PinMismatch             OnMismatch   = PinMismatch.Refuse)
    {

        #region Data

        /// <summary>
        /// The SSH port where an entry names none.
        /// </summary>
        public const UInt16  DefaultPort      = 22;

        /// <summary>
        /// The user name where an entry names none, as section 7 of the white
        /// paper has it.
        /// </summary>
        public const String  DefaultUser      = "ntske";

        /// <summary>
        /// The longest user name.
        /// </summary>
        public const Int32   MaxUserLength    = 32;

        /// <summary>
        /// How many host keys a server may be pinned to.
        /// </summary>
        public const Int32   MaxHostKeyPins   = 16;

        /// <summary>
        /// How many SSH CAs may sign a server's host certificate.
        /// </summary>
        public const Int32   MaxHostCAs       = 4;

        private static readonly Regex  userName     = new ("^[A-Za-z0-9._][A-Za-z0-9._@-]*$",         RegexOptions.CultureInvariant);
        private static readonly Regex  fingerprint  = new ("^SHA256:([A-Za-z0-9+/]{43})=?$",           RegexOptions.CultureInvariant);

        #endregion

        #region Properties

        /// <summary>
        /// The SSH port it is asked on.
        /// </summary>
        public UInt16                 PortOrDefault
            => Port ?? DefaultPort;

        /// <summary>
        /// The user name it is signed in under.
        /// </summary>
        public String                 UserOrDefault
            => User ?? DefaultUser;

        /// <summary>
        /// The host keys it may show; none where it is held to none.
        /// </summary>
        public IReadOnlyList<String>  Pins
            => HostKeyPins ?? [];

        /// <summary>
        /// The SSH CAs that may sign its host certificate; none where it is held to none.
        /// </summary>
        public IReadOnlyList<String>  CAs
            => HostCAs ?? [];

        /// <summary>
        /// Whether it is held to a host key or a CA at all.
        /// </summary>
        public Boolean                IsPinned
            => Pins.Count > 0 || CAs.Count > 0;

        #endregion


        #region Believes(HostKeyBlob, Hostname, Now, out Shown, out Why)

        /// <summary>
        /// Whether the host key a server showed is one this entry holds it to:
        /// a pinned key, or a host certificate for its name, valid now, signed
        /// by one of the CAs.
        /// </summary>
        /// <param name="HostKeyBlob">The host key as the server sent it: a key, or a certificate.</param>
        /// <param name="Hostname">The name it was asked under, which a host certificate has to name.</param>
        /// <param name="Now">The time a certificate has to be valid at.</param>
        /// <param name="Shown">The SHA-256 fingerprint of the key it showed - the certified key, where it showed a certificate.</param>
        /// <param name="Why">Why it is none of them, or what it was believed by.</param>
        public Boolean Believes(Byte[]          HostKeyBlob,
                                String          Hostname,
                                DateTimeOffset  Now,
                                out String      Shown,
                                out String      Why)
        {

            SshCertificate? certificate = null;

            if (SshCertificate.TryParse(HostKeyBlob, out var parsed) && parsed is not null)
                certificate = parsed;

            Shown = SshFingerprint.Sha256(certificate?.SubjectPublicKey ?? HostKeyBlob);

            var shown = Shown;

            if (Pins.Any(pin => String.Equals(pin, shown, StringComparison.Ordinal)))
            {
                Why = $"its host key {shown} is pinned";
                return true;
            }

            if (certificate is not null)
            {

                var ca = certificate.CaFingerprint;

                if (!CAs.Any(trusted => String.Equals(trusted, ca, StringComparison.Ordinal)))
                {
                    Why = $"its host key {shown} is pinned nowhere, and its host certificate was signed by {ca}, which is none of its CAs";
                    return false;
                }

                var validation = SshCertificateValidator.Validate(
                                     certificate,
                                     SshCertType.Host,
                                     Hostname,
                                     new SshCertificateAuthorityTrust().TrustCA(certificate.SignatureKey),
                                     Now
                                 );

                if (!validation.IsValid)
                {
                    Why = $"its host certificate of {ca} is not valid for {Hostname} now: {validation.Reason}";
                    return false;
                }

                Why = $"its host certificate for {Hostname} was signed by its CA {ca}";
                return true;

            }

            Why = IsPinned
                      ? $"its host key {shown} is none it is held to"
                      : $"it is held to no host key and no CA, and showed {shown}";

            return false;

        }

        #endregion


        #region (static) TryParse(JSON, Path, out SSH, out Error)

        /// <summary>
        /// Read the "ssh" object of a server's entry.
        /// </summary>
        /// <param name="JSON">The value of "ssh".</param>
        /// <param name="Path">Where it is in the file: "nts.groups.local.servers[0].ssh".</param>
        public static Boolean TryParse(JToken                                 JSON,
                                       String                                 Path,
                                       [NotNullWhen(true)]  out NTSServerSSH? SSH,
                                       [NotNullWhen(false)] out String?       Error)
        {

            SSH    = null;
            Error  = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object: {{ \"port\", \"user\", \"hostKeyPins\", \"hostCAs\", \"onMismatch\" }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadPort   (json, "port",        Path,                                     out var port,  out Error) ||
                !ConfigurationReader.TryReadString (json, "user",        Path, MaxUserLength,                      out var user,  out Error) ||
                !ConfigurationReader.TryReadStrings(json, "hostKeyPins", Path, MaxHostKeyPins, 100,                out var pins,  out Error) ||
                !ConfigurationReader.TryReadStrings(json, "hostCAs",     Path, MaxHostCAs,     100,                out var cas,   out Error) ||
                !ConfigurationReader.TryReadString (json, "onMismatch",  Path, 16,                                 out var onMismatchText, out Error))
            {
                return false;
            }

            if (user is not null && !userName.IsMatch(user))
            {
                Error = $"'{Path}.user': '{user}' is no user name: letters, digits, '.', '_', '-' and '@', and at most {MaxUserLength} of them.";
                return false;
            }

            if (!TryFingerprints(pins, $"{Path}.hostKeyPins", out var hostKeyPins, out Error) ||
                !TryFingerprints(cas,  $"{Path}.hostCAs",     out var hostCAs,     out Error))
            {
                return false;
            }

            var onMismatch = PinMismatch.Refuse;

            if (onMismatchText is not null)
            {

                if (!PinMismatchExtensions.TryParse(onMismatchText, out onMismatch))
                {
                    Error = $"'{Path}.onMismatch': '{onMismatchText}' is none of \"refuse\", \"record\" and \"accept\".";
                    return false;
                }

                if (onMismatch != PinMismatch.Refuse && hostKeyPins.Count == 0 && hostCAs.Count == 0)
                {
                    Error = $"'{Path}.onMismatch' says what a host key that is none it is held to comes to, but it is held to no host key and no CA.";
                    return false;
                }

            }

            SSH = new NTSServerSSH(
                      port?.ToUInt16(),
                      // The usual name is written as nothing, and read the same.
                      user is not null && user != DefaultUser ? user : null,
                      hostKeyPins.Count > 0 ? hostKeyPins : null,
                      hostCAs.    Count > 0 ? hostCAs     : null,
                      onMismatch
                  );

            return true;

        }

        #endregion

        #region (static) TryParseFingerprint(Text, out Fingerprint)

        /// <summary>
        /// A SHA-256 fingerprint of an SSH key as ssh-keygen -l writes it -
        /// "SHA256:" and 43 characters of base64 - with the padding a copy may
        /// carry taken off.
        /// </summary>
        public static Boolean TryParseFingerprint(String?                          Text,
                                                  [NotNullWhen(true)] out String?  Fingerprint)
        {

            Fingerprint = null;

            var match = fingerprint.Match(Text?.Trim() ?? "");

            if (!match.Success)
                return false;

            Fingerprint = "SHA256:" + match.Groups[1].Value;
            return true;

        }

        private static Boolean TryFingerprints(IReadOnlyList<String>?                   Texts,
                                               String                                   Path,
                                               out IReadOnlyList<String>                Fingerprints,
                                               [NotNullWhen(false)] out String?         Error)
        {

            var parsed = new List<String>();

            Fingerprints  = parsed;
            Error         = null;

            foreach (var text in Texts ?? [])
            {

                if (!TryParseFingerprint(text, out var one))
                {
                    Error = $"'{Path}': '{text}' is no SHA-256 fingerprint of an SSH key, which ssh-keygen -l writes as \"SHA256:\" and 43 characters of base64.";
                    return false;
                }

                if (!parsed.Contains(one))
                    parsed.Add(one);

            }

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The "ssh" object of the entry, with the usual left out.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Port.HasValue)                      json.Add("port",        Port.Value);
            if (User is not null)                   json.Add("user",        User);
            if (Pins.Count > 0)                     json.Add("hostKeyPins", new JArray(Pins));
            if (CAs. Count > 0)                     json.Add("hostCAs",     new JArray(CAs));
            if (OnMismatch != PinMismatch.Refuse)   json.Add("onMismatch",  OnMismatch.AsText());

            return json;

        }

        #endregion

        #region Text

        /// <summary>
        /// What it is, as a sentence says it: "ssh://ntske@time.lan:22, held to
        /// SHA256:..." - for the log.
        /// </summary>
        public String TextFor(String Hostname)

            => $"ssh://{UserOrDefault}@{Hostname}:{PortOrDefault}" +
               (IsPinned
                    ? $", held to {String.Join(", ", Pins.Concat(CAs.Select(ca => $"the CA {ca}")))}"
                    : ", held to no host key");

        #endregion

    }

}
