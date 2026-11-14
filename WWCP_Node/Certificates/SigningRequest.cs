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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// A key this node made for itself, and the signing request that waits to
    /// be answered with its certificate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Who the node is before anybody has said so: the private half of the
    /// key is here and never leaves, the request is handed to whoever issues
    /// certificates, and nothing can be shown to anybody yet. Once the
    /// certificate comes back the two are put together and kept as the kind
    /// the request was made for - an identity like any other in the store -
    /// and the request is gone.
    /// </para>
    /// <para>
    /// <see cref="Id"/> is where the public key hashes to, so the request and
    /// the certificate that answers it are matched by the one thing they both
    /// carry, whatever either is called.
    /// </para>
    /// <para>
    /// A certificate may come back for a key this runtime cannot hold up -
    /// .NET has no key object for an Ed448 or an ML-DSA key today. It is kept
    /// beside its key rather than refused, the request stays a request, and
    /// <see cref="CannotBeHeldUp"/> says why: the runtime that cannot take it
    /// today may take it after an update.
    /// </para>
    /// </remarks>
    public sealed class SigningRequest
    {

        #region Properties

        /// <summary>What the key is called here, which is where its public key hashes to.</summary>
        public String                            Id                  { get; }

        /// <summary>The kind of certificate it is made for, and is kept as once it has come.</summary>
        public CertificateKind                   Kind                { get; }

        /// <summary>The kind of key, as it is written in the API: "ecdsa-p256".</summary>
        public String                            AlgorithmId         { get; }

        /// <summary>The kind of key, as it is written on a page: "ECDSA P-256".</summary>
        public String                            Algorithm           { get; }

        /// <summary>When the key was made.</summary>
        public DateTimeOffset                    CreatedAt           { get; }

        /// <summary>Who the request says its holder is.</summary>
        public String                            Subject             { get; }

        /// <summary>What its certificate is to be called; its common name where this is null.</summary>
        public String?                           Label               { get; init; }

        /// <summary>What its certificate is to be used for, where its kind is kept for some uses and not others; null for every use.</summary>
        public IReadOnlyList<CertificateUsage>?  Usages              { get; init; }

        /// <summary>The profile the request was made to, see <see cref="CSRTemplate"/>.</summary>
        public String                            Template            { get; init; } = CSRTemplate.ClientId;

        /// <summary>The role the request asks for, where its template asks for one.</summary>
        public String?                           Role                { get; init; }

        /// <summary>The key usages the request asks for - all of them. Empty for a key made before that was written down.</summary>
        public IReadOnlyList<String>             KeyUsages           { get; init; } = [];

        /// <summary>The extended key usages the request asks for - all of them.</summary>
        public IReadOnlyList<String>             ExtendedKeyUsages   { get; init; } = [];

        /// <summary>The names and addresses the request asks to be reachable as, where it is a server's.</summary>
        public IReadOnlyList<String>             ReachableAs         { get; init; } = [];

        /// <summary>The request itself, as PEM: what is handed to whoever issues certificates.</summary>
        public String                            CSR                 { get; }

        /// <summary>
        /// Why the certificate that came back for this key is not an identity
        /// of this node: this runtime cannot load it together with its key.
        /// Null while no certificate has come.
        /// </summary>
        public String?                           CannotBeHeldUp      { get; init; }

        /// <summary>Who the certificate that came back and cannot be held up is about, and until when.</summary>
        public String?                           CertificateSubject  { get; init; }

        /// <summary>Who signed it.</summary>
        public String?                           CertificateIssuer   { get; init; }

        /// <summary>When it runs out.</summary>
        public DateTimeOffset?                   CertificateNotAfter { get; init; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A key of this node that waits for its certificate.
        /// </summary>
        /// <param name="Id">Where its public key hashes to.</param>
        /// <param name="Kind">The kind of certificate it is made for.</param>
        /// <param name="AlgorithmId">The kind of key, as the API writes it.</param>
        /// <param name="Algorithm">The kind of key, as a page writes it.</param>
        /// <param name="CreatedAt">When it was made.</param>
        /// <param name="Subject">Who the request says its holder is.</param>
        /// <param name="CSR">The request, as PEM.</param>
        public SigningRequest(String           Id,
                                  CertificateKind  Kind,
                                  String           AlgorithmId,
                                  String           Algorithm,
                                  DateTimeOffset   CreatedAt,
                                  String           Subject,
                                  String           CSR)
        {

            this.Id           = Id;
            this.Kind         = Kind;
            this.AlgorithmId  = AlgorithmId;
            this.Algorithm    = Algorithm;
            this.CreatedAt    = CreatedAt;
            this.Subject      = Subject;
            this.CSR          = CSR;

        }

        #endregion


        #region ToJSON()

        /// <summary>
        /// This request, as a web interface reads it - and as it is written
        /// down beside its key, without the request itself, which has a file
        /// of its own.
        /// </summary>
        /// <param name="WithCSR">Whether the request itself is in it: for a page, and not for the file.</param>
        public JObject ToJSON(Boolean WithCSR = true)
        {

            var json = new JObject(
                           new JProperty("id",                 Id),
                           new JProperty("kind",               Kind.AsText()),
                           new JProperty("algorithm",          AlgorithmId),
                           new JProperty("algorithmName",      Algorithm),
                           new JProperty("createdAt",          CreatedAt.ToString("o")),
                           new JProperty("subject",            Subject),
                           new JProperty("label",              Label),
                           new JProperty("usages",             Usages is null ? null : new JArray(Usages.Select(usage => usage.ToString()))),
                           new JProperty("template",           Template),
                           new JProperty("templateName",       CSRTemplate.Find(Template)?.Name ?? Template),
                           new JProperty("role",               Role),
                           new JProperty("keyUsages",          new JArray(KeyUsages)),
                           new JProperty("extendedKeyUsages",  new JArray(ExtendedKeyUsages)),
                           new JProperty("reachableAs",        new JArray(ReachableAs))
                       );

            if (WithCSR)
                json.Add("csr", CSR);

            if (WithCSR && CannotBeHeldUp is not null)
                json.Add("certificate", new JObject(
                                            new JProperty("subject",         CertificateSubject),
                                            new JProperty("issuer",          CertificateIssuer),
                                            new JProperty("notAfter",        CertificateNotAfter?.ToString("o")),
                                            new JProperty("cannotBeHeldUp",  CannotBeHeldUp)
                                        ));

            return json;

        }

        #endregion

        #region (override) ToString()

        /// <inheritdoc/>
        public override String ToString()
            => $"{Id} ({Algorithm}, {Subject})";

        #endregion

    }

}
