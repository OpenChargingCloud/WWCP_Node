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
    /// One certificate found in a file or a text, with the certificates that
    /// travel with it and its private key where it came with one - as it would
    /// be imported.
    /// </summary>
    /// <param name="Pem">The certificate, the certificates above it that came with it, and its private key where it came with one, as PEM - one import's worth.</param>
    /// <param name="Id">The handle the store would give it: the first 16 hex digits of its fingerprint.</param>
    /// <param name="Thumbprint">Its SHA-256 fingerprint, in full.</param>
    /// <param name="CommonName">Its common name, or its whole subject where it has none.</param>
    /// <param name="Subject">Who it is about.</param>
    /// <param name="Issuer">Who signed it.</param>
    /// <param name="NotBefore">When it starts being valid.</param>
    /// <param name="NotAfter">When it stops.</param>
    /// <param name="KeyAlgorithm">What kind of key it carries, e.g. "ECDSA P-521".</param>
    /// <param name="HasPrivateKey">Whether its private key came with it.</param>
    /// <param name="ChainLength">How many certificates above it came with it.</param>
    /// <param name="IsCA">Whether it says it is a CA, in its basic constraints.</param>
    /// <param name="IsSelfSigned">Whether it signed itself, as a root does.</param>
    /// <param name="InStoreAs">The kinds the store keeps it as already; empty where it is not in the store, and where it was asked without a store.</param>
    public sealed record InspectedCertificate(String                          Pem,
                                              String                          Id,
                                              String                          Thumbprint,
                                              String                          CommonName,
                                              String                          Subject,
                                              String                          Issuer,
                                              DateTimeOffset                  NotBefore,
                                              DateTimeOffset                  NotAfter,
                                              String                          KeyAlgorithm,
                                              Boolean                         HasPrivateKey,
                                              Int32                           ChainLength,
                                              Boolean                         IsCA,
                                              Boolean                         IsSelfSigned,
                                              IReadOnlyList<CertificateKind>  InStoreAs)
    {

        #region ToJSON(Unsuitable)

        /// <summary>
        /// What was found, as the JSON API hands it out: with its PEM, and with
        /// why it cannot be each kind it cannot be.
        /// </summary>
        /// <param name="Unsuitable">For each kind of the store this certificate cannot be kept as, why not.</param>
        public JObject ToJSON(IReadOnlyDictionary<CertificateKind, String> Unsuitable)

            => new (
                   new JProperty("pem",            Pem),
                   new JProperty("id",             Id),
                   new JProperty("thumbprint",     Thumbprint),
                   new JProperty("label",          CommonName),
                   new JProperty("subject",        Subject),
                   new JProperty("issuer",         Issuer),
                   new JProperty("notBefore",      NotBefore.UtcDateTime),
                   new JProperty("notAfter",       NotAfter. UtcDateTime),
                   new JProperty("keyAlgorithm",   KeyAlgorithm),
                   new JProperty("hasPrivateKey",  HasPrivateKey),
                   new JProperty("chainLength",    ChainLength),
                   new JProperty("isCA",           IsCA),
                   new JProperty("selfSigned",     IsSelfSigned),
                   new JProperty("inStoreAs",      new JArray(InStoreAs.Select(kind => kind.AsText()))),
                   new JProperty("unsuitable",     new JObject(Unsuitable.Select(pair => new JProperty(pair.Key.AsText(), pair.Value))))
               );

        #endregion

    }


    /// <summary>
    /// What a file or a text holds, certificate by certificate - or why it
    /// holds nothing that can be read.
    /// </summary>
    /// <remarks>
    /// A text may hold several certificates, and they are not all one import:
    /// a leaf, the sub-CAs above it and its key are one credential; three roots
    /// pasted one after the other are three roots. So what was found is told
    /// apart into certificates each of which would be imported on its own -
    /// every certificate that no other one in the text was issued by, with the
    /// ones above it that came with it - and a key goes to the certificate it
    /// belongs to, wherever it was written.
    /// </remarks>
    /// <param name="Certificates">What was found, one import's worth each.</param>
    /// <param name="Error">Why nothing was found; null where something was.</param>
    /// <param name="PasswordWanted">True where it opens only with a password, and none was given.</param>
    public sealed record CertificateInspection(IReadOnlyList<InspectedCertificate>  Certificates,
                                               String?                              Error           = null,
                                               Boolean                              PasswordWanted  = false)
    {

        /// <summary>
        /// Everything found, as one PEM: what a page puts into the box it was
        /// dropped on.
        /// </summary>
        public String Pem
            => String.Concat(Certificates.Select(certificate => certificate.Pem));

    }

}
