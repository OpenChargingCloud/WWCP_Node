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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// The keys this node makes for itself: each with a signing request that
    /// waits for its certificate, below <c>&lt;store&gt;/requests/</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A certificate with its key arrives in the store by import, from
    /// wherever it was made. The other way round is the better one where it is
    /// to be had: the key is made here, a request is handed to whoever issues
    /// certificates, and only the certificate travels - so there is no moment
    /// at which the key exists anywhere else. Once the certificate has come
    /// the two are put together and kept as the kind the request was made
    /// for, switched, named and told what they are for like every identity,
    /// and the request is gone.
    /// </para>
    /// <para>
    /// Which kinds a node makes keys for is the node's to say -
    /// <see cref="RequestKinds"/> - and none by default: a page offering a
    /// request nobody can answer would be offering a mistake.
    /// </para>
    /// <para>
    /// Three files per key: <c>&lt;id&gt;.key.pem</c>, readable by its owner
    /// alone, <c>&lt;id&gt;.csr.pem</c>, which is no secret, and
    /// <c>&lt;id&gt;.json</c>, what was asked for. A fourth,
    /// <c>&lt;id&gt;.cert.pem</c>, is a certificate that came back for a key
    /// this runtime cannot hold up - see <see cref="SigningRequest"/>.
    /// </para>
    /// </remarks>
    public sealed partial class CertificateStore
    {

        #region Data

        /// <summary>
        /// The directory of the requests, below the store's.
        /// </summary>
        public const String  RequestsDirectoryName  = "requests";

        /// <summary>
        /// The longest a subject may be written.
        /// </summary>
        public const Int32   MaxSubjectLength       = 200;

        /// <summary>
        /// The algorithm a key is made with when nothing says otherwise.
        /// </summary>
        public const String  DefaultAlgorithm       = KeyAlgorithm.DefaultId;

        /// <summary>
        /// How many days before a certificate runs out taking it in says so.
        /// </summary>
        public const Int32   WarnsDaysBefore        = 30;

        private readonly Dictionary<String, SigningRequest>  requests     = new (StringComparer.Ordinal);

        // The public key of every request, which is what a certificate that
        // comes back is matched against to find out whose it is.
        private readonly Dictionary<String, Byte[]>              requestKeys  = new (StringComparer.Ordinal);

        #endregion

        #region Properties

        /// <summary>
        /// The kinds of certificate this node makes keys and signing requests
        /// for: none, unless its kind of node says so.
        /// </summary>
        public IReadOnlyList<CertificateKind> RequestKinds { get; }

        /// <summary>
        /// The keys that wait for their certificate, newest first.
        /// </summary>
        public IReadOnlyList<SigningRequest> Requests
        {
            get
            {

                storeLock.Wait();

                try
                {
                    return [.. requests.Values.OrderByDescending(request => request.CreatedAt)];
                }
                finally
                {
                    storeLock.Release();
                }

            }
        }

        private String RequestsDirectory
            => Path.Combine(Directory, RequestsDirectoryName);

        #endregion


        #region (private static) RequestKindsOf(Kinds, RequestKinds)

        /// <summary>
        /// The kinds keys are made for, held to what can be made: a kind this
        /// store keeps, that carries its key, and that a request can be made
        /// out to - a client's identity, or a server's.
        /// </summary>
        private static IReadOnlyList<CertificateKind> RequestKindsOf(IReadOnlyList<CertificateKind>  Kinds,
                                                                     IEnumerable<CertificateKind>?   RequestKinds)
        {

            var kinds = new List<CertificateKind>();

            foreach (var kind in RequestKinds ?? [])
            {

                if (!Kinds.Contains(kind))
                    throw new ArgumentException($"A key cannot be made for {kind.WithArticle()}: this store does not keep the kind.", nameof(RequestKinds));

                if (!kind.NeedsPrivateKey() || CSRTemplate.DefaultFor(kind) is null)
                    throw new ArgumentException($"A key cannot be made for {kind.WithArticle()}: it is no identity that carries its key.", nameof(RequestKinds));

                if (!kinds.Contains(kind))
                    kinds.Add(kind);

            }

            return kinds;

        }

        #endregion

        #region Request(Id)

        /// <summary>
        /// The key that waits under this identification, or null.
        /// </summary>
        public SigningRequest? Request(String? Id)
        {

            if (Id is null)
                return null;

            storeLock.Wait();

            try
            {
                return requests.GetValueOrDefault(Id);
            }
            finally
            {
                storeLock.Release();
            }

        }

        #endregion


        #region TryCreateRequest(Kind, Subject, Algorithm, Asks, Usages, Label, out Request, out Error, out NotSaved)

        /// <summary>
        /// A new key, and the signing request to be handed to whoever issues
        /// certificates for this node.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The request says what its certificate is for rather than hoping:
        /// a certificate authority handed a request without an extended key
        /// usage frequently issues something that is not what was wanted, and
        /// a node finds that out at the next handshake. What its template is
        /// for - signing in as a client, or being a server - is asked for
        /// whatever else is, and so is a signature, and enciphering a key
        /// where the kind of key can. Everything in <paramref name="Asks"/>
        /// is added to that, and what a kind of key cannot do is refused
        /// here, with the reason, rather than by a certificate authority
        /// without one.
        /// </para>
        /// <para>
        /// A client's request names nothing it is reachable as: what a server
        /// recognises it by is the subject. A server's has to.
        /// </para>
        /// </remarks>
        /// <param name="Kind">The kind of certificate the key is for, and is kept as once it has come.</param>
        /// <param name="Subject">Who this node says it is - plain text is read as a common name, a full distinguished name is taken as written.</param>
        /// <param name="Algorithm">Which kind of key, or null for the usual one.</param>
        /// <param name="Asks">The template, its role, and the usages asked for beside the usual ones; null for the plain request of the kind.</param>
        /// <param name="Usages">What its certificate is to be used for, where its kind is kept for some uses and not others; null for every use.</param>
        /// <param name="Label">What its certificate is to be called; its common name where this is null.</param>
        /// <param name="Request">The key, with its request.</param>
        /// <param name="Error">Why there is none.</param>
        /// <param name="NotSaved">True where its files could not be written: nothing about the request was wrong, and nothing of the key is kept.</param>
        public Boolean TryCreateRequest(CertificateKind                               Kind,
                                        String                                        Subject,
                                        String?                                       Algorithm,
                                        CertificateRequestAsks?                       Asks,
                                        IEnumerable<String>?                          Usages,
                                        String?                                       Label,
                                        [NotNullWhen(true)]  out SigningRequest?  Request,
                                        [NotNullWhen(false)] out String?              Error,
                                        out Boolean                                   NotSaved)
        {

            Request   = null;
            Error     = null;
            NotSaved  = false;

            #region What was asked for

            if (!RequestKinds.Contains(Kind))
            {
                Error = RequestKinds.Count == 0
                            ? $"This {NodeName} makes no keys: its identities are brought to it, each with its key."
                            : $"This {NodeName} makes no key for {Kind.WithArticle()} ({String.Join(", ", RequestKinds.Select(kind => kind.AsText()))}).";
                return false;
            }

            var algorithm = KeyAlgorithm.Find(Algorithm ?? DefaultAlgorithm);

            if (algorithm is null)
            {
                Error = $"'{Algorithm}' is not a key this {NodeName} generates ({String.Join(", ", KeyAlgorithm.All.Select(one => one.Id))}).";
                return false;
            }

            var subject = Subject.Trim();

            if (subject.Length == 0)
            {
                Error = $"A certificate has to say who this {NodeName} is, or nobody will know whose it is. Fill in a subject.";
                return false;
            }

            if (subject.Length > MaxSubjectLength)
            {
                Error = $"The subject may be at most {MaxSubjectLength} characters long.";
                return false;
            }

            // Plain text is what somebody types, so it is read as a common
            // name; a full distinguished name is taken as written.
            var distinguishedName = subject.Contains('=')
                                        ? subject
                                        : $"CN={subject.Replace("\\", "\\\\").Replace(",", "\\,").Replace("=", "\\=")}";

            X509Name subjectName;
            String   subjectText;

            try
            {
                // Read by .NET first because it is stricter about what somebody
                // may type, then handed on in the form Bouncy Castle signs with
                // - so the message about a bad subject is the readable one and
                // the request is still built by the half that knows every
                // algorithm.
                var x500     = new X500DistinguishedName(distinguishedName);
                subjectText  = x500.Name;
                subjectName  = new X509Name(x500.Name);
            }
            catch (Exception e)
            {
                Error = $"'{subject}' is not a usable certificate subject: {e.Message}";
                return false;
            }

            var label = Label?.Trim() is { Length: > 0 } called ? called : null;

            if (label?.Length > CertificateEntry.MaxLabelLength)
            {
                Error = $"A label may be at most {CertificateEntry.MaxLabelLength} characters long.";
                return false;
            }

            List<CertificateUsage>? usages = null;

            if (Usages is not null)
            {

                usages = [];

                foreach (var given in Usages)
                {

                    if (!CertificateUsage.TryParse(given, out var usage))
                    {
                        Error = $"'{given}' is not a usage: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.";
                        return false;
                    }

                    if (!usages.Contains(usage))
                        usages.Add(usage);

                }

                // None named is every use, as it is for a certificate.
                if (usages.Count == 0)
                    usages = null;

            }

            #endregion

            #region What it is made to

            var templates  = CSRTemplate.For(Kind);
            var template   = Asks?.Template is { Length: > 0 } named
                                 ? templates.FirstOrDefault(one => String.Equals(one.Id, named.Trim(), StringComparison.OrdinalIgnoreCase))
                                 : templates.FirstOrDefault();

            if (template is null)
            {
                Error = $"'{Asks?.Template}' is not a template a request for {Kind.WithArticle()} is made to ({String.Join(", ", templates.Select(one => one.Id))}).";
                return false;
            }

            var role = Asks?.Role?.Trim() is { Length: > 0 } said ? said : null;

            if (template.AsksForARole)
            {

                if (role is null)
                {
                    Error = $"A certificate for {template.Name} has to say which role its holder may play ({String.Join(", ", template.Roles)}, or the one its server knows).";
                    return false;
                }

                if (role.Length > CSRTemplate.MaxRoleLength || role.Any(Char.IsControl))
                {
                    Error = $"A role may be at most {CSRTemplate.MaxRoleLength} characters long, and all of them printable.";
                    return false;
                }

            }

            else if (role is not null)
            {
                Error = $"A certificate for {template.Name} has no role to ask for. Leave it out, or pick the template that has one.";
                return false;
            }

            var names = (Asks?.ReachableAs ?? []).Select  (name => name.Trim()).
                                                  Where   (name => name.Length > 0).
                                                  Distinct(StringComparer.OrdinalIgnoreCase).
                                                  ToArray();

            if (template.AsksForNames)
            {

                if (names.Length == 0)
                {
                    Error = $"A certificate for {template.Name} has to name what it is reachable as - a host name or an address - or nobody connecting will believe it.";
                    return false;
                }

                if (names.Any(name => name.Length > 253 || name.Any(character => Char.IsControl(character) || Char.IsWhiteSpace(character))))
                {
                    Error = "What it is reachable as is a host name or an address: no blanks in it, and at most 253 characters.";
                    return false;
                }

            }

            else if (names.Length > 0)
            {
                Error = $"A certificate for {template.Name} is reachable as nothing: it is shown by whoever dials, and recognised by its subject.";
                return false;
            }

            #endregion

            #region What it is asked for

            // What the kind of key brings by itself, then what the template
            // and somebody ticking boxes add - each once, in that order.
            var keyUsageBits   = algorithm.CanEncipher
                                     ? KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment
                                     : KeyUsage.DigitalSignature;

            var keyUsageNames  = new List<String> { "digitalSignature" };

            if (algorithm.CanEncipher)
                keyUsageNames.Add("keyEncipherment");

            foreach (var (name, fromTemplate) in template.KeyUsages.Select(name => (name, true)).
                                                 Concat((Asks?.KeyUsages ?? []).Select(name => (name, false))))
            {

                // Named again, as a page that shows every usage would: asked
                // for anyway.
                if (keyUsageNames.Contains(name.Trim(), StringComparer.OrdinalIgnoreCase))
                    continue;

                var usage = CSRKeyUsage.Find(name);

                if (usage is null)
                {
                    Error = $"'{name}' is not a key usage this {NodeName} asks for ({String.Join(", ", CSRKeyUsage.All.Select(one => one.Id))}).";
                    return false;
                }

                if (!usage.Fits(algorithm))
                {

                    // What a template would like and the kind of key cannot
                    // do is left out; what somebody ticked is theirs to hear.
                    if (fromTemplate)
                        continue;

                    Error = $"A key of the kind {algorithm.Name} cannot be used for {usage.Id}: {usage.Remark}";
                    return false;

                }

                keyUsageBits |= usage.Bit;
                keyUsageNames.Add(usage.Id);

            }

            var purposes      = new List<DerObjectIdentifier>();
            var purposeNames  = new List<String> { template.Purpose };

            foreach (var name in template.ExtendedKeyUsages.Concat(Asks?.ExtendedKeyUsages ?? []))
            {

                if (name.Trim().Length == 0)
                    continue;

                if (!CSRPurpose.TryParse(name, out var purpose, out var written))
                {
                    Error = $"'{name}' is neither an extended key usage this {NodeName} knows ({String.Join(", ", CSRPurpose.All.Select(one => one.Id))}) nor an object identifier such as 1.3.6.1.5.5.7.3.9.";
                    return false;
                }

                if (purposeNames.Contains(written))
                    continue;

                purposes.    Add(purpose);
                purposeNames.Add(written);

            }

            #endregion

            AsymmetricCipherKeyPair pair;

            try
            {
                pair = algorithm.Generate();
            }
            catch (Exception e)
            {
                Error = $"No {algorithm.Name} key could be generated: {e.Message}";
                return false;
            }

            var publicKey  = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetDerEncoded();
            var id         = KeyId(publicKey);

            String csr;

            try
            {
                csr = PKIFactory.GenerateCertificateSigningRequest(
                          pair,
                          subjectName,
                          algorithm,
                          names,
                          template.Purpose == CSRPurpose.ServerAuth
                              ? KeyPurposeID.id_kp_serverAuth
                              : KeyPurposeID.id_kp_clientAuth,
                          keyUsageBits,
                          purposes,
                          template.ExtensionsFor(role)
                      ).ToPEM();
            }
            catch (Exception e)
            {
                Error = $"The signing request could not be made: {e.Message}";
                return false;
            }

            var request = new SigningRequest(id, Kind, algorithm.Id, algorithm.Name, DateTimeOffset.UtcNow, subjectText, csr) {
                              Label              = label,
                              Usages             = usages,
                              Template           = template.Id,
                              Role               = role,
                              KeyUsages          = keyUsageNames,
                              ExtendedKeyUsages  = purposeNames,
                              ReachableAs        = names
                          };

            storeLock.Wait();

            try
            {

                if (requests.ContainsKey(id))
                {
                    // Two identical keys is not something that happens by
                    // chance; it happens when a directory was copied.
                    Error = $"A key with the identification '{id}' is already here.";
                    return false;
                }

                if (!TryWriteRequest(request,
                                     PemEncoding.WriteString(
                                         "PRIVATE KEY",
                                         Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetDerEncoded()
                                     ) + Environment.NewLine,
                                     out Error))
                {
                    NotSaved = true;
                    return false;
                }

                requests   [id] = request;
                requestKeys[id] = publicKey;

            }
            finally
            {
                storeLock.Release();
            }

            log.Metrological(LogLevel.Notice,
                             $"Certificates: a new {algorithm.Name} key '{id}' was generated for {Kind.WithArticle()}, and a signing request for {subjectText}" +
                             (template.Id != CSRTemplate.DefaultFor(Kind)?.Id ? $", made to the template {template.Name}{(role is not null ? $" with the role {role}" : "")}," : "") +
                             " is waiting to be collected.",
                             "certificates", "security");

            Request = request;

            Changed();

            return true;

        }

        #endregion

        #region TryAdoptRequest(Kind, KeyPEM, CSR, CreatedAt, Usages, Label, Asked, out Request, out Error, out NotSaved)

        /// <summary>
        /// Take in a key that was made on this node before its keys were kept
        /// here, with the signing request it was made with: it waits for its
        /// certificate as if it had been made here.
        /// </summary>
        /// <remarks>
        /// For a node that kept such keys somewhere of its own and moves them
        /// over, once. Not a way to bring a key in from anywhere else, and
        /// not offered to anybody: a key that arrived from somewhere else is
        /// one somebody else has a copy of.
        /// </remarks>
        /// <param name="Kind">The kind of certificate the key is for.</param>
        /// <param name="KeyPEM">The private key, as PKCS#8 in PEM.</param>
        /// <param name="CSR">Its signing request, as PEM.</param>
        /// <param name="AlgorithmId">The kind of key, as the API writes it.</param>
        /// <param name="CreatedAt">When it was made.</param>
        /// <param name="Usages">What its certificate is to be used for; null for every use.</param>
        /// <param name="Label">What its certificate is to be called; its common name where this is null.</param>
        /// <param name="Asked">What its request asked for, where that was written down.</param>
        /// <param name="Request">The key, with its request.</param>
        /// <param name="Error">Why it was not taken in.</param>
        /// <param name="NotSaved">True where its files could not be written.</param>
        public Boolean TryAdoptRequest(CertificateKind                               Kind,
                                       String                                        KeyPEM,
                                       String                                        CSR,
                                       String                                        AlgorithmId,
                                       DateTimeOffset                                CreatedAt,
                                       IEnumerable<String>?                          Usages,
                                       String?                                       Label,
                                       SigningRequest?                           Asked,
                                       [NotNullWhen(true)]  out SigningRequest?  Request,
                                       [NotNullWhen(false)] out String?              Error,
                                       out Boolean                                   NotSaved)
        {

            Request   = null;
            NotSaved  = false;

            if (!RequestKinds.Contains(Kind))
            {
                Error = $"This {NodeName} makes no key for {Kind.WithArticle()}.";
                return false;
            }

            if (!TryReadRequest(CSR, out var subject, out var publicKey, out Error))
                return false;

            if (KeyBlockOf(KeyPEM) is null)
            {
                Error = "There is no private key in what was given.";
                return false;
            }

            var id         = KeyId(publicKey);
            var algorithm  = KeyAlgorithm.Find(AlgorithmId);

            var request    = new SigningRequest(id, Kind, algorithm?.Id ?? AlgorithmId, algorithm?.Name ?? AlgorithmId, CreatedAt, subject, CSR) {
                                 Label              = Label,
                                 Usages             = Usages is null ? null : [.. Usages.Select(CertificateUsage.Parse).Distinct()],
                                 Template           = Asked?.Template          ?? CSRTemplate.DefaultFor(Kind)!.Id,
                                 Role               = Asked?.Role,
                                 KeyUsages          = Asked?.KeyUsages         ?? [],
                                 ExtendedKeyUsages  = Asked?.ExtendedKeyUsages ?? [ CSRTemplate.DefaultFor(Kind)!.Purpose ],
                                 ReachableAs        = Asked?.ReachableAs       ?? []
                             };

            storeLock.Wait();

            try
            {

                // Moved over twice, it is the key it was the first time.
                if (requests.TryGetValue(id, out var known))
                {
                    Request = known;
                    return true;
                }

                if (!TryWriteRequest(request, KeyPEM.TrimEnd() + Environment.NewLine, out Error))
                {
                    NotSaved = true;
                    return false;
                }

                requests   [id] = request;
                requestKeys[id] = publicKey;

            }
            finally
            {
                storeLock.Release();
            }

            log.Metrological(LogLevel.Notice,
                             $"Certificates: the {request.Algorithm} key '{id}' for {subject} was taken over; its signing request is waiting to be collected.",
                             "certificates", "security");

            Request = request;

            Changed();

            return true;

        }

        #endregion

        #region TryAnswerRequest(PEM, out Entry, out RequestId, out Warnings, out Error, out NotSaved, AcceptExpired = false)

        /// <summary>
        /// The certificate a certificate authority sent back, and whatever
        /// intermediates came with it: put together with the key that waits
        /// for it, and kept as the kind its request was made for.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Nothing has to be said about which key it is for: it is matched by
        /// its public key. Where no request waits for it, a certificate for
        /// the key of an identity that is here already - a renewal that kept
        /// its key - is put together with that key, and kept beside the one
        /// it renews.
        /// </para>
        /// <para>
        /// What could not be used is refused here, while somebody is looking,
        /// rather than at the next handshake: a certificate for nobody's key,
        /// and one that has run out. A certificate this runtime cannot load
        /// together with its key is kept beside the key and passed over -
        /// <paramref name="Entry"/> is null then, and
        /// <paramref name="Warnings"/> say why.
        /// </para>
        /// </remarks>
        /// <param name="PEM">The certificate, and any intermediates, as PEM.</param>
        /// <param name="Entry">The identity it became, or null where it is kept beside its key and cannot be held up.</param>
        /// <param name="RequestId">The key it answers, or null where it renews an identity that is here already.</param>
        /// <param name="Warnings">What somebody should know about it although it was taken in.</param>
        /// <param name="Error">Why it was not taken in.</param>
        /// <param name="NotSaved">True where its files could not be written: nothing about the certificate was wrong.</param>
        /// <param name="AcceptExpired">Whether one that has run out is taken in all the same: for what a node moves over, and never for what somebody brings.</param>
        public Boolean TryAnswerRequest(String                            PEM,
                                        out CertificateEntry?             Entry,
                                        out String?                       RequestId,
                                        out IReadOnlyList<String>         Warnings,
                                        [NotNullWhen(false)] out String?  Error,
                                        out Boolean                       NotSaved,
                                        Boolean                           AcceptExpired = false)
        {

            Entry      = null;
            RequestId  = null;
            Warnings   = [];
            Error      = null;
            NotSaved   = false;

            #region What was brought

            var brought = new X509Certificate2Collection();

            try
            {
                brought.ImportFromPem(PEM);
            }
            catch (Exception e)
            {
                Error = $"This is not a certificate: {e.Message}";
                return false;
            }

            if (brought.Count == 0)
            {
                Error = "There is no certificate in this. What is expected is PEM - the '-----BEGIN CERTIFICATE-----' kind - " +
                        $"with the certificate of this {NodeName} first and any intermediates after it.";
                return false;
            }

            #endregion

            try
            {

                #region Whose is it?

                X509Certificate2?                 leaf     = null;
                SigningRequest?               request  = null;
                String?                           keyPEM   = null;
                CertificateKind                   kind     = default;
                IReadOnlyList<CertificateUsage>?  usages   = null;
                String?                           label    = null;

                storeLock.Wait();

                try
                {

                    foreach (var certificate in brought)
                    {

                        var spki  = certificate.PublicKey.ExportSubjectPublicKeyInfo();
                        var match = requestKeys.FirstOrDefault(pair => pair.Value.AsSpan().SequenceEqual(spki));

                        if (match.Key is null)
                            continue;

                        leaf     = certificate;
                        request  = requests[match.Key];
                        kind     = request.Kind;
                        usages   = request.Usages;
                        label    = request.Label;

                        break;

                    }

                    if (request is not null)
                    {
                        try
                        {
                            keyPEM = File.ReadAllText(RequestFile(request.Id, "key.pem"));
                        }
                        catch (Exception e)
                        {
                            Error = $"The key '{request.Id}' this certificate answers could not be read: {e.Message}";
                            return false;
                        }
                    }

                    // No request waits for it: the key of an identity that is
                    // here already, then - a renewal that kept its key.
                    else
                    {
                        foreach (var entry in entries.Values.Where(entry => entry.HasPrivateKey && RequestKinds.Contains(entry.Kind)))
                        {

                            if (!TryRead(FullPath(entry), out var held, out _, out _))
                                continue;

                            using (held)
                            {

                                var spki = held.PublicKey.ExportSubjectPublicKeyInfo();

                                leaf = brought.FirstOrDefault(certificate => certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(spki));

                                if (leaf is null || PrivateKeyPemOf(held) is not String key)
                                {
                                    leaf = null;
                                    continue;
                                }

                                keyPEM  = key;
                                kind    = entry.Kind;
                                usages  = entry.Usages;

                                break;

                            }

                        }
                    }

                }
                finally
                {
                    storeLock.Release();
                }

                if (leaf is null || keyPEM is null)
                {
                    Error = $"None of the certificates in this belongs to a key of this {NodeName}. " +
                             "A certificate without its key is only usable here if it answers a signing request made here.";
                    return false;
                }

                #endregion

                var now       = DateTimeOffset.UtcNow;
                var notAfter  = new DateTimeOffset(leaf.NotAfter. ToUniversalTime());
                var notBefore = new DateTimeOffset(leaf.NotBefore.ToUniversalTime());

                if (notAfter <= now && !AcceptExpired)
                {
                    Error = $"This certificate expired on {notAfter:yyyy-MM-dd} and can never be used. " +
                            $"By the clock of this {NodeName} it is now {now:yyyy-MM-dd}.";
                    return false;
                }

                var warnings = new List<String>();

                if (notBefore > now)
                    warnings.Add($"It only becomes valid on {notBefore:yyyy-MM-dd}; until then it is kept and shown to nobody.");

                else if (notAfter > now && (notAfter - now).TotalDays <= WarnsDaysBefore)
                    warnings.Add($"It runs out in {Math.Max(0, (Int32) Math.Floor((notAfter - now).TotalDays))} day(s), on {notAfter:yyyy-MM-dd}.");

                else if (notAfter <= now)
                    warnings.Add($"It ran out on {notAfter:yyyy-MM-dd}.");

                var others = brought.Where(certificate => !certificate.RawData.AsSpan().SequenceEqual(leaf.RawData)).ToArray();

                var chain  = String.Concat(new[] { leaf }.Concat(others).
                                               Select(certificate => PemEncoding.WriteString("CERTIFICATE", certificate.RawData) + "\n"));

                #region A key this runtime cannot hold up

                String? cannot = null;

                try
                {
                    using var paired = X509Certificate2.CreateFromPem(leaf.ExportCertificatePem(), keyPEM);
                }
                catch (Exception e)
                {
                    cannot = $"This runtime cannot load a certificate together with a key of this kind ({e.Message}).";
                }

                if (cannot is not null)
                {

                    if (request is null)
                    {
                        Error = cannot;
                        return false;
                    }

                    var kept = new SigningRequest(request.Id, request.Kind, request.AlgorithmId, request.Algorithm, request.CreatedAt, request.Subject, request.CSR) {
                                   Label                = request.Label,
                                   Usages               = request.Usages,
                                   Template             = request.Template,
                                   Role                 = request.Role,
                                   KeyUsages            = request.KeyUsages,
                                   ExtendedKeyUsages    = request.ExtendedKeyUsages,
                                   ReachableAs          = request.ReachableAs,
                                   CannotBeHeldUp       = cannot,
                                   CertificateSubject   = leaf.Subject,
                                   CertificateIssuer    = leaf.Issuer,
                                   CertificateNotAfter  = notAfter
                               };

                    storeLock.Wait();

                    try
                    {

                        try
                        {
                            File.WriteAllText(RequestFile(request.Id, "cert.pem"), chain);
                            File.WriteAllText(RequestFile(request.Id, "json"),     MetaOf(kept));
                        }
                        catch (Exception e)
                        {
                            Error     = $"The certificate could not be written to '{RequestsDirectory}': {e.Message}";
                            NotSaved  = true;
                            return false;
                        }

                        requests[request.Id] = kept;

                    }
                    finally
                    {
                        storeLock.Release();
                    }

                    warnings.Insert(0, $"{cannot} It is kept beside its key and shown to nobody; a runtime that can load it will.");

                    RequestId  = request.Id;
                    Warnings   = warnings;

                    log.Metrological(LogLevel.Warning,
                                     $"Certificates: a certificate for '{leaf.Subject}' came for the key '{request.Id}' and is kept beside it: {cannot}",
                                     "certificates", "security");

                    Changed();

                    return true;

                }

                #endregion

                // Through the door every identity comes in by: checked for
                // its kind, written as the store writes one, and in the
                // index.
                if (!Import(System.Text.Encoding.ASCII.GetBytes(chain + keyPEM.TrimEnd() + "\n"),
                            kind,
                            null,
                            label,
                            usages?.Select(usage => usage.ToString()),
                            out var imported,
                            out Error,
                            out NotSaved))
                {
                    return false;
                }

                if (request is not null)
                {

                    storeLock.Wait();

                    try
                    {
                        ForgetRequest(request.Id);
                    }
                    finally
                    {
                        storeLock.Release();
                    }

                    log.Metrological(LogLevel.Notice,
                                     $"Certificates: the certificate for '{leaf.Subject}' came for the key '{request.Id}', valid until {notAfter:yyyy-MM-dd}: " +
                                     $"it is {kind.WithArticle()} of this {NodeName} now, '{imported.Id}'." +
                                     (warnings.Count > 0 ? $" {String.Join(" ", warnings)}" : ""),
                                     "certificates", "security");

                    Changed();

                }

                else
                    log.Metrological(LogLevel.Notice,
                                     $"Certificates: a certificate for '{leaf.Subject}' came for the key of an identity that is here already, valid until {notAfter:yyyy-MM-dd}: " +
                                     $"it is kept beside it, as '{imported.Id}'." +
                                     (warnings.Count > 0 ? $" {String.Join(" ", warnings)}" : ""),
                                     "certificates", "security");

                Entry      = imported;
                RequestId  = request?.Id;
                Warnings   = warnings;

                return true;

            }
            finally
            {
                foreach (var certificate in brought)
                    certificate.Dispose();
            }

        }

        #endregion

        #region TryRemoveRequest(Id, out Error, out NotSaved)

        /// <summary>
        /// Take a key that waits for its certificate away, for good: its
        /// request can be answered by nobody afterwards.
        /// </summary>
        /// <param name="Id">The key.</param>
        /// <param name="Error">Why it is still there.</param>
        /// <param name="NotSaved">True where its files could not be removed.</param>
        public Boolean TryRemoveRequest(String                            Id,
                                        [NotNullWhen(false)] out String?  Error,
                                        out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            SigningRequest? request;

            storeLock.Wait();

            try
            {

                if (!requests.TryGetValue(Id, out request))
                {
                    Error = $"This {NodeName} has no key '{Id}' that waits for its certificate.";
                    return false;
                }

                try
                {
                    // The key last: what is left where the rest could not be
                    // removed is still a key with its request.
                    foreach (var extension in new[] { "cert.pem", "json", "csr.pem", "key.pem" })
                        File.Delete(RequestFile(Id, extension));
                }
                catch (Exception e)
                {
                    Error     = $"The key '{Id}' could not be removed from '{RequestsDirectory}': {e.Message}";
                    NotSaved  = true;
                    return false;
                }

                requests.   Remove(Id);
                requestKeys.Remove(Id);

            }
            finally
            {
                storeLock.Release();
            }

            log.Metrological(LogLevel.Notice,
                             $"Certificates: the {request.Algorithm} key '{Id}' for {request.Subject}, which waited for its certificate, was removed.",
                             "certificates", "security");

            Changed();

            return true;

        }

        #endregion


        #region (private) ReadRequests()

        /// <summary>
        /// Read the keys that wait for their certificate again, from nothing.
        /// Called under the lock.
        /// </summary>
        /// <remarks>
        /// A key that cannot be read is skipped with a line in the log rather
        /// than thrown: one unreadable file must not stop a node.
        /// </remarks>
        private void ReadRequests()
        {

            requests.   Clear();
            requestKeys.Clear();

            if (RequestKinds.Count == 0 || !System.IO.Directory.Exists(RequestsDirectory))
                return;

            foreach (var keyFile in System.IO.Directory.GetFiles(RequestsDirectory, "*.key.pem").Order(StringComparer.Ordinal))
            {

                var id = Path.GetFileName(keyFile);
                id = id[..id.IndexOf(".key.pem", StringComparison.Ordinal)];

                try
                {

                    var csr = File.ReadAllText(RequestFile(id, "csr.pem"));

                    if (!TryReadRequest(csr, out var subject, out var publicKey, out var problem))
                    {
                        log.Warning($"Certificates: the key '{id}' in '{RequestsDirectory}' was left where it is - its signing request cannot be read: {problem}",
                                    "certificates");
                        continue;
                    }

                    if (KeyId(publicKey) != id)
                    {
                        log.Warning($"Certificates: the key '{id}' in '{RequestsDirectory}' was left where it is - its signing request is that of another key.",
                                    "certificates");
                        continue;
                    }

                    var meta       = File.Exists(RequestFile(id, "json"))
                                         ? JObject.Parse(File.ReadAllText(RequestFile(id, "json")))
                                         : [];

                    var kind       = CertificateKindExtensions.TryParseKind(meta.Value<String>("kind"), out var written) && RequestKinds.Contains(written)
                                         ? written
                                         : RequestKinds[0];

                    var algorithm  = KeyAlgorithm.Find(meta.Value<String>("algorithm"));

                    var createdAt  = DateTimeOffset.TryParse(meta.Value<String>("createdAt"),
                                                             System.Globalization.CultureInfo.InvariantCulture,
                                                             System.Globalization.DateTimeStyles.RoundtripKind,
                                                             out var parsed)
                                         ? parsed
                                         : new DateTimeOffset(File.GetLastWriteTimeUtc(keyFile));

                    String[] Names(String Name)
                        => meta[Name] is JArray names ? [.. names.Values<String>().OfType<String>()] : [];

                    var usages     = meta["usages"] is JArray marked
                                         ? marked.Values<String>().Select(name => CertificateUsage.TryParse(name)).OfType<CertificateUsage>().ToList()
                                         : null;

                    var came       = meta["certificate"] as JObject;

                    requests[id]   = new SigningRequest(id,
                                                            kind,
                                                            algorithm?.Id   ?? meta.Value<String>("algorithm") ?? DefaultAlgorithm,
                                                            algorithm?.Name ?? meta.Value<String>("algorithm") ?? "a key",
                                                            createdAt,
                                                            meta.Value<String>("subject") ?? subject,
                                                            csr) {
                                         Label                = meta.Value<String>("label"),
                                         Usages               = usages is { Count: > 0 } ? usages : null,
                                         Template             = meta.Value<String>("template") ?? CSRTemplate.DefaultFor(kind)!.Id,
                                         Role                 = meta.Value<String>("role"),
                                         KeyUsages            = Names("keyUsages"),
                                         ExtendedKeyUsages    = meta["extendedKeyUsages"] is JArray ? Names("extendedKeyUsages") : [ CSRTemplate.DefaultFor(kind)!.Purpose ],
                                         ReachableAs          = Names("reachableAs"),
                                         CannotBeHeldUp       = came?.Value<String>("cannotBeHeldUp"),
                                         CertificateSubject   = came?.Value<String>("subject"),
                                         CertificateIssuer    = came?.Value<String>("issuer"),
                                         CertificateNotAfter  = DateTimeOffset.TryParse(came?.Value<String>("notAfter"),
                                                                                        System.Globalization.CultureInfo.InvariantCulture,
                                                                                        System.Globalization.DateTimeStyles.RoundtripKind,
                                                                                        out var until)
                                                                    ? until
                                                                    : null
                                     };

                    requestKeys[id] = publicKey;

                }
                catch (Exception e)
                {
                    log.Warning($"Certificates: the key '{id}' in '{RequestsDirectory}' could not be read and was left where it is - {e.Message}",
                                "certificates");
                }

            }

            if (requests.Count > 0)
                log.Info($"Certificates: {requests.Count} key(s) in '{RequestsDirectory}' wait for their certificate.",
                         "certificates");

        }

        #endregion

        #region (private) TryWriteRequest(Request, KeyPEM, out Error) / ForgetRequest(Id) / MetaOf(Request) / RequestFile(Id, Extension)

        /// <summary>
        /// Write a key down, with its request and what was asked for: the key
        /// first, into a file nobody but its owner may read before anything
        /// is in it. Called under the lock.
        /// </summary>
        private Boolean TryWriteRequest(SigningRequest                Request,
                                        String                            KeyPEM,
                                        [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            try
            {

                OwnerOnly.Directory(RequestsDirectory, Complain);

                var keyFile = RequestFile(Request.Id, "key.pem");

                File.WriteAllText(keyFile, "");
                Protect(keyFile);
                File.WriteAllText(keyFile, KeyPEM);

                File.WriteAllText(RequestFile(Request.Id, "csr.pem"), Request.CSR);
                File.WriteAllText(RequestFile(Request.Id, "json"),    MetaOf(Request));

                return true;

            }
            catch (Exception e)
            {

                // What was written of it goes again: a key without its
                // request is one every start would complain about, and keep.
                foreach (var extension in new[] { "key.pem", "csr.pem", "json" })
                {
                    try
                    {
                        File.Delete(RequestFile(Request.Id, extension));
                    }
                    catch
                    { }
                }

                Error = $"The key could not be written to '{RequestsDirectory}': {e.Message}";
                return false;

            }

        }

        /// <summary>
        /// A request that was answered is gone, with everything of it - its
        /// key is in the identity it became. Called under the lock.
        /// </summary>
        private void ForgetRequest(String Id)
        {

            foreach (var extension in new[] { "cert.pem", "json", "csr.pem", "key.pem" })
            {
                try
                {
                    File.Delete(RequestFile(Id, extension));
                }
                catch (Exception e)
                {
                    log.Warning($"Certificates: '{RequestsDirectoryName}/{Id}.{extension}' could not be removed although its certificate has come: {e.Message}",
                                "certificates");
                }
            }

            requests.   Remove(Id);
            requestKeys.Remove(Id);

        }

        private static String MetaOf(SigningRequest Request)
        {

            var json = Request.ToJSON(WithCSR: false);

            if (Request.CannotBeHeldUp is not null)
                json.Add("certificate", new JObject(
                                            new JProperty("subject",         Request.CertificateSubject),
                                            new JProperty("issuer",          Request.CertificateIssuer),
                                            new JProperty("notAfter",        Request.CertificateNotAfter?.ToString("o")),
                                            new JProperty("cannotBeHeldUp",  Request.CannotBeHeldUp)
                                        ));

            return json.ToString(Formatting.Indented) + Environment.NewLine;

        }

        private String RequestFile(String Id, String Extension)
            => Path.Combine(RequestsDirectory, $"{Id}.{Extension}");

        #endregion

        #region (private static) TryReadRequest(CSR, out Subject, out PublicKey, out Error) / KeyId(SubjectPublicKeyInfo)

        /// <summary>
        /// Who a signing request is about, and the public key it names - which
        /// is read from the request rather than from the key, so that nothing
        /// has to be told which of a dozen kinds of key to expect.
        /// </summary>
        private static Boolean TryReadRequest(String                            CSR,
                                              out String                        Subject,
                                              out Byte[]                        PublicKey,
                                              [NotNullWhen(false)] out String?  Error)
        {

            Subject    = "";
            PublicKey  = [];
            Error      = null;

            try
            {

                if (new PemReader(new StringReader(CSR)).ReadObject() is not Pkcs10CertificationRequest request)
                {
                    Error = "it is no PKCS#10 signing request in PEM.";
                    return false;
                }

                var info   = request.GetCertificationRequestInfo();

                Subject    = info.Subject.ToString();
                PublicKey  = info.SubjectPublicKeyInfo.GetDerEncoded();

                return true;

            }
            catch (Exception e)
            {
                Error = e.Message;
                return false;
            }

        }

        /// <summary>
        /// What a key is called here: the first sixteen hexadecimal digits of
        /// the SHA-256 of its public key, as a certificate carries it.
        /// </summary>
        private static String KeyId(Byte[] SubjectPublicKeyInfo)
            => Convert.ToHexStringLower(SHA256.HashData(SubjectPublicKeyInfo).AsSpan(0, 8));

        #endregion

    }

}
