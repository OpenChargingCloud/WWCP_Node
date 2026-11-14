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

using System.Security.Cryptography;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The keys a node makes for itself, in its certificate store: each with a
    /// signing request that waits for its certificate, and an identity like
    /// any other once that has come.
    /// </summary>
    /// <remarks>
    /// Two questions are kept apart throughout, because they have different
    /// answers: whether a key and its signing request can be <em>made</em>,
    /// which is the same everywhere and true of every kind, and whether this
    /// platform can then <em>load</em> the certificate that comes back
    /// together with its key - which depends on the runtime and the year. .NET
    /// has no key object at all for an Ed448 or an ML-DSA key today, and such
    /// a certificate is kept beside its key rather than refused.
    /// </remarks>
    [TestFixture]
    public class CertificateRequestTests
    {

        #region Data

        private String            directory  = "";
        private EventLog          log        = new ();
        private CertificateStore  store      = default!;

        /// <summary>
        /// Every algorithm, by identification - so a new one in Hermod's list
        /// is a new test case without a line being added here.
        /// </summary>
        public static IEnumerable<String> EveryAlgorithm
            => KeyAlgorithm.All.Select(algorithm => algorithm.Id);

        private const String SunSpecRole = "1.3.6.1.4.1.50316.802.1";

        #endregion

        #region SetUp / TearDown

        private CertificateStore AStore()
        {

            var made = new CertificateStore(directory,
                                            log,
                                            [ CertificateKind.TLSRoot, CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ],
                                            "charging station",
                                            [ "csms", "meters" ],
                                            RequestKinds: [ CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ]);

            made.Reload();

            return made;

        }

        [SetUp]
        public void MakeAStore()
        {
            directory  = Path.Combine(Path.GetTempPath(), "node-certificate-requests-" + Guid.NewGuid().ToString("N")[..12]);
            log        = new EventLog();
            store      = AStore();
        }

        [TearDown]
        public void TakeItAwayAgain()
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }
        }

        #endregion

        #region (private) Helpers

        private SigningRequest AKey(String                   Subject     = "cs001.example.org",
                                        String?                  Algorithm   = "ecdsa-p256",
                                        CertificateRequestAsks?  Asks        = null,
                                        IEnumerable<String>?     Usages      = null,
                                        String?                  Label       = null)
        {

            Assert.That(store.TryCreateRequest(CertificateKind.TLSIdentity, Subject, Algorithm, Asks, Usages, Label, out var request, out var error, out _),
                        Is.True, error);

            return request!;

        }

        /// <summary>
        /// What a certificate authority would send back for a signing
        /// request: the request, signed, and the authority's own certificate.
        /// </summary>
        private static String ACertificateFor(String CSR, TimeSpan? LifeTime = null)
        {

            var request  = (new PemReader(new StringReader(CSR)).ReadObject() as Pkcs10CertificationRequest)!;
            var caKeys   = PKIFactory.GenerateECCKeyPair("secp256r1");

            var ca       = PKIFactory.CreateRootCACertificate(
                               RootKeyPair:  caKeys,
                               SubjectName:  "Test CSMS CA"
                           );

            var issued   = PKIFactory.SignClientCertificate(
                               request,
                               caKeys.Private,
                               ca,
                               lifeTime: LifeTime ?? TimeSpan.FromDays(365)
                           );

            return String.Join(
                       Environment.NewLine,
                       PemEncoding.WriteString("CERTIFICATE", issued.GetEncoded()),
                       PemEncoding.WriteString("CERTIFICATE", ca.    GetEncoded())
                   ) + Environment.NewLine;

        }

        /// <summary>
        /// The extensions a signing request asks for.
        /// </summary>
        private static X509Extensions ExtensionsOf(String CSR)
        {

            var request = (new PemReader(new StringReader(CSR)).ReadObject() as Pkcs10CertificationRequest)!;

            Assert.That(request.Verify(), Is.True, "The signing request is not signed by the key it names.");

            return X509Extensions.GetInstance(
                       AttributePkcs.GetInstance(
                           request.GetCertificationRequestInfo().Attributes!.ToArray().
                               First(entry => AttributePkcs.GetInstance(entry).AttrType.
                                                  Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                       ).AttrValues[0]
                   );

        }

        private String[] RequestFiles
            => Directory.Exists(Path.Combine(directory, CertificateStore.RequestsDirectoryName))
                   ? [.. Directory.GetFiles(Path.Combine(directory, CertificateStore.RequestsDirectoryName)).Select(file => Path.GetFileName(file)!).Order()]
                   : [];

        #endregion


        #region ANodeMakesNoKeys_UnlessItsKindSaysSo()

        /// <summary>
        /// Which kinds a node makes keys for is the node's to say, and none
        /// by default - and only what carries its key, and is kept.
        /// </summary>
        [Test]
        public void ANodeMakesNoKeys_UnlessItsKindSaysSo()
        {

            var plain = new CertificateStore(Path.Combine(directory, "plain"), log, [ CertificateKind.TLSRoot, CertificateKind.TLSIdentity ]);

            Assert.Multiple(() => {

                Assert.That(plain.RequestKinds, Is.Empty);

                Assert.That(plain.TryCreateRequest(CertificateKind.TLSIdentity, "cs001.example.org", null, null, null, null, out _, out var none, out _),
                            Is.False);
                Assert.That(none, Does.Contain("makes no keys"));

                Assert.That(store.TryCreateRequest(CertificateKind.TLSRoot, "cs001.example.org", null, null, null, null, out _, out var noRoot, out _),
                            Is.False, "A key was made for a root.");
                Assert.That(noRoot, Does.Contain("tlsIdentity"));

                Assert.That(() => new CertificateStore(Path.Combine(directory, "roots"), log, [ CertificateKind.TLSRoot ], RequestKinds: [ CertificateKind.TLSRoot ]),
                            Throws.ArgumentException);

                Assert.That(() => new CertificateStore(Path.Combine(directory, "unkept"), log, [ CertificateKind.TLSRoot ], RequestKinds: [ CertificateKind.TLSIdentity ]),
                            Throws.ArgumentException);

            });

        }

        #endregion

        #region EveryAlgorithmMakesAKeyAndARequestThatVerifies(Algorithm)

        /// <summary>
        /// The signing request is signed by the key it names, and says so -
        /// asking for a client certificate, and naming nothing the node is
        /// reachable as: it is not something anybody dials.
        /// </summary>
        [Test]
        [TestCaseSource(nameof(EveryAlgorithm))]
        public void EveryAlgorithmMakesAKeyAndARequestThatVerifies(String Algorithm)
        {

            var request     = AKey(Algorithm: Algorithm);
            var extensions  = ExtensionsOf(request.CSR);
            var usage       = ExtendedKeyUsage.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.ExtendedKeyUsage));

            Assert.Multiple(() => {

                Assert.That(request.Subject,      Does.Contain("cs001.example.org"));
                Assert.That(request.AlgorithmId,  Is.EqualTo(Algorithm));
                Assert.That(request.Id,           Has.Length.EqualTo(16));

                Assert.That(usage.HasKeyPurposeId(KeyPurposeID.id_kp_clientAuth), Is.True,
                            "The request does not ask for a client certificate.");

                Assert.That(usage.HasKeyPurposeId(KeyPurposeID.id_kp_serverAuth), Is.False,
                            "The request also asks to be a server.");

                Assert.That(extensions.GetExtension(X509Extensions.SubjectAlternativeName), Is.Null,
                            "The request names addresses the node is supposedly reachable at.");

                Assert.That(RequestFiles, Is.EqualTo(new[] { $"{request.Id}.csr.pem", $"{request.Id}.json", $"{request.Id}.key.pem" }));

            });

        }

        #endregion

        #region AKeySurvivesARestart()

        /// <summary>
        /// A key whose request is out is still there when the node comes
        /// back - with what it was made for, and to.
        /// </summary>
        [Test]
        public void AKeySurvivesARestart()
        {

            var made   = AKey(Algorithm: "ecdsa-p384",
                              Asks:      new CertificateRequestAsks(Template: CSRTemplate.ModbusTLSId, Role: "GridServiceSunSpec", KeyUsages: [ "keyAgreement" ]),
                              Usages:    [ "meters" ],
                              Label:     "The meters' reader");

            var again  = AStore().Requests.SingleOrDefault(request => request.Id == made.Id);

            Assert.That(again, Is.Not.Null, "The key is gone after a restart.");

            Assert.Multiple(() => {
                Assert.That(again!.Algorithm,                           Is.EqualTo("ECDSA P-384 (secp384r1)"), "What kind of key it is was not remembered.");
                Assert.That(again.Kind,                                 Is.EqualTo(CertificateKind.TLSIdentity));
                Assert.That(again.Subject,                              Does.Contain("cs001.example.org"));
                Assert.That(again.CSR,                                  Is.EqualTo(made.CSR));
                Assert.That(again.Label,                                Is.EqualTo("The meters' reader"));
                Assert.That(again.Usages?.Select(usage => usage.ToString()),  Is.EqualTo(new[] { "meters" }));
                Assert.That(again.Template,                             Is.EqualTo("modbus-tls"));
                Assert.That(again.Role,                                 Is.EqualTo("GridServiceSunSpec"));
                Assert.That(again.KeyUsages,                            Is.EqualTo(new[] { "digitalSignature", "keyAgreement" }));
                Assert.That(again.ExtendedKeyUsages,                    Is.EqualTo(new[] { "clientAuth" }));
            });

        }

        #endregion

        #region ACertificateThatComesBack_MakesTheKeyAnIdentity()

        /// <summary>
        /// The certificate is matched to the key whose request it answers,
        /// and the two are an identity of the store from then on: with its
        /// key, under the label and for the uses its request was made with -
        /// and the request is gone, with its files.
        /// </summary>
        [Test]
        public void ACertificateThatComesBack_MakesTheKeyAnIdentity()
        {

            var other    = AKey("cs002.example.org");
            var request  = AKey(Usages: [ "csms" ], Label: "Who we are to the CSMS");
            var changes  = 0;

            store.OnChanged += () => changes++;

            Assert.That(store.TryAnswerRequest(ACertificateFor(request.CSR), out var entry, out var answered, out var warnings, out var error, out _),
                        Is.True, error);

            Assert.Multiple(() => {

                Assert.That(answered,                        Is.EqualTo(request.Id), "The certificate was filed under another key.");
                Assert.That(warnings,                        Is.Empty);
                Assert.That(changes,                         Is.GreaterThan(0), "Nobody was told that the store changed.");

                Assert.That(entry,                           Is.Not.Null);
                Assert.That(entry!.Kind,                     Is.EqualTo(CertificateKind.TLSIdentity));
                Assert.That(entry.HasPrivateKey,             Is.True, "The identity came without its key.");
                Assert.That(entry.IsActive,                  Is.True);
                Assert.That(entry.Label,                     Is.EqualTo("Who we are to the CSMS"));
                Assert.That(entry.Usages?.Select(usage => usage.ToString()),  Is.EqualTo(new[] { "csms" }));
                Assert.That(entry.Subject,                   Does.Contain("cs001.example.org"));
                // The root is not the identity's: it travels with it, as a sub-CA would.
                Assert.That(entry.ChainLength,               Is.EqualTo(1));

                Assert.That(store.Requests.Select(waiting => waiting.Id),  Is.EqualTo(new[] { other.Id }), "The key that was answered still waits.");
                Assert.That(RequestFiles.Any(file => file.StartsWith(request.Id)),  Is.False, "Files of the answered request are left.");

                Assert.That(store.ByKind(CertificateKind.TLSIdentity).Select(one => one.Id),  Is.EqualTo(new[] { entry.Id }));

            });

            Assert.That(store.TryLoad(entry!, out var loaded, out var problem), Is.True, problem);

            using (loaded)
                Assert.That(loaded!.HasPrivateKey, Is.True, "What is loaded for a handshake has no key.");

            // And it is still an identity, and no request, after a restart.
            var again = AStore();

            Assert.Multiple(() => {
                Assert.That(again.ByKind(CertificateKind.TLSIdentity).Select(one => one.Id),  Is.EqualTo(new[] { entry!.Id }));
                Assert.That(again.Requests.Select(waiting => waiting.Id),                      Is.EqualTo(new[] { other.Id }));
            });

        }

        #endregion

        #region EveryAlgorithmGoesTheWholeWayRound(Algorithm)

        /// <summary>
        /// Every kind of key gets its certificate back - as an identity
        /// where this runtime can hold it up, and kept beside its key, with
        /// the reason, where it cannot. Never refused, and never lost.
        /// </summary>
        [Test]
        [TestCaseSource(nameof(EveryAlgorithm))]
        public void EveryAlgorithmGoesTheWholeWayRound(String Algorithm)
        {

            var request = AKey(Algorithm: Algorithm);

            Assert.That(store.TryAnswerRequest(ACertificateFor(request.CSR), out var entry, out var answered, out var warnings, out var error, out _),
                        Is.True, error);

            Assert.That(answered, Is.EqualTo(request.Id));

            if (entry is not null)
            {
                Assert.Multiple(() => {
                    Assert.That(entry.HasPrivateKey,  Is.True);
                    Assert.That(store.Requests,       Is.Empty);
                });
            }

            else
            {

                var kept = AStore().Requests.Single();

                Assert.Multiple(() => {
                    Assert.That(kept.Id,                   Is.EqualTo(request.Id));
                    Assert.That(kept.CannotBeHeldUp,       Is.Not.Null.And.Not.Empty, "Why it is no identity is not said.");
                    Assert.That(kept.CertificateSubject,   Does.Contain("cs001.example.org"));
                    Assert.That(warnings,                  Is.Not.Empty);
                    Assert.That(RequestFiles,              Does.Contain($"{request.Id}.cert.pem"));
                    Assert.That(store.ByKind(CertificateKind.TLSIdentity),  Is.Empty);
                });

            }

            // What every server understands is an identity on every platform.
            if (Algorithm.StartsWith("ecdsa-") || Algorithm.StartsWith("rsa-"))
                Assert.That(entry, Is.Not.Null, $"A certificate for a {Algorithm} key cannot be held up.");

        }

        #endregion

        #region ACertificateForSomebodyElsesKeyIsRefused()

        /// <summary>
        /// A certificate is only usable here if it answers a request made
        /// here - and what is no certificate at all is said to be none.
        /// </summary>
        [Test]
        public void ACertificateForSomebodyElsesKeyIsRefused()
        {

            var mine    = AKey();
            var theirs  = AStoreOf("theirs").Item2;

            Assert.Multiple(() => {

                Assert.That(store.TryAnswerRequest(ACertificateFor(theirs.CSR), out _, out _, out _, out var notOurs, out var notSaved),
                            Is.False, "A certificate for a key that is not here was taken in.");
                Assert.That(notOurs,   Does.Contain("answers a signing request made here"));
                Assert.That(notSaved,  Is.False);

                Assert.That(store.TryAnswerRequest("this is not a certificate", out _, out _, out _, out var notPEM, out _), Is.False);
                Assert.That(notPEM,    Is.Not.Null);

                Assert.That(store.Requests.Select(request => request.Id),  Is.EqualTo(new[] { mine.Id }));
                Assert.That(store.ByKind(CertificateKind.TLSIdentity),     Is.Empty);

            });

        }

        private (CertificateStore, SigningRequest) AStoreOf(String Name)
        {

            var another = new CertificateStore(Path.Combine(directory, Name), log, [ CertificateKind.TLSIdentity ], RequestKinds: [ CertificateKind.TLSIdentity ]);

            Assert.That(another.TryCreateRequest(CertificateKind.TLSIdentity, "cs999.example.org", null, null, null, null, out var request, out var error, out _),
                        Is.True, error);

            return (another, request!);

        }

        #endregion

        #region ACertificateThatHasRunOut_IsRefusedWhileSomebodyIsLooking()

        /// <summary>
        /// A certificate that can never be used is refused when it is
        /// brought, with both dates - and taken in all the same where a node
        /// moves over what it had.
        /// </summary>
        [Test]
        public void ACertificateThatHasRunOut_IsRefusedWhileSomebodyIsLooking()
        {

            var request  = AKey();
            var expired  = ACertificateFor(request.CSR, TimeSpan.FromSeconds(1));

            Thread.Sleep(1500);

            Assert.Multiple(() => {

                Assert.That(store.TryAnswerRequest(expired, out _, out _, out _, out var error, out _), Is.False);
                Assert.That(error,           Does.Contain("expired on"));
                Assert.That(store.Requests,  Has.Count.EqualTo(1), "The key went with the certificate that was refused.");

            });

            Assert.That(store.TryAnswerRequest(expired, out var entry, out _, out var warnings, out var problem, out _, AcceptExpired: true),
                        Is.True, problem);

            Assert.Multiple(() => {
                Assert.That(entry?.IsExpired,  Is.True);
                Assert.That(warnings,          Has.Some.Contains("ran out"));
            });

        }

        #endregion

        #region ARenewalForTheSameKey_IsKeptBesideTheIdentityItRenews()

        /// <summary>
        /// A certificate authority that renews without a new key sends a
        /// certificate no request waits for: it is put together with the key
        /// of the identity that is here, and kept beside it - for the same
        /// uses.
        /// </summary>
        [Test]
        public void ARenewalForTheSameKey_IsKeptBesideTheIdentityItRenews()
        {

            var request = AKey(Usages: [ "csms" ]);

            Assert.That(store.TryAnswerRequest(ACertificateFor(request.CSR, TimeSpan.FromDays(20)), out var first, out _, out var soon, out var error, out _),
                        Is.True, error);

            Assert.That(soon, Has.Some.Contains("runs out in"), "A certificate that runs out within a month was taken in without a word.");

            Assert.That(store.TryAnswerRequest(ACertificateFor(request.CSR), out var second, out var answered, out _, out error, out _),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(answered,                    Is.Null, "A request is said to have been answered where none waited.");
                Assert.That(second?.Id,                  Is.Not.EqualTo(first?.Id));
                Assert.That(second?.HasPrivateKey,       Is.True);
                Assert.That(second?.Usages?.Select(usage => usage.ToString()),  Is.EqualTo(new[] { "csms" }));
                Assert.That(store.ByKind(CertificateKind.TLSIdentity),          Has.Count.EqualTo(2));
            });

        }

        #endregion

        #region AKeyIsRemoved_WithEverythingOfIt()

        /// <summary>
        /// A key nobody will bring a certificate for is taken away for good.
        /// </summary>
        [Test]
        public void AKeyIsRemoved_WithEverythingOfIt()
        {

            var gone  = AKey();
            var kept  = AKey("cs002.example.org");

            Assert.That(store.TryRemoveRequest(gone.Id, out var error, out _), Is.True, error);

            Assert.Multiple(() => {

                Assert.That(store.Requests.Select(request => request.Id),         Is.EqualTo(new[] { kept.Id }));
                Assert.That(RequestFiles.Any(file => file.StartsWith(gone.Id)),   Is.False);
                Assert.That(AStore().Request(gone.Id),                            Is.Null);

                Assert.That(store.TryRemoveRequest(gone.Id, out var twice, out _), Is.False);
                Assert.That(twice, Does.Contain("no key"));

                Assert.That(store.TryAnswerRequest(ACertificateFor(gone.CSR), out _, out _, out _, out var tooLate, out _), Is.False,
                            "A certificate was taken in for a key that is gone.");
                Assert.That(tooLate, Is.Not.Null);

            });

        }

        #endregion

        #region ARequestAsksForWhatWasTickedBesideTheUsual()

        /// <summary>
        /// Key usages and extended key usages beside the ones every request
        /// has - by name, and by object identifier for the ones no list has.
        /// </summary>
        [Test]
        public void ARequestAsksForWhatWasTickedBesideTheUsual()
        {

            var request     = AKey(Asks: new CertificateRequestAsks(
                                             KeyUsages:          [ "keyAgreement", "nonRepudiation" ],
                                             ExtendedKeyUsages:  [ "serverAuth", "1.3.6.1.4.1.311.20.2.2", "clientAuth", "1.3.6.1.5.5.7.3.1" ]
                                         ));

            var extensions  = ExtensionsOf(request.CSR);
            var keyUsage    = KeyUsage.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.KeyUsage));
            var purposes    = ExtendedKeyUsage.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.ExtendedKeyUsage));

            Assert.Multiple(() => {

                Assert.That(keyUsage.IntValue & 0xFFFF,
                            Is.EqualTo(KeyUsage.DigitalSignature | KeyUsage.KeyAgreement | KeyUsage.NonRepudiation));

                Assert.That(purposes.GetAllUsages().Select(purpose => purpose.Id),
                            Is.EqualTo(new[] { KeyPurposeID.id_kp_clientAuth.Id, KeyPurposeID.id_kp_serverAuth.Id, "1.3.6.1.4.1.311.20.2.2" }),
                            "clientAuth first, each purpose once - named or by its number");

                Assert.That(request.KeyUsages,          Is.EqualTo(new[] { "digitalSignature", "keyAgreement", "nonRepudiation" }));
                Assert.That(request.ExtendedKeyUsages,  Is.EqualTo(new[] { "clientAuth", "serverAuth", "1.3.6.1.4.1.311.20.2.2" }));
                Assert.That(request.Template,           Is.EqualTo(CSRTemplate.ClientId));

            });

        }

        #endregion

        #region AModbusTLSRequestCarriesItsRole()

        /// <summary>
        /// The template for Modbus/TLS asks for a client certificate with the
        /// role its holder may play, in the extension a Modbus/TLS server
        /// reads - and a request made to no template carries none.
        /// </summary>
        [Test]
        public void AModbusTLSRequestCarriesItsRole()
        {

            var request     = AKey(Asks: new CertificateRequestAsks(Template: CSRTemplate.ModbusTLSId, Role: " GridServiceSunSpec "));
            var extensions  = ExtensionsOf(request.CSR);
            var role        = extensions.GetExtension(new DerObjectIdentifier(SunSpecRole));
            var purposes    = ExtendedKeyUsage.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.ExtendedKeyUsage));
            var json        = request.ToJSON();

            Assert.Multiple(() => {

                Assert.That(role,                                                           Is.Not.Null, "The request carries no role extension.");
                Assert.That(role?.IsCritical,                                               Is.False);
                Assert.That(DerUtf8String.GetInstance(role?.GetParsedValue()).GetString(),  Is.EqualTo("GridServiceSunSpec"));
                Assert.That(purposes.HasKeyPurposeId(KeyPurposeID.id_kp_clientAuth),        Is.True);

                Assert.That(request.Template,                         Is.EqualTo("modbus-tls"));
                Assert.That(request.Role,                             Is.EqualTo("GridServiceSunSpec"));
                Assert.That(json["templateName"]?.ToString(),         Does.Contain("Modbus/TLS"));
                Assert.That(json["csr"]?.ToString(),                  Is.EqualTo(request.CSR));

                Assert.That(CSRTemplate.For(CertificateKind.TLSIdentity).      Select(template => template.Id),  Is.EqualTo(new[] { "tls-client", "modbus-tls" }));
                Assert.That(CSRTemplate.For(CertificateKind.TLSServerIdentity).Select(template => template.Id),  Is.EqualTo(new[] { "tls-server" }));

            });

            Assert.That(ExtensionsOf(AKey("cs002.example.org").CSR).GetExtension(new DerObjectIdentifier(SunSpecRole)), Is.Null);

        }

        #endregion

        #region AServersRequestNamesWhatItIsReachableAs()

        /// <summary>
        /// A request for a server's identity asks for a server certificate,
        /// for the names and addresses it is reachable as - and for none
        /// without one, since nobody connecting would believe it.
        /// </summary>
        [Test]
        public void AServersRequestNamesWhatItIsReachableAs()
        {

            Assert.That(store.TryCreateRequest(CertificateKind.TLSServerIdentity,
                                               "meter7.example.org",
                                               null,
                                               new CertificateRequestAsks(ReachableAs: [ "meter7.example.org", " 192.0.2.7 ", "METER7.example.org" ]),
                                               null,
                                               null,
                                               out var request,
                                               out var error,
                                               out _),
                        Is.True, error);

            var extensions  = ExtensionsOf(request!.CSR);
            var purposes    = ExtendedKeyUsage.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.ExtendedKeyUsage));
            var names       = GeneralNames.GetInstance(extensions.GetExtensionParsedValue(X509Extensions.SubjectAlternativeName)).GetNames();

            Assert.Multiple(() => {

                Assert.That(purposes.HasKeyPurposeId(KeyPurposeID.id_kp_serverAuth),  Is.True);
                Assert.That(purposes.HasKeyPurposeId(KeyPurposeID.id_kp_clientAuth),  Is.False);

                Assert.That(names.Select(name => name.TagNo),  Is.EqualTo(new[] { GeneralName.DnsName, GeneralName.IPAddress }));

                Assert.That(request.Kind,         Is.EqualTo(CertificateKind.TLSServerIdentity));
                Assert.That(request.Template,     Is.EqualTo("tls-server"));
                Assert.That(request.ReachableAs,  Is.EqualTo(new[] { "meter7.example.org", "192.0.2.7" }));

                Assert.That(store.TryCreateRequest(CertificateKind.TLSServerIdentity, "meter7.example.org", null, null, null, null, out _, out var nameless, out _),
                            Is.False);
                Assert.That(nameless, Does.Contain("reachable as"));

                Assert.That(store.TryCreateRequest(CertificateKind.TLSIdentity, "cs001.example.org", null,
                                                   new CertificateRequestAsks(ReachableAs: [ "cs001.example.org" ]), null, null, out _, out var dialled, out _),
                            Is.False);
                Assert.That(dialled, Does.Contain("reachable as nothing"));

                Assert.That(store.TryCreateRequest(CertificateKind.TLSServerIdentity, "meter7.example.org", null,
                                                   new CertificateRequestAsks(Template: "modbus-tls", Role: "ReadOnlySunSpec", ReachableAs: [ "meter7" ]), null, null, out _, out var noServers, out _),
                            Is.False, "A server's identity was made to a client's template.");
                Assert.That(noServers, Does.Contain("tls-server"));

            });

        }

        #endregion

        #region WhatSomebodyMayNotAskFor()

        /// <summary>
        /// What somebody types, and what happens when it is wrong: refused
        /// with what may be asked for instead, and nothing of a key kept.
        /// </summary>
        [Test]
        public void WhatSomebodyMayNotAskFor()
        {

            Boolean Made(String Subject, String? Algorithm, CertificateRequestAsks? Asks, out String? Why, IEnumerable<String>? Usages = null)
                => store.TryCreateRequest(CertificateKind.TLSIdentity, Subject, Algorithm, Asks, Usages, null, out _, out Why, out _);

            Assert.Multiple(() => {

                Assert.That(Made("cs001.example.org", "quantum-banana", null, out var unknown),           Is.False, "A key algorithm nobody has heard of was accepted.");
                Assert.That(unknown,           Does.Contain("ecdsa-p256"), "The refusal does not say what may be asked for instead.");

                Assert.That(Made("   ", "ecdsa-p256", null, out var empty),                                 Is.False, "A certificate with nobody's name on it was made.");
                Assert.That(empty,             Does.Contain("who this charging station is"));

                Assert.That(Made(new String('x', CertificateStore.MaxSubjectLength + 1), null, null, out var tooLong),  Is.False);
                Assert.That(tooLong,           Does.Contain("at most"));

                Assert.That(Made("cs001.example.org", "ed25519",    new CertificateRequestAsks(KeyUsages: [ "keyAgreement" ]),                 out var cannotAgree),    Is.False);
                Assert.That(cannotAgree,       Does.Contain("keyAgreement"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", new CertificateRequestAsks(KeyUsages: [ "dataEncipherment" ]),             out var cannotEncipher), Is.False);
                Assert.That(cannotEncipher,    Does.Contain("RSA"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", new CertificateRequestAsks(KeyUsages: [ "keyCertSign" ]),                  out var noAuthority),    Is.False);
                Assert.That(noAuthority,       Does.Contain("nonRepudiation"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", new CertificateRequestAsks(ExtendedKeyUsages: [ "serverAuthentication" ]), out var noPurpose),      Is.False);
                Assert.That(noPurpose,         Does.Contain("serverAuth"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", new CertificateRequestAsks(Template: "quantum-banana"),                    out var noTemplate),     Is.False);
                Assert.That(noTemplate,        Does.Contain("modbus-tls"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", new CertificateRequestAsks(Template: "modbus-tls"),                        out var noRole),         Is.False);
                Assert.That(noRole,            Does.Contain("ReadOnlySunSpec"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", new CertificateRequestAsks(Role: "ReadOnlySunSpec"),                       out var roleOfNothing),  Is.False);
                Assert.That(roleOfNothing,     Does.Contain("no role"));

                Assert.That(Made("cs001.example.org", "ecdsa-p256", null, out var noUsage, [ "not a usage" ]),                               Is.False);
                Assert.That(noUsage,           Does.Contain("not a usage"));

                Assert.That(store.Requests,    Is.Empty, "A key was kept for a request that was refused.");
                Assert.That(RequestFiles,      Is.Empty);

            });

            // What the kind of key brings by itself may be named, as a page
            // that shows every usage would.
            Assert.That(Made("cs001.example.org", "rsa-2048", new CertificateRequestAsks(KeyUsages: [ "digitalSignature", "keyEncipherment", "dataEncipherment" ]), out var error),
                        Is.True, error);

        }

        #endregion

        #region AKeyThatWasKeptElsewhere_IsTakenOver()

        /// <summary>
        /// A node that kept its keys somewhere of its own moves them over,
        /// once: a key with its request waits here as if it had been made
        /// here, and is the key it was where it is moved over twice.
        /// </summary>
        [Test]
        public void AKeyThatWasKeptElsewhere_IsTakenOver()
        {

            var (theirs, made) = AStoreOf("old");
            var key            = File.ReadAllText(Path.Combine(theirs.Directory, CertificateStore.RequestsDirectoryName, $"{made.Id}.key.pem"));
            var createdAt      = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

            Assert.That(store.TryAdoptRequest(CertificateKind.TLSIdentity, key, made.CSR, made.AlgorithmId, createdAt, [ "csms" ], null, null, out var adopted, out var error, out _),
                        Is.True, error);

            Assert.That(store.TryAdoptRequest(CertificateKind.TLSIdentity, key, made.CSR, made.AlgorithmId, createdAt, [ "csms" ], null, null, out var twice, out error, out _),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(adopted!.Id,          Is.EqualTo(made.Id), "A key is called something else where it was moved to.");
                Assert.That(twice!.Id,            Is.EqualTo(made.Id));
                Assert.That(adopted.CreatedAt,    Is.EqualTo(createdAt));
                Assert.That(adopted.Subject,      Does.Contain("cs999.example.org"));
                Assert.That(store.Requests,       Has.Count.EqualTo(1));
                Assert.That(store.TryAdoptRequest(CertificateKind.TLSIdentity, "no key", made.CSR, made.AlgorithmId, createdAt, null, null, null, out _, out var keyless, out _), Is.False);
                Assert.That(keyless,              Does.Contain("no private key"));
            });

            Assert.That(store.TryAnswerRequest(ACertificateFor(made.CSR), out var entry, out _, out _, out error, out _), Is.True, error);
            Assert.That(entry?.HasPrivateKey, Is.True);

        }

        #endregion

    }

}
