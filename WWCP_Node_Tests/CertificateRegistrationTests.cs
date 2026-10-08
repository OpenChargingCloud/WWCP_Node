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
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// One certificate kept as several kinds, kinds and usages somebody made
    /// up, and what a file or a text holds before anything is imported.
    /// </summary>
    public class CertificateRegistrationTests
    {

        #region Data

        private String    directory = "";
        private EventLog  log       = new ();

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory  = Path.Combine(Path.GetTempPath(), "node-certificate-registrations-" + Guid.NewGuid().ToString("N")[..12]);
            log        = new EventLog();
        }

        [TearDown]
        public void TearDown()
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }
        }

        #endregion


        #region (helpers) Root(Name) / Leaf(Name, Issuer, CA) / Pem(...) / PemWithKey(...)

        /// <summary>A self-signed CA certificate, with its private key.</summary>
        private static X509Certificate2 Root(String Name)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        }

        /// <summary>A certificate the issuer signed, with its private key.</summary>
        /// <remarks>
        /// It ends a day before its issuer does, not a span after now: a
        /// certificate counts whole seconds, and where the second turned
        /// between a CA and the leaf it signed, the leaf would have outlived
        /// it, which is refused (a full run of the suite).
        /// </remarks>
        private static X509Certificate2 Leaf(String            Name,
                                             X509Certificate2  Issuer,
                                             Boolean           CA = false)
        {

            var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(CA, false, 0, true));

            return request.Create(Issuer,
                                  DateTimeOffset.UtcNow.AddDays(-1),
                                  new DateTimeOffset(Issuer.NotAfter).AddDays(-1),
                                  Guid.NewGuid().ToByteArray()).
                           CopyWithPrivateKey(key);

        }

        /// <summary>The certificates as one PEM, without their keys.</summary>
        private static Byte[] Pem(params X509Certificate2[] Certificates)

            => System.Text.Encoding.ASCII.GetBytes(String.Concat(Certificates.Select(certificate => certificate.ExportCertificatePem() + "\n")));

        /// <summary>The certificates as one PEM, and the private key of the first one after them.</summary>
        private static Byte[] PemWithKey(params X509Certificate2[] Certificates)

            => System.Text.Encoding.ASCII.GetBytes(
                   String.Concat(Certificates.Select(certificate => certificate.ExportCertificatePem() + "\n")) +
                   Certificates[0].GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem() + "\n"
               );

        private static Byte[] Pkcs12(X509Certificate2 Certificate, String? Password = null)

            => Certificate.Export(X509ContentType.Pkcs12, Password)!;

        #endregion


        #region ACertificateIsKeptAsASecondKindBesideTheFirst()

        [Test]
        public void ACertificateIsKeptAsASecondKindBesideTheFirst()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Both Roots");

            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot,    null, "Our CA", out var first,  out var error),  Is.True, error);
            Assert.That(store.Import(Pem(root), CertificateKind.ClientRoot, null, null,     out var second, out var error2), Is.True, error2);

            Assert.Multiple(() => {
                Assert.That(store.Registrations(first!.Id).Select(entry => entry.Kind),  Is.EqualTo(new[] { CertificateKind.TLSRoot, CertificateKind.ClientRoot }));
                Assert.That(second!.Id,                                                    Is.EqualTo(first!.Id), "one certificate, one handle");
                Assert.That(second!.Label,                                                 Is.EqualTo("Our CA"), "a kind added takes the name the certificate has");
                Assert.That(store.ByKind(CertificateKind.TLSRoot),                         Has.Exactly(1).Items);
                Assert.That(store.ByKind(CertificateKind.ClientRoot),                      Has.Exactly(1).Items);
                Assert.That(File.Exists(store.FullPath(first!)),                           Is.True);
                Assert.That(File.Exists(store.FullPath(second!)),                          Is.True);
                Assert.That(store.FullPath(second!),                                       Is.Not.EqualTo(store.FullPath(first!)), "a file in each kind's directory");
                Assert.That(store.Get(first!.Id, CertificateKind.ClientRoot)?.Kind,         Is.EqualTo(CertificateKind.ClientRoot));
            });

        }

        #endregion

        #region AKindIsSwitchedOnItsOwnAndTheCertificateAsAWhole()

        [Test]
        public void AKindIsSwitchedOnItsOwnAndTheCertificateAsAWhole()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Switched Root");

            Assert.That(store.Import(Pem(root), null, null, [ new (CertificateKind.TLSRoot), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            var id = entries![0].Id;

            Assert.That(store.SetActive(id, CertificateKind.ClientRoot, false, out _, out var error2), Is.True, error2);

            Assert.Multiple(() => {
                Assert.That(store.UsableByKind(CertificateKind.TLSRoot),     Has.Exactly(1).Items, "the other kind is left as it was");
                Assert.That(store.UsableByKind(CertificateKind.ClientRoot),  Is.Empty);
            });

            Assert.That(store.SetActive(id, true, out _, out var error3), Is.True, error3);
            Assert.That(store.Registrations(id).All(entry => entry.IsActive), Is.True, "on as a whole");

            Assert.That(store.SetActive(id, false, out _, out var error4), Is.True, error4);
            Assert.That(store.Registrations(id).Any(entry => entry.IsActive), Is.False,
                        "off as a whole - not left believed as the kind somebody forgot");

        }

        #endregion

        #region TakenOutAsOneKindItStaysAsTheOthers()

        [Test]
        public void TakenOutAsOneKindItStaysAsTheOthers()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Two Kinds");

            Assert.That(store.Import(Pem(root), null, null, [ new (CertificateKind.V2GRoot), new (CertificateKind.OEMRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            var id      = entries![0].Id;
            var v2gFile = store.FullPath(entries[0]);
            var oemFile = store.FullPath(entries[1]);

            Assert.That(store.Remove(id, CertificateKind.OEMRoot, out var error2), Is.True, error2);

            Assert.Multiple(() => {
                Assert.That(File.Exists(oemFile),                              Is.False, "that kind's file is gone");
                Assert.That(File.Exists(v2gFile),                              Is.True,  "the other kind's is not");
                Assert.That(store.Registrations(id).Select(entry => entry.Kind), Is.EqualTo(new[] { CertificateKind.V2GRoot }));
            });

            Assert.That(store.Remove(id, CertificateKind.OEMRoot, out var error3), Is.False);
            Assert.That(error3, Is.EqualTo($"The certificate '{id}' is not kept as an OEM root in this store."));

            Assert.That(store.Import(Pem(root), CertificateKind.OEMRoot, null, null, out _, out var error4), Is.True, error4);
            Assert.That(store.Remove(id, out var error5), Is.True, error5);

            Assert.Multiple(() => {
                Assert.That(store.Entries,               Is.Empty, "taken out as every kind");
                Assert.That(File.Exists(v2gFile),        Is.False);
                Assert.That(File.Exists(oemFile),        Is.False);
            });

        }

        #endregion

        #region ANameIsTheCertificatesWhicheverKindItIsKeptAs()

        [Test]
        public void ANameIsTheCertificatesWhicheverKindItIsKeptAs()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Named Root");

            Assert.That(store.Import(Pem(root), null, "First", [ new (CertificateKind.TLSRoot), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            var id = entries![0].Id;

            Assert.That(store.Relabel(id, "Renamed", out _, out var error2), Is.True, error2);
            Assert.That(store.Registrations(id).Select(entry => entry.Label), Is.EqualTo(new[] { "Renamed", "Renamed" }));

            Assert.That(store.Import(Pem(root), CertificateKind.V2GRoot, null, "Given Anew", out _, out var error3), Is.True, error3);
            Assert.That(store.Registrations(id).Select(entry => entry.Label), Is.EqualTo(new[] { "Given Anew", "Given Anew", "Given Anew" }),
                        "a label given with a kind added is the certificate's");

        }

        #endregion

        #region EveryKindComesBackAfterARestart()

        [Test]
        public void EveryKindComesBackAfterARestart()
        {

            var first = new CertificateStore(directory, log);

            using var root  = Root("Restarted Root");
            using var other = Root("Copied Root");

            Assert.That(first.Import(Pem(root), null, "Ours", [ new (CertificateKind.TLSRoot, [ "nts" ]), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            var id = entries![0].Id;

            Assert.That(first.SetActive(id, CertificateKind.ClientRoot, false, out _, out var error2), Is.True, error2);

            // The same certificate copied by hand into another kind's directory
            // joins it under the name it has.
            File.WriteAllBytes(Path.Combine(directory, "roots", "v2g", "copied.pem"), Pem(root));

            var second = new CertificateStore(directory, log);
            second.Reload();

            var again = second.Registrations(id);

            Assert.Multiple(() => {
                Assert.That(again.Select(entry => entry.Kind),     Is.EqualTo(new[] { CertificateKind.V2GRoot, CertificateKind.TLSRoot, CertificateKind.ClientRoot }));
                Assert.That(again.Select(entry => entry.Label),    Is.EqualTo(new[] { "Ours", "Ours", "Ours" }));
                Assert.That(again.Select(entry => entry.IsActive), Is.EqualTo(new[] { true, true, false }));
                Assert.That(again[1].Usages,                       Is.EqualTo(new CertificateUsage[] { "nts" }));
            });

        }

        #endregion

        #region AFingerprintFindsTheKindThatIsUsable()

        /// <summary>
        /// A server held to a root by its fingerprint finds the root as a kind
        /// it is switched on as, where it is kept as several and switched off as
        /// the first of them.
        /// </summary>
        [Test]
        public void AFingerprintFindsTheKindThatIsUsable()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Pinned Root");

            Assert.That(store.Import(Pem(root), null, null, [ new (CertificateKind.TLSRoot), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            Assert.That(store.SetActive(entries![0].Id, CertificateKind.TLSRoot, false, out _, out var error2), Is.True, error2);

            var found = store.ByFingerprint(entries![0].Thumbprint);

            Assert.Multiple(() => {
                Assert.That(found?.Kind,      Is.EqualTo(CertificateKind.ClientRoot));
                Assert.That(found?.IsUsable,  Is.True);
            });

        }

        #endregion

        #region AnIdentityAndARootInOneImportKeepTheKeyWithTheIdentity()

        [Test]
        public void AnIdentityAndARootInOneImportKeepTheKeyWithTheIdentity()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Self-Signed Identity");

            Assert.That(store.Import(Pkcs12(root), null, null, [ new (CertificateKind.TLSIdentity), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(entries![0].HasPrivateKey,  Is.True,  "the identity presents it");
                Assert.That(entries![1].HasPrivateKey,  Is.False, "the root is kept without it");
                Assert.That(File.ReadAllText(store.FullPath(entries![1])), Does.Not.Contain("PRIVATE KEY"));
            });

            Assert.That(store.Import(Pkcs12(root), CertificateKind.TLSRoot, null, null, out _, out var alone), Is.False,
                        "put in as a root alone, a key that came along is still somebody's key in the wrong place");
            Assert.That(alone, Does.StartWith("That file carries a private key, and a trust anchor must not."));

        }

        #endregion

        #region AnImportRefusedAsOneKindPutsItInAsNone()

        [Test]
        public void AnImportRefusedAsOneKindPutsItInAsNone()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Some CA");
            using var leaf = Leaf("Some Device", root);

            Assert.That(store.Import(PemWithKey(leaf), null, null, [ new (CertificateKind.TLSIdentity), new (CertificateKind.V2GRoot) ], out _, out var error, out _),
                        Is.False);

            Assert.Multiple(() => {
                Assert.That(error,          Does.Contain("is signed by somebody else and is therefore a sub-CA rather than a root"));
                Assert.That(store.Entries,  Is.Empty, "not in as the identity either");
                Assert.That(Directory.EnumerateFiles(Path.Combine(directory, "tls", "identity")), Is.Empty);
            });

        }

        #endregion

        #region AKindMadeUpIsKeptAndForgottenWithItsLastCertificate()

        [Test]
        public void AKindMadeUpIsKeptAndForgottenWithItsLastCertificate()
        {

            var store   = new CertificateStore(directory, log, [ CertificateKind.TLSRoot ]);
            var backend = CertificateKind.Custom("backendRoot", CertificateGroup.TrustAnchor);

            using var root = Root("Backend CA");

            Assert.That(store.Import(Pem(root), backend, null, null, out var entry, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(store.KindsKept,                     Is.EqualTo(new[] { CertificateKind.TLSRoot, backend }));
                Assert.That(entry!.FileName,                     Does.StartWith("custom/roots/backendRoot/"));
                Assert.That(backend.IsTrustAnchor(),             Is.True);
                Assert.That(backend.WithArticle(),               Is.EqualTo("a root of the kind 'backendRoot'"));
            });

            // With the index, it comes back as it was left.
            Assert.That(store.Relabel   (entry!.Id, "Our Backend", out _, out var error3), Is.True, error3);
            Assert.That(store.SetActive (entry!.Id, false,         out _, out var error4), Is.True, error4);

            var restarted = new CertificateStore(directory, log, [ CertificateKind.TLSRoot ]);
            restarted.Reload();

            Assert.Multiple(() => {
                Assert.That(restarted.ByKind(backend).Select(one => one.Label),     Is.EqualTo(new[] { "Our Backend" }));
                Assert.That(restarted.ByKind(backend).Select(one => one.IsActive),  Is.EqualTo(new[] { false }));
            });

            // Without the index, the kind comes back from where its file is.
            File.Delete(Path.Combine(directory, CertificateStore.IndexFileName));

            var again = new CertificateStore(directory, log, [ CertificateKind.TLSRoot ]);
            again.Reload();

            Assert.That(again.ByKind(backend), Has.Exactly(1).Items);
            Assert.That(again.ByKind(backend)[0].Kind.IsCustom, Is.True);

            Assert.That(again.Remove(entry!.Id, out var error2), Is.True, error2);
            Assert.That(again.KindsKept, Is.EqualTo(new[] { CertificateKind.TLSRoot }), "nothing but the certificates remembers it");

        }

        #endregion

        #region ARootOfAKindMadeUpHasToBeACA()

        [Test]
        public void ARootOfAKindMadeUpHasToBeACA()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Issuing Root");
            using var ca   = Leaf("Issuing CA", root, CA: true);
            using var leaf = Leaf("Not A CA", root);

            Assert.That(store.Import(Pem(ca),   CertificateKind.Custom("partnerRoot", CertificateGroup.TrustAnchor), null, null, out _, out var error),   Is.True, error);
            Assert.That(store.Import(Pem(leaf), CertificateKind.Custom("partnerRoot", CertificateGroup.TrustAnchor), null, null, out _, out var refused), Is.False);
            Assert.That(refused, Is.EqualTo("'Not A CA' is not a CA certificate, and a root of the kind 'partnerRoot' has to be one: a root, or a CA below one."));

        }

        #endregion

        #region AnyKindMayBeMarkedWithAUsageOfItsOwn()

        [Test]
        public void AnyKindMayBeMarkedWithAUsageOfItsOwn()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Marked Root");

            Assert.That(store.KnownUsages(CertificateKind.V2GRoot), Is.Empty);

            Assert.That(store.Import(Pem(root), CertificateKind.V2GRoot, null, null, [ "Backend-X" ], out var entry, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(entry!.Usages,                                 Is.EqualTo(new CertificateUsage[] { "backend-x" }), "in lower case");
                Assert.That(entry!.IsFor("backend-x"),                      Is.True);
                Assert.That(store.KnownUsages(CertificateKind.V2GRoot),    Is.EqualTo(new CertificateUsage[] { "backend-x" }));
                Assert.That(store.KnownUsages(CertificateKind.TLSRoot),    Is.EqualTo(new CertificateUsage[] { "dns", "nts" }), "the node's own, and none of a V2G root's");
            });

            Assert.That(store.SetUsages(entry!.Id, null, out _, out var error2), Is.True, error2);
            Assert.That(store.KnownUsages(CertificateKind.V2GRoot), Is.Empty, "no longer offered once no certificate has it");

            Assert.Multiple(() => {
                Assert.That(CertificateUsage.TryParse("no spaces"),   Is.Null, "no usage, and no exception either");
                Assert.That(CertificateUsage.TryParse(" Backend "),   Is.EqualTo((CertificateUsage?) "backend"));
                Assert.That(CertificateKind.TryParse("noSuchKind"),   Is.Null);
            });

            Assert.That(store.TrySettleUsages(CertificateKind.V2GRoot, [ "no spaces" ], out _, out var refused), Is.False);
            Assert.That(refused, Does.StartWith("'no spaces' is not a usage name"));

        }

        #endregion

        #region AUsageOfAKindKeptAsSeveralIsToldAsOne()

        [Test]
        public void AUsageOfAKindKeptAsSeveralIsToldAsOne()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Two Kinds Of Usage");

            Assert.That(store.Import(Pem(root), null, null, [ new (CertificateKind.TLSRoot), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            var id = entries![0].Id;

            Assert.That(store.SetUsages(id, [ "nts" ], out _, out var ambiguous), Is.False);
            Assert.That(ambiguous, Is.EqualTo("'Two Kinds Of Usage' is kept as a TLS root and a client root. Say as which of them it is told what it is for."));

            Assert.That(store.SetUsages(id, CertificateKind.TLSRoot, [ "nts" ], out var told, out var error2), Is.True, error2);

            Assert.Multiple(() => {
                Assert.That(told!.Usages,                                           Is.EqualTo(new CertificateUsage[] { "nts" }));
                Assert.That(store.Get(id, CertificateKind.ClientRoot)!.Usages,       Is.Null, "the other kind is for every use as before");
            });

        }

        #endregion

        #region AUsageIsOfferedToTheKindItIsToldAsAlone()

        /// <summary>
        /// A usage a certificate is marked with is offered to the kind it is
        /// marked with it as, and to no other - not to the same certificate as
        /// another kind either: a meter's identities for "web" made "web" an
        /// offer to its TLS roots, a root "for the web interface".
        /// </summary>
        [Test]
        public void AUsageIsOfferedToTheKindItIsToldAsAlone()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Told As One Kind");

            Assert.That(store.Import(Pem(root), null, null, [ new (CertificateKind.TLSRoot), new (CertificateKind.ClientRoot) ], out var entries, out var error, out _),
                        Is.True, error);

            Assert.That(store.SetUsages(entries![0].Id, CertificateKind.ClientRoot, [ "web" ], out _, out var error2), Is.True, error2);

            Assert.Multiple(() => {
                Assert.That(store.KnownUsages(CertificateKind.ClientRoot),  Is.EqualTo(new CertificateUsage[] { "web" }));
                Assert.That(store.KnownUsages(CertificateKind.TLSRoot),     Is.EqualTo(new CertificateUsage[] { "dns", "nts" }), "the same certificate as another kind");
                Assert.That(store.KnownUsages(CertificateKind.V2GRoot),     Is.Empty, "a kind no certificate is kept as");
            });

        }

        #endregion


        #region ATextOfRootsIsOneCertificateEach()

        [Test]
        public void ATextOfRootsIsOneCertificateEach()
        {

            using var one = Root("Root One");
            using var two = Root("Root Two");

            var found = CertificateStore.Inspect(Pem(one, two), null);

            Assert.Multiple(() => {
                Assert.That(found.Error,                                           Is.Null);
                Assert.That(found.Certificates.Select(cert => cert.CommonName),    Is.EqualTo(new[] { "Root One", "Root Two" }));
                Assert.That(found.Certificates.All(cert => cert.ChainLength == 0), Is.True);
                Assert.That(found.Certificates.All(cert => cert.IsSelfSigned),     Is.True);
                Assert.That(found.Pem,                                             Does.Not.Contain("PRIVATE KEY"));
            });

        }

        #endregion

        #region ALeafWithItsChainAndKeyIsOneCertificate()

        [Test]
        public void ALeafWithItsChainAndKeyIsOneCertificate()
        {

            using var root = Root("Chain Root");
            using var ca   = Leaf("Chain CA", root, CA: true);
            using var leaf = Leaf("Chain Leaf", ca);

            // Root first, key in the middle: the order a text was pasted in is
            // nobody's to rely on.
            var text = System.Text.Encoding.ASCII.GetBytes(
                           root.ExportCertificatePem() + "\n" +
                           leaf.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem() + "\n" +
                           leaf.ExportCertificatePem() + "\n" +
                           ca.  ExportCertificatePem() + "\n"
                       );

            var found = CertificateStore.Inspect(text, null);

            Assert.That(found.Error, Is.Null);
            Assert.That(found.Certificates, Has.Exactly(1).Items);

            var one = found.Certificates[0];

            Assert.Multiple(() => {
                Assert.That(one.CommonName,     Is.EqualTo("Chain Leaf"));
                Assert.That(one.ChainLength,    Is.EqualTo(2));
                Assert.That(one.HasPrivateKey,  Is.True);
                Assert.That(one.Pem,            Does.StartWith(leaf.ExportCertificatePem()), "the leaf first");
                Assert.That(one.Pem,            Does.Contain("-----BEGIN PRIVATE KEY-----"));
            });

            // What was found imports as it was found.
            var store = new CertificateStore(directory, log);

            Assert.That(store.Import(System.Text.Encoding.ASCII.GetBytes(one.Pem), CertificateKind.TLSIdentity, null, null, out var entry, out var error), Is.True, error);
            Assert.That(entry!.ChainLength, Is.EqualTo(2));
            Assert.That(store.InspectFor(text, null).Certificates[0].InStoreAs, Is.EqualTo(new[] { CertificateKind.TLSIdentity }));

        }

        #endregion

        #region APkcs12IsShownAsPemWithItsKey()

        [Test]
        public void APkcs12IsShownAsPemWithItsKey()
        {

            using var root = Root("P12 Root");
            using var leaf = Leaf("P12 Leaf", root);

            var without = CertificateStore.Inspect(Pkcs12(leaf, "secret"), null);
            var opened  = CertificateStore.Inspect(Pkcs12(leaf, "secret"), "secret");

            Assert.Multiple(() => {
                Assert.That(without.PasswordWanted,                  Is.True);
                Assert.That(without.Certificates,                    Is.Empty);
                Assert.That(opened.Error,                            Is.Null);
                Assert.That(opened.Certificates[0].HasPrivateKey,    Is.True);
                Assert.That(opened.Pem,                              Does.Contain("-----BEGIN CERTIFICATE-----").And.Contain("-----BEGIN PRIVATE KEY-----"));
            });

        }

        #endregion

        #region AKeyThatBelongsToNothingIsSaidToBeThat()

        [Test]
        public void AKeyThatBelongsToNothingIsSaidToBeThat()
        {

            using var one   = Root("Key Owner");
            using var other = Root("Somebody Else");

            var text = System.Text.Encoding.ASCII.GetBytes(other.ExportCertificatePem() + "\n" +
                                                           one.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem() + "\n");

            var keyOnly = System.Text.Encoding.ASCII.GetBytes(one.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());

            Assert.Multiple(() => {
                Assert.That(CertificateStore.Inspect(text,    null).Error, Does.StartWith("That text carries a private key that belongs to none of the certificates in it."));
                Assert.That(CertificateStore.Inspect(keyOnly, null).Error, Is.EqualTo("That text holds a private key, and no certificate it belongs to."));
                Assert.That(CertificateStore.Inspect([],      null).Error, Is.EqualTo("There is nothing in that file."));
            });

        }

        #endregion

        #region WhatACertificateCannotBeIsSaidPerKind()

        [Test]
        public void WhatACertificateCannotBeIsSaidPerKind()
        {

            var store = new CertificateStore(directory, log, [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ]);

            using var root = Root("Unsuitable Root");
            using var leaf = Leaf("Unsuitable Leaf", root);

            var withKey     = store.InspectFor(PemWithKey(leaf), null).Certificates[0];
            var withoutKey  = store.InspectFor(Pem(root),        null).Certificates[0];

            Assert.Multiple(() => {
                Assert.That(store.Unsuitable(withKey).Keys,    Is.EquivalentTo(new[] { CertificateKind.TLSRoot, CertificateKind.TLSServer }));
                Assert.That(store.Unsuitable(withoutKey).Keys, Is.EquivalentTo(new[] { CertificateKind.TLSIdentity }));
                Assert.That(store.Unsuitable(withoutKey)[CertificateKind.TLSIdentity], Does.StartWith("A TLS identity has to carry its private key"));
            });

        }

        #endregion

    }

}
