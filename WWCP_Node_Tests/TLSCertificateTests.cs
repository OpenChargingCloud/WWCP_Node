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
    /// The four kinds of certificate that are TLS's rather than ISO 15118's, and
    /// finding any certificate in the store by its fingerprint.
    /// </summary>
    /// <remarks>
    /// Every certificate here is minted in the test, as in the store's own
    /// tests: a fixture certificate expires, and a suite that starts failing on
    /// a Tuesday for that reason teaches everybody to ignore it.
    /// </remarks>
    public class TLSCertificateTests
    {

        #region Data

        private String    directory = "";
        private EventLog  log       = new ();

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory  = Path.Combine(Path.GetTempPath(), "node-tls-certificates-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helpers) Root(Name) / Leaf(Name, Issuer) / Pem(Certificate) / Pkcs12(Certificate) / Store(Kinds)

        private static X509Certificate2 Root(String Name)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        }

        private static X509Certificate2 Leaf(String            Name,
                                             X509Certificate2  Issuer)
        {

            var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

            return request.Create(Issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), Guid.NewGuid().ToByteArray()).
                           CopyWithPrivateKey(key);

        }

        private static Byte[] Pem(X509Certificate2 Certificate)

            => System.Text.Encoding.ASCII.GetBytes(Certificate.ExportCertificatePem());

        private static Byte[] Pkcs12(X509Certificate2 Certificate)

            => Certificate.Export(X509ContentType.Pkcs12, (String?) null)
                   ?? throw new InvalidOperationException("Could not export a PKCS#12.");

        private CertificateStore Store(IEnumerable<CertificateKind>? Kinds = null)

            => new (directory, log, Kinds);

        #endregion


        #region ATLSRootIsATrustAnchorKeptBesideTheOthers()

        /// <summary>
        /// A TLS root is a trust anchor like ISO 15118's three, in a directory of
        /// its own below the roots.
        /// </summary>
        [Test]
        public void ATLSRootIsATrustAnchorKeptBesideTheOthers()
        {

            var store = Store();
            var root  = Root("Time Server CA");

            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, out var entry, out var error),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(CertificateKind.TLSRoot.   IsTrustAnchor(),  Is.True);
                Assert.That(CertificateKind.ClientRoot.IsTrustAnchor(),  Is.True);
                Assert.That(entry!.FileName,                             Does.StartWith("roots/tls/").And.EndWith(".pem"));
                Assert.That(File.Exists(store.FullPath(entry)),          Is.True);
            });

        }

        #endregion

        #region ASubCAIsNoTLSRoot()

        /// <summary>
        /// A certificate somebody else signed is refused as a root, as it is as
        /// any other root.
        /// </summary>
        [Test]
        public void ASubCAIsNoTLSRoot()
        {

            var store = Store();
            var root  = Root("Time Server CA");

            Assert.That(store.Import(Pem(Leaf("Sub CA", root)), CertificateKind.TLSRoot, null, null, out _, out var error),  Is.False);
            Assert.That(error,  Does.Contain("sub-CA"));

        }

        #endregion

        #region AServersCertificateIsKeptWithoutItsKeyAndRefusedWithIt()

        /// <summary>
        /// A server's certificate is kept as it was shown, and refused with a
        /// private key in it: that is the server's key, in the wrong place.
        /// </summary>
        [Test]
        public void AServersCertificateIsKeptWithoutItsKeyAndRefusedWithIt()
        {

            var store  = Store();
            var server = Leaf("time.example.org", Root("Time Server CA"));

            Assert.Multiple(() => {

                Assert.That(store.Import(Pkcs12(server), CertificateKind.TLSServer, null, null, out _, out var refused),  Is.False,  "a server's private key was taken in");
                Assert.That(refused,  Does.Contain("that server's key"));

                Assert.That(store.Import(Pem(server),    CertificateKind.TLSServer, null, null, out var entry, out var error),  Is.True,  error);
                Assert.That(entry?.HasPrivateKey,  Is.False);

            });

        }

        #endregion

        #region ATLSIdentityNeedsItsKey()

        /// <summary>
        /// What this node presents is refused without its private key, and
        /// taken with it.
        /// </summary>
        [Test]
        public void ATLSIdentityNeedsItsKey()
        {

            var store    = Store();
            var identity = Leaf("node.example.org", Root("Our CA"));

            Assert.Multiple(() => {
                Assert.That(store.Import(Pem   (identity), CertificateKind.TLSIdentity, null, null, out _,         out _),      Is.False,  "an identity without its key was taken in");
                Assert.That(store.Import(Pkcs12(identity), CertificateKind.TLSIdentity, null, null, out var entry, out var error),  Is.True,  error);
                Assert.That(entry?.HasPrivateKey,  Is.True);
                Assert.That(entry?.FileName,       Does.StartWith("tls/identity/").And.EndWith(".p12"));
            });

        }

        #endregion

        #region AnEntryIsFoundByItsFingerprintHoweverItIsWritten()

        /// <summary>
        /// A fingerprint finds its entry in upper or lower case, with or without
        /// colons or spaces - and not when it is cut short.
        /// </summary>
        [Test]
        public void AnEntryIsFoundByItsFingerprintHoweverItIsWritten()
        {

            var store       = Store();
            var root        = Root("Time Server CA");

            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, out var entry, out var error),  Is.True,  error);

            var fingerprint = CertificateEntry.ThumbprintOf(root);
            var colons      = String.Join(":", Enumerable.Range(0, 32).Select(i => fingerprint.Substring(2 * i, 2).ToUpperInvariant()));
            var spaced      = String.Join(" ", Enumerable.Range(0, 32).Select(i => fingerprint.Substring(2 * i, 2)));

            Assert.Multiple(() => {
                Assert.That(store.ByFingerprint(fingerprint)?.Id,                     Is.EqualTo(entry!.Id));
                Assert.That(store.ByFingerprint(fingerprint.ToUpperInvariant())?.Id,  Is.EqualTo(entry.Id));
                Assert.That(store.ByFingerprint(colons)?.Id,                          Is.EqualTo(entry.Id),  colons);
                Assert.That(store.ByFingerprint($"  {spaced}  ")?.Id,                 Is.EqualTo(entry.Id),  spaced);
                Assert.That(store.ByFingerprint(fingerprint[..16]),                   Is.Null,  "a handle found an entry as a fingerprint");
                Assert.That(store.ByFingerprint(entry.Id),                            Is.Null,  "a handle found an entry as a fingerprint");
                Assert.That(store.ByFingerprint(new String('0', 64)),                 Is.Null);
                Assert.That(store.ByFingerprint(null),                                Is.Null);
            });

        }

        #endregion

        #region AFingerprintFindsAnEntryOfAnyKind()

        /// <summary>
        /// The fingerprint is asked of everything in the store, whatever it was
        /// kept as.
        /// </summary>
        [Test]
        public void AFingerprintFindsAnEntryOfAnyKind()
        {

            var store  = Store();
            var v2g    = Root("V2G Root");
            var server = Leaf("time.example.org", Root("Time Server CA"));

            Assert.That(store.Import(Pem(v2g),    CertificateKind.V2GRoot,   null, null, out var v2gEntry,    out var error),  Is.True,  error);
            Assert.That(store.Import(Pem(server), CertificateKind.TLSServer, null, null, out var serverEntry, out error),      Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(store.ByFingerprint(CertificateEntry.ThumbprintOf(v2g))?.Kind,     Is.EqualTo(CertificateKind.V2GRoot));
                Assert.That(store.ByFingerprint(CertificateEntry.ThumbprintOf(server))?.Kind,  Is.EqualTo(CertificateKind.TLSServer));
            });

        }

        #endregion

        #region TheCertificateOfAnEntryCanBeHadBack()

        /// <summary>
        /// The certificate an entry is about comes back from its file, and the
        /// usable ones of a kind come back together - without those switched off.
        /// </summary>
        [Test]
        public void TheCertificateOfAnEntryCanBeHadBack()
        {

            var store  = Store();
            var first  = Root("First Time Server CA");
            var second = Root("Second Time Server CA");

            Assert.That(store.Import(Pem(first),  CertificateKind.TLSRoot, null, null, out var firstEntry,  out var error),  Is.True,  error);
            Assert.That(store.Import(Pem(second), CertificateKind.TLSRoot, null, null, out var secondEntry, out error),      Is.True,  error);

            Assert.That(store.TryLoad(firstEntry!, out var loaded, out error),  Is.True,  error);

            using (loaded)
                Assert.That(CertificateEntry.ThumbprintOf(loaded!),  Is.EqualTo(CertificateEntry.ThumbprintOf(first)));

            Assert.That(store.SetActive(secondEntry!.Id, false, out _, out error),  Is.True,  error);

            var usable = store.UsableCertificates(CertificateKind.TLSRoot);

            Assert.That(usable.Select(CertificateEntry.ThumbprintOf),  Is.EqualTo(new[] { CertificateEntry.ThumbprintOf(first) }),
                        "a root that was switched off would still anchor a chain");

            foreach (var certificate in usable)
                certificate.Dispose();

        }

        #endregion

        #region AStoreOfTheTLSKindsMakesTheirDirectoriesOnly()

        /// <summary>
        /// A kind of node that keeps TLS's kinds and none of ISO 15118's gets
        /// their directories and no others.
        /// </summary>
        [Test]
        public void AStoreOfTheTLSKindsMakesTheirDirectoriesOnly()
        {

            var store = Store(CertificateKindExtensions.TLS);

            Assert.Multiple(() => {

                foreach (var kind in CertificateKindExtensions.TLS)
                    Assert.That(Directory.Exists(Path.Combine(directory, kind.Directory())),  Is.True,   kind.AsText());

                foreach (var kind in CertificateKindExtensions.ISO15118)
                    Assert.That(Directory.Exists(Path.Combine(directory, kind.Directory())),  Is.False,  kind.AsText());

                Assert.That(store.Import(Pem(Root("V2G Root")), CertificateKind.V2GRoot, null, null, out _, out var error),  Is.False,  "a kind it does not keep was taken in");

            });

        }

        #endregion

        #region EveryKindHasItsNamesAndIsReadBackFromThem()

        /// <summary>
        /// Every kind has a name, a directory and a description of its own, and
        /// the name reads back as the kind.
        /// </summary>
        [Test]
        public void EveryKindHasItsNamesAndIsReadBackFromThem()
        {

            Assert.Multiple(() => {

                Assert.That(CertificateKindExtensions.All,  Is.EquivalentTo(Enum.GetValues<CertificateKind>()),  "a kind is missing from All");
                Assert.That(CertificateKindExtensions.All,  Is.EquivalentTo(CertificateKindExtensions.ISO15118.Concat(CertificateKindExtensions.TLS)));
                Assert.That(CertificateKindExtensions.All.Select(kind => kind.SortOrder()),  Is.Ordered.And.Unique);
                Assert.That(CertificateKindExtensions.All.Select(kind => kind.Directory()),  Is.Unique);
                Assert.That(CertificateKindExtensions.All.Select(kind => kind.AsText()),     Is.Unique);

                foreach (var kind in CertificateKindExtensions.All)
                {
                    Assert.That(CertificateKindExtensions.TryParseKind(kind.AsText().ToUpperInvariant(), out var parsed) && parsed == kind,  Is.True,  kind.AsText());
                    Assert.That(kind.Describe(),  Is.Not.Empty);
                }

            });

        }

        #endregion

        #region AFingerprintIsReadAsTheWholeOfIt()

        /// <summary>
        /// What reads as a fingerprint, and what does not.
        /// </summary>
        [Test]
        [TestCase("AB:cd:EF:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89",  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
        [TestCase("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",                                   "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
        [TestCase("ab-cd-ef-01-23-45-67-89-ab-cd-ef-01-23-45-67-89-ab-cd-ef-01-23-45-67-89-ab-cd-ef-01-23-45-67-89",  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
        [TestCase("abcdef0123456789",                                                                                   null)]
        [TestCase("abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678",                                    null)]
        [TestCase("abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890",                                  null)]
        [TestCase("zzcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",                                   null)]
        [TestCase("sha256/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",                            null)]
        [TestCase("",                                                                                                   null)]
        public void AFingerprintIsReadAsTheWholeOfIt(String Text, String? Expected)
        {

            var read = CertificateEntry.TryParseFingerprint(Text, out var fingerprint);

            Assert.Multiple(() => {
                Assert.That(read,         Is.EqualTo(Expected is not null));
                Assert.That(fingerprint,  Is.EqualTo(Expected));
            });

        }

        #endregion

        #region WhatIsImportedIsMetrological()

        /// <summary>
        /// What a node trusts from now on is written into the metrological log,
        /// with the fingerprint it will be recognised by.
        /// </summary>
        [Test]
        public void WhatIsImportedIsMetrological()
        {

            var store = Store();
            var root  = Root("Time Server CA");

            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, out var entry, out var error),  Is.True,  error);
            Assert.That(store.SetActive(entry!.Id, false, out _, out error),                                         Is.True,  error);

            var metrological = log.Recent(100).Where(one => one.Metrological).Select(one => one.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(metrological,  Has.Some.Contains("imported").And.Contains(CertificateEntry.ThumbprintOf(root)),  String.Join(" | ", metrological));
                Assert.That(metrological,  Has.Some.Contains("was switched off"),                                          String.Join(" | ", metrological));
            });

        }

        #endregion

    }

}
