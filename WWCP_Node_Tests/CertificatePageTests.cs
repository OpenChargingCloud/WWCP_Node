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
    /// The three pages a kind is looked after on - the certificates alone, who
    /// the node is as a client, who a server of it is - and a kind's
    /// certificates moved to another kind, as a meter's identities became
    /// server identities.
    /// </summary>
    public class CertificatePageTests
    {

        #region Data

        private String    directory = "";
        private EventLog  log       = new ();

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory  = Path.Combine(Path.GetTempPath(), "node-certificate-pages-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helpers) Identity(Name)

        /// <summary>A self-signed identity, as a PKCS#12 with its private key.</summary>
        private static Byte[] Identity(String Name)
        {

            using var key         = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var certificate = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256).
                                        CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return certificate.Export(X509ContentType.Pkcs12);

        }

        #endregion


        #region EveryKindIsLookedAfterOnItsPage()

        /// <summary>
        /// Without a private key a kind is a certificate alone, whatever its
        /// group - a tariff certificate, which only checks, among them; with
        /// one it is who the node is as a client, unless it is who a server of
        /// the node is.
        /// </summary>
        [Test]
        public void EveryKindIsLookedAfterOnItsPage()
        {

            Assert.Multiple(() => {

                foreach (var kind in new[] { CertificateKind.V2GRoot, CertificateKind.MORoot, CertificateKind.OEMRoot, CertificateKind.TLSRoot,
                                             CertificateKind.ClientRoot, CertificateKind.TLSServer, CertificateKind.TariffVerification })
                    Assert.That(kind.Page, Is.EqualTo(CertificatePage.Certificates), kind.AsText());

                foreach (var kind in new[] { CertificateKind.TLSIdentity, CertificateKind.Vehicle, CertificateKind.Contract, CertificateKind.OEMProvisioning })
                    Assert.That(kind.Page, Is.EqualTo(CertificatePage.Identities), kind.AsText());

                Assert.That(CertificateKind.TLSServerIdentity.Page,                                Is.EqualTo(CertificatePage.ServerCertificates));

                Assert.That(CertificateKind.Custom("ownRoot",     CertificateGroup.TrustAnchor).Page,  Is.EqualTo(CertificatePage.Certificates));
                Assert.That(CertificateKind.Custom("ownLogin",    CertificateGroup.Credential). Page,  Is.EqualTo(CertificatePage.Identities), "a credential made up carries its key");
                Assert.That(CertificateKind.Custom("ownServer",   CertificateGroup.Recognised). Page,  Is.EqualTo(CertificatePage.Certificates));

                Assert.That(CertificateKind.AsText(CertificatePage.Certificates),                   Is.EqualTo("certificates"));
                Assert.That(CertificateKind.AsText(CertificatePage.Identities),                     Is.EqualTo("identities"));
                Assert.That(CertificateKind.AsText(CertificatePage.ServerCertificates),             Is.EqualTo("serverCertificates"));

            });

        }

        #endregion

        #region AKindMovedKeepsItsCertificatesNamesSwitchesAndUses()

        /// <summary>
        /// A meter's identities, which its listeners show, kept as TLS server
        /// identities from the start that names them so on: each file moved
        /// into the other kind's directory, with the name it was given, its
        /// switch and what it is for - by a store that no longer keeps the kind
        /// they were, and so had set them aside. Asked again, it moves nothing.
        /// </summary>
        [Test]
        public void AKindMovedKeepsItsCertificatesNamesSwitchesAndUses()
        {

            var before = new CertificateStore(directory, log, [ CertificateKind.TLSIdentity ], Listeners: [ "modbus", "web" ]);

            Assert.That(before.Import(Identity("meter-001"), CertificateKind.TLSIdentity, null, "Web interface", [ "web" ], out var web,    out var error),  Is.True, error);
            Assert.That(before.Import(Identity("meter-002"), CertificateKind.TLSIdentity, null, null,            null,      out var modbus, out var error2), Is.True, error2);
            Assert.That(before.SetActive(modbus!.Id, false, out _, out var error3), Is.True, error3);

            var after = new CertificateStore(directory, log, [ CertificateKind.TLSRoot, CertificateKind.TLSServerIdentity ], Listeners: [ "modbus", "web" ]);

            after.Reload();

            Assert.That(after.ByKind(CertificateKind.TLSServerIdentity), Is.Empty, "not moved yet");

            // What follows the store - a meter's listeners, which pick the
            // identity they show from it - hears of the move at once.
            var changes = 0;
            after.OnChanged += () => changes++;

            Assert.That(after.MoveKind(CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity, out var moved, out var error4), Is.True, error4);
            Assert.That(changes, Is.Positive, "what follows the store did not hear of the move");

            var movedWeb     = after.Get(web!.Id,    CertificateKind.TLSServerIdentity);
            var movedModbus  = after.Get(modbus.Id, CertificateKind.TLSServerIdentity);

            Assert.Multiple(() => {

                Assert.That(moved,                                               Is.EqualTo(2));
                Assert.That(movedWeb?.Label,                                     Is.EqualTo("Web interface"), "its name");
                Assert.That(movedWeb?.Usages,                                    Is.EqualTo(new CertificateUsage[] { "web" }), "what it is for");
                Assert.That(movedWeb?.IsActive,                                  Is.True);
                Assert.That(movedModbus?.IsActive,                               Is.False, "its switch");
                Assert.That(movedModbus?.Usages,                                 Is.Null, "every listener, as before");
                Assert.That(movedWeb?.FileName,                                  Does.StartWith("tls/server-identity/"));
                Assert.That(File.Exists(after.FullPath(movedWeb!)),              Is.True, "its file where the kind's are");
                Assert.That(Directory.EnumerateFiles(Path.Combine(directory, "tls", "identity")), Is.Empty, "and none left where they were");
                Assert.That(after.Get(web!.Id, CertificateKind.TLSIdentity),      Is.Null);
                Assert.That(after.UsableFor(CertificateKind.TLSServerIdentity, "modbus").Select(entry => entry.Id),
                                                                                 Is.Empty, "the one switched off is shown nowhere, the other one on the web interface alone");

            });

            Assert.That(after.MoveKind(CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity, out var again, out var error5), Is.True, error5);
            Assert.That(again, Is.Zero, "nothing left to move");

            var restarted = new CertificateStore(directory, log, [ CertificateKind.TLSRoot, CertificateKind.TLSServerIdentity ], Listeners: [ "modbus", "web" ]);

            restarted.Reload();

            Assert.Multiple(() => {
                Assert.That(restarted.Get(web!.Id, CertificateKind.TLSServerIdentity)?.Label,     Is.EqualTo("Web interface"), "the index says so after a restart");
                Assert.That(restarted.Get(modbus.Id, CertificateKind.TLSServerIdentity)?.IsActive, Is.False);
            });

        }

        #endregion

        #region AFileWhoseNameIsTakenIsLeftWhereItIs()

        /// <summary>
        /// A file of the same name in the other kind's directory is not written
        /// over: the one to move stays where it is, and the log says so.
        /// </summary>
        [Test]
        public void AFileWhoseNameIsTakenIsLeftWhereItIs()
        {

            var store = new CertificateStore(directory, log, [ CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ]);

            Assert.That(store.Import(Identity("meter-003"), CertificateKind.TLSIdentity, null, null, out var entry, out var error), Is.True, error);

            var name     = Path.GetFileName(store.FullPath(entry!));
            var squatter = Path.Combine(directory, "tls", "server-identity", name);

            File.WriteAllText(squatter, "not a certificate");

            Assert.That(store.MoveKind(CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity, out var moved, out var error2), Is.True, error2);

            Assert.Multiple(() => {
                Assert.That(moved,                                            Is.Zero);
                Assert.That(File.ReadAllText(squatter),                       Is.EqualTo("not a certificate"), "not written over");
                Assert.That(store.Get(entry!.Id, CertificateKind.TLSIdentity), Is.Not.Null, "still kept as it was");
                Assert.That(File.Exists(store.FullPath(entry!)),              Is.True);
            });

        }

        #endregion

    }

}
