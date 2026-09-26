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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a TLS root or a server certificate may be used for: the name
    /// servers, the time servers, both - or, never told, every use.
    /// </summary>
    /// <remarks>
    /// Every certificate here is minted in the test, as in the other tests of
    /// the store, so that none of them expires on a Tuesday.
    /// </remarks>
    public class CertificateUsageTests
    {

        #region Data

        private String    directory = "";
        private EventLog  log       = new ();

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory  = Path.Combine(Path.GetTempPath(), "node-certificate-usages-" + Guid.NewGuid().ToString("N")[..12]);
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
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helpers) Root(Name) / Pem(Certificate) / Imported(Store, Name, Kind, Usages)

        /// <summary>
        /// A self-signed certificate, which is what a root is.
        /// </summary>
        private static X509Certificate2 Root(String Name)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        }

        private static Byte[] Pem(X509Certificate2 Certificate)

            => System.Text.Encoding.ASCII.GetBytes(Certificate.ExportCertificatePem());

        /// <summary>
        /// A certificate of the given name, imported into the given store for the
        /// given usages - where nothing is expected to be wrong with that.
        /// </summary>
        private static CertificateEntry Imported(CertificateStore      Store,
                                                 String                Name,
                                                 CertificateKind       Kind    = CertificateKind.TLSRoot,
                                                 IEnumerable<String>?  Usages  = null)
        {

            using var root = Root(Name);

            Assert.That(Store.Import(Pem(root), Kind, null, null, Usages, out var entry, out var error), Is.True, error);

            return entry!;

        }

        #endregion


        #region ATLSRootIsForEveryUseUntilItIsToldOtherwise()

        /// <summary>
        /// Never told, a TLS root is for every use - which is what every TLS
        /// root was before there were usages, and what a store written then
        /// still means.
        /// </summary>
        [Test]
        public void ATLSRootIsForEveryUseUntilItIsToldOtherwise()
        {

            var store  = new CertificateStore(directory, log);
            var entry  = Imported(store, "Anybody's Root");

            Assert.Multiple(() => {
                Assert.That(entry.Usages,                                                 Is.Null);
                Assert.That(entry.IsFor(CertificateUsages.DNS),                           Is.True);
                Assert.That(entry.IsFor(CertificateUsages.NTS),                           Is.True);
                Assert.That(store.UsableFor(CertificateKind.TLSRoot, CertificateUsages.NTS),  Has.Count.EqualTo(1));
                Assert.That(entry.ToJSON()["usages"]!.Type,                               Is.EqualTo(JTokenType.Null), "said as null, which is every use");
            });

        }

        #endregion

        #region ACertificateMayBeForSeveralUses()

        /// <summary>
        /// One root for the name servers and the time servers alike: one entry,
        /// and one thing to switch off when it is withdrawn.
        /// </summary>
        [Test]
        public void ACertificateMayBeForSeveralUses()
        {

            var store   = new CertificateStore(directory, log);
            var both    = Imported(store, "Our Resolvers' And Clocks' Root", Usages: [ "NTS", "dns", "nts" ]);
            var dnsOnly = Imported(store, "Our Resolvers' Root",             Usages: [ CertificateUsages.DNS ]);

            Assert.Multiple(() => {

                Assert.That(both.Usages,     Is.EqualTo(new[] { "dns", "nts" }), "in lower case, each once, in the order the store lists them");
                Assert.That(store.Entries,   Has.Count.EqualTo(2));

                Assert.That(store.UsableFor(CertificateKind.TLSRoot, CertificateUsages.DNS).Select(entry => entry.Id),
                            Is.EquivalentTo(new[] { both.Id, dnsOnly.Id }));

                Assert.That(store.UsableFor(CertificateKind.TLSRoot, CertificateUsages.NTS).Select(entry => entry.Id),
                            Is.EquivalentTo(new[] { both.Id }), "a root for the name servers alone vouches for no time server");

            });

        }

        #endregion

        #region UsagesSurviveARestart()

        [Test]
        public void UsagesSurviveARestart()
        {

            var first   = new CertificateStore(directory, log);
            var entry   = Imported(first, "Our Clocks' Root", Usages: [ CertificateUsages.NTS ]);
            var never   = Imported(first, "Anybody's Root");

            // A second store over the same directory is what the next start is.
            var second  = new CertificateStore(directory, log);
            second.Reload();

            Assert.Multiple(() => {
                Assert.That(second.Get(entry.Id)!.Usages,  Is.EqualTo(new[] { CertificateUsages.NTS }), "the index remembers what a file cannot say");
                Assert.That(second.Get(never.Id)!.Usages,  Is.Null,                                     "and every use stays every use");
            });

        }

        #endregion

        #region AnIndexWrittenBeforeThereWereUsagesMeansEveryUse()

        [Test]
        public void AnIndexWrittenBeforeThereWereUsagesMeansEveryUse()
        {

            var first  = new CertificateStore(directory, log);
            var entry  = Imported(first, "Our Clocks' Root", Usages: [ CertificateUsages.NTS ]);

            // The index as a node before usages wrote it: the field is not there.
            var index  = Path.Combine(directory, CertificateStore.IndexFileName);
            var json   = JObject.Parse(File.ReadAllText(index));

            foreach (var certificate in json["certificates"]!.Children<JObject>())
                certificate.Remove("usages");

            File.WriteAllText(index, json.ToString());

            var second = new CertificateStore(directory, log);
            second.Reload();

            Assert.Multiple(() => {
                Assert.That(second.Get(entry.Id)!.Usages,                         Is.Null);
                Assert.That(second.Get(entry.Id)!.IsFor(CertificateUsages.DNS),   Is.True);
                Assert.That(second.Get(entry.Id)!.IsActive,                       Is.True, "and nothing else about it was lost");
            });

        }

        #endregion

        #region UsagesAreChangedAndWrittenDown()

        /// <summary>
        /// A root told it may vouch for the time servers can make the node
        /// believe a time: a change of what it is for is written into the
        /// metrological log like every other change of the store, and tagged as
        /// a matter of security.
        /// </summary>
        [Test]
        public void UsagesAreChangedAndWrittenDown()
        {

            var store   = new CertificateStore(directory, log);
            var entry   = Imported(store, "Our Resolvers' Root", Usages: [ CertificateUsages.DNS ]);
            var before  = log.LastId;

            Assert.That(store.SetUsages(entry.Id, [ CertificateUsages.DNS, CertificateUsages.NTS ], out var changed, out var error), Is.True, error);

            var said    = log.Recent(100, before, "security").ToArray();

            Assert.Multiple(() => {
                Assert.That(changed!.Usages,                                       Is.EqualTo(new[] { "dns", "nts" }));
                Assert.That(store.UsableFor(CertificateKind.TLSRoot, "nts"),       Has.Count.EqualTo(1));
                Assert.That(said.Select(entry => entry.Message),                   Has.Some.Contains("is now for dns and nts, where it was for dns"));
                Assert.That(said.All(entry => entry.Metrological),                 Is.True, "every change of the store is evidence");
            });

            Assert.That(store.SetUsages(entry.Id, null, out var again, out error), Is.True, error);
            Assert.That(again!.Usages, Is.Null, "none given is every use again");

        }

        #endregion

        #region ImportingTheSameCertificateAgainMayChangeItsUsages()

        /// <summary>
        /// Usages given at a second import are the usages from then on, as a
        /// label given is the label; an import that says nothing about them
        /// leaves them alone.
        /// </summary>
        [Test]
        public void ImportingTheSameCertificateAgainMayChangeItsUsages()
        {

            var store     = new CertificateStore(directory, log);

            using var root = Root("Our Root");

            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, [ CertificateUsages.DNS ], out var first,  out var error), Is.True, error);
            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, [ CertificateUsages.NTS ], out var second, out error),     Is.True, error);
            Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null,                            out var third,  out error),     Is.True, error);

            Assert.Multiple(() => {
                Assert.That(store.Entries,    Has.Count.EqualTo(1));
                Assert.That(second!.Usages,   Is.EqualTo(new[] { CertificateUsages.NTS }));
                Assert.That(third!.Usages,    Is.EqualTo(new[] { CertificateUsages.NTS }), "said nothing, changed nothing");
            });

        }

        #endregion

        #region WhatAUsageIsNotIsSaidSo()

        [Test]
        public void WhatAUsageIsNotIsSaidSo()
        {

            var store = new CertificateStore(directory, log);

            using var root = Root("Some Root");

            Assert.Multiple(() => {

                Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, [ "ntp" ], out _, out var unknown),  Is.False);
                Assert.That(unknown,  Does.Contain("'ntp' is not a usage this node knows").And.Contain("dns, nts"));

                Assert.That(store.Import(Pem(root), CertificateKind.V2GRoot, null, null, [ CertificateUsages.NTS ], out _, out var kind),  Is.False);
                Assert.That(kind,     Does.Contain("only a TLS root and a server certificate"));

                Assert.That(store.Import(Pem(root), CertificateKind.TLSRoot, null, null, [], out _, out var none),  Is.False);
                Assert.That(none,     Does.Contain("switch off"));

                Assert.That(store.Entries,  Is.Empty, "nothing refused was half-imported");

            });

        }

        #endregion

        #region AKindOfNodeMayAddAUsage()

        /// <summary>
        /// A backend a kind of node dials is a usage of its own - and still one
        /// of a closed list, so that a typo is refused where it is typed.
        /// </summary>
        [Test]
        public void AKindOfNodeMayAddAUsage()
        {

            var store  = new CertificateStore(directory, log, Usages: [ "Backend" ]);
            var entry  = Imported(store, "Our Backend's Root", Usages: [ "backend", CertificateUsages.NTS ]);

            Assert.Multiple(() => {
                Assert.That(store.Usages,  Is.EqualTo(new[] { "dns", "nts", "backend" }));
                Assert.That(entry.Usages,  Is.EqualTo(new[] { "nts", "backend" }));
            });

            Assert.That(() => new CertificateStore(directory, log, Usages: [ "not a usage" ]),
                        Throws.ArgumentException);

        }

        #endregion

        #region AServerCertificateIsForAUseToo()

        /// <summary>
        /// Somebody else's server certificate, kept to recognise that server:
        /// which servers it is recognised as is a usage, as a root's is.
        /// </summary>
        [Test]
        public void AServerCertificateIsForAUseToo()
        {

            var store  = new CertificateStore(directory, log);
            var entry  = Imported(store, "time.example.org", CertificateKind.TLSServer, [ CertificateUsages.NTS ]);

            Assert.Multiple(() => {
                Assert.That(entry.Kind,                            Is.EqualTo(CertificateKind.TLSServer));
                Assert.That(entry.IsFor(CertificateUsages.NTS),    Is.True);
                Assert.That(entry.IsFor(CertificateUsages.DNS),    Is.False);
            });

        }

        #endregion

    }

}
