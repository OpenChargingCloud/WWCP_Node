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

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// The upload of the certificates page: a file or a text looked into before
    /// anything is imported, every certificate in it put in as every kind
    /// ticked, and a certificate kept as several kinds changed and taken out as
    /// one of them - in every kind of node's store, with a kind made up where
    /// the store keeps none that would do.
    /// </summary>
    public abstract partial class NodeConformanceTests
    {

        #region (private static helpers) RootText(Name) / LeafWithKeyText(Name)

        /// <summary>A self-signed CA certificate as PEM, without its key.</summary>
        private static String RootText(String Name)
        {

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request    = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            using var root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return root.ExportCertificatePem() + "\n";

        }

        /// <summary>A self-signed certificate that is no CA, as PEM, with its key.</summary>
        private static String LeafWithKeyText(String Name)
        {

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request    = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

            using var leaf = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return leaf.ExportCertificatePem() + "\n" + key.ExportPkcs8PrivateKeyPem() + "\n";

        }

        /// <summary>
        /// A kind this store keeps to believe a root as - its first trust anchor,
        /// or else one made up - as the upload names it.
        /// </summary>
        private JObject ARootKind(String MadeUp)
        {

            var kept = Node.Certificates.Kinds.Where(kind => kind.IsTrustAnchor()).Select(kind => (CertificateKind?) kind).FirstOrDefault();

            return kept is CertificateKind kind
                       ? new JObject(new JProperty("kind", kind.AsText()))
                       : new JObject(new JProperty("kind", MadeUp), new JProperty("group", "trustAnchor"));

        }

        #endregion


        #region ATextIsLookedIntoWithoutPuttingAnythingIn()

        /// <summary>
        /// Looked into, a text of two roots is two certificates, each with its
        /// PEM, and the store is as it was; a PKCS#12 comes back as PEM with
        /// its key, for the box it was dropped on.
        /// </summary>
        [Test]
        public async Task ATextIsLookedIntoWithoutPuttingAnythingIn()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http        = await SignedIn();

            var before            = InTheStore();
            var text              = RootText("Looked-At Root One") + RootText("Looked-At Root Two");

            var (roots,    found) = await Send(http, HttpMethod.Post, "api/v1/certificates/inspect", new JObject(new JProperty("pem", text)));
            var (pkcs12,   keyed) = await Send(http, HttpMethod.Post, "api/v1/certificates/inspect", new JObject(new JProperty("content", Identity("Looked-At Identity"))));

            Assert.Multiple(() => {

                Assert.That(roots,                                                       Is.EqualTo(HttpStatusCode.OK), found.ToString());
                Assert.That(found["certificates"]!.Select(one => one.Value<String>("label")), Is.EqualTo(new[] { "Looked-At Root One", "Looked-At Root Two" }));
                Assert.That(found["pem"]!.Value<String>(),                               Does.Contain("-----BEGIN CERTIFICATE-----").And.Not.Contain("PRIVATE KEY"));
                Assert.That(found["certificates"]![0]!["inStoreAs"]!.Children(),         Is.Empty);

                Assert.That(pkcs12,                                                      Is.EqualTo(HttpStatusCode.OK), keyed.ToString());
                Assert.That(keyed["certificates"]![0]!.Value<Boolean>("hasPrivateKey"),  Is.True);
                Assert.That(keyed["pem"]!.Value<String>(),                               Does.Contain("-----BEGIN PRIVATE KEY-----"));

                Assert.That(InTheStore(),                                                Is.EquivalentTo(before), "nothing was put in");

            });

        }

        #endregion

        #region AProtectedFileIsSaidToWantItsPassword()

        [Test]
        public async Task AProtectedFileIsSaidToWantItsPassword()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http = await SignedIn();

            using var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var identity = new CertificateRequest("CN=Locked Identity", key, HashAlgorithmName.SHA256).
                                     CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            var locked     = Convert.ToBase64String(identity.Export(X509ContentType.Pkcs12, "opensesame")!);

            var (without, wanted) = await Send(http, HttpMethod.Post, "api/v1/certificates/inspect", new JObject(new JProperty("content", locked)));
            var (with,    opened) = await Send(http, HttpMethod.Post, "api/v1/certificates/inspect", new JObject(new JProperty("content", locked), new JProperty("password", "opensesame")));

            Assert.Multiple(() => {
                Assert.That(without,                                  Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(wanted.Value<Boolean>("passwordWanted"),  Is.True, wanted.ToString());
                Assert.That(with,                                     Is.EqualTo(HttpStatusCode.OK), opened.ToString());
            });

        }

        #endregion

        #region EveryCertificateOfATextGoesInAsEveryKindTicked()

        /// <summary>
        /// Two roots in one text, ticked as a kind the store keeps and as a kind
        /// made up, are two certificates, each kept as both kinds - and the
        /// store offers the kind made up from then on.
        /// </summary>
        [Test]
        public async Task EveryCertificateOfATextGoesInAsEveryKindTicked()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http       = await SignedIn();

            var kept             = ARootKind("uploadedRoot");
            var text             = RootText("Ticked Root One") + RootText("Ticked Root Two");

            var (status, said)   = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kinds", new JArray(kept, new JObject(new JProperty("kind", "ourOtherRoot"), new JProperty("group", "trustAnchor")))),
                                                  new JProperty("pem",   text)
                                              ));

            var store            = await GetJSON(http, "api/v1/certificates");
            var id               = said["imported"]?[0]?.Value<String>("id");
            var (_, one)         = await Send(http, HttpMethod.Get, $"api/v1/certificates/{id}");

            Assert.Multiple(() => {
                Assert.That(status,                                           Is.EqualTo(HttpStatusCode.Created), said.ToString());
                Assert.That(said["imported"]!.Children().Count(),             Is.EqualTo(4), "two certificates, each as both kinds");
                Assert.That(said["refused"]!.Children(),                      Is.Empty);
                Assert.That(store["trustAnchors"]!.Values<String>(),           Does.Contain("ourOtherRoot"), "a kind made up is a kind of the store's from then on");
                Assert.That(store["kinds"]!["ourOtherRoot"]!.Value<Boolean>("custom"), Is.True);
                Assert.That(one["kinds"]!.Values<String>(),                    Is.EquivalentTo(new[] { kept.Value<String>("kind"), "ourOtherRoot" }));
            });

        }

        #endregion

        #region ACertificateOfATextThatCannotGoInIsSaidSoAndTheOthersGoIn()

        [Test]
        public async Task ACertificateOfATextThatCannotGoInIsSaidSoAndTheOthersGoIn()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http       = await SignedIn();

            var (status, said)   = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kinds", new JArray(new JObject(new JProperty("kind", "partlyRoot"), new JProperty("group", "trustAnchor")))),
                                                  new JProperty("pem",   RootText("A Root That Goes In") + LeafWithKeyText("A Key In The Wrong Place"))
                                              ));

            Assert.Multiple(() => {
                Assert.That(status,                                                Is.EqualTo(HttpStatusCode.Created), said.ToString());
                Assert.That(said["imported"]!.Select(one => one.Value<String>("label")), Is.EqualTo(new[] { "A Root That Goes In" }));
                Assert.That(said["refused"]![0]!.Value<String>("label"),           Is.EqualTo("A Key In The Wrong Place"));
                Assert.That(said["refused"]![0]!.Value<String>("error"),           Does.StartWith("That file carries a private key, and a trust anchor must not."));
            });

        }

        #endregion

        #region AKindMadeUpIsNamedWithoutItsGroupOnceItIsKept()

        /// <summary>
        /// A kind made up is a kind of the store's once a certificate is kept
        /// as it: named again, it needs no group - which the page sends for a
        /// kind it does not know yet, and only for that.
        /// </summary>
        [Test]
        public async Task AKindMadeUpIsNamedWithoutItsGroupOnceItIsKept()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http        = await SignedIn();

            var (made,  first)    = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kinds", new JArray(new JObject(new JProperty("kind", "keptMark"), new JProperty("group", "trustAnchor")))),
                                                  new JProperty("pem",   RootText("The First Of A Kind"))
                                              ));

            var (again, second)   = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kinds", new JArray(new JObject(new JProperty("kind", "keptMark")))),
                                                  new JProperty("pem",   RootText("The Second Of A Kind"))
                                              ));

            Assert.Multiple(() => {
                Assert.That(made,   Is.EqualTo(HttpStatusCode.Created), first.ToString());
                Assert.That(again,  Is.EqualTo(HttpStatusCode.Created), second.ToString());
                Assert.That(second["imported"]?[0]?.Value<String>("kind"),  Is.EqualTo("keptMark"));
            });

        }

        #endregion

        #region AKindNobodyKnowsWithoutItsGroupIsRefused()

        [Test]
        public async Task AKindNobodyKnowsWithoutItsGroupIsRefused()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http       = await SignedIn();

            var before           = InTheStore();

            var (status, said)   = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kinds", new JArray(new JObject(new JProperty("kind", "neverHeardOf")))),
                                                  new JProperty("pem",   RootText("A Root Of No Kind"))
                                              ));

            Assert.Multiple(() => {
                Assert.That(status,                      Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(said.Value<String>("error"), Does.StartWith($"'neverHeardOf' is no kind this {Node.Kind.Name} knows. To make it up, say which group it is in"));
                Assert.That(InTheStore(),                Is.EquivalentTo(before));
            });

        }

        #endregion

        #region ACertificateKeptAsSeveralKindsIsChangedAndTakenOutAsOne()

        /// <summary>
        /// Switched off and taken out as one of the kinds it is kept as, a
        /// certificate stays as the others; taken out without a kind, it goes as
        /// every kind.
        /// </summary>
        [Test]
        public async Task ACertificateKeptAsSeveralKindsIsChangedAndTakenOutAsOne()
        {

            Assume.That(Node.Certificates.Kinds, Is.Not.Empty, $"The store of this {Node.Kind.Name} keeps nothing.");

            using var http       = await SignedIn();

            var (created, said)  = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kinds", new JArray(new JObject(new JProperty("kind", "firstMark"),  new JProperty("group", "trustAnchor")),
                                                                                    new JObject(new JProperty("kind", "secondMark"), new JProperty("group", "trustAnchor")))),
                                                  new JProperty("pem",   RootText("A Root Kept Twice"))
                                              ));

            Assert.That(created, Is.EqualTo(HttpStatusCode.Created), said.ToString());

            var id               = said["imported"]![0]!.Value<String>("id")!;
            var path             = $"api/v1/certificates/{id}";

            var (off,    switched) = await Send(http, HttpMethod.Patch,  path, new JObject(new JProperty("kind", "secondMark"), new JProperty("active", false)));
            var asFirst            = Node.Certificates.Get(id, CertificateKind.Custom("firstMark", CertificateGroup.TrustAnchor));
            var (out1,   _)        = await Send(http, HttpMethod.Delete, path + "?kind=secondMark");
            var left               = Node.Certificates.Registrations(id).Select(entry => entry.Kind.AsText()).ToArray();
            var (out2,   _)        = await Send(http, HttpMethod.Delete, path);

            Assert.Multiple(() => {
                Assert.That(off,                                Is.EqualTo(HttpStatusCode.OK), switched.ToString());
                Assert.That(switched.Value<Boolean>("active"),  Is.False);
                Assert.That(asFirst?.IsActive,                  Is.True, "the other kind is left as it was");
                Assert.That(out1,                               Is.EqualTo(HttpStatusCode.OK));
                Assert.That(left,                               Is.EqualTo(new[] { "firstMark" }));
                Assert.That(out2,                               Is.EqualTo(HttpStatusCode.OK));
                Assert.That(Node.Certificates.Registrations(id), Is.Empty);
            });

        }

        #endregion

    }

}
