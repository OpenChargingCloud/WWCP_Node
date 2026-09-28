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
    /// The node's own certificate store, over the wire: what a TLS root is
    /// for, an identity that comes with its key and one that does not, a file
    /// copied into the directory by hand, and who changed what.
    /// </summary>
    /// <remarks>
    /// Asked of the kinds of certificate the store of this kind of node keeps:
    /// what the answer is expected to say is read off the store, and a test of
    /// a kind the store does not keep is not run - inconclusive, and saying
    /// why.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region (private static helpers) RootPem(Name) / Identity(Name, WithKey)

        /// <summary>
        /// A self-signed root, as the text of a PEM file base64-encoded - which
        /// is what an upload from the browser turns into.
        /// </summary>
        private static String RootPem(String Name)
        {

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request    = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            using var root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return Convert.ToBase64String(Encoding.ASCII.GetBytes(root.ExportCertificatePem()));

        }

        /// <summary>
        /// A certificate the node could present, with its private key, as an
        /// unprotected PKCS#12 base64-encoded - or, without the key, as the
        /// certificate alone.
        /// </summary>
        private static String Identity(String   Name,
                                       Boolean  WithKey = true)
        {

            using var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request        = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.2") ], false));

            using var identity = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return WithKey
                       ? Convert.ToBase64String(identity.Export(X509ContentType.Pkcs12))
                       : Convert.ToBase64String(Encoding.ASCII.GetBytes(identity.ExportCertificatePem()));

        }

        #endregion

        #region (private) Keeps(Kind) / ARootIn(HTTP, Name, Usages)

        /// <summary>
        /// Go on only where the store of this kind of node keeps certificates
        /// of the given kind.
        /// </summary>
        private void Keeps(CertificateKind Kind)

            => Assume.That(Node.Certificates.Kinds, Does.Contain(Kind),
                           $"The store of a {Node.Kind.Name} keeps no {Kind.AsText()}.");

        /// <summary>
        /// A TLS root of the given name, put into the store through the API,
        /// and its entry.
        /// </summary>
        private static async Task<JObject> ARootIn(HttpClient  HTTP,
                                                   String      Name,
                                                   JToken?     Usages = null)
        {

            var body = new JObject(
                           new JProperty("kind",     CertificateKind.TLSRoot.AsText()),
                           new JProperty("content",  RootPem(Name))
                       );

            if (Usages is not null)
                body["usages"] = Usages;

            var (created, entry) = await Send(HTTP, HttpMethod.Post, "api/v1/certificates", body);

            Assert.That(created, Is.EqualTo(HttpStatusCode.Created), entry.ToString());

            return entry;

        }

        #endregion


        #region ARootIsUploadedForTheUsesItIsFor()

        [Test]
        public async Task ARootIsUploadedForTheUsesItIsFor()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http  = await SignedIn();

            var entry       = await ARootIn(http, "Our Clocks' Root",       new JArray("nts"));
            _               = await ARootIn(http, "Our Clocks' Other Root", new JArray("nts"));

            var store       = await GetJSON(http, "api/v1/certificates");

            Assert.Multiple(() => {
                Assert.That(entry["usages"]!.Values<String>(),                                     Is.EqualTo(new[] { "nts" }));
                Assert.That(entry["label"]!.Value<String>(),                                       Is.EqualTo("Our Clocks' Root"), "its common name, where no label was given");
                Assert.That(store["certificates"]!["tlsRoot"]!.Children().Count(),                 Is.EqualTo(2));
                Assert.That(store["certificates"]!["tlsRoot"]![0]!["usages"]!.Values<String>(),   Is.EqualTo(new[] { "nts" }));
            });

        }

        #endregion

        #region WhatARootIsForIsChangedAndTakenBackToEveryUse()

        [Test]
        public async Task WhatARootIsForIsChangedAndTakenBackToEveryUse()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http  = await SignedIn();

            var entry             = await ARootIn(http, "Our Resolvers' Root", new JArray("dns"));
            var path              = $"api/v1/certificates/{entry["id"]}";

            var (both,  forBoth)  = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("usages", new JArray("nts", "dns"))));
            var (label, relabel)  = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("label",  "Our Root")));
            var (every, forAll)   = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("usages", JValue.CreateNull())));

            Assert.Multiple(() => {
                Assert.That(both,                                   Is.EqualTo(HttpStatusCode.OK), forBoth.ToString());
                Assert.That(forBoth["usages"]!.Values<String>(),    Is.EqualTo(new[] { "dns", "nts" }));
                Assert.That(label,                                  Is.EqualTo(HttpStatusCode.OK), relabel.ToString());
                Assert.That(relabel["label"]!.Value<String>(),      Is.EqualTo("Our Root"));
                Assert.That(relabel["usages"]!.Values<String>(),    Is.EqualTo(new[] { "dns", "nts" }), "a PATCH without them leaves them alone");
                Assert.That(every,                                  Is.EqualTo(HttpStatusCode.OK), forAll.ToString());
                Assert.That(forAll["usages"]!.Type,                 Is.EqualTo(JTokenType.Null),       "null is every use again");
                Assert.That(Node.Log.Recent(200, Tag: "security").Any(line => line.Message.Contains("is now for every use")),
                            Is.True,
                            "a change of what a root vouches for is a matter of security, and said as one");
            });

        }

        #endregion

        #region WhatIsNotAUsageOrAKindOfThisStoreIsRefusedWhereItIsTyped()

        [Test]
        public async Task WhatIsNotAUsageOrAKindOfThisStoreIsRefusedWhereItIsTyped()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http  = await SignedIn();

            var (unknown, said)      = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                      new JProperty("kind",     "tlsRoot"),
                                                      new JProperty("content",  RootPem("Some Root")),
                                                      new JProperty("usages",   new JArray("ntp"))
                                                  ));

            var (notAList, listSaid) = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                      new JProperty("kind",     "tlsRoot"),
                                                      new JProperty("content",  RootPem("Another Root")),
                                                      new JProperty("usages",   "dns")
                                                  ));

            // A kind this store does not keep, where there is one: a vehicle's
            // store keeps every kind there is.
            var notKept              = CertificateKindExtensions.All.
                                           Where (kind => !Node.Certificates.Kinds.Contains(kind)).
                                           Select(kind => (CertificateKind?) kind).
                                           FirstOrDefault();

            HttpStatusCode? refused  = null;
            var kindSaid             = new JObject();

            if (notKept is CertificateKind kindNotKept)
                (refused, kindSaid)  = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                           new JProperty("kind",     kindNotKept.AsText()),
                                           new JProperty("content",  RootPem("A Root Of A Kind Not Kept"))
                                       ));

            var (_, store)           = await Send(http, HttpMethod.Get, "api/v1/certificates");

            Assert.Multiple(() => {

                Assert.That(unknown,              Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(said.ToString(),      Does.Contain("'ntp' is not a usage").And.Contain(String.Join(", ", Node.Certificates.UsagesFor(CertificateKind.TLSRoot))));

                Assert.That(notAList,             Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(listSaid.ToString(),  Does.Contain("has to be a list of usages"));

                if (refused is not null)
                {
                    Assert.That(refused,                           Is.EqualTo(HttpStatusCode.BadRequest), $"{notKept?.AsText()}, which this store does not keep");
                    Assert.That(kindSaid.Value<String>("error"),   Is.EqualTo("'kind' has to be one of " + String.Join(", ", Node.Certificates.Kinds.Select(kind => kind.AsText())) + "."),
                                "the kinds this store keeps, and not every kind there is");
                }

                Assert.That(store["certificates"]!.Values().SelectMany(kind => kind.Children()).Any(),
                            Is.False,
                            "nothing refused was half-imported");

            });

        }

        #endregion

        #region AnIdentityIsToldOnlyTheListenersOfItsNode()

        /// <summary>
        /// An identity is told the listeners it is shown on, and only those of
        /// this kind of node - not the services a root vouches for. A kind of
        /// node that names no listener has an identity told nothing at all.
        /// </summary>
        [Test]
        public async Task AnIdentityIsToldOnlyTheListenersOfItsNode()
        {

            Keeps(CertificateKind.TLSIdentity);

            using var http  = await SignedIn();

            var (status, said) = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                new JProperty("kind",     "tlsIdentity"),
                                                new JProperty("content",  Identity("Not For The Name Servers")),
                                                new JProperty("usages",   new JArray("dns"))
                                            ));

            Assert.Multiple(() => {
                Assert.That(status,           Is.EqualTo(HttpStatusCode.BadRequest), said.ToString());
                Assert.That(said.ToString(),  Node.Certificates.Listeners.Count == 0
                                                  ? Does.Contain("names none")
                                                  : Does.Contain("'dns' is not a listener"));
            });

        }

        #endregion

        #region AnIdentityComesWithItsKeyAndIsSwitchedOffRenamedAndDeleted()

        [Test]
        public async Task AnIdentityComesWithItsKeyAndIsSwitchedOffRenamedAndDeleted()
        {

            Keeps(CertificateKind.TLSIdentity);

            using var http  = await SignedIn();

            var (created, entry)  = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                   new JProperty("kind",     "tlsIdentity"),
                                                   new JProperty("content",  Identity("node-001")),
                                                   new JProperty("label",    "What This Node Presents")
                                               ));

            Assert.That(created, Is.EqualTo(HttpStatusCode.Created), entry.ToString());

            var stored            = Node.Certificates.Get(entry["id"]!.Value<String>())!;

            // A kind of node whose listeners need an identity may refuse to be
            // left without one - see WWCPNode.WhatWouldLose - and a node of
            // that kind is not asked here what it would do without this one.
            Assume.That(Node.WhatWouldLose(stored, false, stored.Usages), Is.Null,
                        $"A {Node.Kind.Name} needs the identity it has just been given.");

            var path              = $"api/v1/certificates/{entry["id"]}";
            var file              = Node.Certificates.FullPath(stored);

            var (_, withKey)      = await Send(http, HttpMethod.Get,    "api/v1/certificates");
            var (off, switched)   = await Send(http, HttpMethod.Patch,  path, new JObject(new JProperty("active", false)));
            var (_, one)          = await Send(http, HttpMethod.Get,    path);
            var wasThere          = File.Exists(file);
            var (gone, after)     = await Send(http, HttpMethod.Delete, path);
            var (missing, _)      = await Send(http, HttpMethod.Get,    path);

            Assert.Multiple(() => {

                Assert.That(entry["hasPrivateKey"]!.Value<Boolean>(),        Is.True);
                Assert.That(entry["label"]!.Value<String>(),                 Is.EqualTo("What This Node Presents"));
                Assert.That(withKey["keysAreUnencrypted"]!.Value<Boolean>(), Is.True, "said on the page, where somebody looks at the consequences");
                Assert.That(entry.ToString(),                                Does.Not.Contain("PRIVATE KEY"), "the key is not in the answer");

                Assert.That(off,                                             Is.EqualTo(HttpStatusCode.OK), switched.ToString());
                Assert.That(one["active"]!.Value<Boolean>(),                 Is.False);
                Assert.That(one["usable"]!.Value<Boolean>(),                 Is.False, "switched off is not usable, whatever its dates say");

                Assert.That(wasThere,                                        Is.True, $"the store keeps it as a file of its own: {file}");
                Assert.That(gone,                                            Is.EqualTo(HttpStatusCode.OK), after.ToString());
                Assert.That(File.Exists(file),                               Is.False, "its file goes with it");
                Assert.That(missing,                                         Is.EqualTo(HttpStatusCode.NotFound));

            });

        }

        #endregion

        #region AnIdentityWithoutItsKeyIsRefused()

        [Test]
        public async Task AnIdentityWithoutItsKeyIsRefused()
        {

            Keeps(CertificateKind.TLSIdentity);

            using var http  = await SignedIn();

            var (status, said) = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                new JProperty("kind",     "tlsIdentity"),
                                                new JProperty("content",  Identity("node-002", WithKey: false))
                                            ));

            var (_, store)     = await Send(http, HttpMethod.Get, "api/v1/certificates");

            Assert.Multiple(() => {
                Assert.That(status,                                                     Is.EqualTo(HttpStatusCode.BadRequest), said.ToString());
                Assert.That(store["certificates"]!["tlsIdentity"]!.Children().Any(),    Is.False,
                            "something the node cannot present with is not an identity of its own");
            });

        }

        #endregion

        #region ACertificateCopiedIntoTheDirectoryIsAdoptedWhenItIsReadAgain()

        [Test]
        public async Task ACertificateCopiedIntoTheDirectoryIsAdoptedWhenItIsReadAgain()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http  = await SignedIn();

            var (_, before)     = await Send(http, HttpMethod.Get, "api/v1/certificates");

            var roots           = Path.Combine(Node.Certificates.Directory,
                                               CertificateKind.TLSRoot.Directory().Replace('/', Path.DirectorySeparatorChar));

            System.IO.Directory.CreateDirectory(roots);
            File.WriteAllBytes(Path.Combine(roots, "copied-by-hand.pem"), Convert.FromBase64String(RootPem("Copied By Hand")));

            var (status, after) = await Send(http, HttpMethod.Post, "api/v1/certificates/reload", new JObject());

            Assert.Multiple(() => {
                Assert.That(before["certificates"]!["tlsRoot"]!.Children().Any(),   Is.False);
                Assert.That(status,                                                 Is.EqualTo(HttpStatusCode.OK), after.ToString());
                Assert.That(after["certificates"]!["tlsRoot"]!.Select(entry => entry["label"]!.Value<String>()),
                            Is.EqualTo(new[] { "Copied By Hand" }));
            });

        }

        #endregion

        #region AHandleWrittenInCapitalsIsFound()

        /// <summary>
        /// The store spells a handle in lower case, and somebody may have
        /// copied it out of something that writes capitals.
        /// </summary>
        [Test]
        public async Task AHandleWrittenInCapitalsIsFound()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http     = await SignedIn();

            var handle         = (await ARootIn(http, "A Root Asked For In Capitals"))["id"]!.Value<String>()!;

            var (found, entry) = await Send(http, HttpMethod.Get, $"api/v1/certificates/{handle.ToUpperInvariant()}");

            Assert.Multiple(() => {
                Assert.That(handle,                      Is.EqualTo(handle.ToLowerInvariant()), "a handle as the store spells it");
                Assert.That(found,                       Is.EqualTo(HttpStatusCode.OK), entry.ToString());
                Assert.That(entry.Value<String>("id"),   Is.EqualTo(handle));
            });

        }

        #endregion

        #region ARefusedChangeChangesNothing()

        /// <summary>
        /// Whatever can refuse a change is asked before any of it is made: a
        /// request refused for its "active" or its usages does not rename the
        /// certificate first, as it did while the three were made one after
        /// the other.
        /// </summary>
        [Test]
        public async Task ARefusedChangeChangesNothing()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http     = await SignedIn();

            var handle         = (await ARootIn(http, "A Root Nobody Renames"))["id"]!.Value<String>()!;
            var path           = $"api/v1/certificates/{handle}";

            var (notYes, _)    = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("label", "Renamed By A Refusal"), new JProperty("active", "yes")));
            var (bogus,  _)    = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("label", "Renamed By A Refusal"), new JProperty("usages", new JArray("bogus"))));

            var (_, kept)      = await Send(http, HttpMethod.Get, path);

            Assert.Multiple(() => {
                Assert.That(notYes,                          Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(bogus,                           Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(kept.Value<String>("label"),     Is.EqualTo("A Root Nobody Renames"), "a refused request renamed it");
                Assert.That(kept.Value<Boolean>("active"),   Is.True);
            });

        }

        #endregion

        #region WhoChangedSomethingIsInTheLog()

        /// <summary>
        /// The node says what changed; who changed it only the request knows,
        /// and says it: the name resolution, the time source, and every change
        /// of the certificate store.
        /// </summary>
        [Test]
        public async Task WhoChangedSomethingIsInTheLog()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http     = await SignedIn();

            var (dns,    _)    = await Send(http, HttpMethod.Put,    "api/v1/configuration/dns", new JObject());
            var (nts,    _)    = await Send(http, HttpMethod.Put,    "api/v1/configuration/nts", new JObject());
            var handle         = (await ARootIn(http, "A Root Somebody Put In"))["id"]!.Value<String>()!;
            var (patch,  _)    = await Send(http, HttpMethod.Patch,  $"api/v1/certificates/{handle}", new JObject(new JProperty("label", "A Root Somebody Renamed")));
            var (reload, _)    = await Send(http, HttpMethod.Post,   "api/v1/certificates/reload", new JObject());
            var (delete, _)    = await Send(http, HttpMethod.Delete, $"api/v1/certificates/{handle}");

            var said           = Node.Log.Recent(Int32.MaxValue).
                                          Where (entry => entry.Tags.Contains("web")).
                                          Select(entry => $"{entry.Level}: {entry.Message}").
                                          ToArray();

            Assert.Multiple(() => {
                Assert.That(new[] { dns, nts, patch, reload, delete }, Is.All.EqualTo(HttpStatusCode.OK));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' changed the name resolution of this {Node.Kind.Name}."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' changed the time source of this {Node.Kind.Name}."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' put 'A Root Somebody Put In' into the certificate store as a tlsRoot ({handle})."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' changed the certificate 'A Root Somebody Renamed' ({handle}) in the certificate store."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' had the certificate store read again from its directory."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' took the certificate 'A Root Somebody Renamed' ({handle}) out of the certificate store."));
            });

        }

        #endregion

    }

}
