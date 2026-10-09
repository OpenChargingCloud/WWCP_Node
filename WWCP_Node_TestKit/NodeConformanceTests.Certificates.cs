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

        #region (private static helpers) RootPem(Name) / RootAndItsHandle(Name) / Identity(Name, WithKey)

        /// <summary>
        /// A self-signed root, as the text of a PEM file base64-encoded - which
        /// is what an upload from the browser turns into.
        /// </summary>
        private static String RootPem(String Name)

            => RootAndItsHandle(Name).Content;

        /// <summary>
        /// A self-signed root as <see cref="RootPem"/> makes one, and the handle
        /// the store will give it - for a test that has to be where its file
        /// goes before it is there.
        /// </summary>
        private static (String Content, String Handle) RootAndItsHandle(String Name)
        {

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request    = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            using var root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return (Convert.ToBase64String(Encoding.ASCII.GetBytes(root.ExportCertificatePem())),
                    CertificateEntry.ThumbprintOf(root)[..CertificateEntry.IdLength]);

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

        #region (private) InTheStore()

        /// <summary>
        /// The handles of what the store holds now, to be held against what it
        /// holds after a request that was refused - rather than asking the store
        /// to be empty: a kind of node may keep certificates of its own there
        /// from its first start, as a meter keeps the identity its Modbus/TLS
        /// listener shows and the root its clients are issued by.
        /// </summary>
        private String[] InTheStore()

            => [.. Node.Certificates.Entries.Select(entry => entry.Id)];

        #endregion

        #region (private) TheIndexCannotBeWritten() / WhatIsSaidOf(Entry)

        /// <summary>
        /// Where the store writes its index before moving it over the old one,
        /// a directory: every change that is written into the index fails, as on
        /// a full disk, and nothing else does. Returns where it is, to be taken
        /// away again.
        /// </summary>
        private String TheIndexCannotBeWritten()
        {

            var blocked = Path.Combine(Node.Certificates.Directory, CertificateStore.IndexFileName + ".new");

            System.IO.Directory.CreateDirectory(blocked);

            return blocked;

        }

        /// <summary>
        /// What a change of a certificate can change of it, in one line: its
        /// label, whether it is on, and what it is for.
        /// </summary>
        private static String WhatIsSaidOf(JObject Entry)

            => $"'{Entry.Value<String>("label")}', " +
               $"{(Entry.Value<Boolean>("active") ? "on" : "off")}, " +
               $"for {(Entry["usages"] is JArray usages ? String.Join(" and ", usages.Values<String>()) : "every use")}";

        #endregion

        #region (private) Keeps(Kind) / ARootIn(HTTP, Name, Usages)

        /// <summary>
        /// Go on only where the store of this kind of node keeps certificates
        /// of the given kind.
        /// </summary>
        private void Keeps(CertificateKind Kind)

            => Assume.That(Node.Certificates.Kinds, Does.Contain(Kind),
                           $"The store of this {Node.Kind.Name} keeps no {Kind.AsText()}.");

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


        #region TheStoreSaysWhatEachOfItsKindsIsFor()

        /// <summary>
        /// What the page's usage fields are drawn from: for every kind the
        /// store keeps, whether one of it is told what it is for and what it
        /// may be told - the store's word, not the kind's - and which kinds are
        /// believed, presented and recognised.
        /// </summary>
        /// <remarks>
        /// Asked of the kind's own answer, so that what a kind of node adds to
        /// it - see WWCPNode.CompleteCertificatesJSON - cannot overwrite what
        /// every node says. A TLS root and a server certificate may be told the
        /// node's services, and an identity the listeners its kind names; and a
        /// page that offered an identity the services a root vouches for was
        /// offering what the store then refused.
        /// </remarks>
        [Test]
        public async Task TheStoreSaysWhatEachOfItsKindsIsFor()
        {

            using var http = await SignedIn();

            var store      = await GetJSON(http, "api/v1/certificates");
            var kinds      = Node.Certificates.Kinds;

            Assert.Multiple(() => {

                Assert.That(store["usages"]!.Values<String>(),         Is.EqualTo(Node.Certificates.Usages.Select(usage => usage.ToString())), "what a page may offer");
                Assert.That(((JObject) store["kinds"]!).Properties().Select(kind => kind.Name),
                            Is.EquivalentTo(kinds.Select(kind => kind.AsText())),
                            "the kinds this store keeps, and no others");

                foreach (var kind in kinds)
                {
                    Assert.That(store["kinds"]![kind.AsText()]!["hasUsages"]!.Value<Boolean>(),  Is.EqualTo(Node.Certificates.HasUsages(kind)),  $"whether {kind.WithArticle()} is told what it is for");
                    Assert.That(store["kinds"]![kind.AsText()]!["usages"]!.Values<String>(),     Is.EqualTo(Node.Certificates.KnownUsages(kind).Select(usage => usage.ToString())),  $"what {kind.WithArticle()} is offered");
                    Assert.That(store["kinds"]![kind.AsText()]!["page"]!.Value<String>(),        Is.EqualTo(CertificateKind.AsText(kind.Page)),  $"the page {kind.WithArticle()} is looked after on");
                    Assert.That(store["kinds"]![kind.AsText()]!["withArticle"]!.Value<String>(), Is.EqualTo(kind.WithArticle()),  "how a sentence names one of it");
                }

                if (kinds.Contains(CertificateKind.TLSRoot))
                    Assert.That(Node.Certificates.UsagesFor(CertificateKind.TLSRoot).Select(usage => usage.ToString()),  Does.Contain("dns").And.Contain("nts"),
                                "a TLS root may vouch for the node's name servers and time servers");

                if (kinds.Contains(CertificateKind.TLSServerIdentity))
                    Assert.That(Node.Certificates.UsagesFor(CertificateKind.TLSServerIdentity),  Is.EqualTo(Node.Certificates.Listeners),
                                "a server identity is told the listeners its kind of node names, and nothing a root vouches for");

                if (kinds.Contains(CertificateKind.TLSIdentity))
                    Assert.That(Node.Certificates.UsagesFor(CertificateKind.TLSIdentity),        Is.Empty,
                                "who the node is as a client is offered no listener");

                Assert.That(store["trustAnchors"]!.Values<String>(),  Is.EquivalentTo(kinds.Where(kind => kind.Group == CertificateGroup.TrustAnchor).Select(kind => kind.AsText())), "what the node believes");
                Assert.That(store["credentials"]!. Values<String>(),  Is.EquivalentTo(kinds.Where(kind => kind.Group == CertificateGroup.Credential). Select(kind => kind.AsText())), "what it presents");
                Assert.That(store["recognised"]!.  Values<String>(),  Is.EquivalentTo(kinds.Where(kind => kind.Group == CertificateGroup.Recognised). Select(kind => kind.AsText())), "what it recognises a server by");

            });

        }

        #endregion

        #region ARootMayBeMarkedWithAUsageMadeUp()

        /// <summary>
        /// A root of any kind may be marked with a usage nobody defined - for a
        /// configuration or code to name later - and the store offers it for as
        /// long as a certificate is marked with it, and no longer.
        /// </summary>
        [Test]
        public async Task ARootMayBeMarkedWithAUsageMadeUp()
        {

            var kind = Node.Certificates.Kinds.
                           Where (kind => kind.IsTrustAnchor() && kind != CertificateKind.ClientRoot).
                           Select(kind => (CertificateKind?) kind).
                           FirstOrDefault();

            Assume.That(kind, Is.Not.Null, $"The store of this {Node.Kind.Name} keeps no root.");

            using var http  = await SignedIn();

            var (status, said) = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                new JProperty("kind",     kind!.Value.AsText()),
                                                new JProperty("content",  RootPem("A Root Marked For Our Backend")),
                                                new JProperty("usages",   new JArray("Our-Backend"))
                                            ));

            var offered        = (await GetJSON(http, "api/v1/certificates"))["kinds"]![kind!.Value.AsText()]!["usages"]!.Values<String>().ToArray();
            var (deleted, _)   = await Send(http, HttpMethod.Delete, $"api/v1/certificates/{said["id"]}");
            var offeredAfter   = (await GetJSON(http, "api/v1/certificates"))["kinds"]![kind!.Value.AsText()]!["usages"]!.Values<String>().ToArray();

            Assert.Multiple(() => {
                Assert.That(status,                          Is.EqualTo(HttpStatusCode.Created), said.ToString());
                Assert.That(said["usages"]!.Values<String>(), Is.EqualTo(new[] { "our-backend" }), "in lower case");
                Assert.That(offered,                         Does.Contain("our-backend"));
                Assert.That(deleted,                         Is.EqualTo(HttpStatusCode.OK));
                Assert.That(offeredAfter,                    Does.Not.Contain("our-backend"), "nothing but the certificates remembers it");
            });

        }

        #endregion

        #region ARootIsUploadedForTheUsesItIsFor()

        [Test]
        public async Task ARootIsUploadedForTheUsesItIsFor()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http  = await SignedIn();

            var rootsBefore = Node.Certificates.ByKind(CertificateKind.TLSRoot).Count;

            var entry       = await ARootIn(http, "Our Clocks' Root",       new JArray("nts"));
            _               = await ARootIn(http, "Our Clocks' Other Root", new JArray("nts"));

            var store       = await GetJSON(http, "api/v1/certificates");
            var listed      = store["certificates"]!["tlsRoot"]!.Children<JObject>().
                                  FirstOrDefault(root => root.Value<String>("id") == entry.Value<String>("id"));

            Assert.Multiple(() => {
                Assert.That(entry["usages"]!.Values<String>(),                        Is.EqualTo(new[] { "nts" }));
                Assert.That(entry["label"]!.Value<String>(),                          Is.EqualTo("Our Clocks' Root"), "its common name, where no label was given");
                Assert.That(store["certificates"]!["tlsRoot"]!.Children().Count(),    Is.EqualTo(rootsBefore + 2));
                Assert.That(listed?["usages"]?.Values<String>(),                      Is.EqualTo(new[] { "nts" }), "and so the store lists it");
            });

        }

        #endregion

        #region ARootUploadedWithoutUsagesIsForEveryUse()

        /// <summary>
        /// A root uploaded without saying what it is for vouches for every use,
        /// and its entry says so with null - not with an empty list, which
        /// would be a root for nothing.
        /// </summary>
        [Test]
        public async Task ARootUploadedWithoutUsagesIsForEveryUse()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http  = await SignedIn();

            var entry       = await ARootIn(http, "Our Root For Everything");
            var (_, read)   = await Send(http, HttpMethod.Get, $"api/v1/certificates/{entry["id"]}");

            Assert.Multiple(() => {
                Assert.That(entry.ContainsKey("usages"),  Is.True,                  "what it is for is left out rather than said");
                Assert.That(entry["usages"]?.Type,        Is.EqualTo(JTokenType.Null));
                Assert.That(read ["usages"]?.Type,        Is.EqualTo(JTokenType.Null), "and read back, the same");
            });

        }

        #endregion

        #region ACertificateThatIsNotThereIsSaidToBeNone()

        /// <summary>
        /// A handle nothing in the store has is a 404 with a sentence, read or
        /// changed - and deleting it is one as well.
        /// </summary>
        [Test]
        public async Task ACertificateThatIsNotThereIsSaidToBeNone()
        {

            using var http          = await SignedIn();

            var path                = "api/v1/certificates/nothing-by-this-handle";

            var (read,    saidRead)  = await Send(http, HttpMethod.Get,    path);
            var (changed, saidPatch) = await Send(http, HttpMethod.Patch,  path, new JObject(new JProperty("active", false)));
            var (deleted, _)         = await Send(http, HttpMethod.Delete, path);

            Assert.Multiple(() => {
                Assert.That(read,                              Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(saidRead. Value<String>("error"),  Is.EqualTo("There is no such certificate in this store."));
                Assert.That(changed,                           Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(saidPatch.Value<String>("error"),  Is.EqualTo("There is no such certificate in this store."));
                Assert.That(deleted,                           Is.EqualTo(HttpStatusCode.NotFound));
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

            var before               = InTheStore();

            var (unknown, said)      = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                      new JProperty("kind",     "tlsRoot"),
                                                      new JProperty("content",  RootPem("Some Root")),
                                                      new JProperty("usages",   new JArray("not a usage!"))
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

            Assert.Multiple(() => {

                Assert.That(unknown,              Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(said.ToString(),      Does.Contain("'not a usage!' is not a usage name"));

                Assert.That(notAList,             Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(listSaid.ToString(),  Does.Contain("has to be a list of usages"));

                if (refused is not null)
                {
                    Assert.That(refused,                           Is.EqualTo(HttpStatusCode.BadRequest), $"{notKept?.AsText()}, which this store does not keep");
                    Assert.That(kindSaid.Value<String>("error"),   Is.EqualTo("'kind' has to be one of " + String.Join(", ", Node.Certificates.Kinds.Select(kind => kind.AsText())) + "."),
                                "the kinds this store keeps, and not every kind there is");
                }

                Assert.That(InTheStore(), Is.EquivalentTo(before), "nothing refused was half-imported");

            });

        }

        #endregion

        #region AnIdentityMarkedForSomethingElseIsShownOnNoListener()

        /// <summary>
        /// A server identity may be marked with a usage that is no listener of
        /// this kind of node - for a configuration or code to name later - and
        /// is then shown on none of its listeners: a usage that is not a
        /// listener does not make it one.
        /// </summary>
        [Test]
        public async Task AnIdentityMarkedForSomethingElseIsShownOnNoListener()
        {

            Keeps(CertificateKind.TLSServerIdentity);

            using var http  = await SignedIn();

            var (status, said) = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                new JProperty("kind",     "tlsServerIdentity"),
                                                new JProperty("content",  Identity("Not For A Listener")),
                                                new JProperty("usages",   new JArray("dns"))
                                            ));

            var stored = Node.Certificates.Get(said.Value<String>("id"), CertificateKind.TLSServerIdentity);

            Assert.Multiple(() => {
                Assert.That(status,  Is.EqualTo(HttpStatusCode.Created), said.ToString());
                Assert.That(stored,  Is.Not.Null);
                foreach (var listener in Node.Certificates.Listeners)
                    Assert.That(stored!.IsFor(listener), Is.False, $"shown on {listener}");
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
                        $"This {Node.Kind.Name} needs the identity it has just been given.");

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

            var before         = InTheStore();

            var (status, said) = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                new JProperty("kind",     "tlsIdentity"),
                                                new JProperty("content",  Identity("node-002", WithKey: false))
                                            ));

            Assert.Multiple(() => {
                Assert.That(status,        Is.EqualTo(HttpStatusCode.BadRequest), said.ToString());
                Assert.That(InTheStore(),  Is.EquivalentTo(before),
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
            var labelsBefore    = before["certificates"]!["tlsRoot"]!.Select(entry => entry["label"]!.Value<String>()!).ToArray();

            var roots           = Path.Combine(Node.Certificates.Directory,
                                               CertificateKind.TLSRoot.Directory().Replace('/', Path.DirectorySeparatorChar));

            System.IO.Directory.CreateDirectory(roots);
            File.WriteAllBytes(Path.Combine(roots, "copied-by-hand.pem"), Convert.FromBase64String(RootPem("Copied By Hand")));

            var (status, after) = await Send(http, HttpMethod.Post, "api/v1/certificates/reload", new JObject());

            Assert.Multiple(() => {
                Assert.That(labelsBefore,  Does.Not.Contain("Copied By Hand"));
                Assert.That(status,        Is.EqualTo(HttpStatusCode.OK), after.ToString());
                Assert.That(after["certificates"]!["tlsRoot"]!.Select(entry => entry["label"]!.Value<String>()!),
                            Is.EquivalentTo(labelsBefore.Append("Copied By Hand")),
                            "what was there, and the one copied in");
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

            var (notYes, saidOfYes)  = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("label", "Renamed By A Refusal"), new JProperty("active", "yes")));
            var (bogus,  _)          = await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("label", "Renamed By A Refusal"), new JProperty("usages", new JArray("no usage!"))));

            var (_, kept)            = await Send(http, HttpMethod.Get, path);

            Assert.Multiple(() => {
                Assert.That(notYes,                          Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(saidOfYes.Value<String>("error"), Is.EqualTo("'active' has to be true or false."));
                Assert.That(bogus,                           Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(kept.Value<String>("label"),     Is.EqualTo("A Root Nobody Renames"), "a refused request renamed it");
                Assert.That(kept.Value<Boolean>("active"),   Is.True);
            });

        }

        #endregion

        #region AChangeTheStoreCannotWriteIsAServerError(Change)

        /// <summary>
        /// A change of the store that is fine in itself, and that the store's
        /// files cannot be written with, is answered 500 with why - and changes
        /// nothing, now or when the store is read again. A certificate whose
        /// file could not be written was a 400, as if something had been wrong
        /// with it; a label, on or off and what a certificate is for were
        /// answered as done while the index could not keep them, and were gone
        /// at the next start.
        /// </summary>
        [TestCase("POST, its file")]
        [TestCase("POST, the index")]
        [TestCase("POST again, with a label")]
        [TestCase("PATCH label")]
        [TestCase("PATCH active")]
        [TestCase("PATCH usages")]
        public async Task AChangeTheStoreCannotWriteIsAServerError(String Change)
        {

            Keeps(CertificateKind.TLSRoot);

            using var http              = await SignedIn();

            // One that is there, for the changes of one that is there...
            var (thereContent, handle)  = RootAndItsHandle("A Root That Is There");
            var (made, there)           = await Send(http, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                         new JProperty("kind",     "tlsRoot"),
                                                         new JProperty("content",  thereContent),
                                                         new JProperty("usages",   new JArray("dns"))
                                                     ));

            Assert.That(made, Is.EqualTo(HttpStatusCode.Created), there.ToString());

            var path                    = $"api/v1/certificates/{handle}";

            // ...and one that is not yet, with where its file would go.
            var (content, itsHandle)    = RootAndItsHandle("A Root That Is Not There Yet");
            var itsFile                 = Node.Certificates.FullPath($"{CertificateKind.TLSRoot.Directory()}/{itsHandle}{CertificateKind.TLSRoot.Extension()}");
            var index                   = Path.Combine(Node.Certificates.Directory, CertificateStore.IndexFileName);

            var before                  = InTheStore();
            var (_, was)                = await Send(http, HttpMethod.Get, path);

            // Where the new one's file goes is a directory, or where the index
            // is written first is.
            String blocked;

            if (Change == "POST, its file")
                System.IO.Directory.CreateDirectory(blocked = itsFile);
            else
                blocked = TheIndexCannotBeWritten();

            var (status, said) = Change switch {
                "POST, its file"            => await Send(http, HttpMethod.Post,  "api/v1/certificates", new JObject(new JProperty("kind", "tlsRoot"), new JProperty("content", content))),
                "POST, the index"           => await Send(http, HttpMethod.Post,  "api/v1/certificates", new JObject(new JProperty("kind", "tlsRoot"), new JProperty("content", content))),
                "POST again, with a label"  => await Send(http, HttpMethod.Post,  "api/v1/certificates", new JObject(new JProperty("kind", "tlsRoot"), new JProperty("content", thereContent), new JProperty("label", "A Root Renamed On Its Way In"))),
                "PATCH label"               => await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("label",  "A Root Renamed"))),
                "PATCH active"              => await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("active", false))),
                "PATCH usages"              => await Send(http, HttpMethod.Patch, path, new JObject(new JProperty("usages", new JArray("nts")))),
                _                           => throw new ArgumentException($"No change '{Change}' here.", nameof(Change))
            };

            var inTheStore              = InTheStore();
            var (_, now)                = await Send(http, HttpMethod.Get, path);

            // What the log says of the index: that the change was not made -
            // not that labels and on/off would not survive a restart, which was
            // said of changes that had been put back (found by the gateway).
            var logged                  = Node.Log.Recent(Int32.MaxValue, Tag: "certificates").
                                                   Select(entry => entry.Message).
                                                   Where (message => message.StartsWith($"Certificates: '{CertificateStore.IndexFileName}' could not be written", StringComparison.Ordinal)).
                                                   ToArray();

            // And as at the next start: the directory read again, with nothing
            // in the way any more.
            System.IO.Directory.Delete(blocked);

            var (reread, _)             = await Send(http, HttpMethod.Post, "api/v1/certificates/reload", new JObject());
            var readAgain               = InTheStore();
            var (_, thereReadAgain)     = await Send(http, HttpMethod.Get, path);

            Assert.Multiple(() => {

                Assert.That(status,                          Is.EqualTo(HttpStatusCode.InternalServerError), said.ToString());
                Assert.That(said.Value<String>("error"),     Does.StartWith(Change == "POST, its file"
                                                                                ? "That certificate could not be written to the store: "
                                                                                : $"'{index}' could not be written: "));

                Assert.That(inTheStore,                      Is.EquivalentTo(before),             "what is in the store");
                Assert.That(WhatIsSaidOf(now),               Is.EqualTo(WhatIsSaidOf(was)),       "what is said of the one that was there");

                if (Change == "POST, its file")
                    Assert.That(logged,                      Is.Empty,                            "what the log says of the index, which was not written");
                else
                    Assert.That(logged,                      Has.Exactly(1).StartsWith($"Certificates: '{CertificateStore.IndexFileName}' could not be written, so the change was not made - "),
                                                                                                  "what the log says of the index");

                Assert.That(reread,                          Is.EqualTo(HttpStatusCode.OK));
                Assert.That(readAgain,                       Is.EquivalentTo(before),             "what is in the store, read again: a file left behind is adopted");
                Assert.That(WhatIsSaidOf(thereReadAgain),    Is.EqualTo(WhatIsSaidOf(was)),       "what is said of the one that was there, read again");

            });

        }

        #endregion

        #region ReadingTheStoreAgainIsNotAChangeThatWasNotMade()

        /// <summary>
        /// The store read again from its directory while its index cannot be
        /// written is logged as what it is: no change of anybody's was put back
        /// then, and "the change was not made" is said only where one was.
        /// </summary>
        [Test]
        public async Task ReadingTheStoreAgainIsNotAChangeThatWasNotMade()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http   = await SignedIn();

            await ARootIn(http, "A Root Read Again");

            TheIndexCannotBeWritten();

            var (reread, _)  = await Send(http, HttpMethod.Post, "api/v1/certificates/reload", new JObject());

            var logged       = Node.Log.Recent(Int32.MaxValue, Tag: "certificates").
                                        Select(entry => entry.Message).
                                        Where (message => message.StartsWith($"Certificates: '{CertificateStore.IndexFileName}' could not be written", StringComparison.Ordinal)).
                                        ToArray();

            Assert.Multiple(() => {
                Assert.That(reread,  Is.EqualTo(HttpStatusCode.OK));
                Assert.That(logged,  Is.Not.Empty,                                  "that the index could not be written");
                Assert.That(logged,  Has.None.Contains("the change was not made"),  "a change put back, where there was none");
            });

        }

        #endregion

        #region ADeletionItsFileDoesNotLetHappenIsAServerError()

        /// <summary>
        /// A certificate whose file cannot be deleted stays in the store, and
        /// the request is answered 500 with why. It was a 404, as if there had
        /// been no such certificate.
        /// </summary>
        [Test]
        [Platform("Win", Reason = "A file somebody holds open is deleted all the same on Linux, and a test run as root there deletes what it likes: nothing but Windows keeps a file from being deleted.")]
        public async Task ADeletionItsFileDoesNotLetHappenIsAServerError()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http   = await SignedIn();

            var handle       = (await ARootIn(http, "A Root Somebody Holds Open"))["id"]!.Value<String>()!;
            var file         = Node.Certificates.FullPath(Node.Certificates.Get(handle)!);

            HttpStatusCode  status;
            JObject         said;

            using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                (status, said) = await Send(http, HttpMethod.Delete, $"api/v1/certificates/{handle}");

            Assert.Multiple(() => {
                Assert.That(status,                       Is.EqualTo(HttpStatusCode.InternalServerError), said.ToString());
                Assert.That(said.Value<String>("error"),  Does.Contain("could not be deleted: "));
                Assert.That(InTheStore(),                 Does.Contain(handle), "it is still in the store");
                Assert.That(File.Exists(file),            Is.True);
            });

        }

        #endregion

        #region ARefusalIsWhatItWasWhileTheStoreCannotWrite()

        /// <summary>
        /// What was wrong with a change is answered as it was while the store
        /// cannot write: a 500 is the files', and only where it was the files
        /// that refused.
        /// </summary>
        [Test]
        public async Task ARefusalIsWhatItWasWhileTheStoreCannotWrite()
        {

            Keeps(CertificateKind.TLSRoot);

            using var http          = await SignedIn();

            var handle              = (await ARootIn(http, "A Root Refused Around"))["id"]!.Value<String>()!;

            TheIndexCannotBeWritten();

            var (notOne,   _)       = await Send(http, HttpMethod.Post,   "api/v1/certificates", new JObject(
                                                     new JProperty("kind",     "tlsRoot"),
                                                     new JProperty("content",  Convert.ToBase64String(Encoding.ASCII.GetBytes("not a certificate")))
                                                 ));
            var (tooLong,  _)       = await Send(http, HttpMethod.Patch,  $"api/v1/certificates/{handle}", new JObject(
                                                     new JProperty("label",    new String('x', CertificateEntry.MaxLabelLength + 1))
                                                 ));
            var (notThere, _)       = await Send(http, HttpMethod.Delete, "api/v1/certificates/nothing-by-this-handle");

            Assert.Multiple(() => {
                Assert.That(notOne,    Is.EqualTo(HttpStatusCode.BadRequest), "a file that holds no certificate");
                Assert.That(tooLong,   Is.EqualTo(HttpStatusCode.BadRequest), "a label too long");
                Assert.That(notThere,  Is.EqualTo(HttpStatusCode.NotFound),   "a certificate the store does not have");
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
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' put 'A Root Somebody Put In' into the certificate store as a TLS root ({handle})."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' changed the certificate 'A Root Somebody Renamed' ({handle}) in the certificate store."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' had the certificate store read again from its directory."));
                Assert.That(said, Has.One.EqualTo($"Notice: '{AdminLogin}' took the certificate 'A Root Somebody Renamed' ({handle}) out of the certificate store."));
            });

        }

        #endregion

    }

}
