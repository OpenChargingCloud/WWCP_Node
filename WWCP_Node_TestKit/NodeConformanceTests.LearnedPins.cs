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
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// A pin learned on first use while the NTS or the DNS page was open, and
    /// that page's next save of something else.
    /// </summary>
    /// <remarks>
    /// The node writes what it learns into the server's entry of the file, and
    /// a page sends the whole list back - from what it loaded, which was before.
    /// Sent as the pages send it, with what each server was shown held to, the
    /// node keeps what it learned in between: without that, the save of the
    /// other server took the root out of the file and out of effect, for a
    /// time server and a name server alike.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region Data

        /// <summary>
        /// The time server of <see cref="NodeSetup.ServersToLearnFrom"/> that
        /// learns its root on first use.
        /// </summary>
        protected const String TimeServerToLearn  = "time.example.org";

        /// <summary>
        /// The other time server of <see cref="NodeSetup.ServersToLearnFrom"/>.
        /// </summary>
        protected const String AnotherTimeServer  = "other.example.org";

        /// <summary>
        /// The name server of <see cref="NodeSetup.ServersToLearnFrom"/> that
        /// learns its root on first use, as the file says it: over TLS, on the
        /// loopback address, on a port nothing listens on - it is never asked.
        /// </summary>
        protected JObject NameServerToLearn { get; private set; } = new ();

        #endregion

        #region (private static helpers) CA(Name) / ServerCertificate(Name, Issuer) / Trusted(Leaf, Root) / Fingerprint(Certificate)

        private static X509Certificate2 CA(String Name)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        }

        private static X509Certificate2 ServerCertificate(String            Name,
                                                          X509Certificate2  Issuer)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);
            var names   = new SubjectAlternativeNameBuilder();

            if (IPAddress.TryParse(Name, out var address))
                names.AddIpAddress(address);
            else
                names.AddDnsName(Name);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
            request.CertificateExtensions.Add(names.Build());

            return request.Create(Issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), Guid.NewGuid().ToByteArray());

        }

        /// <summary>
        /// What a handshake hands over for a certificate whose root the machine
        /// knows - the given one.
        /// </summary>
        private static X509Chain Trusted(X509Certificate2  Leaf,
                                         X509Certificate2  Root)
        {

            var chain = new X509Chain();

            chain.ChainPolicy.TrustMode       = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode  = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(Root);

            Assert.That(chain.Build(Leaf), Is.True, "the test's own chain did not build");

            return chain;

        }

        private static String Fingerprint(X509Certificate2 Certificate)

            => Convert.ToHexString(SHA256.HashData(Certificate.RawData)).ToLowerInvariant();

        #endregion

        #region (private static) KeysOf(HeldTo)

        /// <summary>
        /// What a server is held to, as the answer says it, in the keys an entry
        /// says it with - what the pages make of it: one fingerprint of a kind
        /// under the singular key and several under the plural, and what a
        /// mismatch comes to only where it is not a refusal.
        /// </summary>
        private static IEnumerable<JProperty> KeysOf(JToken? HeldTo)
        {

            if (HeldTo is not JObject held)
                yield break;

            foreach (var (kind, key) in new[] { ("certificate", "certificateFingerprint"), ("root", "rootFingerprint") })
            {

                String[] fingerprints = held[kind + "s"] is JArray several
                                            ? [.. several.Values<String>().OfType<String>()]
                                            : held.Value<String>(kind) is String one ? [ one ] : [];

                if      (fingerprints.Length == 1)  yield return new JProperty(key,       fingerprints[0]);
                else if (fingerprints.Length >  1)  yield return new JProperty(key + "s", new JArray(fingerprints));

            }

            if (held.Value<String>("onMismatch") is String onMismatch && onMismatch != "refuse")
                yield return new JProperty("onMismatch", onMismatch);

            if (held.Value<String>("trustOnFirstUse") is String trustOnFirstUse)
                yield return new JProperty("trustOnFirstUse", trustOnFirstUse);

        }

        #endregion


        #region ARootATimeServerLearnedWhileThePageWasOpenIsKeptByItsNextSave()

        /// <summary>
        /// The page is loaded; the first key exchange after that believes the
        /// time server and holds it to its root from then on; the page saves
        /// the other server's priority, with the list as it loaded it.
        /// </summary>
        [Test, WithNode(NodeSetup.ServersToLearnFrom)]
        public async Task ARootATimeServerLearnedWhileThePageWasOpenIsKeptByItsNextSave()
        {

            using var http  = await SignedIn();

            var page        = await GetJSON(http, "api/v1/configuration/nts");
            var sources     = page["timeSources"]!.Children<JObject>().ToArray();

            Assert.That(sources.Select(source => source.Value<String>("hostname")!.TrimEnd('.')),
                        Is.EqualTo(new[] { TimeServerToLearn, AnotherTimeServer }));

            Assert.That(sources[0]["heldTo"]!.Value<String>("root"), Is.Null, "nothing learned yet when the page was loaded");

            using var ca     = CA("Time Server CA");
            using var leaf   = ServerCertificate(TimeServerToLearn, ca);

            using (var chain = Trusted(leaf, ca))
                Assert.That(Node.JudgeTimeServer(DomainName.Parse(TimeServerToLearn), leaf, chain, SslPolicyErrors.None).Learned,
                            Is.EqualTo(TrustOnFirstUse.Root),
                            "the key exchange after the page was loaded learned the root");

            var learned      = Fingerprint(ca);

            // The list as the page sends it back: each server as it loaded it,
            // with what it was held to then, and the same again as what the
            // page showed - and the one change made on it.
            var servers      = new JArray(
                                   sources.Select(source => {

                                       var entry = new JObject(
                                                       new JProperty("hostname", source.Value<String>("hostname")!.TrimEnd('.'))
                                                   );

                                       foreach (var key in KeysOf(source["heldTo"]))
                                           entry.Add(key);

                                       entry.Add("pinsAsShown", new JObject(KeysOf(source["heldTo"])));

                                       return entry;

                                   })
                               );

            servers[1]["priority"] = 5;

            var (status, answer) = await Send(http, HttpMethod.Put, "api/v1/configuration/nts", new JObject(new JProperty("servers", servers)));

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), answer.ToString());

            var sourcesNow   = answer["timeSources"]!.Children<JObject>().ToArray();
            var file         = JObject.Parse(File.ReadAllText(Node.ConfigFile.Path))["nts"]!["servers"]!;

            Assert.Multiple(() => {
                Assert.That(sourcesNow[1].Value<Int32>("priority"),         Is.EqualTo(5),        "the change the page made");
                Assert.That(sourcesNow[0]["heldTo"]?.Value<String>("root"), Is.EqualTo(learned),  "the root learned while the page was open, in effect and in what the page redraws from");
                Assert.That(file[0]!.Value<String>("rootFingerprint"),      Is.EqualTo(learned),  "and in the file");
                Assert.That(file[0]!.Value<String>("trustOnFirstUse"),      Is.EqualTo("root"));
            });

        }

        #endregion

        #region ARootANameServerLearnedWhileThePageWasOpenIsKeptByItsNextSave()

        /// <summary>
        /// The same for a name server asked over TLS: the page is loaded, the
        /// first handshake after that learns its root, and the page saves the
        /// other server's timeout.
        /// </summary>
        [Test, WithNode(NodeSetup.ServersToLearnFrom)]
        public async Task ARootANameServerLearnedWhileThePageWasOpenIsKeptByItsNextSave()
        {

            using var http  = await SignedIn();

            var page        = await GetJSON(http, "api/v1/configuration/dns");
            var shown       = page["servers"]!.Children<JObject>().ToArray();

            Assert.That(shown,                                        Has.Length.EqualTo(2));
            Assert.That(shown[0].Value<String>("rootFingerprint"),    Is.Null, "nothing learned yet when the page was loaded");

            Assert.That(DNSConfiguration.TryParseServer(NameServerToLearn, out var nameServer, out var problem), Is.True, problem);

            using var ca     = CA("Name Server CA");
            using var leaf   = ServerCertificate("127.0.0.1", ca);

            using (var chain = Trusted(leaf, ca))
                Assert.That(Node.JudgeNameServer(nameServer!, leaf, chain, SslPolicyErrors.None).Learned,
                            Is.EqualTo(TrustOnFirstUse.Root),
                            "the handshake after the page was loaded learned the root");

            var learned      = Fingerprint(ca);

            // The list as the page sends it back: the keys the file keeps, as
            // the page loaded them, and what the page showed each server held
            // to - and the one change made on it.
            var servers      = new JArray(
                                   shown.Select(server => {

                                       var entry = new JObject(
                                                       new JProperty("address",              server["address"]),
                                                       new JProperty("port",                 server["port"]),
                                                       new JProperty("transport",            server["transport"]),
                                                       new JProperty("queryTimeoutSeconds",  server["queryTimeoutSeconds"])
                                                   );

                                       foreach (var key in new[] { "certificateFingerprint", "certificateFingerprints",
                                                                   "rootFingerprint",        "rootFingerprints",
                                                                   "onMismatch",             "trustOnFirstUse" })
                                           if (server[key] is JToken value && value.Type != JTokenType.Null)
                                               entry.Add(key, value);

                                       entry.Add("pinsAsShown", new JObject(KeysOf(server["heldTo"])));

                                       return entry;

                                   })
                               );

            servers[1]["queryTimeoutSeconds"] = 2;

            var (status, answer) = await Send(http, HttpMethod.Put, "api/v1/configuration/dns", new JObject(new JProperty("servers", servers)));

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), answer.ToString());

            var serversNow   = answer["servers"]!.Children<JObject>().ToArray();
            var file         = JObject.Parse(File.ReadAllText(Node.ConfigFile.Path))["dns"]!["servers"]!;

            Assert.Multiple(() => {
                Assert.That(serversNow[1].Value<Double>("queryTimeoutSeconds"),  Is.EqualTo(2),        "the change the page made, in effect and in what the page redraws from");
                Assert.That(serversNow[0].Value<String>("rootFingerprint"),      Is.EqualTo(learned),  "the root learned while the page was open, in effect");
                Assert.That(file[0]!.Value<String>("rootFingerprint"),           Is.EqualTo(learned),  "and in the file");
                Assert.That(file[0]!.Value<String>("trustOnFirstUse"),           Is.EqualTo("root"));
            });

        }

        #endregion

    }

}
