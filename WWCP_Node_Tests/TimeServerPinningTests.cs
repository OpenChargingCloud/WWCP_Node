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

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Which certificates of its time servers a node believes, asked without a
    /// key exchange: the certificate, and the chain the machine built for it,
    /// handed to the judgement as a key exchange hands them over.
    /// </summary>
    /// <remarks>
    /// The certificates are minted here, under a CA of the test's own that no
    /// machine trusts - which is the case a root of the node's own is for. A
    /// chain the machine did trust is made by building it against that CA, and
    /// handing it over without errors.
    /// </remarks>
    public class TimeServerPinningTests
    {

        #region Data

        private static readonly DomainName  Server  = DomainName.Parse("time.example.org");

        private String            directory  = "";
        private X509Certificate2  ca         = default!;
        private X509Certificate2  otherCA    = default!;
        private X509Certificate2  leaf       = default!;
        private X509Certificate2  otherLeaf  = default!;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory  = Path.Combine(Path.GetTempPath(), "node-pinning-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

            ca         = CA("Time Server CA");
            otherCA    = CA("Some Other CA");
            leaf       = Leaf(Server.Trimmed, ca);
            otherLeaf  = Leaf(Server.Trimmed, ca);

        }

        [TearDown]
        public void TearDown()
        {

            ca.       Dispose();
            otherCA.  Dispose();
            leaf.     Dispose();
            otherLeaf.Dispose();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (helpers) CA(Name) / Leaf(Name, Issuer) / Pem(Certificate)

        internal static X509Certificate2 CA(String Name)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        }

        internal static X509Certificate2 Leaf(String            Name,
                                              X509Certificate2  Issuer,
                                              ECDsa?            Key   = null)
        {

            var key     = Key ?? ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);
            var names   = new SubjectAlternativeNameBuilder();

            names.AddDnsName(Name);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
            request.CertificateExtensions.Add(names.Build());

            return request.Create(Issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), Guid.NewGuid().ToByteArray());

        }

        private static Byte[] Pem(X509Certificate2 Certificate)

            => System.Text.Encoding.ASCII.GetBytes(Certificate.ExportCertificatePem());

        #endregion

        #region (helpers) Node(Servers) / Untrusted(Leaf) / Trusted(Leaf, Root)

        /// <summary>
        /// A node whose "nts.servers" say what the JSON given says.
        /// </summary>
        private WWCPNode Node(String Servers = """[ "time.example.org" ]""")
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "nts": { "servers": {{Servers}} } }""");

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        /// <summary>
        /// What a key exchange hands over for a certificate whose root the
        /// machine does not know.
        /// </summary>
        private static (X509Chain Chain, SslPolicyErrors Errors) Untrusted(X509Certificate2 Leaf)
        {

            var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            return (chain, chain.Build(Leaf) ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors);

        }

        /// <summary>
        /// What a key exchange hands over for a certificate whose root the
        /// machine does know - the given one.
        /// </summary>
        private static (X509Chain Chain, SslPolicyErrors Errors) Trusted(X509Certificate2  Leaf,
                                                                         X509Certificate2  Root)
        {

            var chain = new X509Chain();

            chain.ChainPolicy.TrustMode       = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode  = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(Root);

            Assert.That(chain.Build(Leaf), Is.True, "the test's own chain did not build");

            return (chain, SslPolicyErrors.None);

        }

        private static String[] Metrological(WWCPNode Node, UInt64 Since)

            => [.. Node.Log.Recent(100, Since, null).Where(entry => entry.Metrological).Select(entry => entry.Message)];

        #endregion


        #region AServerWhoseRootNobodyKnowsIsRefusedAndWrittenDown()

        /// <summary>
        /// A certificate that chains to no root the machine or the node knows is
        /// refused, and the metrological log says so and why.
        /// </summary>
        [Test]
        public async Task AServerWhoseRootNobodyKnowsIsRefusedAndWrittenDown()
        {

            await using var node  = Node();
            var before            = node.Log.LastId;
            var (chain, errors)   = Untrusted(leaf);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,  Is.False);
                    Assert.That(judgement.Outcome,   Is.EqualTo("untrusted"));
                    Assert.That(Metrological(node, before),  Has.Some.Contains("was refused").And.Contains("chains to no root"));
                });

            }

        }

        #endregion

        #region AServerIsBelievedThroughARootOfTheNodesOwn()

        /// <summary>
        /// A TLS root of the node's store is a root for its time servers, where
        /// the machine knows none.
        /// </summary>
        [Test]
        public async Task AServerIsBelievedThroughARootOfTheNodesOwn()
        {

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(ca), CertificateKind.TLSRoot, null, "our time servers", out _, out var error),  Is.True,  error);

            var before           = node.Log.LastId;
            var (chain, errors)  = Untrusted(leaf);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,         Is.True,  String.Join(" | ", judgement.Steps.Select(step => step.Text)));
                    Assert.That(judgement.AnchoredBy,       Is.EqualTo("our time servers"));
                    Assert.That(judgement.RootFingerprint,  Is.EqualTo(CertificateEntry.ThumbprintOf(ca)));
                    Assert.That(Metrological(node, before), Is.Empty,  "a server believed at the first time is no news");
                });

            }

        }

        #endregion

        #region ARootThatIsSwitchedOffAnchorsNothing()

        /// <summary>
        /// A root switched off in the store is a root nobody believes.
        /// </summary>
        [Test]
        public async Task ARootThatIsSwitchedOffAnchorsNothing()
        {

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(ca), CertificateKind.TLSRoot, null, null, out var entry, out var error),  Is.True,  error);
            Assert.That(node.Certificates.SetActive(entry!.Id, false, out _, out error),                                    Is.True,  error);

            var (chain, errors) = Untrusted(leaf);

            using (chain)
                Assert.That(node.JudgeTimeServer(Server, leaf, chain, errors).Outcome,  Is.EqualTo("untrusted"));

        }

        #endregion

        #region ARootForTheNameServersAloneVouchesForNoTimeServer()

        /// <summary>
        /// A TLS root of the node's store vouches for the time servers where it
        /// is for them - told so, or never told what it is for - and not where
        /// it was kept for the name servers alone.
        /// </summary>
        [Test]
        public async Task ARootForTheNameServersAloneVouchesForNoTimeServer()
        {

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(ca), CertificateKind.TLSRoot, null, "our resolvers",
                                                 [ CertificateUsages.DNS ], out var entry, out var error),  Is.True,  error);

            var (chain, errors) = Untrusted(leaf);

            using (chain)
            {

                var forNameServers = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.That(node.Certificates.SetUsages(entry!.Id, [ CertificateUsages.DNS, CertificateUsages.NTS ], out _, out error),  Is.True,  error);

                var forBoth        = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(forNameServers.Outcome,  Is.EqualTo("untrusted"),  "a root for the name servers vouched for a time server");
                    Assert.That(forBoth.Accepted,        Is.True,  String.Join(" | ", forBoth.Steps.Select(step => step.Text)));
                    Assert.That(forBoth.AnchoredBy,      Is.EqualTo("our resolvers"));
                });

            }

        }

        #endregion

        #region TheRootAServerIsHeldToAnchorsItWhateverItIsFor()

        /// <summary>
        /// Naming a root in a server's configuration says what a usage says, and
        /// more narrowly: the root a server is held to anchors that server even
        /// where the store keeps it for the name servers alone.
        /// </summary>
        [Test]
        public async Task TheRootAServerIsHeldToAnchorsItWhateverItIsFor()
        {

            await using var node = Node($$"""
                                          [ { "hostname": "time.example.org", "rootFingerprint": "{{CertificateEntry.ThumbprintOf(ca)}}" } ]
                                          """);

            Assert.That(node.Certificates.Import(Pem(ca), CertificateKind.TLSRoot, null, "our resolvers",
                                                 [ CertificateUsages.DNS ], out _, out var error),  Is.True,  error);

            var (chain, errors) = Untrusted(leaf);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,    Is.True,  String.Join(" | ", judgement.Steps.Select(step => step.Text)));
                    Assert.That(judgement.AnchoredBy,  Is.EqualTo("our resolvers"));
                });

            }

        }

        #endregion

        #region ACertificateThatIsTheOneItIsHeldToIsBelieved()

        /// <summary>
        /// A server held to its certificate, showing that one, is believed.
        /// </summary>
        [Test]
        public async Task ACertificateThatIsTheOneItIsHeldToIsBelieved()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(leaf).ToUpperInvariant()}}" } ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,           Is.True);
                    Assert.That(judgement.Outcome,            Is.EqualTo("accepted"));
                    Assert.That(judgement.HeldToCertificate,  Is.EqualTo(CertificateEntry.ThumbprintOf(leaf)),  "the pin was not read as the fingerprint it spells");
                    Assert.That(judgement.Steps.Select(step => step.Text),  Has.Some.Contains("it is the one it showed"));
                });

            }

        }

        #endregion

        #region AnotherCertificateIsRefusedAndWrittenDown()

        /// <summary>
        /// A server held to its certificate, showing another one from the very
        /// same CA, is refused - and the metrological log has both fingerprints.
        /// </summary>
        [Test]
        public async Task AnotherCertificateIsRefusedAndWrittenDown()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(leaf)}}" } ]""");

            var before           = node.Log.LastId;
            var (chain, errors)  = Trusted(otherLeaf, ca);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, otherLeaf, chain, errors);
                var entry     = node.Log.Recent(100, before, null).Single(one => one.Metrological);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,  Is.False);
                    Assert.That(judgement.Outcome,   Is.EqualTo("pinMismatch"));
                    Assert.That(entry.Level,         Is.EqualTo(LogLevel.Error));
                    Assert.That(entry.Message,       Does.Contain("was refused").
                                                     And.Contain(CertificateEntry.ThumbprintOf(otherLeaf)).
                                                     And.Contain(CertificateEntry.ThumbprintOf(leaf)));
                    Assert.That(entry.Data?["heldTo"]?.Value<String>("certificate"),  Is.EqualTo(CertificateEntry.ThumbprintOf(leaf)));
                    Assert.That(entry.Data?.Value<String>("certificate"),             Is.EqualTo(CertificateEntry.ThumbprintOf(otherLeaf)));
                });

            }

        }

        #endregion

        #region AnotherCertificateIsUsedAndWrittenDownWhereTheConfigurationSaysSo()

        /// <summary>
        /// With "onMismatch": "record", the same server is used all the same -
        /// and written down as a warning.
        /// </summary>
        [Test]
        public async Task AnotherCertificateIsUsedAndWrittenDownWhereTheConfigurationSaysSo()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(leaf)}}", "onMismatch": "record" } ]""");

            var before           = node.Log.LastId;
            var (chain, errors)  = Trusted(otherLeaf, ca);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, otherLeaf, chain, errors);
                var entry     = node.Log.Recent(100, before, null).Single(one => one.Metrological);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,  Is.True);
                    Assert.That(judgement.Outcome,   Is.EqualTo("recorded"));
                    Assert.That(entry.Level,         Is.EqualTo(LogLevel.Warning));
                    Assert.That(entry.Message,       Does.Contain("used all the same"));
                });

            }

        }

        #endregion

        #region AnotherRootIsRefused()

        /// <summary>
        /// A server held to a root, whose chain ends at another one, is refused.
        /// </summary>
        [Test]
        public async Task AnotherRootIsRefused()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "rootFingerprint": "{{CertificateEntry.ThumbprintOf(otherCA)}}" } ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Outcome,  Is.EqualTo("pinMismatch"));
                    Assert.That(judgement.Steps.Select(step => step.Text),  Has.Some.Contains($"its chain ends at {CertificateEntry.ThumbprintOf(ca)}"));
                });

            }

        }

        #endregion

        #region TheRootAServerIsHeldToAnchorsItFromTheStoreWhateverItWasKeptAs()

        /// <summary>
        /// The root a server is held to is found in the store by its fingerprint
        /// and anchors that server's chain, whatever kind of certificate it was
        /// kept as - and anchors nobody else's.
        /// </summary>
        [Test]
        public async Task TheRootAServerIsHeldToAnchorsItFromTheStoreWhateverItWasKeptAs()
        {

            await using var node = Node($$"""
                                          [ { "hostname": "time.example.org", "rootFingerprint": "{{CertificateEntry.ThumbprintOf(ca)}}" },
                                            "time.example.net" ]
                                          """);

            Assert.That(node.Certificates.Import(Pem(ca), CertificateKind.V2GRoot, null, "kept as a V2G root", out _, out var error),  Is.True,  error);

            var (chain, errors) = Untrusted(leaf);

            using (chain)
            {

                var held  = node.JudgeTimeServer(Server, leaf, chain, errors);

                using var elsewhere  = Leaf("time.example.net", ca);
                var (other, errors2) = Untrusted(elsewhere);

                using (other)
                {

                    var unheld = node.JudgeTimeServer(DomainName.Parse("time.example.net"), elsewhere, other, errors2);

                    Assert.Multiple(() => {
                        Assert.That(held.Accepted,      Is.True,  String.Join(" | ", held.Steps.Select(step => step.Text)));
                        Assert.That(held.AnchoredBy,    Is.EqualTo("kept as a V2G root"));
                        Assert.That(unheld.Outcome,     Is.EqualTo("untrusted"),  "a V2G root anchored a time server that is not held to it");
                    });

                }

            }

        }

        #endregion

        #region ACertificateForAnotherNameIsRefusedWhateverItIsHeldTo()

        /// <summary>
        /// A certificate that is not issued for the server's name is refused,
        /// even when it is the very one the server is held to.
        /// </summary>
        [Test]
        public async Task ACertificateForAnotherNameIsRefusedWhateverItIsHeldTo()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(leaf)}}" } ]""");

            var (chain, _) = Trusted(leaf, ca);

            using (chain)
                Assert.That(node.JudgeTimeServer(Server, leaf, chain, SslPolicyErrors.RemoteCertificateNameMismatch).Outcome,  Is.EqualTo("wrongName"));

        }

        #endregion

        #region TheSameVerdictIsWrittenDownOnceAndItsEndAgain()

        /// <summary>
        /// A server refused at every round is written into the metrological log
        /// once, and again when it is believed after that.
        /// </summary>
        [Test]
        public async Task TheSameVerdictIsWrittenDownOnceAndItsEndAgain()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(leaf)}}" } ]""");

            var before = node.Log.LastId;

            for (var round = 0; round < 3; round++)
            {
                var (chain, errors) = Trusted(otherLeaf, ca);
                using (chain)
                    node.JudgeTimeServer(Server, otherLeaf, chain, errors);
            }

            var whileRefused = Metrological(node, before);

            var (good, noErrors) = Trusted(leaf, ca);

            using (good)
                node.JudgeTimeServer(Server, leaf, good, noErrors);

            var afterwards = Metrological(node, before);

            Assert.Multiple(() => {
                Assert.That(whileRefused,  Has.Length.EqualTo(1),  String.Join(" | ", whileRefused));
                Assert.That(afterwards,    Has.Length.EqualTo(2),  String.Join(" | ", afterwards));
                Assert.That(afterwards[1], Does.Contain("believed again"));
            });

        }

        #endregion

        #region WhatAServerIsHeldToIsReadAndWrittenBack()

        /// <summary>
        /// Pins are read in any of the ways a fingerprint is written, and
        /// written back in the one way the store keeps them - and what cannot
        /// be a pin is refused with the sentence that says why.
        /// </summary>
        [Test]
        public void WhatAServerIsHeldToIsReadAndWrittenBack()
        {

            var fingerprint = CertificateEntry.ThumbprintOf(leaf);
            var colons      = String.Join(":", Enumerable.Range(0, 32).Select(i => fingerprint.Substring(2 * i, 2).ToUpperInvariant()));

            Assert.That(NTSServerConfiguration.TryParse(JObject.Parse($$"""{ "hostname": "time.example.org", "rootFingerprint": "{{colons}}", "onMismatch": "Record" }"""),
                                                        0, out var server, out var error),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(server!.RootFingerprint,  Is.EqualTo(fingerprint));
                Assert.That(server.OnMismatch,        Is.EqualTo(PinMismatch.Record));
                Assert.That(server.ToJSON().ToString(Newtonsoft.Json.Formatting.None),
                            Is.EqualTo($$"""{"hostname":"time.example.org.","rootFingerprint":"{{fingerprint}}","onMismatch":"record"}"""));
            });

            Assert.Multiple(() => {

                Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "time.example.org", "certificateFingerprint": "ab:cd" }"""), 1, out _, out error),  Is.False);
                Assert.That(error,  Does.StartWith("'nts.servers[1].certificateFingerprint' holds 'ab:cd', which is not a SHA-256 fingerprint"));

                Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "time.example.org", "onMismatch": "record" }"""), 2, out _, out error),  Is.False);
                Assert.That(error,  Does.Contain("is held to none"));

                Assert.That(NTSServerConfiguration.TryParse(JObject.Parse($$"""{ "hostname": "time.example.org", "rootFingerprint": "{{fingerprint}}", "onMismatch": "ignore" }"""), 3, out _, out error),  Is.False);
                Assert.That(error,  Does.Contain("has to be 'refuse', 'record' or 'accept'"));

            });

        }

        #endregion

        #region AChangeToWhatAServerIsHeldToIsWrittenDown()

        /// <summary>
        /// Holding a server to a fingerprint is a change of the NTS
        /// configuration, and written into the metrological log as one - and
        /// what was made of the server before is forgotten with it.
        /// </summary>
        [Test]
        public async Task AChangeToWhatAServerIsHeldToIsWrittenDown()
        {

            await using var node = Node();

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
                node.JudgeTimeServer(Server, leaf, chain, errors);

            Assert.That(node.LastJudgementOf(Server),  Is.Not.Null);

            var before = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse($$"""{ "servers": [ { "hostname": "time.example.org", "certificateFingerprint": "{{CertificateEntry.ThumbprintOf(leaf)}}" } ] }"""),
                                                       out var error),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(Metrological(node, before),    Has.Some.StartsWith("NTS configuration changed").
                                                               And.Contains($"time.example.org held to certificate {CertificateEntry.ThumbprintOf(leaf)}, refused otherwise"));
                Assert.That(node.LastJudgementOf(Server),  Is.Null,  "what was made of the server before its pin was kept");
            });

        }

        #endregion

        #region TheNTSAnswerSaysWhatEachServerIsHeldToAndWhatWasMadeOfIt()

        /// <summary>
        /// The NTS page reads, for each server, what it is held to and what the
        /// node made of its certificate last.
        /// </summary>
        [Test]
        public async Task TheNTSAnswerSaysWhatEachServerIsHeldToAndWhatWasMadeOfIt()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "rootFingerprint": "{{CertificateEntry.ThumbprintOf(ca)}}" }, "time.example.net" ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
                node.JudgeTimeServer(Server, leaf, chain, errors);

            var servers = node.NTSConfigurationJSON()["timeSources"] as JArray;
            var held    = servers?.FirstOrDefault(server => server.Value<String>("hostname") == "time.example.org.");
            var unheld  = servers?.FirstOrDefault(server => server.Value<String>("hostname") == "time.example.net.");

            Assert.Multiple(() => {
                Assert.That(held?["heldTo"]?.Value<String>("root"),          Is.EqualTo(CertificateEntry.ThumbprintOf(ca)));
                Assert.That(held?["heldTo"]?.Value<String>("onMismatch"),    Is.EqualTo("refuse"));
                Assert.That(held?["judgement"]?.Value<String>("outcome"),    Is.EqualTo("accepted"));
                Assert.That(unheld?["heldTo"]?.Type,                         Is.EqualTo(JTokenType.Null));
                Assert.That(unheld?["judgement"]?.Type,                      Is.EqualTo(JTokenType.Null));
            });

        }

        #endregion

        #region EveryServerOfTheGroupAsksTheNode()

        /// <summary>
        /// Every server of the group asks the node about its certificate: the
        /// default four, and those a file names.
        /// </summary>
        [Test]
        public async Task EveryServerOfTheGroupAsksTheNode()
        {

            await using (var node = new WWCPNode(AccountsPath:  Path.Combine(directory, "accounts"),
                                                 ConfigFile:    new WWCPConfigFile(Path.Combine(directory, "none.json")),
                                                 LogToConsole:  false,
                                                 BridgeDebugLog: false))
            {
                Assert.That(node.TimeSources.Sources.All(source => source.RemoteCertificateValidator is not null),  Is.True,  "a default server asks nobody");
            }

            await using (var node = Node("""[ "a.example", { "hostname": "b.example", "priority": 1 } ]"""))
            {

                Assert.That(node.TimeSources.Sources.All(source => source.RemoteCertificateValidator is not null),  Is.True,  "a server the file names asks nobody");

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "hostname": "c.example" }"""), out var error),  Is.True,  error);

                Assert.That(node.TimeSources.Sources.All(source => source.RemoteCertificateValidator is not null),  Is.True,  "a server saved later asks nobody");

            }

        }

        #endregion

        #region (helper) Fingerprint(Certificate) / ServerEntry(Node) / Security(Node, Since)

        private static String Fingerprint(X509Certificate2 Certificate)
            => CertificateEntry.ThumbprintOf(Certificate);

        /// <summary>
        /// The entry of the first time server, as the configuration file says it now.
        /// </summary>
        private static JObject ServerEntry(WWCPNode Node)
            => (JObject) JObject.Parse(File.ReadAllText(Node.ConfigFile.Path))["nts"]!["servers"]![0]!;

        private static String[] Security(WWCPNode Node, UInt64 Since)

            => [.. Node.Log.Recent(100, Since, "security").Select(entry => entry.Message)];

        #endregion


        #region AServerMayBeHeldToSeveralCertificates()

        /// <summary>
        /// Two certificates are a renewal that has been announced: the server is
        /// held to either of them, and to nothing else.
        /// </summary>
        [Test]
        public async Task AServerMayBeHeldToSeveralCertificates()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprints": [ "{{Fingerprint(otherLeaf)}}", "{{Fingerprint(leaf)}}" ] } ]""");

            using var third = Leaf(Server.Trimmed, ca);

            ServerJudgement Judge(X509Certificate2 Certificate)
            {
                var (chain, errors) = Trusted(Certificate, ca);
                using (chain)
                    return node.JudgeTimeServer(Server, Certificate, chain, errors);
            }

            Assert.Multiple(() => {
                Assert.That(Judge(leaf).     Outcome,  Is.EqualTo("accepted"));
                Assert.That(Judge(otherLeaf).Outcome,  Is.EqualTo("accepted"));
                Assert.That(Judge(third).    Outcome,  Is.EqualTo("pinMismatch"));
            });

        }

        #endregion

        #region AServerMayBeHeldToSeveralRoots()

        /// <summary>
        /// Two roots are a CA moving to a new one, written down before it
        /// happens.
        /// </summary>
        [Test]
        public async Task AServerMayBeHeldToSeveralRoots()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "rootFingerprints": [ "{{Fingerprint(otherCA)}}", "{{Fingerprint(ca)}}" ] } ]""");

            using var thirdCA    = CA("A Third CA");
            using var fromOther  = Leaf(Server.Trimmed, otherCA);
            using var fromThird  = Leaf(Server.Trimmed, thirdCA);

            ServerJudgement Judge(X509Certificate2 Certificate, X509Certificate2 Root)
            {
                var (chain, errors) = Trusted(Certificate, Root);
                using (chain)
                    return node.JudgeTimeServer(Server, Certificate, chain, errors);
            }

            Assert.Multiple(() => {
                Assert.That(Judge(leaf,      ca).     Outcome,  Is.EqualTo("accepted"));
                Assert.That(Judge(fromOther, otherCA).Outcome,  Is.EqualTo("accepted"));
                Assert.That(Judge(fromThird, thirdCA).Outcome,  Is.EqualTo("pinMismatch"));
            });

        }

        #endregion

        #region AMismatchAcceptedIsUsedAndSaidAsAMatterOfSecurity()

        /// <summary>
        /// "accept": the server is used, and the mismatch is said, tagged as a
        /// matter of security - for a time server in the metrological log as
        /// well, because it bears on the time.
        /// </summary>
        [Test]
        public async Task AMismatchAcceptedIsUsedAndSaidAsAMatterOfSecurity()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprint": "{{Fingerprint(leaf)}}", "onMismatch": "accept" } ]""");

            var before           = node.Log.LastId;
            var (chain, errors)  = Trusted(otherLeaf, ca);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, otherLeaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,          Is.True);
                    Assert.That(judgement.Outcome,           Is.EqualTo("tolerated"));
                    Assert.That(Security(node, before),      Has.Some.Contains("used all the same"));
                    Assert.That(Metrological(node, before),  Has.Some.Contains("used all the same"));
                });

            }

        }

        #endregion

        #region ATimeServerLearnsItsRootOnFirstUse()

        /// <summary>
        /// "trustOnFirstUse": "root" - the root the first believed certificate
        /// chains to is written into the server's entry, and from then on the
        /// server is held to it like to a root somebody typed.
        /// </summary>
        [Test]
        public async Task ATimeServerLearnsItsRootOnFirstUse()
        {

            await using var node = Node("""[ { "hostname": "time.example.org", "trustOnFirstUse": "root" } ]""");

            var before           = node.Log.LastId;
            var (chain, errors)  = Trusted(leaf, ca);

            ServerJudgement first;

            using (chain)
                first = node.JudgeTimeServer(Server, leaf, chain, errors);

            var entry = ServerEntry(node);

            using var elsewhere    = Leaf(Server.Trimmed, otherCA);
            var (other, errors2)   = Trusted(elsewhere, otherCA);

            ServerJudgement second;

            using (other)
                second = node.JudgeTimeServer(Server, elsewhere, other, errors2);

            Assert.Multiple(() => {

                Assert.That(first.Accepted,                          Is.True);
                Assert.That(first.Learned,                           Is.EqualTo(TrustOnFirstUse.Root));
                Assert.That(entry.Value<String>("rootFingerprint"),  Is.EqualTo(Fingerprint(ca)),  "written down as a pin somebody typed would be");
                Assert.That(entry.Value<String>("trustOnFirstUse"),  Is.EqualTo("root"),           "and still saying where it came from");
                Assert.That(Metrological(node, before),              Has.Some.Contains("trusted on first use"));

                Assert.That(second.Outcome,                          Is.EqualTo("pinMismatch"),    "another root afterwards is another root");
                Assert.That(second.Learned,                          Is.EqualTo(TrustOnFirstUse.None));

            });

        }

        #endregion

        #region ATimeServerLearnsItsCertificateOnFirstUse()

        /// <summary>
        /// "trustOnFirstUse": "certificate" - and a renewal afterwards is a
        /// mismatch, used here because the entry says "accept", and a change,
        /// said because it is one.
        /// </summary>
        [Test]
        public async Task ATimeServerLearnsItsCertificateOnFirstUse()
        {

            await using var node = Node("""[ { "hostname": "time.example.org", "trustOnFirstUse": "certificate", "onMismatch": "accept" } ]""");

            var (chain, errors)    = Trusted(leaf, ca);
            var (renewed, errors2) = Trusted(otherLeaf, ca);

            ServerJudgement first, second;

            using (chain)
                first  = node.JudgeTimeServer(Server, leaf,      chain,   errors);

            using (renewed)
                second = node.JudgeTimeServer(Server, otherLeaf, renewed, errors2);

            Assert.Multiple(() => {
                Assert.That(first.Learned,                                          Is.EqualTo(TrustOnFirstUse.Certificate));
                Assert.That(ServerEntry(node).Value<String>("certificateFingerprint"),  Is.EqualTo(Fingerprint(leaf)));
                Assert.That(second.Outcome,                                         Is.EqualTo("tolerated"));
                Assert.That(second.Changed,                                         Is.True);
                Assert.That(second.Previously!.Certificate,                         Is.EqualTo(Fingerprint(leaf)));
            });

        }

        #endregion

        #region NothingIsLearnedFromACertificateNobodyBelieves()

        /// <summary>
        /// Trust on first use narrows what is believed, as every pin does, and
        /// never widens it: a certificate that chains to nothing is refused, and
        /// nothing about it is written down to hold the server to.
        /// </summary>
        [Test]
        public async Task NothingIsLearnedFromACertificateNobodyBelieves()
        {

            await using var node = Node("""[ { "hostname": "time.example.org", "trustOnFirstUse": "root" } ]""");

            var (chain, errors) = Untrusted(leaf);

            using (chain)
            {

                var judgement = node.JudgeTimeServer(Server, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Outcome,                        Is.EqualTo("untrusted"));
                    Assert.That(judgement.Learned,                        Is.EqualTo(TrustOnFirstUse.None));
                    Assert.That(ServerEntry(node).ContainsKey("rootFingerprint"),  Is.False);
                    Assert.That(node.KnownServers.Get("nts", Server.Trimmed),      Is.Null, "and what was refused is not remembered as what it was believed with");
                });

            }

        }

        #endregion

        #region ARootLearnedWhileAPageWasOpenIsKeptByItsSave()

        /// <summary>
        /// A page loaded before the first key exchange and saved after it: the
        /// other server's priority changed, and every server sent with what the
        /// page showed it held to. The root learned in between stays - in the
        /// file, and in effect: another root afterwards is another root, not a
        /// second first use.
        /// </summary>
        [Test]
        public async Task ARootLearnedWhileAPageWasOpenIsKeptByItsSave()
        {

            await using var node = Node("""[ { "hostname": "time.example.org", "trustOnFirstUse": "root" }, "other.example.org" ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
                Assert.That(node.JudgeTimeServer(Server, leaf, chain, errors).Learned, Is.EqualTo(TrustOnFirstUse.Root));

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""
                            { "servers": [ { "hostname": "time.example.org", "trustOnFirstUse": "root",
                                             "pinsAsShown": { "trustOnFirstUse": "root" } },
                                           { "hostname": "other.example.org", "priority": 5,
                                             "pinsAsShown": { } } ] }
                            """), out var error),
                        Is.True,
                        error);

            var entry            = ServerEntry(node);

            using var elsewhere  = Leaf(Server.Trimmed, otherCA);
            var (other, errors2) = Trusted(elsewhere, otherCA);

            ServerJudgement again;

            using (other)
                again = node.JudgeTimeServer(Server, elsewhere, other, errors2);

            Assert.Multiple(() => {

                Assert.That(entry.Value<String>("rootFingerprint"),  Is.EqualTo(Fingerprint(ca)),  "the root learned while the page was open");
                Assert.That(entry.Value<String>("trustOnFirstUse"),  Is.EqualTo("root"));
                Assert.That(node.NTSConfigurationJSON()["timeSources"]![1]!.Value<Int32>("priority"),
                            Is.EqualTo(5),
                            "and the change the page made");

                Assert.That(again.Outcome,                           Is.EqualTo("pinMismatch"));
                Assert.That(again.Learned,                           Is.EqualTo(TrustOnFirstUse.None));

            });

        }

        #endregion

        #region ARootAPageShowedAndTookAwayIsTakenAway()

        /// <summary>
        /// The page showed the root learned on first use, and it was taken away
        /// there: gone, and to be learned again.
        /// </summary>
        [Test]
        public async Task ARootAPageShowedAndTookAwayIsTakenAway()
        {

            await using var node = Node("""[ { "hostname": "time.example.org", "trustOnFirstUse": "root" } ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
                node.JudgeTimeServer(Server, leaf, chain, errors);

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse($$"""
                            { "servers": [ { "hostname": "time.example.org", "trustOnFirstUse": "root",
                                             "pinsAsShown": { "rootFingerprint": "{{Fingerprint(ca)}}", "trustOnFirstUse": "root" } } ] }
                            """), out var error),
                        Is.True,
                        error);

            var entry = ServerEntry(node);

            Assert.Multiple(() => {
                Assert.That(entry.Value<String>("rootFingerprint"),  Is.Null);
                Assert.That(entry.Value<String>("trustOnFirstUse"),  Is.EqualTo("root"), "to be learned again");
                Assert.That(node.NTSConfigurationJSON()["timeSources"]![0]!["heldTo"]!.Value<String>("root"),
                            Is.Null,
                            "and out of effect");
            });

        }

        #endregion

        #region AServerRenamedOnAPageKeepsWhatItIsSentWith()

        /// <summary>
        /// Renamed on the page, a server keeps what it was held to under its old
        /// name where the page sends it so: a name this node does not have was
        /// held to nothing in between, and what the page sends is what counts.
        /// </summary>
        [Test]
        public async Task AServerRenamedOnAPageKeepsWhatItIsSentWith()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "rootFingerprint": "{{Fingerprint(ca)}}" } ]""");

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse($$"""
                            { "servers": [ { "hostname": "time2.example.org", "rootFingerprint": "{{Fingerprint(ca)}}",
                                             "pinsAsShown": { "rootFingerprint": "{{Fingerprint(ca)}}" } } ] }
                            """), out var error),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(ServerEntry(node).Value<String>("hostname")?.TrimEnd('.'),  Is.EqualTo("time2.example.org"));
                Assert.That(ServerEntry(node).Value<String>("rootFingerprint"),  Is.EqualTo(Fingerprint(ca)));
            });

        }

        #endregion

        #region AnEntryThatDoesNotSayWhatWasShownIsTakenAsItIs()

        /// <summary>
        /// Without "pinsAsShown" an entry is what its server is held to from
        /// then on, as an entry of the file is: what writes the list without
        /// having shown it writes what it means.
        /// </summary>
        [Test]
        public async Task AnEntryThatDoesNotSayWhatWasShownIsTakenAsItIs()
        {

            await using var node = Node("""[ { "hostname": "time.example.org", "trustOnFirstUse": "root" } ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
                node.JudgeTimeServer(Server, leaf, chain, errors);

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""
                            { "servers": [ { "hostname": "time.example.org", "trustOnFirstUse": "root" } ] }
                            """), out var error),
                        Is.True,
                        error);

            Assert.That(ServerEntry(node).Value<String>("rootFingerprint"), Is.Null);

        }

        #endregion

        #region AnotherCertificateThanBeforeIsSaidWithoutAnyPin()

        /// <summary>
        /// Held to nothing, a server showing another certificate than it was
        /// believed with is said all the same - with both fingerprints - and
        /// remembered with the new one.
        /// </summary>
        [Test]
        public async Task AnotherCertificateThanBeforeIsSaidWithoutAnyPin()
        {

            await using var node = Node();

            var (chain, errors)    = Trusted(leaf, ca);
            var (renewed, errors2) = Trusted(otherLeaf, ca);

            ServerJudgement first;

            using (chain)
                first = node.JudgeTimeServer(Server, leaf, chain, errors);

            var before = node.Log.LastId;

            ServerJudgement second;

            using (renewed)
                second = node.JudgeTimeServer(Server, otherLeaf, renewed, errors2);

            Assert.Multiple(() => {
                Assert.That(first.FirstSeen,                                            Is.True);
                Assert.That(second.Accepted,                                            Is.True);
                Assert.That(second.Changed,                                             Is.True);
                Assert.That(Security(node, before),                                     Has.Some.Contains("showed another certificate").And.Contains(Fingerprint(leaf)).And.Contains(Fingerprint(otherLeaf)));
                Assert.That(Metrological(node, before),                                 Has.Some.Contains("showed another certificate"), "a time server's, which bears on the time");
                Assert.That(node.KnownServers.Get("nts", Server.Trimmed)!.Certificate,  Is.EqualTo(Fingerprint(otherLeaf)));
            });

        }

        #endregion

        #region WhatAServerWasBelievedWithSurvivesARestart()

        [Test]
        public async Task WhatAServerWasBelievedWithSurvivesARestart()
        {

            await using (var first = Node())
            {
                var (chain, errors) = Trusted(leaf, ca);
                using (chain)
                    first.JudgeTimeServer(Server, leaf, chain, errors);
            }

            Assert.That(File.Exists(Path.Combine(directory, KnownServers.DefaultFileName)), Is.True, "beside the configuration file");

            await using var second = Node();

            var (renewed, errors2) = Trusted(otherLeaf, ca);

            using (renewed)
            {

                var judgement = second.JudgeTimeServer(Server, otherLeaf, renewed, errors2);

                Assert.Multiple(() => {
                    Assert.That(judgement.FirstSeen,              Is.False, "the restart forgot what it was believed with");
                    Assert.That(judgement.Changed,                Is.True);
                    Assert.That(judgement.Previously!.Certificate, Is.EqualTo(Fingerprint(leaf)));
                });

            }

        }

        #endregion

        #region TheNTSAnswerSaysEveryPinAndWhatAServerWasBelievedWith()

        [Test]
        public async Task TheNTSAnswerSaysEveryPinAndWhatAServerWasBelievedWith()
        {

            await using var node = Node($$"""[ { "hostname": "time.example.org", "certificateFingerprints": [ "{{Fingerprint(leaf)}}", "{{Fingerprint(otherLeaf)}}" ], "trustOnFirstUse": "root" } ]""");

            var (chain, errors) = Trusted(leaf, ca);

            using (chain)
                node.JudgeTimeServer(Server, leaf, chain, errors);

            var server = (node.NTSConfigurationJSON()["timeSources"] as JArray)!.Single();

            Assert.Multiple(() => {
                Assert.That(server["heldTo"]!.Value<String>("certificate"),         Is.EqualTo(Fingerprint(leaf)), "the first, where a page reads one");
                Assert.That(server["heldTo"]!["certificates"]!.Values<String>(),    Is.EqualTo(new[] { Fingerprint(leaf), Fingerprint(otherLeaf) }));
                Assert.That(server["heldTo"]!.Value<String>("root"),                Is.EqualTo(Fingerprint(ca)),   "learned on first use");
                Assert.That(server["heldTo"]!.Value<String>("trustOnFirstUse"),     Is.EqualTo("root"));
                Assert.That(server["known"]!.Value<String>("certificate"),          Is.EqualTo(Fingerprint(leaf)));
            });

        }

        #endregion

    }

}
