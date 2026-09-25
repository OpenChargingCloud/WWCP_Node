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
                Assert.That(error,  Does.StartWith("'nts.servers[1]'.certificateFingerprint is not a SHA-256 fingerprint"));

                Assert.That(NTSServerConfiguration.TryParse(JObject.Parse("""{ "hostname": "time.example.org", "onMismatch": "record" }"""), 2, out _, out error),  Is.False);
                Assert.That(error,  Does.Contain("is held to none"));

                Assert.That(NTSServerConfiguration.TryParse(JObject.Parse($$"""{ "hostname": "time.example.org", "rootFingerprint": "{{fingerprint}}", "onMismatch": "ignore" }"""), 3, out _, out error),  Is.False);
                Assert.That(error,  Does.Contain("has to be 'refuse' or 'record'"));

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

    }

}
