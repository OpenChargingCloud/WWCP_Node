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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a server is held to, as the configuration file writes it: any
    /// number of certificates and roots, what a mismatch comes to, and what is
    /// learned on first use.
    /// </summary>
    public class ServerPinsTests
    {

        #region Data

        private static readonly String A = new ('a', 64);
        private static readonly String B = new ('b', 64);
        private static readonly String C = new ('c', 64);
        private static readonly String R = new ('d', 64);

        #endregion

        #region (helper) Parsed(JSON)

        private static ServerPins? Parsed(String JSON)
        {

            Assert.That(ServerPins.TryParse(JObject.Parse(JSON), "nts.servers[0]", out var pins, out var error), Is.True, error);

            return pins;

        }

        #endregion


        #region SeveralPinsOfAKindAddUp()

        /// <summary>
        /// One pin the way a file said it before there could be several, a list
        /// beside it, and the two together: they add up, each once.
        /// </summary>
        [Test]
        public void SeveralPinsOfAKindAddUp()
        {

            var pins = Parsed($$"""
                               { "certificateFingerprint":  "{{C}}",
                                 "certificateFingerprints": [ "{{A}}", "{{B.ToUpperInvariant()}}", "{{C}}" ],
                                 "rootFingerprints":        [ "{{R}}" ] }
                               """)!;

            var written = new JObject();
            pins.WriteInto(written);

            Assert.Multiple(() => {
                Assert.That(pins.Certificates,  Is.EqualTo(new[] { C, A, B }), "each once, in the form the store keeps them");
                Assert.That(pins.Roots,         Is.EqualTo(new[] { R }));
                Assert.That(pins.IsPinned,      Is.True);
                Assert.That(written["certificateFingerprints"]!.Values<String>(),  Is.EqualTo(new[] { C, A, B }), "several as a list");
                Assert.That(written.Value<String>("rootFingerprint"),              Is.EqualTo(R),                "and one the way it always was");
                Assert.That(written.ContainsKey("rootFingerprints"),               Is.False);
                Assert.That(pins.Text,          Is.EqualTo($"certificate {C} or {A} or {B} and root {R}, refused otherwise"));
            });

        }

        #endregion

        #region AServerHeldToNothingSaysNothing()

        [Test]
        public void AServerHeldToNothingSaysNothing()
        {

            Assert.That(Parsed("""{ "hostname": "time.example.org" }"""), Is.Null);

        }

        #endregion

        #region TrustOnFirstUseIsReadAndWrittenBack()

        /// <summary>
        /// A server that learns what to hold on to says so, before it has
        /// anything to hold on to - and a mismatch may already say what it will
        /// come to.
        /// </summary>
        [Test]
        public void TrustOnFirstUseIsReadAndWrittenBack()
        {

            var pins    = Parsed("""{ "trustOnFirstUse": "Root", "onMismatch": "accept" }""")!;
            var written = new JObject();

            pins.WriteInto(written);

            var server  = new NTSServerConfiguration(org.GraphDefined.Vanaheimr.Hermod.DNS.DomainName.Parse("time.example.org"), Pins: pins);

            Assert.Multiple(() => {
                Assert.That(pins.TrustOnFirstUse,                      Is.EqualTo(TrustOnFirstUse.Root));
                Assert.That(pins.OnMismatch,                           Is.EqualTo(PinMismatch.Accept));
                Assert.That(pins.IsPinned,                             Is.False);
                Assert.That(pins.SaysAnything,                         Is.True);
                Assert.That(written.Value<String>("trustOnFirstUse"),  Is.EqualTo("root"));
                Assert.That(written.Value<String>("onMismatch"),       Is.EqualTo("accept"));
                Assert.That(server.ToJSON().Type,                      Is.EqualTo(JTokenType.Object), "not a bare name: it says more than the name");
                Assert.That(pins.ToString(),                           Is.EqualTo("its root, once it is first believed"));
            });

        }

        #endregion

        #region WhatAServerLearnsIsAddedToWhatItIsHeldTo()

        [Test]
        public void WhatAServerLearnsIsAddedToWhatItIsHeldTo()
        {

            var pins    = Parsed($$"""{ "certificateFingerprint": "{{A}}", "trustOnFirstUse": "root" }""")!;
            var learned = pins.Learning(TrustOnFirstUse.Root, R);

            Assert.Multiple(() => {
                Assert.That(learned.Certificates,     Is.EqualTo(new[] { A }));
                Assert.That(learned.Roots,            Is.EqualTo(new[] { R }));
                Assert.That(learned.SameAs(pins),     Is.False);
                Assert.That(learned.SameAs(Parsed($$"""{ "certificateFingerprint": "{{A}}", "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""")),
                            Is.True,
                            "the same pins, however they came to be written down");
            });

        }

        #endregion

        #region WhatIsNotAPinIsSaidSo(JSON, Expected)

        [TestCase("""{ "trustOnFirstUse": "always" }""",                "has to be 'root' or 'certificate'")]
        [TestCase("""{ "certificateFingerprints": "ab" }""",           "must be an array")]
        [TestCase("""{ "rootFingerprints": [ "xyz" ] }""",             "is not a SHA-256 fingerprint")]
        [TestCase("""{ "onMismatch": "accept" }""",                    "is held to none")]
        [TestCase("""{ "rootFingerprint": "ab:cd", "onMismatch": "x" }""", "is not a SHA-256 fingerprint")]
        public void WhatIsNotAPinIsSaidSo(String JSON, String Expected)
        {

            Assert.That(ServerPins.TryParse(JObject.Parse(JSON), "nts.servers[0]", out _, out var error), Is.False);
            Assert.That(error, Does.Contain(Expected));

        }

        #endregion

        #region SeventeenPinsAreTooMany()

        [Test]
        public void SeventeenPinsAreTooMany()
        {

            var many = new JArray(Enumerable.Range(0, ServerPins.MaxPins + 1).Select(i => i.ToString("x64")));

            Assert.That(ServerPins.TryParse(new JObject(new JProperty("rootFingerprints", many)), "nts.servers[0]", out _, out var error), Is.False);
            Assert.That(error, Does.Contain($"at most {ServerPins.MaxPins}").Or.Contain($"more than {ServerPins.MaxPins}"));

        }

        #endregion

    }

}
