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


        #region (helper) AfterAPageSaved(Now, Shown, Sent)

        /// <summary>
        /// What a server is held to once a page saved its entry, each of the
        /// three written as an entry says it.
        /// </summary>
        private static ServerPins? AfterAPageSaved(String Now, String Shown, String Sent)
        {

            Assert.That(ServerPins.TryAfterAPageSaved(Parsed(Now), Parsed(Shown), Parsed(Sent), "nts.servers[0]", out var pins, out var error),
                        Is.True,
                        error);

            return pins;

        }

        #endregion

        #region WhatAServerLearnedWhileThePageWasOpenIsKept()

        /// <summary>
        /// The page showed a server that was still to learn its root, the server
        /// learned it before the page saved, and the page sends what it showed.
        /// </summary>
        [Test]
        public void WhatAServerLearnedWhileThePageWasOpenIsKept()
        {

            var pins = AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""",
                                       Shown:   """{ "trustOnFirstUse": "root" }""",
                                       Sent:    """{ "trustOnFirstUse": "root" }""");

            Assert.That(pins?.SameAs(Parsed($$"""{ "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""")),
                        Is.True,
                        pins?.ToString());

        }

        #endregion

        #region WhatThePageTookAwayIsTakenAway()

        /// <summary>
        /// The page showed the root the server had learned, and it was taken
        /// away there - to have it learned again.
        /// </summary>
        [Test]
        public void WhatThePageTookAwayIsTakenAway()
        {

            var pins = AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""",
                                       Shown: $$"""{ "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""",
                                       Sent:    """{ "trustOnFirstUse": "root" }""");

            Assert.Multiple(() => {
                Assert.That(pins?.Roots,            Is.Empty);
                Assert.That(pins?.TrustOnFirstUse,  Is.EqualTo(TrustOnFirstUse.Root));
            });

        }

        #endregion

        #region WhatThePageAddedIsAddedToWhatItDidNotShow()

        [Test]
        public void WhatThePageAddedIsAddedToWhatItDidNotShow()
        {

            var pins = AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""",
                                       Shown:   """{ "trustOnFirstUse": "root" }""",
                                       Sent:  $$"""{ "certificateFingerprint": "{{A}}", "trustOnFirstUse": "root" }""");

            Assert.Multiple(() => {
                Assert.That(pins?.Certificates,  Is.EqualTo(new[] { A }), "added on the page");
                Assert.That(pins?.Roots,         Is.EqualTo(new[] { R }), "learned while the page was open");
            });

        }

        #endregion

        #region WhatSomebodyElseChangedStaysWhereThePageChangedNothing()

        /// <summary>
        /// Somebody else held the server to another root in between, and to
        /// what a mismatch comes to; the page, which showed the old root, only
        /// added a certificate.
        /// </summary>
        [Test]
        public void WhatSomebodyElseChangedStaysWhereThePageChangedNothing()
        {

            var pins = AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{B}}", "onMismatch": "accept" }""",
                                       Shown: $$"""{ "rootFingerprint": "{{A}}" }""",
                                       Sent:  $$"""{ "rootFingerprint": "{{A}}", "certificateFingerprint": "{{C}}" }""");

            Assert.Multiple(() => {
                Assert.That(pins?.Roots,         Is.EqualTo(new[] { B }));
                Assert.That(pins?.Certificates,  Is.EqualTo(new[] { C }));
                Assert.That(pins?.OnMismatch,    Is.EqualTo(PinMismatch.Accept));
            });

        }

        #endregion

        #region WhatAMismatchComesToAndWhatIsLearnedAreThePagesWhereItChangedThem()

        [Test]
        public void WhatAMismatchComesToAndWhatIsLearnedAreThePagesWhereItChangedThem()
        {

            var pins = AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{R}}", "trustOnFirstUse": "root" }""",
                                       Shown:   """{ "trustOnFirstUse": "root" }""",
                                       Sent:    """{ "trustOnFirstUse": "certificate", "onMismatch": "record" }""");

            Assert.Multiple(() => {
                Assert.That(pins?.TrustOnFirstUse,  Is.EqualTo(TrustOnFirstUse.Certificate));
                Assert.That(pins?.OnMismatch,       Is.EqualTo(PinMismatch.Record));
                Assert.That(pins?.Roots,            Is.EqualTo(new[] { R }), "what the page did not show is not what it changed");
            });

        }

        #endregion

        #region NothingLeftIsNothing()

        [Test]
        public void NothingLeftIsNothing()
        {

            Assert.That(AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{R}}", "onMismatch": "accept" }""",
                                        Shown: $$"""{ "rootFingerprint": "{{R}}", "onMismatch": "accept" }""",
                                        Sent:    """{ }"""),
                        Is.Null,
                        "and what a mismatch comes to goes with the last pin, which the file refuses on a server held to nothing");

        }

        #endregion

        #region WhatAMismatchComesToGoesWithTheLastPinWhoeverSaidIt()

        /// <summary>
        /// Somebody else said "accept" in between, and the page, which showed a
        /// refusal, took the last pin away: what is left is nothing, and not an
        /// "accept" on a server held to nothing, which the file refuses at the
        /// next start.
        /// </summary>
        [Test]
        public void WhatAMismatchComesToGoesWithTheLastPinWhoeverSaidIt()
        {

            Assert.That(AfterAPageSaved(Now:   $$"""{ "rootFingerprint": "{{R}}", "onMismatch": "accept" }""",
                                        Shown: $$"""{ "rootFingerprint": "{{R}}" }""",
                                        Sent:    """{ }"""),
                        Is.Null);

        }

        #endregion

        #region MoreThanSixteenAfterASaveAreRefused()

        /// <summary>
        /// Sixteen roots sent, and one learned that the page did not show: more
        /// than the file takes, and not cut down to fit.
        /// </summary>
        [Test]
        public void MoreThanSixteenAfterASaveAreRefused()
        {

            var sixteen = new JArray(Enumerable.Range(1, ServerPins.MaxPins).Select(i => i.ToString("x64")));

            Assert.That(ServerPins.TryAfterAPageSaved(Parsed($$"""{ "rootFingerprint": "{{R}}" }"""),
                                                      null,
                                                      Parsed(new JObject(new JProperty("rootFingerprints", sixteen)).ToString()),
                                                      "nts.servers[0]",
                                                      out _,
                                                      out var error),
                        Is.False);

            Assert.That(error, Does.Contain($"{ServerPins.MaxPins + 1} roots").And.Contain("Load the page again"));

        }

        #endregion

        #region WhatThePageShowedIsReadByTheServersPlace()

        [Test]
        public void WhatThePageShowedIsReadByTheServersPlace()
        {

            var section = JObject.Parse($$"""
                              { "servers": [
                                  { "hostname": "a.example", "pinsAsShown": { "rootFingerprint": "{{R}}" } },
                                  "b.example",
                                  { "hostname": "c.example", "pinsAsShown": { } },
                                  { "hostname": "d.example", "pinsAsShown": null },
                                  { "hostname": "e.example" }
                              ] }
                              """);

            Assert.That(ServerPins.TryParseAsShown(section, "nts", out var asShown, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(asShown.Keys,       Is.EquivalentTo(new[] { 0, 2 }), "a bare name, null and nothing are not what a page showed");
                Assert.That(asShown[0]?.Roots,  Is.EqualTo(new[] { R }));
                Assert.That(asShown[2],         Is.Null, "shown held to nothing");
            });

        }

        #endregion

        #region WhatThePageShowedIsCheckedAsAnEntryIs(JSON, Expected)

        [TestCase("""{ "servers": [ { "hostname": "a.example", "pinsAsShown": "root" } ] }""",
                  "'nts.servers[0].pinsAsShown' must be an object")]
        [TestCase("""{ "servers": [ { "hostname": "a.example", "pinsAsShown": { "rootFingerprint": "xyz" } } ] }""",
                  "'nts.servers[0].pinsAsShown.rootFingerprint' holds 'xyz'")]
        public void WhatThePageShowedIsCheckedAsAnEntryIs(String JSON, String Expected)
        {

            Assert.That(ServerPins.TryParseAsShown(JObject.Parse(JSON), "nts", out _, out var error), Is.False);
            Assert.That(error, Does.Contain(Expected));

        }

        #endregion

    }

}
