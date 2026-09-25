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

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the libraries below write through DebugX, as the event log gets it:
    /// above all, which tags a line is given - and by whose table.
    /// </summary>
    /// <remarks>
    /// The tags are what the Logs page filters by, so a wrong one is not
    /// cosmetic: a line about the accounts that says "nts" is shown to
    /// somebody looking for the time servers, and hidden from nobody. And the
    /// table is the kind of node's, because what is worth a tag depends on
    /// what a node overhears: a local controller hears OCPP going past it to a
    /// CSMS, which a vehicle never does.
    /// </remarks>
    [TestFixture]
    public class TraceBridgeTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-trace-bridge-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helper) TagsOf(Line, Tags = null)

        /// <summary>
        /// The tags a line is given: written into a bridge of its own, and read
        /// back from that bridge's log.
        /// </summary>
        private static IReadOnlyList<String> TagsOf(String                                     Line,
                                                    IEnumerable<(String Needle, String Tag)>?  Tags   = null)
        {

            var log = new EventLog();

            using (var bridge = TraceBridge.Attach(log, Tags))
                bridge.WriteLine(Line);

            return log.Recent(100).Single(entry => entry.Message == Line).Tags;

        }

        #endregion


        #region AWordThatOnlyEndsInAProtocolNameIsNotAboutIt()

        /// <summary>
        /// "nts" inside "accounts" is not the time servers.
        /// </summary>
        /// <remarks>
        /// Found anywhere in a line, the needle tagged every line that said
        /// "accounts", "clients" or "events" as one about the time servers -
        /// the first start's own complaint about the account store among them,
        /// which then stood on the Logs page as "[warning trace nts]".
        /// </remarks>
        [Test]
        public void AWordThatOnlyEndsInAProtocolNameIsNotAboutIt()
        {

            var firstStart = @"Could not find database file 'C:\Node\accounts\UsersAPI\users.db'!";

            Assert.Multiple(() => {
                Assert.That(TagsOf(firstStart),                                  Does.Not.Contain("nts"));
                Assert.That(TagsOf("2 clients, 12 events and 3 agents waiting"),  Does.Not.Contain("nts"));
                Assert.That(TagsOf(firstStart),                                  Is.EqualTo(new[] { TraceBridge.TraceTag }));
            });

        }

        #endregion

        #region AProtocolNameCountsWhereverAWordOfItsOwnBegins()

        /// <summary>
        /// The names still count where a word of their own begins, whatever
        /// follows them: at the start, after a sign, and at a capital.
        /// </summary>
        /// <remarks>
        /// What keeps the fix from overshooting. Whole words would have been
        /// the obvious rule and the wrong one: "OCPPv2.1", "https" and
        /// "certificates" are the words these names turn up in, and "mDNS" and
        /// "OCPPWebSocketServer" put theirs in the middle.
        /// </remarks>
        [Test]
        public void AProtocolNameCountsWhereverAWordOfItsOwnBegins()
        {

            Assert.Multiple(() => {
                Assert.That(TagsOf("NTS-KE handshake with ptbtime1.ptb.de failed"),  Does.Contain("nts"));
                Assert.That(TagsOf("Sending an NTP request"),                        Does.Contain("nts"));
                Assert.That(TagsOf("OCPPv2.1 BootNotification accepted"),            Does.Contain("ocpp"));
                Assert.That(TagsOf("OCPPWebSocketServer: a new connection"),         Does.Contain("websocket"));
                Assert.That(TagsOf("mDNS query for _ocpp._tcp.local"),               Does.Contain("dns"));
                Assert.That(TagsOf("GET https://example.org/ answered 200"),         Does.Contain("http"));
                Assert.That(TagsOf("The ServerCertificate has expired"),             Does.Contain("tls"));
                Assert.That(TagsOf("ISO15118: SupportedAppProtocolReq"),             Does.Contain("15118"));
            });

        }

        #endregion

        #region AKindsOwnTableTakesThePlaceOfTheDefault()

        /// <summary>
        /// A table handed in is the whole table: its tags are given, and the
        /// default's are not given beside them.
        /// </summary>
        /// <remarks>
        /// In place of the default rather than on top of it, so that a kind of
        /// node says exactly what it overhears - a local controller has no use
        /// for a "15118" tag on a line that only mentions V2G in passing, and
        /// would otherwise have one on it.
        /// </remarks>
        [Test]
        public void AKindsOwnTableTakesThePlaceOfTheDefault()
        {

            (String Needle, String Tag)[] controller = [ ("csms",    "csms"),
                                                         ("forward", "routing") ];

            Assert.Multiple(() => {

                Assert.That(TagsOf("Forwarding it to the CSMS", controller),
                            Is.EqualTo(new[] { TraceBridge.TraceTag, "csms", "routing" }));

                Assert.That(TagsOf("A V2G message over OCPP", controller),
                            Is.EqualTo(new[] { TraceBridge.TraceTag }),
                            "the default's tags given beside the kind's");

                // The same rule for the kind's needles as for the default's.
                Assert.That(TagsOf("Its forwarded messages", controller),
                            Does.Contain("routing"));

                Assert.That(TagsOf("A misforwarded message", controller),
                            Does.Not.Contain("routing"));

            });

        }

        #endregion

        #region ATableWithoutANeedleIsRefused()

        /// <summary>
        /// An empty needle is refused where the table is handed in.
        /// </summary>
        /// <remarks>
        /// It is found at the start of every line, so every line would carry its
        /// tag - a mistake that would otherwise only show on the Logs page,
        /// where it looks like a node that is about one thing all the time.
        /// </remarks>
        [Test]
        public void ATableWithoutANeedleIsRefused()
        {

            var log = new EventLog();

            Assert.Multiple(() => {
                Assert.That(() => TraceBridge.Attach(log, [ ("",     "csms") ]), Throws.ArgumentException);
                Assert.That(() => TraceBridge.Attach(log, [ ("csms", " ")    ]), Throws.ArgumentException);
            });

        }

        #endregion

        #region ANodeTagsWhatItOverhearsByTheTableOfItsKind()

        /// <summary>
        /// The table a node is handed is the one its debug bridge reads by.
        /// </summary>
        /// <remarks>
        /// Through Trace, the way a library below writes: nothing in this test
        /// talks to the bridge directly, because the kind of node never does
        /// either.
        /// </remarks>
        [Test]
        public async Task ANodeTagsWhatItOverhearsByTheTableOfItsKind()
        {

            var line = $"Forwarding a message to the CSMS ({Guid.NewGuid():N})";

            await using var node = new WWCPNode(
                                       AccountsPath:      Path.Combine(directory, "accounts"),
                                       ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                       CertificatesPath:  Path.Combine(directory, "certificates"),
                                       LogToConsole:      false,
                                       BridgeDebugLog:    true,
                                       TraceTags:         [ ("csms",    "csms"),
                                                            ("forward", "routing") ]
                                   );

            System.Diagnostics.Trace.WriteLine(line);

            Assert.That(node.Log.Recent(2000).Single(entry => entry.Message == line).Tags,
                        Is.EqualTo(new[] { TraceBridge.TraceTag, "csms", "routing" }));

        }

        #endregion

    }

}
