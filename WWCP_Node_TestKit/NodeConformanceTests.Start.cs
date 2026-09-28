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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// What a kind of node starts with, and what its start makes of the file
    /// it is given.
    /// </summary>
    /// <remarks>
    /// The node below reads the file and starts the check of the clock; a
    /// kind that handed it a time client of its own, or read the file before
    /// it, would start otherwise than every other - which the kinds' suites
    /// each asked of their own, as "TheDefaultFourAreWhatAStationStartsWith"
    /// and the like.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region TheDefaultFourAreWhatEveryKindStartsWith()

        /// <summary>
        /// A node whose file only switches the time client off still has the
        /// four PTB servers it would ask, as peers, two of which have to
        /// answer - and the first of them is the single client's, which the
        /// detailed test starts from.
        /// </summary>
        [Test]
        public void TheDefaultFourAreWhatEveryKindStartsWith()
        {

            Assert.Multiple(() => {
                Assert.That(Node.NTSEnabled,                          Is.False,  "the fixture switched it off");
                Assert.That(Node.TimeSources.Bands(),                 Has.Count.EqualTo(1),  "peers, asked together");
                Assert.That(Node.TimeSources.Bands()[0],              Has.Count.EqualTo(4));
                Assert.That(Node.TimeSources.Bands()[0][0].Hostname,  Is.EqualTo(Node.NTSClient.Hostname));
                Assert.That(Node.TimeSources.MinServers,              Is.EqualTo(2));
            });

        }

        #endregion

        #region ASwitchedOffTimeClientSchedulesNothing()

        /// <summary>
        /// The whole reason the fixture writes that section: switched off, no
        /// check of the clock is put on the network at all - and the start says
        /// that the clock is not being checked, rather than nothing.
        /// </summary>
        [Test]
        public void ASwitchedOffTimeClientSchedulesNothing()
        {

            var said = Node.Log.Recent(500).Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(said,  Has.Some.Contains("is not being checked: NTS is switched off"),  String.Join(" | ", said));
                Assert.That(said,  Has.None.Contains("will be checked against"),                   String.Join(" | ", said));
            });

        }

        #endregion

        #region ARunningNodePutsANewIntervalIntoItsClockCheckAtOnce()

        /// <summary>
        /// How often the clock is checked, and whether it is, are put into the
        /// check of a running node at once - not at its next start: each save
        /// sets the timer once, and says so once.
        /// </summary>
        /// <remarks>
        /// With the time client on, and held to a server on this machine that
        /// nothing answers on, so that a check that comes due asks nobody else.
        /// </remarks>
        [Test, WithNode(NodeSetup.TimeClientOn)]
        public async Task ARunningNodePutsANewIntervalIntoItsClockCheckAtOnce()
        {

            using var http          = await SignedIn();

            var (interval, first)   = await Send(http, HttpMethod.Put, "api/v1/configuration/nts", new JObject(new JProperty("checkEverySeconds", 600)));
            var (switched, second)  = await Send(http, HttpMethod.Put, "api/v1/configuration/nts", new JObject(new JProperty("enabled",           false)));

            var said                = Node.Log.Recent(500).Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {

                Assert.That(interval,  Is.EqualTo(HttpStatusCode.OK), first. ToString());
                Assert.That(switched,  Is.EqualTo(HttpStatusCode.OK), second.ToString());

                Assert.That(said.Count(line => line.Contains("will be checked against") && line.Contains("every 15 minute(s)")),  Is.EqualTo(1),
                            "the start set the timer once: " + String.Join(" | ", said));

                Assert.That(said.Count(line => line.Contains("will be checked against") && line.Contains("every 10 minute(s)")),  Is.EqualTo(1),
                            "the new interval reached the timer once: " + String.Join(" | ", said));

                Assert.That(said.Count(line => line.Contains("is not being checked: NTS is switched off")),                        Is.EqualTo(1),
                            "switching NTS off reached the timer once: " + String.Join(" | ", said));

            });

        }

        #endregion

        #region AFileThatNamesANameServerTheWayTheLogDoesStopsTheNode()

        /// <summary>
        /// "udp://213.133.98.98:53" is how the log writes a name server, and no
        /// form the file takes: a node whose file says so stops at its
        /// construction, with a sentence that names the entry and the file to
        /// repair - rather than with an ArgumentException, as some kinds of
        /// node did, or not at all.
        /// </summary>
        /// <remarks>
        /// The file is the kind's own, wherever its NewNode puts it: as far
        /// below the new directory as the running node's file is below this
        /// fixture's.
        /// </remarks>
        [Test]
        public async Task AFileThatNamesANameServerTheWayTheLogDoesStopsTheNode()
        {

            var elsewhere = Path.Combine(Directory, "another");
            var file      = Path.Combine(elsewhere, Path.GetRelativePath(Directory, Node.ConfigFile.Path));

            System.IO.Directory.CreateDirectory(elsewhere);

            Exception?  thrown  = null;
            WWCPNode?   made    = null;

            try
            {
                made = NewNode(elsewhere, JObject.Parse("""{ "dns": { "servers": [ "udp://213.133.98.98:53" ] }, "nts": { "enabled": false } }"""));
            }
            catch (Exception e)
            {
                thrown = e;
            }

            if (made is not null)
                await made.DisposeAsync();

            Assert.Multiple(() => {
                Assert.That(thrown,           Is.TypeOf<InvalidOperationException>(),      $"the {Node.Kind.Name} was made anyway, or stopped otherwise: {thrown}");
                Assert.That(thrown?.Message,  Does.Contain("'dns.servers'").And.Contain("udp://213.133.98.98:53"));
                Assert.That(thrown?.Message,  Does.Contain(file),                             "the sentence does not say which file to repair");
            });

        }

        #endregion

    }

}
