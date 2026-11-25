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

using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the connections page is told of the charging stations a peer gets: the counts by
    /// their targets, which stations are at it now, and what is held back for it.
    /// </summary>
    public class PeerStationsTests
    {

        [Test]
        public void TheCounts_AsBefore_WhereNothingElseIsSaid()
        {

            var json = new PeerStations(First: 2, InReserve: 1, WithoutTarget: 4, Now: 6).ToJSON();

            Assert.Multiple(() => {
                Assert.That(json["first"]?.Value<Int32>(),          Is.EqualTo(2));
                Assert.That(json["inReserve"]?.Value<Int32>(),      Is.EqualTo(1));
                Assert.That(json["withoutTarget"]?.Value<Int32>(),  Is.EqualTo(4));
                Assert.That(json["now"]?.Value<Int32>(),            Is.EqualTo(6));
                Assert.That(json["heldBack"]?.Value<Int32>(),       Is.EqualTo(0));
                Assert.That(json["sessions"]?.Value<Int32>(),       Is.EqualTo(0));
                Assert.That(json.ContainsKey("at"),                 Is.False, "stations are said to be at it where none is known");
                Assert.That(json.ContainsKey("heldBackSince"),      Is.False, "a time is said where nothing is held back");
            });

        }

        [Test]
        public void WhoIsAtIt_AndWhatIsHeldBack()
        {

            var since = DateTimeOffset.Parse("2026-11-25T13:02:11Z");
            var json  = new PeerStations(1, 0, 0, 1, At: [ "cs001", "cs007" ], HeldBack: 3, HeldBackSince: since, Sessions: 1).ToJSON();

            Assert.Multiple(() => {
                Assert.That(json["at"]?.Values<String>(),                                    Is.EqualTo(new[] { "cs001", "cs007" }));
                Assert.That(json["heldBack"]?.Value<Int32>(),                                Is.EqualTo(3));
                Assert.That(DateTimeOffset.Parse(json.Value<String>("heldBackSince")!),      Is.EqualTo(since));
                Assert.That(json["sessions"]?.Value<Int32>(),                                Is.EqualTo(1));
            });

        }

        [Test]
        public void Equal_ByTheStationsAtIt_NotByTheirList()
        {

            var one     = new PeerStations(1, 0, 0, 1, At: [ "cs001" ], HeldBack: 2);
            var another = new PeerStations(1, 0, 0, 1, At: new List<String> { "cs001" }, HeldBack: 2);

            Assert.Multiple(() => {
                Assert.That(one,                                          Is.EqualTo(another));
                Assert.That(one.GetHashCode(),                            Is.EqualTo(another.GetHashCode()));
                Assert.That(one with { At = [ "cs002" ] },                Is.Not.EqualTo(another));
                Assert.That(one with { HeldBack = 3 },                    Is.Not.EqualTo(another));
                Assert.That(one with { Sessions = 1 },                    Is.Not.EqualTo(another));
                Assert.That(one with { HeldBackSince = DateTimeOffset.UnixEpoch }, Is.Not.EqualTo(another));
                Assert.That(new PeerStations(1, 0, 0, 1, At: []),         Is.EqualTo(new PeerStations(1, 0, 0, 1)), "an empty list of stations is said to differ from none");
            });

        }

    }

}
