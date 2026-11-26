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

using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using HermodIPAddress = org.GraphDefined.Vanaheimr.Hermod.IPAddress;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the time server of the SSH logins says about its clock, from the check of the clock
    /// against the legal group: <see cref="TimeServerClock"/> and <see cref="TimeServerUpstream"/>.
    /// </summary>
    [TestFixture]
    public class TimeServerClockTests
    {

        #region Data

        private static readonly DateTimeOffset  now         = new (2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
        private static readonly TimeSpan        tolerance   = TimeSpan.FromSeconds(1);
        private static readonly TimeSpan        maxAge      = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan        resolution  = TimeSpan.FromTicks(10);

        private static readonly TimeServerUpstream ptb      = new ("ptbtime1.ptb.de",
                                                                   System.Net.IPAddress.Parse("192.53.103.108"),
                                                                   Stratum:         1,
                                                                   RootDelay:       TimeSpan.FromMilliseconds(2),
                                                                   RootDispersion:  TimeSpan.FromMilliseconds(3),
                                                                   RoundTrip:       TimeSpan.FromMilliseconds(10),
                                                                   LeapIndicator:   0);

        #endregion

        #region (private static) Clock(Checked, Upstream, Age, OffsetMilliseconds)

        private static TimeServerClock? Clock(Boolean              Checked,
                                              TimeServerUpstream?  Upstream,
                                              TimeSpan?            Age,
                                              Double?              OffsetMilliseconds)

            => TimeServerClock.Of(Checked,
                                  Upstream,
                                  Age.HasValue ? now - Age.Value : null,
                                  OffsetMilliseconds.HasValue ? TimeSpan.FromMilliseconds(OffsetMilliseconds.Value) : null,
                                  tolerance,
                                  maxAge,
                                  now,
                                  resolution);

        #endregion


        #region AClockThatIsNotChecked_SaysWhatNornSaysByDefault()

        /// <summary>
        /// NTS switched off: nothing to say but stratum 1, "LOCL" - an uncalibrated local clock.
        /// </summary>
        [Test]
        public void AClockThatIsNotChecked_SaysWhatNornSaysByDefault()
        {
            Assert.That(Clock(false, ptb, TimeSpan.FromMinutes(1), 1), Is.Null);
        }

        #endregion

        #region AClockThatWasFoundRight_IsOneStratumBelowItsServer()

        [Test]
        public void AClockThatWasFoundRight_IsOneStratumBelowItsServer()
        {

            var clock = Clock(true, ptb, TimeSpan.FromSeconds(100), -4)!;

            Assert.Multiple(() => {
                Assert.That(clock.IsSynchronised,   Is.True);
                Assert.That(clock.Why,              Is.Null);
                Assert.That(clock.Stratum,          Is.EqualTo(2));
                Assert.That(clock.Reference,        Is.EqualTo(ReferenceIdentifier.From(192, 53, 103, 108)), "an IPv4 server's address is the reference");
                Assert.That(clock.RootDelay,        Is.EqualTo(TimeSpan.FromMilliseconds(12)),               "its root delay and the round trip to it");
                // Its root dispersion, the offset found, the resolution, and 100 s at 15 ppm.
                Assert.That(clock.RootDispersion,   Is.EqualTo(TimeSpan.FromMilliseconds(3 + 4 + 1.5) + resolution));
                Assert.That(clock.LeapIndicator,    Is.Zero);
                Assert.That(clock.Upstream,         Is.SameAs(ptb));
            });

        }

        #endregion

        #region AtTheLimits_ItIsStillSynchronised()

        [Test]
        public void AtTheLimits_ItIsStillSynchronised()
        {
            Assert.That(Clock(true, ptb, maxAge, 1000)!.IsSynchronised,   Is.True, "a check exactly MaxAge old, the clock exactly Tolerance off");
            Assert.That(Clock(true, ptb, maxAge, -1000)!.IsSynchronised,  Is.True);
        }

        #endregion

        #region AClockNeverChecked_IsNotSynchronised()

        [Test]
        public void AClockNeverChecked_IsNotSynchronised()
        {

            var clock = Clock(true, null, null, null)!;

            Assert.Multiple(() => {
                Assert.That(clock.IsSynchronised,  Is.False);
                Assert.That(clock.LeapIndicator,   Is.EqualTo(3));
                Assert.That(clock.Stratum,         Is.EqualTo(16));
                Assert.That(clock.Why,             Is.EqualTo("neverChecked"));
            });

        }

        #endregion

        #region AStaleCheck_IsNotSynchronised()

        [Test]
        public void AStaleCheck_IsNotSynchronised()
        {

            var clock = Clock(true, ptb, maxAge + TimeSpan.FromSeconds(1), 1)!;

            Assert.Multiple(() => {
                Assert.That(clock.IsSynchronised,  Is.False);
                Assert.That(clock.LeapIndicator,   Is.EqualTo(3));
                Assert.That(clock.Stratum,         Is.EqualTo(16));
                Assert.That(clock.Why,             Is.EqualTo("stale"));
                Assert.That(clock.Reference,       Is.EqualTo(ReferenceIdentifier.From(192, 53, 103, 108)), "still names its server, against loops");
            });

        }

        #endregion

        #region AClockFoundOff_IsNotSynchronised()

        [TestCase( 1001)]
        [TestCase(-1001)]
        [TestCase( 30000)]
        public void AClockFoundOff_IsNotSynchronised(Double OffsetMilliseconds)
        {

            var clock = Clock(true, ptb, TimeSpan.FromSeconds(10), OffsetMilliseconds)!;

            Assert.Multiple(() => {
                Assert.That(clock.IsSynchronised,  Is.False);
                Assert.That(clock.LeapIndicator,   Is.EqualTo(3));
                Assert.That(clock.Stratum,         Is.EqualTo(16));
                Assert.That(clock.Why,             Is.EqualTo("offBy"));
            });

        }

        #endregion

        #region ALeapSecondItsServerAnnounces_IsAnnouncedOn()

        [TestCase((Byte) 1)]
        [TestCase((Byte) 2)]
        public void ALeapSecondItsServerAnnounces_IsAnnouncedOn(Byte LeapIndicator)
        {
            Assert.That(Clock(true, ptb with { LeapIndicator = LeapIndicator }, TimeSpan.FromSeconds(10), 1)!.LeapIndicator,
                        Is.EqualTo(LeapIndicator));
        }

        #endregion

        #region TheStratumEndsAt15()

        [Test]
        public void TheStratumEndsAt15()
        {
            Assert.That(Clock(true, ptb with { Stratum = 15 }, TimeSpan.FromSeconds(10), 1)!.Stratum,  Is.EqualTo(15));
            Assert.That(Clock(true, ptb with { Stratum = 14 }, TimeSpan.FromSeconds(10), 1)!.Stratum,  Is.EqualTo(15));
            Assert.That(Clock(true, ptb with { Stratum = 3  }, TimeSpan.FromSeconds(10), 1)!.Stratum,  Is.EqualTo(4));
        }

        #endregion

        #region TheReference_OfAnIPv6Server_IsTheStartOfTheMD5OfItsAddress()

        [Test]
        public void TheReference_OfAnIPv6Server_IsTheStartOfTheMD5OfItsAddress()
        {

            var address  = System.Net.IPAddress.Parse("2001:638:610:be01::108");
            var hash     = MD5.HashData(address.GetAddressBytes());

            Assert.Multiple(() => {
                Assert.That(TimeServerClock.ReferenceOf(ptb with { Address = address }),
                            Is.EqualTo(ReferenceIdentifier.From(hash[0], hash[1], hash[2], hash[3])),
                            "RFC 5905 § 7.3");
                Assert.That(TimeServerClock.ReferenceOf(ptb with { Address = System.Net.IPAddress.Parse("::ffff:192.53.103.108") }),
                            Is.EqualTo(ReferenceIdentifier.From(192, 53, 103, 108)),
                            "an IPv4 address mapped into IPv6 is an IPv4 address");
                Assert.That(TimeServerClock.ReferenceOf(ptb with { Address = null }),
                            Is.Not.EqualTo(TimeServerClock.ReferenceOf(ptb with { Address = null, Hostname = "ptbtime2.ptb.de" })),
                            "without an address, its name tells servers apart");
            });

        }

        #endregion


        #region (private static) Answer(Name, Address, Stratum, OffsetMilliseconds, ...)

        private static NTSMeasurementResult Answer(String   Name,
                                                   String   Address,
                                                   Byte     Stratum,
                                                   Double   OffsetMilliseconds,
                                                   Double   RootDispersionSeconds  = 0.001,
                                                   Boolean  Authenticated          = true)

            => new (DomainName.Parse(Name),
                    Guid.Empty) {

                   Success  = true,
                   NTP      = new NTPMeasurementResult {
                                  Success                 = true,
                                  NTSAuthenticationValid  = Authenticated,
                                  Offset                  = TimeSpan.FromMilliseconds(OffsetMilliseconds),
                                  RemoteAddress           = HermodIPAddress.Parse(Address),
                                  Stratum                 = Stratum,
                                  RootDelaySeconds        = 0.002,
                                  RootDispersionSeconds   = RootDispersionSeconds,
                                  RoundTripDelay          = TimeSpan.FromMilliseconds(10)
                              }

               };

        #endregion

        #region TheUpstream_IsTheAgreeingServerOfTheLowestStratum()

        /// <summary>
        /// Of the servers the time of a round rests on, the one of the lowest stratum - and not
        /// one that disagrees with the rest, or one that did not authenticate, whatever its
        /// stratum; between two of the same stratum, the closer to its reference.
        /// </summary>
        [Test]
        public void TheUpstream_IsTheAgreeingServerOfTheLowestStratum()
        {

            var verdict  = TimeSyncVerdict.From(
                               [
                                   Answer("two.example",     "192.0.2.2", 2,      1.0),
                                   Answer("far.example",     "192.0.2.3", 1,      1.5, RootDispersionSeconds: 0.5),
                                   Answer("near.example",    "192.0.2.4", 1,      2.0),
                                   Answer("outlier.example", "192.0.2.5", 1, 120000.0, RootDispersionSeconds: 0.0001),
                                   Answer("forged.example",  "192.0.2.6", 1,      1.0, RootDispersionSeconds: 0.0001, Authenticated: false)
                               ],
                               MinServers:    2,
                               MaxDeviation:  TimeSpan.FromSeconds(60)
                           );

            var upstream = TimeServerUpstream.Of(verdict, TimeSpan.FromSeconds(60))!;

            Assert.Multiple(() => {
                Assert.That(upstream.Hostname,        Is.EqualTo("near.example"));
                Assert.That(upstream.Address,         Is.EqualTo(System.Net.IPAddress.Parse("192.0.2.4")));
                Assert.That(upstream.Stratum,         Is.EqualTo(1));
                Assert.That(upstream.RootDelay,       Is.EqualTo(TimeSpan.FromMilliseconds(2)));
                Assert.That(upstream.RootDispersion,  Is.EqualTo(TimeSpan.FromMilliseconds(1)));
                Assert.That(upstream.RoundTrip,       Is.EqualTo(TimeSpan.FromMilliseconds(10)));
            });

        }

        #endregion

        #region ARoundWithoutATime_HasNoUpstream()

        [Test]
        public void ARoundWithoutATime_HasNoUpstream()
        {

            var verdict = TimeSyncVerdict.From([ Answer("one.example", "192.0.2.2", 1, 1.0) ],
                                               MinServers:    2,
                                               MaxDeviation:  TimeSpan.FromSeconds(60));

            Assert.That(verdict.IsUsable,                                         Is.False);
            Assert.That(TimeServerUpstream.Of(verdict, TimeSpan.FromSeconds(60)), Is.Null);

        }

        #endregion

    }

}
