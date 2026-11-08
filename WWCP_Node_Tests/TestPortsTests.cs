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
using System.Net.Sockets;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// How the kit hands out ports: none twice in a test run.
    /// </summary>
    /// <remarks>
    /// The operating system hands one out twice, and a test run that asks a
    /// thousand times on Linux is given the same one again and again - a
    /// charging station's setup was stopped by it, told that its display and
    /// its web interface would both listen on 127.0.0.1:36729. What it offers
    /// cannot be arranged here, so the taking is asked with offers the tests
    /// make up: ports below 20000, which neither Linux nor Windows hands to
    /// anybody who asks for any free port, nor the kit where it looks for one
    /// elsewhere, and which no other test of this run is given. A statistical test of a few thousand real ports is not one to
    /// run on a machine other test runs share: it would take their ports away.
    /// Where it matters what somebody else holds, the test holds a real port
    /// of its own.
    /// </remarks>
    [TestFixture]
    public class TestPortsTests
    {

        #region APortIsHandedOutOnce()

        /// <summary>
        /// Offered a port it has handed out already, the kit looks for one
        /// elsewhere.
        /// </summary>
        [Test]
        public void APortIsHandedOutOnce()
        {

            var elsewhere  = new Queue<UInt16>([ 5001 ]);

            var first      = TestPorts.Take(Bound:      port => port is 0 ? (UInt16) 5000 : port,
                                            Elsewhere:  elsewhere.Dequeue);

            var second     = TestPorts.Take(Bound:      port => port is 0 ? (UInt16) 5000 : port,
                                            Elsewhere:  elsewhere.Dequeue);

            Assert.Multiple(() => {
                Assert.That(first,            Is.EqualTo(5000));
                Assert.That(second,           Is.EqualTo(5001),  "5000 was handed out twice");
                Assert.That(elsewhere.Count,  Is.Zero,           "the kit did not look elsewhere");
            });

        }

        #endregion

        #region AFreePortCannotBeClaimedAgain()

        /// <summary>
        /// A port handed out as free is claimed with it: a helper that binds a
        /// port of its own is told that this one is somebody else's.
        /// </summary>
        [Test]
        public void AFreePortCannotBeClaimedAgain()
        {

            var port = TestPorts.Free();

            Assert.That(TestPorts.TryClaim(port),  Is.False);

        }

        #endregion

        #region AnOfferOfNothingButPortsHandedOutIsGivenUpOnWithASentence()

        /// <summary>
        /// Where nothing but ports handed out already is found, the kit gives up
        /// after so many attempts, with a sentence - rather than looking for
        /// ever.
        /// </summary>
        [Test]
        public void AnOfferOfNothingButPortsHandedOutIsGivenUpOnWithASentence()
        {

            var asked = 0;

            Assert.That(TestPorts.Take(Bound: port => (UInt16) 5002, Elsewhere: () => 5002), Is.EqualTo(5002));

            var problem = Assert.Throws<InvalidOperationException>(() => TestPorts.Take(Bound:      port => { asked++; return (UInt16) 5002; },
                                                                                        Elsewhere:  () => 5002));

            Assert.Multiple(() => {
                Assert.That(asked,             Is.EqualTo(TestPorts.MaxAttempts));
                Assert.That(problem?.Message,  Is.EqualTo($"{TestPorts.MaxAttempts} ports were tried, and every one of them had been handed out in this test run already or was held by somebody else."));
            });

        }

        #endregion

        #region WhatIsTurnedDownIsHeldUntilSomethingIsTaken()

        /// <summary>
        /// What is turned down is let go of - once something has been taken, and
        /// not before: let go of at once, it would be the very port the
        /// operating system offers next. What is taken is not let go of.
        /// </summary>
        [Test]
        public void WhatIsTurnedDownIsHeldUntilSomethingIsTaken()
        {

            Assert.That(TestPorts.TryClaim(5003), Is.True, "the test's own premise");

            var offered   = new Queue<(UInt16 Port, String Name)>([ (5003, "turned down"), (5004, "taken") ]);
            var events    = new List<String>();

            var taken     = TestPorts.Take(Bound:      port => {
                                                           var next = offered.Dequeue();
                                                           events.Add($"offered {next.Name}");
                                                           return next;
                                                       },
                                           PortOf:     offer => offer.Port,
                                           LetGo:      offer => events.Add($"let go of {offer.Name}"),
                                           Elsewhere:  () => 5004);

            Assert.Multiple(() => {
                Assert.That(taken.Port,  Is.EqualTo(5004));
                Assert.That(events,      Is.EqualTo(new[] { "offered turned down", "offered taken", "let go of turned down" }));
            });

        }

        #endregion

        #region AStretchOfPortsHandedOutIsNoDeadEnd()

        /// <summary>
        /// Where the operating system's offers have come round to a stretch of
        /// ports handed out already - longer than the kit tries ports - a port
        /// is found all the same, elsewhere. Windows offers the next port up at
        /// each bind to port 0: asked again and again, it offered a hundred
        /// ports in a row that a charging station's test run had been handed.
        /// </summary>
        [Test]
        public void AStretchOfPortsHandedOutIsNoDeadEnd()
        {

            for (var port = 6000; port < 6000 + 2 * TestPorts.MaxAttempts; port++)
                Assert.That(TestPorts.TryClaim((UInt16) port), Is.True, "the test's own premise");

            var next   = (UInt16) 6000;

            var taken  = TestPorts.Take(Bound:      port => port is 0 ? next++ : port,
                                        Elsewhere:  () => 7000);

            Assert.Multiple(() => {
                Assert.That(taken,  Is.EqualTo(7000));
                Assert.That(next,   Is.EqualTo(6001),  "the operating system is asked once");
            });

        }

        #endregion

        #region APortSomebodyElseHoldsIsPassedOver()

        /// <summary>
        /// A port looked for elsewhere that somebody else holds, or that may not
        /// be bound at all - Windows keeps ranges of the dynamic ports for
        /// itself, and says AccessDenied of them - is passed over.
        /// </summary>
        [Test]
        public void APortSomebodyElseHoldsIsPassedOver()
        {

            Assert.That(TestPorts.TryClaim(5005), Is.True, "the test's own premise");

            var elsewhere  = new Queue<UInt16>([ 7001, 7002, 7003 ]);

            var taken      = TestPorts.Take(Bound:      port => port switch {
                                                                    0     => 5005,
                                                                    7001  => throw new SocketException((Int32) SocketError.AddressAlreadyInUse),
                                                                    7002  => throw new SocketException((Int32) SocketError.AccessDenied),
                                                                    _     => port
                                                                },
                                            Elsewhere:  elsewhere.Dequeue);

            Assert.Multiple(() => {
                Assert.That(taken,            Is.EqualTo(7003));
                Assert.That(elsewhere.Count,  Is.Zero);
            });

        }

        #endregion

        #region AnyOtherRefusalOfAPortElsewhereStands()

        /// <summary>
        /// Any other refusal of a port looked for elsewhere stands: passing over
        /// is for a port somebody has.
        /// </summary>
        [Test]
        public void AnyOtherRefusalOfAPortElsewhereStands()
        {

            Assert.That(TestPorts.TryClaim(5006), Is.True, "the test's own premise");

            var refused = Assert.Throws<SocketException>(() => TestPorts.Take(Bound:      port => port is 0
                                                                                                      ? (UInt16) 5006
                                                                                                      : throw new SocketException((Int32) SocketError.AddressNotAvailable),
                                                                              Elsewhere:  () => 7004));

            Assert.That(refused!.SocketErrorCode, Is.EqualTo(SocketError.AddressNotAvailable));

        }

        #endregion

        #region ElsewhereIsAPortThisRunHasNotBeenHanded()

        /// <summary>
        /// A port is looked for elsewhere among those this test run has not been
        /// handed.
        /// </summary>
        [Test]
        public void ElsewhereIsAPortThisRunHasNotBeenHanded()
        {

            Assert.That(TestPorts.TryClaim(5007), Is.True, "the test's own premise");

            var picks = new Queue<UInt16>([ 5007, 5008 ]);

            Assert.Multiple(() => {
                Assert.That(TestPorts.Unclaimed(picks.Dequeue),  Is.EqualTo(5008));
                Assert.That(picks.Count,                         Is.Zero);
            });

        }

        #endregion

        #region ElsewhereIsBelowTheDynamicPorts()

        /// <summary>
        /// A port is looked for elsewhere below the dynamic ports of Windows and
        /// of Linux, where neither takes the local port of an outgoing
        /// connection from: from <see cref="TestPorts.LowestPortElsewhere"/> to
        /// <see cref="TestPorts.HighestPortElsewhere"/>, below 32768.
        /// </summary>
        [Test]
        public void ElsewhereIsBelowTheDynamicPorts()
        {

            var picked = Enumerable.Range(0, 1000).Select(_ => TestPorts.APortElsewhere()).ToArray();

            Assert.Multiple(() => {
                Assert.That(picked,                          Is.All.InRange(TestPorts.LowestPortElsewhere, TestPorts.HighestPortElsewhere));
                Assert.That(picked,                          Is.All.LessThan(32768));
            });

        }

        #endregion

        #region APortSomebodyListensOnForEveryAddressIsPassedOver()

        /// <summary>
        /// A port looked for elsewhere that somebody listens on for every
        /// address - on 0.0.0.0, next to which Windows binds a listener on
        /// 127.0.0.1 - is passed over, and another one taken: a port is tried
        /// as a <see cref="ClosedPort"/> holds its own.
        /// </summary>
        [Test]
        public void APortSomebodyListensOnForEveryAddressIsPassedOver()
        {

            var handedOut  = TestPorts.Free();

            var somebody   = new TcpListener(IPAddress.Any, 0);
            somebody.Start();

            try
            {

                var held       = (UInt16) ((IPEndPoint) somebody.LocalEndpoint).Port;
                var elsewhere  = new List<UInt16>();

                var port       = TestPorts.Free(Holding:    number => ClosedPort.Bind(number is 0 ? handedOut : number, Exclusively: true),
                                                Pause:      TimeSpan.Zero,
                                                Elsewhere:  () => {
                                                                var next = elsewhere.Count == 0
                                                                               ? held
                                                                               : TestPorts.Unclaimed(TestPorts.APortElsewhere);
                                                                elsewhere.Add(next);
                                                                return next;
                                                            });

                Assert.Multiple(() => {
                    Assert.That(elsewhere[0],              Is.EqualTo(held),       "the port somebody listens on was not looked at");
                    Assert.That(port,                      Is.Not.EqualTo(held),   "a port somebody listens on was handed out");
                    Assert.That(port,                      Is.EqualTo(elsewhere[^1]));
                    Assert.That(TestPorts.TryClaim(port),  Is.False,               "handed out, and so claimed");
                });

            }
            finally
            {
                somebody.Stop();
            }

        }

        #endregion


        #region NoRoomForASocketIsAskedAgain()

        /// <summary>
        /// Where the operating system has no buffer space left for a socket -
        /// WSAENOBUFS, 10055 - the socket is asked for again: the charging
        /// station's run of this suite lost a test in its set-up at Free that
        /// way, while the whole suites of other runs filled the machine.
        /// </summary>
        [Test]
        public void NoRoomForASocketIsAskedAgain()
        {

            var asked = 0;
            var made  = TestPorts.OnceThereIsRoom(() => ++asked < 3 ? throw new SocketException((Int32) SocketError.NoBufferSpaceAvailable) : "a socket",
                                                  TimeSpan.Zero);

            Assert.Multiple(() => {
                Assert.That(made,   Is.EqualTo("a socket"));
                Assert.That(asked,  Is.EqualTo(3));
            });

        }

        #endregion

        #region NoRoomEveryTimeStands()

        /// <summary>
        /// Where there is no room every time, the refusal stands after
        /// <see cref="TestPorts.RoomAttempts"/> attempts.
        /// </summary>
        [Test]
        public void NoRoomEveryTimeStands()
        {

            var asked   = 0;
            var waited  = new List<TimeSpan>();
            var full    = Assert.Throws<SocketException>(() => TestPorts.OnceThereIsRoom<String>(() => { asked++; throw new SocketException((Int32) SocketError.NoBufferSpaceAvailable); },
                                                                                               TimeSpan.FromMilliseconds(200),
                                                                                               waited.Add));

            Assert.Multiple(() => {
                Assert.That(full!.SocketErrorCode,  Is.EqualTo(SocketError.NoBufferSpaceAvailable));
                Assert.That(asked,                  Is.EqualTo(TestPorts.RoomAttempts));
                Assert.That(waited.Select(pause => pause.TotalMilliseconds),
                            Is.EqualTo(Enumerable.Range(1, TestPorts.RoomAttempts - 1).Select(attempt => 200.0 * attempt)),
                            "each pause longer than the one before, as the room comes back, and none after the last");
            });

        }

        #endregion

        #region AnyOtherRefusalStandsAtOnce()

        /// <summary>
        /// Any other refusal of a socket stands at once: asking again is for a
        /// machine short of room, not for a port somebody has.
        /// </summary>
        [Test]
        public void AnyOtherRefusalStandsAtOnce()
        {

            var asked = 0;
            var taken = Assert.Throws<SocketException>(() => TestPorts.OnceThereIsRoom<String>(() => { asked++; throw new SocketException((Int32) SocketError.AddressAlreadyInUse); },
                                                                                              TimeSpan.Zero));

            Assert.Multiple(() => {
                Assert.That(taken!.SocketErrorCode,  Is.EqualTo(SocketError.AddressAlreadyInUse));
                Assert.That(asked,                   Is.EqualTo(1));
            });

        }

        #endregion

        #region AFreePortOutlastsNoRoom()

        /// <summary>
        /// Free hands out a port where the first listeners it asked for found
        /// no room.
        /// </summary>
        [Test]
        public void AFreePortOutlastsNoRoom()
        {

            var asked = 0;
            var port  = TestPorts.Free(Holding:    number => {

                                                       if (++asked < 3)
                                                           throw new SocketException((Int32) SocketError.NoBufferSpaceAvailable);

                                                       return ClosedPort.Bind(number, Exclusively: true);

                                                   },
                                       Pause:      TimeSpan.Zero,
                                       Elsewhere:  null);

            Assert.Multiple(() => {
                Assert.That(port,                     Is.GreaterThan(0));
                Assert.That(asked,                    Is.GreaterThanOrEqualTo(3));
                Assert.That(TestPorts.TryClaim(port), Is.False, "handed out, and so claimed");
            });

        }

        #endregion

    }

}
