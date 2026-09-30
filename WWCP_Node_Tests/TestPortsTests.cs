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
    /// make up: ports below 32768, which neither Linux nor Windows hands to
    /// anybody who asks for any free port, and which no other test of this run
    /// is given. A statistical test of a few thousand real ports is not one to
    /// run on a machine other test runs share: it would take their ports away.
    /// </remarks>
    [TestFixture]
    public class TestPortsTests
    {

        #region APortIsHandedOutOnce()

        /// <summary>
        /// Offered a port it has handed out already, the kit asks again.
        /// </summary>
        [Test]
        public void APortIsHandedOutOnce()
        {

            var offers  = new Queue<UInt16>([ 5000, 5000, 5001 ]);

            var first   = TestPorts.Take(offers.Dequeue);
            var second  = TestPorts.Take(offers.Dequeue);

            Assert.Multiple(() => {
                Assert.That(first,         Is.EqualTo(5000));
                Assert.That(second,        Is.EqualTo(5001),  "5000 was handed out twice");
                Assert.That(offers.Count,  Is.Zero,           "the kit did not ask again");
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
        /// An offer that never makes anything but ports handed out already is
        /// given up on after so many attempts, with a sentence - rather than
        /// asked for ever.
        /// </summary>
        [Test]
        public void AnOfferOfNothingButPortsHandedOutIsGivenUpOnWithASentence()
        {

            var asked = 0;

            Assert.That(TestPorts.Take(() => 5002), Is.EqualTo(5002));

            var problem = Assert.Throws<InvalidOperationException>(() => TestPorts.Take(() => { asked++; return 5002; }));

            Assert.Multiple(() => {
                Assert.That(asked,             Is.EqualTo(TestPorts.MaxAttempts));
                Assert.That(problem?.Message,  Is.EqualTo($"{TestPorts.MaxAttempts} ports were offered, and this test run had been handed every one of them already."));
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

            var taken     = TestPorts.Take(Offer:   () => {
                                                        var next = offered.Dequeue();
                                                        events.Add($"offered {next.Name}");
                                                        return next;
                                                    },
                                           PortOf:  offer => offer.Port,
                                           LetGo:   offer => events.Add($"let go of {offer.Name}"));

            Assert.Multiple(() => {
                Assert.That(taken.Port,  Is.EqualTo(5004));
                Assert.That(events,      Is.EqualTo(new[] { "offered turned down", "offered taken", "let go of turned down" }));
            });

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
            var port  = TestPorts.Free(Listening: () => {

                                                      if (++asked < 3)
                                                          throw new SocketException((Int32) SocketError.NoBufferSpaceAvailable);

                                                      var listener = new TcpListener(IPAddress.Loopback, 0);
                                                      listener.Start();
                                                      return listener;

                                                  },
                                       Pause:     TimeSpan.Zero);

            Assert.Multiple(() => {
                Assert.That(port,                     Is.GreaterThan(0));
                Assert.That(asked,                    Is.GreaterThanOrEqualTo(3));
                Assert.That(TestPorts.TryClaim(port), Is.False, "handed out, and so claimed");
            });

        }

        #endregion

    }

}
