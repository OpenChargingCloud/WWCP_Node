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
    /// A server that is no node - a stub of a peer - whose port somebody else
    /// took before it could bind it is made again on a fresh port, and given
    /// up on only when that happens every time (proposed by the hub, whose
    /// stub OCPI peers had a loop of their own for it).
    /// </summary>
    /// <remarks>
    /// Somebody else is a listener on the port a stub is made on: the way
    /// another test run on the same machine takes it in the gap between Free
    /// letting it go and the stub binding it.
    /// </remarks>
    [TestFixture]
    public class StartedOnAFreshPortTests
    {

        #region Data

        private readonly List<TcpListener> squatters = [];

        #endregion

        #region TearDown

        [TearDown]
        public void LetTheSquattersGo()
        {

            foreach (var squatter in squatters)
                squatter.Stop();

            squatters.Clear();

        }

        #endregion


        #region AStubWhosePortWasTakenIsStartedAgainOnAFreshOne()

        /// <summary>
        /// The first stub is made on a port somebody listens on, and fails to
        /// start; it is let go of, and the next is made on a fresh port.
        /// </summary>
        [Test]
        public async Task AStubWhosePortWasTakenIsStartedAgainOnAFreshOne()
        {

            var taken  = Squatted();
            var made   = new List<Stub>();

            var stub   = await TestPorts.StartedOnAFreshPort(Make:   port => Made(made, made.Count == 0 ? taken : port),
                                                             Start:  stub => stub.Start());

            try
            {
                Assert.Multiple(() => {
                    Assert.That(made,           Has.Count.EqualTo(2));
                    Assert.That(made[0].LetGo,  Is.True,  "the stub on the taken port was let go of");
                    Assert.That(stub,           Is.SameAs(made[1]));
                    Assert.That(stub.Port,      Is.Not.EqualTo(taken));
                    Assert.That(stub.Listening, Is.True);
                });
            }
            finally
            {
                await stub.DisposeAsync();
            }

        }

        #endregion

        #region APortTakenSaidEitherWayIsTriedAgain(Refusal)

        /// <summary>
        /// A port somebody has is said as AddressAlreadyInUse, or - on Windows,
        /// for a port in a range the system keeps for itself - as AccessDenied;
        /// either way the stub is made again on a fresh port.
        /// </summary>
        [TestCase(SocketError.AddressAlreadyInUse)]
        [TestCase(SocketError.AccessDenied)]
        public async Task APortTakenSaidEitherWayIsTriedAgain(SocketError Refusal)
        {

            var made  = new List<Stub>();

            var stub  = await TestPorts.StartedOnAFreshPort(Make:   port => Made(made, port),
                                                            Start:  stub => made.Count == 1 ? throw new SocketException((Int32) Refusal) : stub.Start());

            try
            {
                Assert.Multiple(() => {
                    Assert.That(made,           Has.Count.EqualTo(2));
                    Assert.That(made[0].LetGo,  Is.True);
                    Assert.That(stub,           Is.SameAs(made[1]));
                    Assert.That(stub.Listening, Is.True);
                });
            }
            finally
            {
                await stub.DisposeAsync();
            }

        }

        #endregion

        #region ASocketRefusedForAnotherReasonIsNotTriedAgain()

        /// <summary>
        /// A socket refused for another reason than a port somebody has is not
        /// made again on another port - a fresh port cannot help it - and the
        /// stub is let go of before the refusal stands.
        /// </summary>
        [Test]
        public void ASocketRefusedForAnotherReasonIsNotTriedAgain()
        {

            var made     = new List<Stub>();

            var refused  = Assert.ThrowsAsync<SocketException>(() => TestPorts.StartedOnAFreshPort(Make:   port => Made(made, port),
                                                                                                   Start:  stub => throw new SocketException((Int32) SocketError.NetworkUnreachable)));

            Assert.Multiple(() => {
                Assert.That(refused!.SocketErrorCode,  Is.EqualTo(SocketError.NetworkUnreachable));
                Assert.That(made,                      Has.Count.EqualTo(1));
                Assert.That(made[0].LetGo,             Is.True);
            });

        }

        #endregion

        #region AStubWhosePortsStayTakenIsGivenUpOn()

        /// <summary>
        /// Where the port is taken at every attempt, the refusal stands after
        /// <see cref="TestPorts.StartAttempts"/> of them, and every stub made is
        /// let go of.
        /// </summary>
        [Test]
        public void AStubWhosePortsStayTakenIsGivenUpOn()
        {

            var taken    = Squatted();
            var made     = new List<Stub>();

            var refused  = Assert.ThrowsAsync<SocketException>(() => TestPorts.StartedOnAFreshPort(Make:   port => Made(made, taken),
                                                                                                   Start:  stub => stub.Start()));

            Assert.Multiple(() => {
                Assert.That(made,                           Has.Count.EqualTo(TestPorts.StartAttempts));
                Assert.That(made.All(stub => stub.LetGo),   Is.True);
                Assert.That(refused!.SocketErrorCode,       Is.AnyOf(SocketError.AddressAlreadyInUse, SocketError.AccessDenied));
            });

        }

        #endregion

        #region AStubWhoseStartFailsOtherwiseIsLetGo()

        /// <summary>
        /// A start that fails for another reason than a taken port is not
        /// tried again, and the stub is let go of before the failure stands.
        /// </summary>
        [Test]
        public void AStubWhoseStartFailsOtherwiseIsLetGo()
        {

            var made = new List<Stub>();

            Assert.ThrowsAsync<InvalidOperationException>(() => TestPorts.StartedOnAFreshPort(Make:   port => Made(made, port),
                                                                                              Start:  stub => throw new InvalidOperationException("not today")));

            Assert.Multiple(() => {
                Assert.That(made,           Has.Count.EqualTo(1));
                Assert.That(made[0].LetGo,  Is.True);
            });

        }

        #endregion


        #region (private) Squatted()

        /// <summary>
        /// A port somebody listens on, claimed so that nothing of this run is
        /// handed it.
        /// </summary>
        private UInt16 Squatted()
        {

            var squatter = new TcpListener(IPAddress.Loopback, 0);
            squatter.Start();
            squatters.Add(squatter);

            var port = (UInt16) ((IPEndPoint) squatter.LocalEndpoint).Port;
            TestPorts.TryClaim(port);

            return port;

        }

        #endregion

        #region (private static) Made(Made, Port)

        private static Stub Made(List<Stub> Made, UInt16 Port)
        {
            var stub = new Stub(Port);
            Made.Add(stub);
            return stub;
        }

        #endregion

        #region (private class) Stub

        /// <summary>
        /// A stub of a peer: a listener on the loopback address, bound when it
        /// is started.
        /// </summary>
        private sealed class Stub(UInt16 Port) : IAsyncDisposable
        {

            private TcpListener? listener;

            public UInt16   Port       { get; }  = Port;
            public Boolean  Listening  => listener is not null;
            public Boolean  LetGo      { get; private set; }

            public Task Start()
            {
                var started = new TcpListener(IPAddress.Loopback, Port);
                started.Start();
                listener = started;
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                listener?.Stop();
                LetGo = true;
                return ValueTask.CompletedTask;
            }

        }

        #endregion

    }

}
