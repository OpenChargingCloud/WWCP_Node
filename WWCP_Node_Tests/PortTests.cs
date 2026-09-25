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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The ports a node listens on: its own, and those a kind of node takes
    /// beside it - which one could not be had, what it was for, and what the
    /// node lets go of again when one of them cannot.
    /// </summary>
    /// <remarks>
    /// A kind of node may listen on more than the node's port: a charging
    /// station has a display with a server and a port of its own, so that the
    /// screen in the car park and the administration are two sockets that can
    /// be bound to two addresses. Those are taken in OnListening, once the
    /// node's own port is had and before the node calls itself started.
    /// </remarks>
    public class PortTests
    {

        #region Data

        private String directory = "";

        /// <summary>
        /// What the second port of the kind of node below is for.
        /// </summary>
        private static readonly NodePort Display = new ("The display");

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-ports-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

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


        #region (class) NodeWithASecondPort

        /// <summary>
        /// A kind of node that takes a second port beside the node's own - or
        /// finds it taken, and says so the way a charging station's display
        /// does.
        /// </summary>
        private sealed class NodeWithASecondPort(String   Folder,
                                                 IPPort   Port,
                                                 Boolean  SecondPortIsTaken)

            : WWCPNode(HTTPPort:          Port,
                       AccountsPath:      Path.Combine(Folder, "accounts"),
                       ConfigFile:        WithoutTimeClient(Folder),
                       CertificatesPath:  Path.Combine(Folder, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false)

        {

            /// <summary>Whether the node's own port was had by the time the second one was asked for.</summary>
            public Boolean?  OwnPortWasHad    { get; private set; }

            /// <summary>Whether the node called itself started by then.</summary>
            public Boolean?  WasRunningAlready  { get; private set; }

            /// <summary>The port the second server would have had.</summary>
            public IPPort    SecondPort       { get; } = FreePort();

            protected override Task OnListening()
            {

                OwnPortWasHad      = !CanBeHad(HTTPPort);
                WasRunningAlready  = ConfigurationJSON()["http"]?.Value<Boolean>("running");

                if (SecondPortIsTaken)
                    throw new PortUnavailableException(
                              SecondPort,
                              new SocketException((Int32) SocketError.AddressAlreadyInUse),
                              Display
                          );

                return Task.CompletedTask;

            }

        }

        #endregion

        #region (helper) WithoutTimeClient(Directory)

        /// <summary>
        /// A configuration file that switches the time client off, so that a
        /// started node asks no time server anything.
        /// </summary>
        private static WWCPConfigFile WithoutTimeClient(String Directory)
        {

            var path = Path.Combine(Directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(path, """{ "nts": { "enabled": false } }""");

            return new WWCPConfigFile(path);

        }

        #endregion

        #region (helper) FreePort() / CanBeHad(Port)

        private static IPPort FreePort()
        {

            var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();

            var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();

            return IPPort.Parse((UInt16) port);

        }

        /// <summary>
        /// Whether something else could listen on this port of the loopback
        /// address right now.
        /// </summary>
        private static Boolean CanBeHad(IPPort Port)
        {

            var listener = new TcpListener(System.Net.IPAddress.Loopback, Port.ToUInt16());

            try
            {
                listener.Start();
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
            finally
            {
                listener.Stop();
            }

        }

        #endregion


        #region ThePortOfTheNodeIsTheWebInterfaces()

        /// <summary>
        /// The node's own port, when something else is on it: which port, what
        /// it was for, and why not - in a sentence.
        /// </summary>
        [Test]
        public async Task ThePortOfTheNodeIsTheWebInterfaces()
        {

            var taken = new TcpListener(System.Net.IPAddress.Loopback, 0);
            taken.Start();

            try
            {

                var port = IPPort.Parse((UInt16) ((IPEndPoint) taken.LocalEndpoint).Port);

                await using var node = new WWCPNode(
                                           HTTPPort:          port,
                                           AccountsPath:      Path.Combine(directory, "accounts"),
                                           ConfigFile:        WithoutTimeClient(directory),
                                           CertificatesPath:  Path.Combine(directory, "certificates"),
                                           LogToConsole:      false,
                                           BridgeDebugLog:    false
                                       );

                var problem = Assert.ThrowsAsync<PortUnavailableException>(async () => await node.Start())!;

                Assert.Multiple(() => {
                    Assert.That(problem.Port,     Is.EqualTo(port));
                    Assert.That(problem.Whose,    Is.EqualTo(NodePort.WebInterface),  "It did not say what the port was for.");
                    Assert.That(problem.Because,  Is.EqualTo(SocketError.AddressAlreadyInUse));
                    Assert.That(problem.Message,  Does.StartWith($"The web interface could not be given port {port}"));
                });

            }
            finally
            {
                taken.Stop();
            }

        }

        #endregion

        #region APortOfItsKindIsTakenBeforeTheNodeIsStarted()

        /// <summary>
        /// A kind of node takes its own ports once the node's is had, and
        /// before the node calls itself started.
        /// </summary>
        /// <remarks>
        /// Before, because a node that says it is listening - in its log, and
        /// on its Configuration page - and then finds its display's port taken
        /// has said something untrue; and after, so that the kind need not ask
        /// whether the node's own port worked out.
        /// </remarks>
        [Test]
        public async Task APortOfItsKindIsTakenBeforeTheNodeIsStarted()
        {

            await using var node = new NodeWithASecondPort(directory, FreePort(), SecondPortIsTaken: false);

            await node.Start();

            Assert.Multiple(() => {
                Assert.That(node.OwnPortWasHad,      Is.True,   "The kind was asked for its port before the node had its own.");
                Assert.That(node.WasRunningAlready,  Is.False,  "The node called itself started before the kind had its port.");
                Assert.That(node.ConfigurationJSON()["http"]?.Value<Boolean>("running"),  Is.True);
            });

        }

        #endregion

        #region APortOfItsKindThatCannotBeHadLeavesTheNodesOwnFree()

        /// <summary>
        /// When a port of the kind cannot be had, that is what the start ends
        /// with - and the node's own port is let go of again, the node is not
        /// started, and it has not said that it was listening.
        /// </summary>
        /// <remarks>
        /// By the time the display fails, the web interface has been listening
        /// for a moment. A process that is about to end would have it taken
        /// away anyway; a caller that catches this and carries on - a test, or
        /// a node made to try another port - would not.
        /// </remarks>
        [Test]
        public async Task APortOfItsKindThatCannotBeHadLeavesTheNodesOwnFree()
        {

            await using var node = new NodeWithASecondPort(directory, FreePort(), SecondPortIsTaken: true);

            var problem = Assert.ThrowsAsync<PortUnavailableException>(async () => await node.Start())!;

            Assert.Multiple(() => {

                Assert.That(problem.Whose,    Is.EqualTo(Display),          "It did not say which of the two servers wanted it.");
                Assert.That(problem.Port,     Is.EqualTo(node.SecondPort));
                Assert.That(problem.Message,  Does.StartWith("The display could not be given port"));

                Assert.That(CanBeHad(node.HTTPPort),  Is.True,   "The node was still holding its port after the kind could not have one.");

                Assert.That(node.ConfigurationJSON()["http"]?.Value<Boolean>("running"),  Is.False);

                Assert.That(node.Log.Recent(100).Any(entry => entry.Message.Contains("listening on", StringComparison.OrdinalIgnoreCase)),
                            Is.False,
                            "It said it was listening.");

            });

        }

        #endregion

    }

}
