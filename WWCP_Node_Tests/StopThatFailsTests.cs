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

using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A node whose stopping fails: it says so, and all the same its port is
    /// closed, it is not stopped a second time, and letting go of it lets go
    /// of its log file.
    /// </summary>
    /// <remarks>
    /// What fails here is what a node of a particular kind ends before the
    /// server stops - its <c>OnStopping</c> - which is where a local
    /// controller hangs up on its CSMS and closes its station port.
    /// </remarks>
    [TestFixture]
    public class StopThatFailsTests
    {

        #region Data

        private String                          directory  = default!;
        private readonly List<FailingToStop>    made       = [];

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeTheDirectory()
        {
            directory = Path.Combine(Path.GetTempPath(), $"stop-fails-{Guid.NewGuid().ToString("N")[..12]}");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task LetGoOfEverything()
        {

            foreach (var node in made)
            {
                try
                {
                    await node.DisposeAsync();
                }
                catch (InvalidOperationException)
                {
                    // Its stopping fails; that is what it is for.
                }
            }

            made.Clear();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // A file a node let go of a moment too late; the temporary
                // directory is the system's to clear.
            }

        }

        #endregion


        #region (helper) Started()

        /// <summary>
        /// A node whose stopping fails, started on a fresh port, with a log
        /// file of its own.
        /// </summary>
        private async Task<FailingToStop> Started()
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var here          = Path.Combine(directory, Guid.NewGuid().ToString("N")[..8]);
                var configuration = Path.Combine(here, WWCPConfigFile.DefaultFileName);

                Directory.CreateDirectory(here);
                File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

                return new FailingToStop(
                           HTTPPort:          IPPort.Parse(TestPorts.Free()),
                           AccountsPath:      Path.Combine(here, "accounts"),
                           ConfigFile:        new WWCPConfigFile(configuration),
                           CertificatesPath:  Path.Combine(here, "certificates"),
                           LogPath:           Path.Combine(here, "logs")
                       );

            });

            made.Add(node);

            return node;

        }

        #endregion

        #region (helper) Read(File)

        /// <summary>
        /// What a log file says, read beside whoever may still be writing it.
        /// </summary>
        private static String Read(String File)
        {

            using var stream = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();

        }

        #endregion


        #region AStopThatFailsSaysSoAndStillClosesThePort()

        /// <summary>
        /// The failure reaches whoever stopped the node - and its port is
        /// closed all the same: a station or a browser that comes to it is
        /// refused, and not answered by a node that thinks it has stopped.
        /// </summary>
        [Test]
        public async Task AStopThatFailsSaysSoAndStillClosesThePort()
        {

            var node = await Started();
            var port = node.HTTPPort.ToUInt16();

            Assert.That(async () => await node.Stop(),
                        Throws.InstanceOf<InvalidOperationException>().With.Message.EqualTo(FailingToStop.Why));

            using var client  = new TcpClient();

            var refused = await Assert.CatchAsync<SocketException>(async () => await client.ConnectAsync(System.Net.IPAddress.Loopback, port),
                                                              "the node still listens on its port");

            Assert.That(refused?.SocketErrorCode, Is.EqualTo(SocketError.ConnectionRefused));

        }

        #endregion

        #region ANodeWhoseStopFailedIsNotStoppedAgain()

        /// <summary>
        /// Stopped is stopped, even where stopping failed: a second stop - the
        /// one that letting go of the node does, say - does nothing, and so
        /// cannot fail the same way again.
        /// </summary>
        [Test]
        public async Task ANodeWhoseStopFailedIsNotStoppedAgain()
        {

            var node = await Started();

            Assert.That(async () => await node.Stop(), Throws.InstanceOf<InvalidOperationException>());

            Assert.Multiple(() => {
                Assert.That(async () => await node.Stop(),          Throws.Nothing,  "a second stop started over");
                Assert.That(async () => await node.DisposeAsync(),  Throws.Nothing,  "letting go of a stopped node stopped it again");
                Assert.That(node.Stoppings,                         Is.EqualTo(1),   "what the node ends before the server stops was ended again");
            });

        }

        #endregion

        #region LettingGoOfANodeWhoseStopFailsLetsGoOfItsLogFile()

        /// <summary>
        /// Letting go of a node whose stopping fails says that it failed - and
        /// lets go of the node all the same: nothing logged afterwards reaches
        /// its log file, which is closed.
        /// </summary>
        [Test]
        public async Task LettingGoOfANodeWhoseStopFailsLetsGoOfItsLogFile()
        {

            var node = await Started();

            node.Log.Notice("Written while the node runs.", "test");

            var file = node.LogFile;

            Assert.That(file, Is.Not.Null, "the node wrote no log file");

            Assert.That(async () => await node.DisposeAsync(), Throws.InstanceOf<InvalidOperationException>());

            node.Log.Notice("Written after the node was let go of.", "test");

            var written = Read(file!);

            Assert.Multiple(() => {
                Assert.That(written, Does.Contain    ("Written while the node runs."));
                Assert.That(written, Does.Not.Contain("Written after the node was let go of."),
                            "the log file of a node that was let go of was still written");
            });

        }

        #endregion


        #region (private class) FailingToStop

        /// <summary>
        /// A node of no particular kind whose stopping fails: what it ends
        /// before the server stops throws - and it counts how often it was
        /// asked to.
        /// </summary>
        private sealed class FailingToStop(IPPort          HTTPPort,
                                           String          AccountsPath,
                                           WWCPConfigFile  ConfigFile,
                                           String          CertificatesPath,
                                           String          LogPath)

            : WWCPNode(HTTPPort:          HTTPPort,
                       AccountsPath:      AccountsPath,
                       ConfigFile:        ConfigFile,
                       CertificatesPath:  CertificatesPath,
                       LogToConsole:      false,
                       LogPath:           LogPath,
                       BridgeDebugLog:    false)

        {

            /// <summary>
            /// What its stopping says.
            /// </summary>
            public const String Why = "What this node holds open would not end.";

            /// <summary>
            /// How often it was asked to end what it holds open.
            /// </summary>
            public Int32 Stoppings { get; private set; }

            /// <summary>
            /// The file its log is written to, once something was.
            /// </summary>
            public String? LogFile
                => fileLog?.CurrentFile;

            protected override Task OnStopping()
            {
                Stoppings++;
                return Task.FromException(new InvalidOperationException(Why));
            }

        }

        #endregion

    }

}
