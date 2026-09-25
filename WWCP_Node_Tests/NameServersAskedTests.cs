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
using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// How a node asks its name servers when a page wants to know what they
    /// say: one of them on its own, the way the node asks it - and all of
    /// them, which the node asks at once.
    /// </summary>
    /// <remarks>
    /// Measured on a local controller, with name servers that never answer:
    /// one asked on its own, at three seconds and with "max retries = 0",
    /// took 6.2 seconds, because it was asked twice; one configured for TCP
    /// was asked over UDP; and two asked together, at three seconds each,
    /// took 10.0 - the timeout of the client, because the one of each server
    /// was not looked at. Nothing here leaves this machine: the name servers
    /// are sockets on the loopback address that take every question and
    /// answer none.
    /// </remarks>
    public class NameServersAskedTests
    {

        #region Data

        /// <summary>
        /// How long each name server here is given, when it is given its own.
        /// </summary>
        private static readonly TimeSpan OwnTimeout = TimeSpan.FromMilliseconds(400);

        private String directory = "";

        private readonly List<IDisposable> silent = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-dns-asked-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            foreach (var socket in silent)
                socket.Dispose();

            silent.Clear();

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


        #region (helper) SilentNameServer()

        /// <summary>
        /// A name server that takes every question over UDP and answers none,
        /// and the port it is on.
        /// </summary>
        private UdpClient SilentNameServer(out UInt16 Port)
        {

            var socket = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            silent.Add(socket);

            Port = (UInt16) ((IPEndPoint) socket.Client.LocalEndPoint!).Port;

            return socket;

        }

        #endregion

        #region (helper) Node(DNS)

        /// <summary>
        /// A node with the given "dns" section, and with the time client
        /// switched off.
        /// </summary>
        private WWCPNode Node(String DNS)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "dns": {{DNS}}, "nts": { "enabled": false } }""");

            var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();
            var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();

            return new WWCPNode(
                       HTTPPort:          IPPort.Parse((UInt16) port),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Server(Port, Transport = "UDP")

        /// <summary>
        /// One entry of the list of name servers, on the loopback address and
        /// with a timeout of its own.
        /// </summary>
        private static String Server(UInt16 Port, String Transport = "UDP")

            => $$"""{ "address": "127.0.0.1", "port": {{Port}}, "transport": "{{Transport}}", "queryTimeoutSeconds": {{OwnTimeout.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}} }""";

        #endregion


        #region ANameServerOnItsOwnIsAskedOnceWhenTheNodeSaysSo()

        /// <summary>
        /// A node told not to ask again asks a name server on its own once:
        /// its timeout, and not twice its timeout.
        /// </summary>
        [Test]
        public async Task ANameServerOnItsOwnIsAskedOnceWhenTheNodeSaysSo()
        {

            SilentNameServer(out var port);

            await using var node = Node($$"""{ "enabled": true, "servers": [ {{Server(port)}} ], "maxRetries": 0 }""");

            var stopwatch = Stopwatch.StartNew();
            var answer    = await node.ResolveAsync("once.example", Server: 0);
            stopwatch.Stop();

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                Assert.That(stopwatch.Elapsed,            Is.LessThan(OwnTimeout * 1.75),
                            "a name server the node asks once was asked again");
            });

        }

        #endregion

        #region AndAsOftenAsItSays()

        /// <summary>
        /// And one told to ask again asks it again - so that the test above
        /// is about the node's setting, and not about a node that has
        /// stopped trying twice.
        /// </summary>
        [Test]
        public async Task AndAsOftenAsItSays()
        {

            SilentNameServer(out var port);

            await using var node = Node($$"""{ "enabled": true, "servers": [ {{Server(port)}} ], "maxRetries": 1 }""");

            var stopwatch = Stopwatch.StartNew();
            var answer    = await node.ResolveAsync("twice.example", Server: 0);
            stopwatch.Stop();

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                Assert.That(stopwatch.Elapsed,            Is.GreaterThanOrEqualTo(OwnTimeout * 2),
                            "a name server the node asks twice was asked once");
            });

        }

        #endregion

        #region ANameServerOnItsOwnIsAskedOverWhatItIsConfiguredFor()

        /// <summary>
        /// A name server reached over TCP is asked over TCP when it is asked on
        /// its own - and not over UDP, which is what a client made from its
        /// address and port did.
        /// </summary>
        /// <remarks>
        /// Only TCP listens here, on a port TCP chose: a question that arrives
        /// there came over TCP, and one sent over UDP never does. The test used
        /// to listen over UDP as well, on one port for both - and on a Windows
        /// machine that keeps ranges of ports for Hyper-V and WinNAT, the one
        /// protocol was refused the port the other had chosen: 10013 in 2 of
        /// 15 runs, and the other way round in 300 of 300 tries.
        /// </remarks>
        [Test]
        public async Task ANameServerOnItsOwnIsAskedOverWhatItIsConfiguredFor()
        {

            var tcp  = new TcpListener(System.Net.IPAddress.Loopback, 0);

            tcp.Start();

            try
            {

                var port      = (UInt16) ((IPEndPoint) tcp.LocalEndpoint).Port;
                var connected = tcp.AcceptTcpClientAsync();

                await using var node = Node($$"""{ "enabled": true, "servers": [ {{Server(port, "TCP")}} ], "maxRetries": 0 }""");

                var answer = await node.ResolveAsync("tcp.example", Server: 0);

                Assert.Multiple(() => {
                    Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                    Assert.That(connected.IsCompleted,        Is.True,  "the name server was not asked over TCP");
                });

                if (connected.IsCompletedSuccessfully)
                    connected.Result.Dispose();

            }
            finally
            {
                tcp.Stop();
            }

        }

        #endregion

        #region AllNameServersAreAskedAtOnceEachForItsOwnTime()

        /// <summary>
        /// All of them, the way the node resolves anything: at once, and each
        /// for as long as its own timeout says - not the client's, and not one
        /// after another.
        /// </summary>
        /// <remarks>
        /// Three that never answer, at 0.4 seconds each, and a client that
        /// would wait five: one after another would be 1.2 seconds, and the
        /// client's timeout five.
        /// </remarks>
        [Test]
        public async Task AllNameServersAreAskedAtOnceEachForItsOwnTime()
        {

            SilentNameServer(out var first);
            SilentNameServer(out var second);
            SilentNameServer(out var third);

            await using var node = Node($$"""
                                          { "enabled": true,
                                            "servers": [ {{Server(first)}}, {{Server(second)}}, {{Server(third)}} ],
                                            "queryTimeoutSeconds": 5,
                                            "maxRetries": 0,
                                            "useCache": false }
                                          """);

            var stopwatch = Stopwatch.StartNew();
            var answer    = await node.ResolveAsync("together.example");
            stopwatch.Stop();

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                Assert.That(stopwatch.Elapsed,            Is.LessThan(OwnTimeout * 2.5),
                            "the name servers were not asked at once, each for its own time");
            });

        }

        #endregion

    }

}
