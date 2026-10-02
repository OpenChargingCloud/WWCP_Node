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
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

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
        /// <remarks>
        /// Under the second after which Hermod's UDP client sends a question
        /// again within one try (DNSUDPClient.DefaultRetransmissionInterval):
        /// each try is one question, so the questions a name server counts are
        /// the tries. Given ten seconds, each try was four.
        /// </remarks>
        private static readonly TimeSpan OwnTimeout = TimeSpan.FromMilliseconds(400);

        private String directory = "";

        private readonly List<IDisposable> nameServers = [];

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

            foreach (var socket in nameServers)
                socket.Dispose();

            nameServers.Clear();

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

            nameServers.Add(socket);

            Port = (UInt16) ((IPEndPoint) socket.Client.LocalEndPoint!).Port;

            return socket;

        }

        #endregion

        #region (helper) AnsweringNameServer(out Port)

        /// <summary>
        /// A name server that answers every question over UDP at once, and
        /// always the same: there is no record of that name and type (NOERROR,
        /// and no answers).
        /// </summary>
        /// <remarks>
        /// The answer is the question turned round: its ID, the QR bit and
        /// recursion available set, the question section as it came, and
        /// nothing after it - no answers, and none of the additional records
        /// the question carried, its cookie among them (RFC 1035, section
        /// 4.1.1; a server that knows no cookies answers without one, RFC 7873,
        /// section 5.2.1).
        /// </remarks>
        private void AnsweringNameServer(out UInt16 Port)
        {

            var socket = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            nameServers.Add(socket);

            Port = (UInt16) ((IPEndPoint) socket.Client.LocalEndPoint!).Port;

            _ = Task.Run(async () => {

                try
                {
                    while (true)
                    {

                        var question = await socket.ReceiveAsync();
                        var bytes    = question.Buffer;
                        var at       = 12;

                        while (bytes[at] != 0)
                            at += bytes[at] + 1;

                        // The empty label, the type and the class end the question.
                        var answer   = bytes[..(at + 5)];

                        answer[2]    = (Byte) (0x80 | (bytes[2] & 0x01));   // QR, a standard query, RD as asked
                        answer[3]    = 0x80;                                // RA, NOERROR
                        answer[6]    = answer[7]  = 0;                      // no answers,
                        answer[8]    = answer[9]  = 0;                      // no authorities,
                        answer[10]   = answer[11] = 0;                      // no additional records

                        await socket.SendAsync(answer, answer.Length, question.RemoteEndPoint);

                    }
                }
                catch (Exception)
                {
                    // The socket was closed at the end of the test.
                }

            });

        }

        #endregion

        #region (helper) QuestionsAsked(NameServer)

        /// <summary>
        /// What a silent name server was asked, by record type and how often:
        /// "A: 1, AAAA: 1".
        /// </summary>
        /// <remarks>
        /// Every question is sent before the node gives up waiting for its
        /// answer. They are read until none has come for a quarter of a
        /// second, which only makes sure that one still on its way through the
        /// loopback interface is counted as well.
        /// </remarks>
        private static async Task<String> QuestionsAsked(UdpClient NameServer)
        {

            var asked = new SortedDictionary<DNSResourceRecordTypes, Int32>();

            while (true)
            {

                using var quiet = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

                Byte[] question;

                try
                {
                    question = (await NameServer.ReceiveAsync(quiet.Token)).Buffer;
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                // Twelve bytes of header, then the name asked for, label by
                // label up to the empty one, then its type (RFC 1035, sections
                // 4.1.1 and 4.1.2).
                var at = 12;

                while (question[at] != 0)
                    at += question[at] + 1;

                var type = (DNSResourceRecordTypes) ((question[at + 1] << 8) | question[at + 2]);

                asked[type] = asked.GetValueOrDefault(type) + 1;

            }

            return String.Join(", ", asked.Select(count => $"{count.Key}: {count.Value}"));

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

            return new WWCPNode(
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Server(Port, Transport = "UDP", Timeout = null)

        /// <summary>
        /// One entry of the list of name servers, on the loopback address and
        /// with a timeout of its own: the one given, or else OwnTimeout.
        /// </summary>
        private static String Server(UInt16 Port, String Transport = "UDP", TimeSpan? Timeout = null)

            => $$"""{ "address": "127.0.0.1", "port": {{Port}}, "transport": "{{Transport}}", "queryTimeoutSeconds": {{(Timeout ?? OwnTimeout).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}} }""";

        #endregion


        #region ANameServerOnItsOwnIsAskedOnceWhenTheNodeSaysSo()

        /// <summary>
        /// A node told not to ask again asks a name server on its own once:
        /// one question for each record type, and not two.
        /// </summary>
        /// <remarks>
        /// Counted at the name server, not timed. Taken against 1.75 times the
        /// server's timeout, the test failed after 1.94 seconds in a nightly
        /// that ran every test project of its solution at once, saying the
        /// node had asked again. With the thread pool held up the same way
        /// here, it failed 3 times in 3 runs, where counting finds one A and
        /// one AAAA every time.
        /// </remarks>
        [Test]
        public async Task ANameServerOnItsOwnIsAskedOnceWhenTheNodeSaysSo()
        {

            var nameServer = SilentNameServer(out var port);

            await using var node = Node($$"""{ "enabled": true, "servers": [ {{Server(port)}} ], "maxRetries": 0 }""");

            var answer = await node.ResolveAsync("once.example", Server: 0);
            var asked  = await QuestionsAsked(nameServer);

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                Assert.That(asked,                        Is.EqualTo("A: 1, AAAA: 1"),
                            "a name server the node asks once was not asked once for each record type");
            });

        }

        #endregion

        #region AndAsOftenAsItSays()

        /// <summary>
        /// And one told to ask again asks it again, two questions for each
        /// record type - so that the test above is about the node's setting,
        /// and not about a node that has stopped trying twice.
        /// </summary>
        [Test]
        public async Task AndAsOftenAsItSays()
        {

            var nameServer = SilentNameServer(out var port);

            await using var node = Node($$"""{ "enabled": true, "servers": [ {{Server(port)}} ], "maxRetries": 1 }""");

            var answer = await node.ResolveAsync("twice.example", Server: 0);
            var asked  = await QuestionsAsked(nameServer);

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                Assert.That(asked,                        Is.EqualTo("A: 2, AAAA: 2"),
                            "a name server the node asks twice was not asked twice for each record type");
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

        #region AllNameServersAreAskedAtOnce()

        /// <summary>
        /// All of them, the way the node resolves anything: at once, and not
        /// one after another - the last is asked while the first are still
        /// being waited for.
        /// </summary>
        /// <remarks>
        /// Two that never answer, at twenty seconds each, and after them one
        /// that answers at once. Asked one after another, the third would be
        /// asked after forty seconds; asked at once, its answer is the first
        /// thing there, and the node does not wait for the other two.
        /// </remarks>
        [Test]
        public async Task AllNameServersAreAskedAtOnce()
        {

            SilentNameServer   (out var first);
            SilentNameServer   (out var second);
            AnsweringNameServer(out var third);

            var waited = TimeSpan.FromSeconds(20);

            await using var node = Node($$"""
                                          { "enabled": true,
                                            "servers": [ {{Server(first, Timeout: waited)}}, {{Server(second, Timeout: waited)}}, {{Server(third, Timeout: waited)}} ],
                                            "maxRetries": 0,
                                            "useCache": false }
                                          """);

            var stopwatch = Stopwatch.StartNew();
            var answer    = await node.ResolveAsync("together.example");
            stopwatch.Stop();

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),     Is.True);
                Assert.That(answer.Value<String>("server"),  Does.StartWith($"udp://127.0.0.1:{third},"));
                Assert.That(stopwatch.Elapsed,               Is.LessThan(waited / 2),
                            "the name servers were not asked at once");
            });

        }

        #endregion

        #region EachForItsOwnTime()

        /// <summary>
        /// And each for as long as its own timeout says - not the client's.
        /// </summary>
        /// <remarks>
        /// Three that never answer, at 0.4 seconds each, and a client that
        /// would wait ten: each is asked once for each record type, and the
        /// node has its answer long before the client's timeout. Together with
        /// "at once", this was one test that took the node's answer against 2.5
        /// times the servers' timeout, and with the thread pool held up by
        /// sleepers it failed in 6 of 7 runs.
        /// </remarks>
        [Test]
        public async Task EachForItsOwnTime()
        {

            var first  = SilentNameServer(out var firstPort);
            var second = SilentNameServer(out var secondPort);
            var third  = SilentNameServer(out var thirdPort);

            await using var node = Node($$"""
                                          { "enabled": true,
                                            "servers": [ {{Server(firstPort)}}, {{Server(secondPort)}}, {{Server(thirdPort)}} ],
                                            "queryTimeoutSeconds": 10,
                                            "maxRetries": 0,
                                            "useCache": false }
                                          """);

            var stopwatch = Stopwatch.StartNew();
            var answer    = await node.ResolveAsync("together.example");
            stopwatch.Stop();

            var asked     = new[] { await QuestionsAsked(first), await QuestionsAsked(second), await QuestionsAsked(third) };

            Assert.Multiple(() => {
                Assert.That(answer.Value<Boolean>("ok"),  Is.False);
                Assert.That(asked,                        Is.All.EqualTo("A: 1, AAAA: 1"),
                            "not every name server was asked once for each record type");
                Assert.That(stopwatch.Elapsed,            Is.LessThan(TimeSpan.FromSeconds(5)),
                            "the name servers were given the client's time, not their own");
            });

        }

        #endregion

    }

}
