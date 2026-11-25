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
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// "web.requestBodyTimeout": how long the body of one request to the web
    /// interface may take to arrive - five minutes where the file says
    /// nothing, rather than Hermod's 30 seconds, which a part of a file sent
    /// from a browser over a slow line did not make.
    /// </summary>
    public class WebRequestBodyTimeoutTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-web-body-" + Guid.NewGuid().ToString("N")[..12]);
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
            { }
        }

        #endregion


        #region (helpers) Node(Section, ...) / StatusOfASlowBody(Node, Pause)

        private WWCPNode Node(String?            Section     = null,
                              HTTPServer?        HTTPServer  = null,
                              Logging.EventLog?  Log         = null)
        {

            var configFile = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }{{(Section is not null ? $", \"web\": {Section}" : "")}} }""");

            return HTTPServer is null
                       ? new WWCPNode(HTTPPort:          TestKit.TestPorts.Free(),
                                      AccountsPath:      Path.Combine(directory, "accounts"),
                                      ConfigFile:        new WWCPConfigFile(configFile),
                                      CertificatesPath:  Path.Combine(directory, "certificates"),
                                      Log:               Log,
                                      LogToConsole:      false,
                                      BridgeDebugLog:    false,
                                      SSH:               new SSHSettings(OnByDefault: false))
                       : new WWCPNode(HTTPServer:        HTTPServer,
                                      AccountsPath:      Path.Combine(directory, "accounts"),
                                      ConfigFile:        new WWCPConfigFile(configFile),
                                      CertificatesPath:  Path.Combine(directory, "certificates"),
                                      Log:               Log,
                                      LogToConsole:      false,
                                      BridgeDebugLog:    false,
                                      SSH:               new SSHSettings(OnByDefault: false));

        }

        /// <summary>
        /// The status line the node answers a sign-in with whose body stops
        /// half-way for the given pause, or null where it closed the connection
        /// without one.
        /// </summary>
        private static async Task<String?> StatusOfASlowBody(WWCPNode  Node,
                                                            TimeSpan  Pause)
        {

            const String body = "login=nobody&password=nothing";

            using var tcp     = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", Node.HTTPPort.ToUInt16());

            var stream        = tcp.GetStream();

            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                                        "POST /ext/login HTTP/1.1\r\n" +
                                        $"Host: 127.0.0.1:{Node.HTTPPort}\r\n" +
                                        "Content-Type: application/x-www-form-urlencoded\r\n" +
                                        $"Content-Length: {body.Length}\r\n" +
                                        "Connection: close\r\n" +
                                        "\r\n" +
                                        body[..10]));

            await Task.Delay(Pause);

            try
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes(body[10..]));
            }
            catch (IOException)
            { }

            using var reader  = new StreamReader(stream, Encoding.ASCII);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

            try
            {
                return await reader.ReadLineAsync(timeout.Token);
            }
            catch (IOException)
            {
                return null;
            }

        }

        #endregion


        #region TheKeyIsReadWrittenBackAndRefused()

        /// <summary>
        /// Seconds, read as a time span and written back as seconds; nothing
        /// where absent; refused where no number or not between a second and a
        /// day; and the switches' word over the file's.
        /// </summary>
        [Test]
        public void TheKeyIsReadWrittenBackAndRefused()
        {

            Assert.That(WebConfiguration.TryParse(JObject.Parse("""{ "requestBodyTimeout": 600 }"""), out var web, out var error), Is.True, error);

            String? Refusal(String JSON)
                => WebConfiguration.TryParse(JObject.Parse(JSON), out _, out var why) ? null : why;

            Assert.That(WebConfiguration.TryParse(JObject.Parse("{}"), out var empty, out _), Is.True);

            Assert.Multiple(() => {

                Assert.That(web!.RequestBodyTimeout,                           Is.EqualTo(TimeSpan.FromMinutes(10)));
                Assert.That(web.ToJSON()["requestBodyTimeout"]?.Value<Double>(), Is.EqualTo(600));
                Assert.That(empty!.RequestBodyTimeout,                         Is.Null);
                Assert.That(empty.ToJSON().ContainsKey("requestBodyTimeout"),  Is.False);

                Assert.That(Refusal("""{ "requestBodyTimeout": "long" }"""),  Does.Contain("'web.requestBodyTimeout' must be a number of seconds"));
                Assert.That(Refusal("""{ "requestBodyTimeout": 0 }"""),       Does.Contain("'web.requestBodyTimeout' must be between 1 and 86400 seconds"));
                Assert.That(Refusal("""{ "requestBodyTimeout": 86401 }"""),   Does.Contain("'web.requestBodyTimeout' must be between 1 and 86400 seconds"));

                Assert.That(new WebConfiguration(RequestBodyTimeout: TimeSpan.FromSeconds(7)).Over(web).RequestBodyTimeout,  Is.EqualTo(TimeSpan.FromSeconds(7)));
                Assert.That(new WebConfiguration().Over(web).RequestBodyTimeout,                                             Is.EqualTo(TimeSpan.FromMinutes(10)));

            });

        }

        #endregion

        #region FiveMinutesWhereTheFileSaysNothingAndWhatItSaysOtherwise()

        /// <summary>
        /// The web interface's server is given five minutes for a body where
        /// the file says nothing - not Hermod's 30 seconds - and what the file
        /// says otherwise; the Configuration page is told which.
        /// </summary>
        [Test]
        public async Task FiveMinutesWhereTheFileSaysNothingAndWhatItSaysOtherwise()
        {

            await using (var node = Node())
                Assert.That(node.HTTPServer.BodyReadTimeout,  Is.EqualTo(TimeSpan.FromMinutes(5)));

            await using (var node = Node(Section: """{ "requestBodyTimeout": 3600 }"""))
                Assert.That(node.HTTPServer.BodyReadTimeout,  Is.EqualTo(TimeSpan.FromHours(1)));

        }

        #endregion

        #region ABodyIsGivenWhatTheFileSaysAndNoMore()

        /// <summary>
        /// A body that stops half-way for three seconds: answered where it is
        /// given ten, and refused where it is given one.
        /// </summary>
        [Test]
        public async Task ABodyIsGivenWhatTheFileSaysAndNoMore()
        {

            await using (var node = Node(Section: """{ "requestBodyTimeout": 10 }"""))
            {

                await node.Start();

                var status = await StatusOfASlowBody(node, TimeSpan.FromSeconds(3));

                Assert.That(status, Does.StartWith("HTTP/1.1 ").And.Not.Contain(" 408"), "a body within its time is read and answered");

            }

            await using (var node = Node(Section: """{ "requestBodyTimeout": 1 }"""))
            {

                await node.Start();

                var status = await StatusOfASlowBody(node, TimeSpan.FromSeconds(3));

                Assert.That(status is null || status.Contains(" 408"), Is.True, $"a body past its time is refused, and was answered '{status}'");

            }

        }

        #endregion

        #region AServerHandedInKeepsItsOwn()

        /// <summary>
        /// A server handed in keeps how long it gives a body, and the log says
        /// that the file's word is not used.
        /// </summary>
        [Test]
        public async Task AServerHandedInKeepsItsOwn()
        {

            var said    = new List<String>();
            var log     = new Logging.EventLog();
            log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

            var handed  = new HTTPServer(IPAddress:        IPv4Address.Localhost,
                                         TCPPort:          TestKit.TestPorts.Free(),
                                         BodyReadTimeout:  TimeSpan.FromSeconds(42));

            await using (var node = Node(Section: """{ "requestBodyTimeout": 600 }""", HTTPServer: handed, Log: log))
                Assert.That(node.HTTPServer.BodyReadTimeout,  Is.EqualTo(TimeSpan.FromSeconds(42)));

            Assert.That(said, Has.Some.Contains("'web.requestBodyTimeout' is not used: the HTTP server was handed in"));

        }

        #endregion

    }

}
