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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a node calls itself in what it says: the name of its kind.
    /// </summary>
    /// <remarks>
    /// Somebody who reads "the clock of this node" in front of a charging
    /// station has to know what a node is to know that it means the station.
    /// A kind of node gives its name for exactly that - "The electric vehicle
    /// is shutting down." - and the node's own sentences say it too: in the
    /// log, and in what a page is told when it asks for something the node
    /// will not do.
    ///
    /// Name resolution and the time client are switched off here, so that
    /// what is asked is refused before anything goes out; the one node that
    /// is started has a port nobody else has.
    /// </remarks>
    public class KindOfNodeTests
    {

        #region Data

        private String directory = "";

        /// <summary>
        /// A charging station, as it says what kind of node it is.
        /// </summary>
        private static readonly NodeKind Station = new ("charging station", "station", "ChargingStation", "ChargingStation", "station");

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-kind-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Kind, Frontend = null, FrontendSecurityHeaders = null)

        /// <summary>
        /// A node of the given kind, with name resolution and the time client
        /// switched off, and the web interface it was handed, if any - served
        /// with the security headers it was handed, if any.
        /// </summary>
        private WWCPNode Node(NodeKind?               Kind,
                              IStaticContentSource?   Frontend                 = null,
                              SecurityHeaderOptions?  FrontendSecurityHeaders  = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            return new WWCPNode(
                       Kind:              Kind,
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       Frontend:          Frontend,
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false,
                       FrontendSecurityHeaders:  FrontendSecurityHeaders
                   );

        }

        #endregion


        #region ItsSentencesNameItsKind()

        /// <summary>
        /// A charging station says "this charging station": when its clock is
        /// not checked, when a name or the time is asked for with nobody to ask,
        /// and when a page empties the list of its name servers.
        /// </summary>
        [Test]
        public async Task ItsSentencesNameItsKind()
        {

            await using var node = await TestPorts.StartedOnFreshPorts(() => Node(Station));

            var resolved  = await node.ResolveAsync("example.org");
            var synced    = await node.SyncTimeAsync();
            var emptied   = node.TryUpdateDNSConfiguration(JObject.Parse("""{ "servers": [] }"""), out var error);
            var said      = node.Log.Recent(500).Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {

                Assert.That(said,                             Has.Some.EqualTo("The clock of this charging station is not being checked: NTS is switched off."));
                Assert.That(resolved.Value<String>("error"),  Is.EqualTo("Name resolution is switched off on this charging station."));
                Assert.That(synced.  Value<String>("error"),  Is.EqualTo("NTS is switched off on this charging station."));
                Assert.That(emptied,                          Is.False);
                Assert.That(error,                            Does.Contain("this charging station"));

                Assert.That(said.Append(resolved.ToString()).Append(synced.ToString()).Append(error ?? ""),
                            Has.None.Contains("this node"),
                            "a sentence still says what the node is rather than what kind it is");

            });

        }

        #endregion

        #region ANodeOfNoParticularKindSaysSo()

        /// <summary>
        /// And a node of no particular kind says "this WWCP node", which is
        /// what it calls itself in its first line too.
        /// </summary>
        [Test]
        public async Task ANodeOfNoParticularKindSaysSo()
        {

            await using var node = Node(null);

            var resolved = await node.ResolveAsync("example.org");

            Assert.That(resolved.Value<String>("error"),  Is.EqualTo("Name resolution is switched off on this WWCP node."));

        }

        #endregion

        #region AWebInterfaceWithNoBundleIsSaidOfANodeOfNoParticularKindToo()

        /// <summary>
        /// A node of no particular kind that is handed a web interface with no
        /// bundle in it says so in its log, as a vehicle or a station does.
        /// </summary>
        /// <remarks>
        /// That sentence is written in the constructor, where "Kind" is the
        /// parameter and not the property - and the parameter is null for a
        /// node of no particular kind. Read from there, the sentence that was
        /// to say what is missing ended the node with a NullReferenceException
        /// before it had a log to say anything in.
        /// </remarks>
        [Test]
        public async Task AWebInterfaceWithNoBundleIsSaidOfANodeOfNoParticularKindToo()
        {

            var empty = Path.Combine(directory, "frontend");

            Directory.CreateDirectory(empty);

            await using var node = Node(null, new FileSystemContentSource(empty));

            Assert.That(node.Log.Recent(100).Where(entry => entry.Level == LogLevel.Error).Select(entry => entry.Message),
                        Has.Some.EndsWith("Build the bundle, or point the WWCP node at a directory that has one."));

        }

        #endregion

        #region AKindSaysWhatItsPagesMayLoad()

        /// <summary>
        /// The pages of the web interface are served with Hermod's strict
        /// security headers - unless the kind of node says what its pages need
        /// on top, as a smartphone does for the tiles of its map: then with
        /// exactly those.
        /// </summary>
        [Test]
        public async Task AKindSaysWhatItsPagesMayLoad()
        {

            var bundle = Path.Combine(directory, "frontend");

            Directory.CreateDirectory(bundle);
            File.WriteAllText(Path.Combine(bundle, "index.html"), "<!DOCTYPE html><title>Node</title>");

            var wider = SecurityHeaderOptions.Default with {
                            ContentSecurityPolicy  = SecurityHeaderOptions.DefaultContentSecurityPolicy.Replace("img-src 'self' data:", "img-src 'self' data: https://tile.example.org"),
                            PermissionsPolicy      = "camera=(), microphone=(), geolocation=(self)"
                        };

            async Task<HttpResponseMessage> PageOf(SecurityHeaderOptions? Headers)
            {

                await using var node = await TestPorts.StartedOnFreshPorts(() => Node(Station, new FileSystemContentSource(bundle), Headers));

                using var client = new HttpClient();

                return await client.GetAsync($"http://127.0.0.1:{node.HTTPPort}/");

            }

            var strict  = await PageOf(null);
            var said    = await PageOf(wider);

            static String HeaderOf(HttpResponseMessage Response, String Name)
                => Response.Headers.TryGetValues(Name, out var values) ? String.Join(", ", values) : "";

            Assert.Multiple(() => {

                Assert.That(strict.StatusCode,                              Is.EqualTo(HttpStatusCode.OK));
                Assert.That(HeaderOf(strict, "Content-Security-Policy"),    Is.EqualTo(SecurityHeaderOptions.DefaultContentSecurityPolicy));
                Assert.That(HeaderOf(strict, "Permissions-Policy"),         Does.Contain("geolocation=()"));

                Assert.That(said.StatusCode,                                Is.EqualTo(HttpStatusCode.OK));
                Assert.That(HeaderOf(said,   "Content-Security-Policy"),    Does.Contain("img-src 'self' data: https://tile.example.org;"));
                Assert.That(HeaderOf(said,   "Content-Security-Policy"),    Does.Contain("style-src 'self';"), "a kind widening one source widened another");
                Assert.That(HeaderOf(said,   "Permissions-Policy"),         Does.Contain("geolocation=(self)"));

            });

        }

        #endregion

    }

}
