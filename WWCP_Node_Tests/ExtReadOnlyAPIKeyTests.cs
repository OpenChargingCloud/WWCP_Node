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
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A read-only API key below "/ext" (POI3-ISSUES.md S37): the HTTPExt API
    /// lets an API key in as its account whatever its rights, so the node
    /// refuses every request there that is not a read and brings such a key,
    /// with 403, as the JSON API does.
    /// </summary>
    [TestFixture]
    public class ExtReadOnlyAPIKeyTests
    {

        #region Data

        private          String          directory  = "";
        private readonly List<WWCPNode>  nodes      = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-ext-read-only-key-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var node in nodes)
            {
                try
                {
                    await node.DisposeAsync();
                }
                catch (Exception)
                { }
            }

            nodes.Clear();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (helpers) Started(Web) / Send(Node, Method, Path, Headers, Body) / KeyOfTheAdministrator(Node, Rights)

        /// <summary>
        /// A node with the JSON API every node has, whose file says the given
        /// "web" section, started on fresh ports.
        /// </summary>
        private async Task<WWCPNode> Started(String Web = "{}")
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var home        = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
                var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

                File.WriteAllText(configFile, $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "web": {{Web}} }""");

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(home, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(configFile),
                                        CertificatesPath:  Path.Combine(home, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false,
                                        SSH:               new SSHSettings(OnByDefault: false));

                _ = new NodeHTTPAPI(made.HTTPServer, made, made.ExtAPI, made.Log);

                return made;

            });

            nodes.Add(node);

            return node;

        }

        /// <summary>
        /// One request to the node, with the given header fields, on a
        /// connection of its own and without a cookie jar.
        /// </summary>
        private static async Task<HttpResponseMessage> Send(WWCPNode                       Node,
                                                            HttpMethod                     Method,
                                                            String                         Path,
                                                            IEnumerable<(String, String)>  Headers,
                                                            HttpContent?                   Body   = null)
        {

            using var handler  = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
            using var client   = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var request  = new HttpRequestMessage(Method, $"http://127.0.0.1:{Node.HTTPPort}/{Path}") { Content = Body };

            foreach (var (name, value) in Headers)
                Assert.That(request.Headers.TryAddWithoutValidation(name, value), Is.True, $"{name}: {value}");

            var response = await client.SendAsync(request);

            await response.Content.LoadIntoBufferAsync();

            return response;

        }

        private static async Task<String?> DescriptionOf(HttpResponseMessage Response)
        {
            try
            {
                return JObject.Parse(await Response.Content.ReadAsStringAsync())["description"]?.Value<String>();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// A new API key of the administrator with the given rights, kept as its
        /// hash; the key itself is what a request presents.
        /// </summary>
        private static async Task<String> KeyOfTheAdministrator(WWCPNode      Node,
                                                                APIKeyRights  Rights)
        {

            var key    = Guid.NewGuid().ToString("N");

            var added  = await Node.ExtAPI.AddAPIKey(new APIKey(APIKey_Id.Parse(key),
                                                                User_Id.Parse(WWCPNode.DefaultAdminUser),
                                                                AccessRights:  Rights,
                                                                Created:       DateTimeOffset.UtcNow).AsKept());

            Assert.That(added.Result, Is.EqualTo(CommandResult.Success), added.Description?.FirstText());

            return key;

        }

        #endregion


        #region AReadOnlyAPIKeyChangesNothingBelowExt()

        /// <summary>
        /// A read-only API key reads below "/ext", but adds no API key and
        /// changes no account there, though the HTTPExt API lets it in as its
        /// account; a key that may write is let through to the route.
        /// </summary>
        [Test]
        public async Task AReadOnlyAPIKeyChangesNothingBelowExt()
        {

            var node       = await Started();
            var readOnly   = await KeyOfTheAdministrator(node, APIKeyRights.ReadOnly);
            var readWrite  = await KeyOfTheAdministrator(node, APIKeyRights.ReadWrite);
            var keys       = node.ExtAPI.APIKeys.Count();

            // A key that may write, which the read-only one would hand itself.
            var another    = new APIKey(APIKey_Id.Parse(Guid.NewGuid().ToString("N")),
                                        User_Id.Parse(WWCPNode.DefaultAdminUser),
                                        AccessRights:  APIKeyRights.ReadWrite,
                                        Created:       DateTimeOffset.UtcNow);

            using var addKey      = await Send(node,
                                               new HttpMethod("ADD"),
                                               $"ext/users/{WWCPNode.DefaultAdminUser}/APIKeys",
                                               [ ("API-Key", readOnly) ],
                                               new StringContent(another.ToJSON().ToString(), Encoding.UTF8, "application/json"));

            using var setUser     = await Send(node,
                                               new HttpMethod("SET"),
                                               $"ext/users/{WWCPNode.DefaultAdminUser}",
                                               [ ("API-Key", readOnly) ],
                                               new StringContent("""{ "name": "Mallory" }""", Encoding.UTF8, "application/json"));

            using var read        = await Send(node,
                                               HttpMethod.Get,
                                               $"ext/users/{WWCPNode.DefaultAdminUser}",
                                               [ ("API-Key", readOnly), ("Accept", "application/json") ]);

            using var byReadWrite = await Send(node,
                                               new HttpMethod("SET"),
                                               $"ext/users/{WWCPNode.DefaultAdminUser}",
                                               [ ("API-Key", readWrite) ],
                                               new StringContent("""{ "name": "Mallory" }""", Encoding.UTF8, "application/json"));

            using (Assert.EnterMultipleScope())
            {
                Assert.That(addKey.     StatusCode,          Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(await DescriptionOf(addKey),     Is.EqualTo(ReadOnlyAPIKeyPipeline.Refusal));
                Assert.That(setUser.    StatusCode,          Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(await DescriptionOf(setUser),    Is.EqualTo(ReadOnlyAPIKeyPipeline.Refusal));
                Assert.That(node.ExtAPI.APIKeys.Count(),     Is.EqualTo(keys), "an API key was added");
                Assert.That(read.       StatusCode,          Is.Not.EqualTo(HttpStatusCode.Forbidden), "a read is no change");
                Assert.That(await DescriptionOf(byReadWrite), Is.Not.EqualTo(ReadOnlyAPIKeyPipeline.Refusal), "a key that may write");
            }

        }

        #endregion

    }

}
