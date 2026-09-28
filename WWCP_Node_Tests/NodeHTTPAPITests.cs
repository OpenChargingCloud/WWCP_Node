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
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The JSON API every node has, asked of a node of no particular kind:
    /// where it differed between the eight copies it replaces, and what a kind
    /// of node says through it.
    /// </summary>
    /// <remarks>
    /// What it answers otherwise is asked of every kind through its own suite -
    /// the local controller's ran unchanged against it.
    /// </remarks>
    public class NodeHTTPAPITests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-api-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (class) TestNode / TestAPI

        /// <summary>
        /// A node that says what a kind of node says: a certificate it uses,
        /// and what its store's answer adds.
        /// </summary>
        private sealed class TestNode(IPPort          Port,
                                      String          Here,
                                      WWCPConfigFile  File)

            : WWCPNode(HTTPPort:          Port,
                       AccountsPath:      Path.Combine(Here, "accounts"),
                       ConfigFile:        File,
                       CertificatesPath:  Path.Combine(Here, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false)

        {

            public String?   Used  { get; set; }

            public TestAPI?  API   { get; set; }

            protected override void CompleteCertificatesJSON(JObject JSON)
                => JSON["chosen"] = new JObject(new JProperty("forTheTest", Used));

            public override String? WhatUses(String Handle)
                => Used is not null && Handle.Equals(Used, StringComparison.OrdinalIgnoreCase)
                       ? "The test uses that certificate."
                       : null;

        }

        /// <summary>
        /// The API of a kind of node that adds to the status, and that asks more
        /// for its clock and its log than a sign-in.
        /// </summary>
        private sealed class TestAPI(WWCPNode     TheNode,
                                     Permission?  ClockNeeds,
                                     Permission?  LogNeeds)

            : NodeHTTPAPI(TheNode.HTTPServer, TheNode, TheNode.ExtAPI, TheNode.Log)

        {

            protected override IEnumerable<JProperty> ProductStatus()
            {
                yield return new JProperty("testedAs", "a kind of node");
            }

            protected override Permission? ToReadTheClock  => ClockNeeds;
            protected override Permission? ToReadTheLog    => LogNeeds;

        }

        #endregion

        #region (helpers) FreePort() / Started(Clock, Log) / Client(...) / Send(...)

        private static IPPort FreePort()
        {

            var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();

            var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();

            return IPPort.Parse((UInt16) port);

        }

        /// <summary>
        /// A node with the API of a kind of node, started - on a port nobody
        /// else has, and without asking a time server.
        /// </summary>
        private async Task<TestNode> Started(Permission? Clock = null, Permission? Log = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "nts": { "enabled": false } }""");

            var node = new TestNode(FreePort(), directory, new WWCPConfigFile(configuration));

            node.API = new TestAPI(node, Clock, Log);

            await node.Start();

            return node;

        }

        /// <summary>
        /// A client that says who it is with a password, as a script does.
        /// </summary>
        private static HttpClient Client(WWCPNode Node, String? Login = null, String? Password = null)
        {

            var client = new HttpClient { BaseAddress = new Uri(Node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            if (Login is not null)
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                                 "Basic",
                                                                 Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Login}:{Password}"))
                                                             );

            return client;

        }

        private static HttpClient Root(WWCPNode Node)
            => Client(Node, "root", Node.GeneratedPassword);

        private static async Task<(HttpStatusCode Status, JObject JSON)> Send(HttpClient  HTTP,
                                                                             HttpMethod  Method,
                                                                             String      Path,
                                                                             JObject?    JSON = null)
        {

            using var request   = new HttpRequestMessage(Method, Path);

            if (JSON is not null)
                request.Content = new StringContent(JSON.ToString(), Encoding.UTF8, "application/json");

            using var response  = await HTTP.SendAsync(request);
            var text            = await response.Content.ReadAsStringAsync();

            return (response.StatusCode, text.Length > 0 ? JObject.Parse(text) : new JObject());

        }

        #endregion

        #region (helper) AccountIn(Node, Name, Role, Password)

        /// <summary>
        /// An account of the given name and password, in the group of the given
        /// role - made the way the node makes its first one, in its
        /// organization, so that it may sign in.
        /// </summary>
        private static async Task<IUser> AccountIn(WWCPNode  Node,
                                                   String    Name,
                                                   String    Role,
                                                   String    Password)
        {

            Assert.That(Node.ExtAPI.TryGetOrganization(Organization_Id.Parse(Node.Kind.Organization), out var organization) &&
                        organization is Organization, Is.True, "the node's organization is not there");

            var account = await Node.ExtAPI.CreateUser(
                                    User_Id.Parse(Name),
                                    I18NString.Create(Languages.en, Name),
                                    SimpleEMailAddress.Parse($"{Name}@localhost"),
                                    User2OrganizationEdgeLabel.IsMember,
                                    (Organization) organization!,
                                    Password:                  Password,
                                    SkipDefaultNotifications:  true,
                                    SkipNewUserEMail:          true,
                                    SkipNewUserNotifications:  true,
                                    AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                    IsAuthenticated:           true
                                );

            Assert.That(account,                                                          Is.Not.Null, $"The account '{Name}' was not made.");
            Assert.That(Node.ExtAPI.TryGetUser(User_Id.Parse(Name), out var stored),      Is.True);
            Assert.That(Node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group) && group is UserGroup, Is.True, $"The node has no group '{Role}'.");

            await Node.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            return stored!;

        }

        #endregion

        #region (helper) EventStream

        /// <summary>
        /// The event stream of a node, read line by line: the data of every log
        /// entry it delivers, and whether it has ended.
        /// </summary>
        private sealed class EventStream(HttpResponseMessage Response, StreamReader Reader) : IAsyncDisposable
        {

            public static async Task<EventStream> Open(HttpClient HTTP)
            {

                var response = await HTTP.SendAsync(new HttpRequestMessage(HttpMethod.Get, "api/v1/events"),
                                                    HttpCompletionOption.ResponseHeadersRead);

                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), "the event stream did not open");

                return new EventStream(response, new StreamReader(await response.Content.ReadAsStreamAsync()));

            }

            /// <summary>
            /// The message of the next log entry the stream delivers, or null
            /// when it ends first - or the timeout, when it does neither.
            /// </summary>
            public async Task<String?> NextLogMessage(TimeSpan Within)
            {

                using var giveUp = new CancellationTokenSource(Within);

                while (true)
                {

                    var line = await Reader.ReadLineAsync(giveUp.Token);

                    if (line is null)
                        return null;

                    if (line.StartsWith("data:", StringComparison.Ordinal) &&
                        JObject.Parse(line[5..]) is JObject data &&
                        data.Value<String>("message") is String message)
                    {
                        return message;
                    }

                }

            }

            public ValueTask DisposeAsync()
            {
                Reader.Dispose();
                Response.Dispose();
                return ValueTask.CompletedTask;
            }

        }

        #endregion


        #region TheStatusNamesTheKindByItsProductAndSaysWhatTheKindAdds()

        [Test]
        public async Task TheStatusNamesTheKindByItsProductAndSaysWhatTheKindAdds()
        {

            await using var node  = await Started();

            using var http = Root(node);

            var (status, json) = await Send(http, HttpMethod.Get, "api/v1/status");

            Assert.Multiple(() => {
                Assert.That(status,                           Is.EqualTo(HttpStatusCode.OK), json.ToString());
                Assert.That(json.Value<String>("service"),    Is.EqualTo(node.Kind.Product));
                Assert.That(json.Value<String>("version"),    Is.EqualTo(node.Version));
                Assert.That(json.Value<String>("testedAs"),   Is.EqualTo("a kind of node"));
                Assert.That(json.Properties().Select(property => property.Name).Take(3),
                            Is.EqualTo(new[] { "service", "version", "testedAs" }),
                            "what the kind adds comes after the version");
            });

        }

        #endregion

        #region TheClockIsAtClockForAnybodySignedIn()

        /// <summary>
        /// At /api/v1/clock, and not at /api/v1/configuration/time as it was on
        /// five kinds of node - which is a JSON 404 now, like any other path the
        /// API does not have.
        /// </summary>
        [Test]
        public async Task TheClockIsAtClockForAnybodySignedIn()
        {

            await using var node       = await Started();

            using var root      = Root(node);
            using var nobody    = Client(node);

            var (clock,  said)  = await Send(root,   HttpMethod.Get, "api/v1/clock");
            var (signedOut, _)  = await Send(nobody, HttpMethod.Get, "api/v1/clock");
            var (old,  oldSaid) = await Send(root,   HttpMethod.Get, "api/v1/configuration/time");

            Assert.Multiple(() => {
                Assert.That(clock,                           Is.EqualTo(HttpStatusCode.OK), said.ToString());
                Assert.That(said.Value<String>("now"),       Is.Not.Null, "the clock says what time it is");
                Assert.That(signedOut,                       Is.EqualTo(HttpStatusCode.Unauthorized));
                Assert.That(old,                             Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(oldSaid.Value<String>("error"),  Is.EqualTo("Unknown API path"));
            });

        }

        #endregion

        #region AKindOfNodeMayAskMoreForItsClockAndItsLog()

        /// <summary>
        /// A kind of node whose accounts include people the clock or the log is
        /// not for asks for a permission they do not have: a viewer, who may
        /// read everything and change nothing, is refused where the kind asks
        /// for more than reading - and told which roles would do.
        /// </summary>
        [Test]
        public async Task AKindOfNodeMayAskMoreForItsClockAndItsLog()
        {

            await using var node      = await Started(Clock: Permission.Edit(NodeResources.NTS),
                                               Log:   Permission.Edit(NodeResources.Configuration));

            var password       = "A-Viewer-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

            await AccountIn(node, "viewer1", "viewer", password);

            using var viewer   = Client(node, "viewer1", password);
            using var root     = Root(node);

            var (clock, clockSaid)   = await Send(viewer, HttpMethod.Get, "api/v1/clock");
            var (logs,  logsSaid)    = await Send(viewer, HttpMethod.Get, "api/v1/logs");
            using var stream         = await viewer.GetAsync("api/v1/events", HttpCompletionOption.ResponseHeadersRead);
            var (rootClock, _)       = await Send(root,   HttpMethod.Get, "api/v1/clock");
            var (rootLogs,  _)       = await Send(root,   HttpMethod.Get, "api/v1/logs");

            Assert.Multiple(() => {
                Assert.That(clock,                        Is.EqualTo(HttpStatusCode.Forbidden), clockSaid.ToString());
                Assert.That(clockSaid.ToString(),         Does.Contain("systemadmin"));
                Assert.That(logs,                         Is.EqualTo(HttpStatusCode.Forbidden), logsSaid.ToString());
                Assert.That(stream.StatusCode,            Is.EqualTo(HttpStatusCode.Forbidden), "the stream asks what the log asks");
                Assert.That(rootClock,                    Is.EqualTo(HttpStatusCode.OK));
                Assert.That(rootLogs,                     Is.EqualTo(HttpStatusCode.OK));
            });

        }

        #endregion

        #region EveryMethodBelowTheAPIIsAnsweredWithAJSON404()

        [TestCase("GET")]
        [TestCase("POST")]
        [TestCase("PUT")]
        [TestCase("PATCH")]
        [TestCase("DELETE")]
        public async Task EveryMethodBelowTheAPIIsAnsweredWithAJSON404(String Method)
        {

            await using var node      = await Started();

            using var root     = Root(node);

            var (status, json) = await Send(root, new HttpMethod(Method), "api/v1/nothing/here", Method is "GET" or "DELETE" ? null : new JObject());

            Assert.Multiple(() => {
                Assert.That(status,                        Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(json.Value<String>("error"),   Is.EqualTo("Unknown API path"), "not the web interface's page");
            });

        }

        #endregion

        #region WhatIsNotAPlaceOrAHostIsRefusedInASentence(Path, Body, Expected)

        /// <summary>
        /// A name server's place that is not a place, and a host that is not a
        /// name: refused with 400 and a sentence - two copies took them as they
        /// came, and threw out of the handler.
        /// </summary>
        [TestCase("api/v1/configuration/dns/query", """{ "name": "example.org", "recordTypes": [ "A" ], "server": "first" }""", "'server' must be the place of a name server in the list, counted from 0.")]
        [TestCase("api/v1/configuration/dns/query", """{ "name": "example.org", "recordTypes": [ "A" ], "server": -1 }""",     "'server' must be the place of a name server in the list, counted from 0.")]
        [TestCase("api/v1/configuration/nts/test",  """{ "host": { "name": "time.example.org" } }""",                         "'host' must be the name or the address of a time server.")]
        public async Task WhatIsNotAPlaceOrAHostIsRefusedInASentence(String Path, String Body, String Expected)
        {

            await using var node      = await Started();

            using var root     = Root(node);

            var (status, json) = await Send(root, HttpMethod.Post, Path, JObject.Parse(Body));

            Assert.Multiple(() => {
                Assert.That(status,                       Is.EqualTo(HttpStatusCode.BadRequest), json.ToString());
                Assert.That(json.Value<String>("error"),  Is.EqualTo(Expected));
            });

        }

        #endregion

        #region ACertificateTheKindUsesIsNotDeletedAndItsChoiceIsInTheAnswer()

        /// <summary>
        /// What a kind of node says about its store beyond every node's is in the
        /// answer, and a certificate it uses is not deleted under it - 409, in
        /// the kind's own sentence - until it no longer does.
        /// </summary>
        [Test]
        public async Task ACertificateTheKindUsesIsNotDeletedAndItsChoiceIsInTheAnswer()
        {

            await using var node      = await Started();

            using var root     = Root(node);

            using var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request        = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=A Root The Test Uses", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));

            using var rootCA   = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            var (created, entry) = await Send(root, HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kind",     "tlsRoot"),
                                                  new JProperty("content",  Convert.ToBase64String(Encoding.ASCII.GetBytes(rootCA.ExportCertificatePem())))
                                              ));

            Assert.That(created, Is.EqualTo(HttpStatusCode.Created), entry.ToString());

            var handle            = entry.Value<String>("id")!;

            node.Used             = handle;

            var (_, store)        = await Send(root, HttpMethod.Get,    "api/v1/certificates");
            var (refused, said)   = await Send(root, HttpMethod.Delete, $"api/v1/certificates/{handle}");

            node.Used             = null;

            var (deleted, after)  = await Send(root, HttpMethod.Delete, $"api/v1/certificates/{handle}");

            Assert.Multiple(() => {
                Assert.That(store["chosen"]?.Value<String>("forTheTest"),  Is.EqualTo(handle), "what the kind adds to the answer");
                Assert.That(refused,                                       Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(said.Value<String>("error"),                   Is.EqualTo("The test uses that certificate."));
                Assert.That(deleted,                                       Is.EqualTo(HttpStatusCode.OK), after.ToString());
                Assert.That(after["certificates"]!["tlsRoot"]!.Children().Any(), Is.False);
            });

        }

        #endregion


        #region AStreamOpenedWithAPasswordEndsWithANewPassword()

        /// <summary>
        /// A stream opened with a password is asked about the password before
        /// every entry, as a new request with it is: changed, the stream ends,
        /// and what is logged after the change is not sent down it. Held to the
        /// account alone, as it was, it went on.
        /// </summary>
        [Test]
        public async Task AStreamOpenedWithAPasswordEndsWithANewPassword()
        {

            await using var node            = await Started();

            var password             = "A-Driver-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
            var reader               = await AccountIn(node, "reader1", "viewer", password);

            using var http           = Client(node, "reader1", password);

            await using var stream   = await EventStream.Open(http);

            node.Log.Info("Before the new password.", "test");

            // What the stream replays of the log before it is skipped: what
            // counts is the entry logged now.
            String? before;

            do
            {
                before = await stream.NextLogMessage(TimeSpan.FromSeconds(10));
            }
            while (before is not null && !before.Contains("Before the new password."));

            var changed              = await node.ExtAPI.ChangePassword(reader, "A-New-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)), password, SuppressNotifications: true);

            Assert.That(changed.Result, Is.EqualTo(CommandResult.Success), $"the password could not be changed: {changed.Description}");

            node.Log.Info("After the new password.", "test");

            String? after = null;

            try
            {
                // Entries of the change itself may come first; what counts is
                // that the one after it never does, and that the stream ends.
                do
                {
                    after = await stream.NextLogMessage(TimeSpan.FromSeconds(10));
                }
                while (after is not null && !after.Contains("After the new password."));
            }
            catch (OperationCanceledException)
            {
                Assert.Fail("The stream neither ended nor went on - a stream opened with the old password was still open after ten seconds.");
            }

            Assert.Multiple(() => {
                Assert.That(before,  Does.Contain("Before the new password."));
                Assert.That(after,   Is.Null, "the entry logged after the new password was sent to a stream opened with the old one");
            });

        }

        #endregion

        #region AStreamOpenedWithAPasswordIsNotRationedLikeAGuess()

        /// <summary>
        /// Fifteen entries in a row to a stream opened with a password: each of
        /// them asks about the password again, and none of them is counted as a
        /// guess - Hermod believes credentials it verified, and the sign-in's
        /// rate limit would otherwise end the stream after ten.
        /// </summary>
        [Test]
        public async Task AStreamOpenedWithAPasswordIsNotRationedLikeAGuess()
        {

            await using var node           = await Started();

            var password            = "A-Reader-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

            await AccountIn(node, "reader2", "viewer", password);

            using var http          = Client(node, "reader2", password);

            await using var stream  = await EventStream.Open(http);

            for (var line = 1; line <= 15; line++)
                node.Log.Info($"Line {line} of fifteen.", "test");

            var received = new List<String>();

            while (received.Count < 15)
            {

                var message = await stream.NextLogMessage(TimeSpan.FromSeconds(20));

                if (message is null)
                    break;

                if (message.Contains("of fifteen."))
                    received.Add(message);

            }

            Assert.That(received, Has.Count.EqualTo(15), $"the stream ended after {received.Count} of fifteen entries");

        }

        #endregion

    }

}
