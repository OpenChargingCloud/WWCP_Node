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
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a kind of node says through the JSON API every node has: its
    /// status, what reading the clock and the log needs, its certificates
    /// and what uses them, and who is signed in.
    /// </summary>
    /// <remarks>
    /// What every node answers alike is asked by the conformance suite of
    /// WWCP_Node_TestKit - of a node of no particular kind here, see
    /// <see cref="PlainNodeConformance"/>, and of every kind of node in its
    /// own suite.
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

            /// <summary>
            /// What the test says a change would leave without its certificate,
            /// given whether it would be on and what it would be for.
            /// </summary>
            public Func<Boolean, IReadOnlyList<String>?, String?>?  Loses  { get; set; }

            /// <summary>
            /// Every change the node was asked about, as it would leave the certificate.
            /// </summary>
            public List<(Boolean Active, IReadOnlyList<String>? Usages)>  AskedAbout  { get; } = [];

            protected override void CompleteCertificatesJSON(JObject JSON)
                => JSON["chosen"] = new JObject(new JProperty("forTheTest", Used));

            public override String? WhatUses(String Handle)
                => Used is not null && Handle.Equals(Used, StringComparison.OrdinalIgnoreCase)
                       ? "The test uses that certificate."
                       : null;

            public override String? WhatWouldLose(CertificateEntry        Entry,
                                                  Boolean                 ActiveAfter,
                                                  IReadOnlyList<String>?  UsagesAfter)
            {
                AskedAbout.Add((ActiveAfter, UsagesAfter));
                return Loses?.Invoke(ActiveAfter, UsagesAfter);
            }

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

            protected override IEnumerable<JProperty> ProductMe(IUser User)
            {
                yield return new JProperty("roleTitle", $"Tester, as '{User.Id}'");
            }

            protected override Permission? ToReadTheClock  => ClockNeeds;
            protected override Permission? ToReadTheLog    => LogNeeds;

        }

        #endregion

        #region (helper) Imported(HTTP, Name, Usages = null)

        /// <summary>
        /// A TLS root of the given name, put into the node's store through the
        /// API - for what is left, and nothing else - and its handle.
        /// </summary>
        private static async Task<String> Imported(HttpClient  HTTP,
                                                   String      Name,
                                                   JToken?     Usages = null)
        {

            using var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request       = new System.Security.Cryptography.X509Certificates.CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));

            using var rootCA  = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            var body          = new JObject(
                                    new JProperty("kind",     "tlsRoot"),
                                    new JProperty("content",  Convert.ToBase64String(Encoding.ASCII.GetBytes(rootCA.ExportCertificatePem())))
                                );

            if (Usages is not null)
                body["usages"] = Usages;

            var (created, entry) = await Send(HTTP, HttpMethod.Post, "api/v1/certificates", body);

            Assert.That(created, Is.EqualTo(HttpStatusCode.Created), entry.ToString());

            return entry.Value<String>("id")!;

        }

        #endregion

        #region (helpers) Started(Clock, Log) / Client(...) / Send(...)

        /// <summary>
        /// A node with the API of a kind of node, started - on a port nobody
        /// else has, made again on a fresh one where another process took it
        /// first, and without asking a time server.
        /// </summary>
        private async Task<TestNode> Started(Permission? Clock = null, Permission? Log = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "nts": { "enabled": false } }""");

            return await TestPorts.StartedOnFreshPorts(() => {

                var node = new TestNode(IPPort.Parse(TestPorts.Free()), directory, new WWCPConfigFile(configuration));

                node.API = new TestAPI(node, Clock, Log);

                return node;

            });

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
            var (_,         viewerIs) = await Send(viewer, HttpMethod.Get, "api/v1/auth/me");
            var (_,         rootIs)   = await Send(root,   HttpMethod.Get, "api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(clock,                        Is.EqualTo(HttpStatusCode.Forbidden), clockSaid.ToString());
                Assert.That(clockSaid.ToString(),         Does.Contain("systemadmin"));
                Assert.That(logs,                         Is.EqualTo(HttpStatusCode.Forbidden), logsSaid.ToString());
                Assert.That(stream.StatusCode,            Is.EqualTo(HttpStatusCode.Forbidden), "the stream asks what the log asks");
                Assert.That(rootClock,                    Is.EqualTo(HttpStatusCode.OK));
                Assert.That(rootLogs,                     Is.EqualTo(HttpStatusCode.OK));
                Assert.That(viewerIs.Value<Boolean?>("mayReadTheLog"), Is.False, "'me' tells the viewer the log is for them, and the log refuses them");
                Assert.That(rootIs.  Value<Boolean?>("mayReadTheLog"), Is.True,  "'me' tells the administrator the log is not for them");
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

        #region AChangeThatWouldLeaveSomethingWithoutItsCertificateIsRefusedBeforeAnyOfItIsMade()

        /// <summary>
        /// Switched off, a certificate the kind of node needs on would leave
        /// something without it: 409 in the kind's sentence, and nothing of the
        /// request made - not the new label that came with it either. A
        /// deletion takes it away as much, and is refused as well; a change
        /// that leaves it on goes through.
        /// </summary>
        [Test]
        public async Task AChangeThatWouldLeaveSomethingWithoutItsCertificateIsRefusedBeforeAnyOfItIsMade()
        {

            await using var node      = await Started();

            using var root     = Root(node);

            var handle         = await Imported(root, "A Root The Test Needs On");

            node.Loses         = (active, _) => active ? null : "The test would have no root to believe.";

            var (refused,  said)     = await Send(root, HttpMethod.Patch,  $"api/v1/certificates/{handle}", new JObject(
                                                                                                                new JProperty("label",   "Renamed On The Way Out"),
                                                                                                                new JProperty("active",  false)
                                                                                                            ));
            var (_,        kept)     = await Send(root, HttpMethod.Get,    $"api/v1/certificates/{handle}");
            var (notGone,  goneSaid) = await Send(root, HttpMethod.Delete, $"api/v1/certificates/{handle}");
            var (renamed,  named)    = await Send(root, HttpMethod.Patch,  $"api/v1/certificates/{handle}", new JObject(
                                                                                                                new JProperty("label",   "Renamed And On")
                                                                                                            ));

            node.Loses         = null;

            var (deleted,  _)        = await Send(root, HttpMethod.Delete, $"api/v1/certificates/{handle}");

            Assert.Multiple(() => {
                Assert.That(refused,                             Is.EqualTo(HttpStatusCode.Conflict), said.ToString());
                Assert.That(said.Value<String>("error"),         Is.EqualTo("The test would have no root to believe."));
                Assert.That(kept.Value<String>("label"),         Is.EqualTo("A Root The Test Needs On"), "the refused request renamed it");
                Assert.That(kept.Value<Boolean>("active"),       Is.True,                                "the refused request switched it off");
                Assert.That(notGone,                             Is.EqualTo(HttpStatusCode.Conflict), goneSaid.ToString());
                Assert.That(goneSaid.Value<String>("error"),     Is.EqualTo("The test would have no root to believe."));
                Assert.That(renamed,                             Is.EqualTo(HttpStatusCode.OK), named.ToString());
                Assert.That(named.Value<String>("label"),        Is.EqualTo("Renamed And On"));
                Assert.That(deleted,                             Is.EqualTo(HttpStatusCode.OK));
            });

        }

        #endregion

        #region AChangeIsAskedAboutAsTheStoreWouldKeepItAndRefusedUsagesChangeNothing()

        /// <summary>
        /// What the node is asked about is the certificate as the store would
        /// keep it: its usages as the store writes them, the ones it has where
        /// the request leaves them alone, and null for every use. Usages the
        /// store would refuse are refused before the label that came with them
        /// is changed.
        /// </summary>
        [Test]
        public async Task AChangeIsAskedAboutAsTheStoreWouldKeepItAndRefusedUsagesChangeNothing()
        {

            await using var node      = await Started();

            using var root     = Root(node);

            var handle         = await Imported(root, "A Root For Names", new JArray("dns"));

            var (spelt,   _)        = await Send(root, HttpMethod.Patch, $"api/v1/certificates/{handle}", new JObject(new JProperty("usages", new JArray(" NTS ", "dns"))));
            var (off,     _)        = await Send(root, HttpMethod.Patch, $"api/v1/certificates/{handle}", new JObject(new JProperty("active", false)));
            var (every,   _)        = await Send(root, HttpMethod.Patch, $"api/v1/certificates/{handle}", new JObject(new JProperty("usages", JValue.CreateNull())));
            var asked               = node.AskedAbout.ToArray();

            var (unknown, unknownSaid) = await Send(root, HttpMethod.Patch, $"api/v1/certificates/{handle}", new JObject(
                                                                                                                new JProperty("label",   "Renamed By A Refusal"),
                                                                                                                new JProperty("usages",  new JArray("ntp"))
                                                                                                            ));
            var (_,       kept)     = await Send(root, HttpMethod.Get,   $"api/v1/certificates/{handle}");

            Assert.Multiple(() => {
                Assert.That(spelt,                              Is.EqualTo(HttpStatusCode.OK));
                Assert.That(off,                                Is.EqualTo(HttpStatusCode.OK));
                Assert.That(every,                              Is.EqualTo(HttpStatusCode.OK));
                Assert.That(asked,                              Has.Length.EqualTo(3));
                Assert.That(asked[0].Active,                    Is.True);
                Assert.That(asked[0].Usages,                    Is.EqualTo(new[] { "dns", "nts" }), "as the store keeps them");
                Assert.That(asked[1].Active,                    Is.False);
                Assert.That(asked[1].Usages,                    Is.EqualTo(new[] { "dns", "nts" }), "the ones it has, which the request left alone");
                Assert.That(asked[2].Active,                    Is.False,                            "off, as the request before left it");
                Assert.That(asked[2].Usages,                    Is.Null,                             "every use");
                Assert.That(unknown,                            Is.EqualTo(HttpStatusCode.BadRequest), unknownSaid.ToString());
                Assert.That(unknownSaid.Value<String>("error"), Does.Contain("'ntp'"));
                Assert.That(kept.Value<String>("label"),        Is.EqualTo("A Root For Names"),     "the refused request renamed it");
            });

        }

        #endregion

        #region WhatAKindSaysAboutWhoIsSignedInComesAfterThePermissions()

        [Test]
        public async Task WhatAKindSaysAboutWhoIsSignedInComesAfterThePermissions()
        {

            await using var node      = await Started();

            using var root     = Root(node);

            var (status, me)   = await Send(root, HttpMethod.Get, "api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(status,                        Is.EqualTo(HttpStatusCode.OK), me.ToString());
                Assert.That(me.Value<String>("username"),  Is.EqualTo("root"));
                Assert.That(me.Value<String>("roleTitle"), Is.EqualTo("Tester, as 'root'"));
                Assert.That(me.Properties().Select(property => property.Name),
                            Is.EqualTo(new[] { "username", "roles", "permissions", "mayReadTheLog", "roleTitle" }),
                            "what the kind adds comes after what every node says");
            });

        }

        #endregion


    }

}
