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
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    #region (enum) NodeSetup / (attribute) WithNodeAttribute

    /// <summary>
    /// What the configuration file of the node a test is run against says,
    /// beyond the time client being switched off.
    /// </summary>
    public enum NodeSetup
    {

        /// <summary>
        /// Nothing more: the time client switched off, so that nothing asks a
        /// time server, and name resolution as the node has it by default.
        /// </summary>
        Offline,

        /// <summary>
        /// One name server, on the loopback address, that never answers - see
        /// <see cref="TestKit.SilentNameServer"/> - asked with a timeout of a
        /// second and no second try.
        /// </summary>
        SilentNameServer,

        /// <summary>
        /// Two time servers and two name servers to be held to their
        /// certificates, the first of each learning its root on first use - see
        /// <see cref="NodeConformanceTests.TimeServerToLearn"/> and
        /// <see cref="NodeConformanceTests.NameServerToLearn"/>.
        /// </summary>
        ServersToLearnFrom

    }

    /// <summary>
    /// The node a test is run against, where it needs another than the
    /// <see cref="NodeSetup.Offline"/> one.
    /// </summary>
    /// <param name="Setup">What its configuration file says.</param>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class WithNodeAttribute(NodeSetup Setup)

        : PropertyAttribute(Key, Setup.ToString())

    {

        /// <summary>
        /// The name of the test's property that carries the setup.
        /// </summary>
        public const String Key = "NodeSetup";

    }

    #endregion


    /// <summary>
    /// What every node has to answer, whatever its kind, asked of one of the
    /// kind whose test suite derives a fixture from this.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same tests used to be in the suite of every kind of node, copied
    /// and drifting: the local controller's, the charging station's, the
    /// CSMS's and the e-mobility provider's each had their own copy of the
    /// sign-in, the configuration, the log and the event stream, and the
    /// vehicle, the gateway, the roaming hub and the meter had some of them,
    /// or none. They are here once now, and a kind of node says only how one
    /// of it is made - see <see cref="NewNode"/> - and, where it signs in
    /// otherwise than by the HTTPExt API's form, how.
    /// </para>
    /// <para>
    /// One fixture and not one per topic, so that a test added here is run by
    /// every kind of node without any of them adding a line for it. A test
    /// that needs a node configured otherwise says which with
    /// <see cref="WithNodeAttribute"/>.
    /// </para>
    /// <para>
    /// A whole node per test, because half of what is worth testing here
    /// changes the node: a test that repoints the name servers must not decide
    /// what the next test reads. And <b>nothing reaches the network</b>: the
    /// time client is switched off before the node is made, and the name
    /// servers are only ever asked when a test has put one of its own in
    /// their place.
    /// </para>
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region What the kind of node says

        /// <summary>
        /// A node of this kind, made and not started, in the given directory
        /// and with the given configuration file.
        /// </summary>
        /// <remarks>
        /// On a port nobody else has - see <see cref="TestPorts.Free"/> - with
        /// its accounts in the directory, its configuration file there with
        /// what is given written into it before the node reads it, and its log
        /// on neither the console nor the disk. Its certificate store is where
        /// the kind keeps it, which may be anywhere in the directory. A kind
        /// that needs more to be made - a second port, a key infrastructure -
        /// makes it here.
        /// </remarks>
        /// <param name="Directory">Where the node keeps what it keeps; it exists.</param>
        /// <param name="Configuration">What its configuration file says; the kind may add what it needs to it.</param>
        protected abstract WWCPNode NewNode(String   Directory,
                                            JObject  Configuration);

        /// <summary>
        /// The account the first start of a node makes, and signs its password
        /// out on the console: "root", unless the kind names it otherwise.
        /// </summary>
        protected virtual String AdminLogin
            => WWCPNode.DefaultAdminUser;

        /// <summary>
        /// Where a browser signs in, relative to the web interface: the
        /// HTTPExt API's form, unless the kind signs in elsewhere.
        /// </summary>
        protected virtual String SignInPath
            => $"{WWCPNode.ExtAPIPath.ToString().Trim('/')}/login";

        /// <summary>
        /// What a browser sends to sign in: form-urlencoded, and the field is
        /// called "login" rather than "username" - unless the kind signs in
        /// otherwise.
        /// </summary>
        protected virtual HttpContent SignInBody(String  Login,
                                                 String  Password)

            => new FormUrlEncodedContent([
                   new KeyValuePair<String, String>("login",     Login),
                   new KeyValuePair<String, String>("password",  Password)
               ]);

        #endregion

        #region Properties

        /// <summary>
        /// The node under test, listening, from SetUp until TearDown.
        /// </summary>
        protected WWCPNode  Node            { get; private set; } = default!;

        /// <summary>
        /// The password the node made up for its first account at its first
        /// start.
        /// </summary>
        protected String    Password        { get; private set; } = default!;

        /// <summary>
        /// Where its web interface is, ending with a slash: every path a test
        /// asks for is relative to it.
        /// </summary>
        protected String    BaseURL         { get; private set; } = default!;

        /// <summary>
        /// The directory holding what the node keeps, removed again in
        /// TearDown.
        /// </summary>
        protected String    Directory       { get; private set; } = default!;

        /// <summary>
        /// What the node's configuration file said when it was made.
        /// </summary>
        protected JObject   Configuration   { get; private set; } = default!;

        #endregion

        #region Data

        /// <summary>
        /// The name server of <see cref="NodeSetup.SilentNameServer"/>, while
        /// a test has one.
        /// </summary>
        private SilentNameServer? silentNameServer;

        #endregion


        #region SetUp / TearDown

        [SetUp]
        public async Task StartTheNode()
        {

            var setup      = TestContext.CurrentContext.Test.Properties.Get(WithNodeAttribute.Key) is String named
                                 ? Enum.Parse<NodeSetup>(named)
                                 : NodeSetup.Offline;

            nodeLeftRunning  = false;

            Directory      = Path.Combine(Path.GetTempPath(), $"node-conformance-{Guid.NewGuid().ToString("N")[..12]}");
            System.IO.Directory.CreateDirectory(Directory);

            Configuration  = ConfigurationFor(setup);
            Node           = NewNode(Directory, (JObject) Configuration.DeepClone());
            BaseURL        = BaseURLOf(Node);

            await Node.Start();

            // After Start(), because that is what makes the account. Null would
            // mean accounts were already there, and the directory is new.
            Password       = Node.GeneratedPassword
                                 ?? throw new InvalidOperationException($"The {Node.Kind.Name} did not make up a password at its first start!");

        }

        [TearDown]
        public async Task StopTheNode()
        {

            // Not a node whose stop was given up on: asked to stop again, it
            // would hang this teardown the way it hung the test.
            if (Node is not null && !nodeLeftRunning)
                await Node.DisposeAsync();

            silentNameServer?.Dispose();
            silentNameServer = null;

            Remove(Directory);

        }

        #endregion

        #region (private) ConfigurationFor(Setup)

        /// <summary>
        /// What the configuration file of a node says for the given setup.
        /// </summary>
        private JObject ConfigurationFor(NodeSetup Setup)
        {

            var configuration = new JObject(
                                    new JProperty("nts", new JObject(
                                        new JProperty("enabled", false)
                                    ))
                                );

            switch (Setup)
            {

                case NodeSetup.SilentNameServer:

                    silentNameServer = new SilentNameServer();

                    configuration["dns"] = new JObject(
                                               new JProperty("servers",     new JArray(
                                                   new JObject(
                                                       new JProperty("address",              "127.0.0.1"),
                                                       new JProperty("port",                 silentNameServer.Port),
                                                       new JProperty("transport",            "UDP"),
                                                       new JProperty("queryTimeoutSeconds",  1)
                                                   )
                                               )),
                                               new JProperty("maxRetries",  0)
                                           );
                    break;

                case NodeSetup.ServersToLearnFrom:

                    NameServerToLearn = new JObject(
                                            new JProperty("address",              "127.0.0.1"),
                                            new JProperty("port",                 TestPorts.Free()),
                                            new JProperty("transport",            "TLS"),
                                            new JProperty("queryTimeoutSeconds",  1),
                                            new JProperty("trustOnFirstUse",      "root")
                                        );

                    configuration["nts"]!["servers"] = new JArray(
                                                           new JObject(
                                                               new JProperty("hostname",         TimeServerToLearn),
                                                               new JProperty("trustOnFirstUse",  "root")
                                                           ),
                                                           AnotherTimeServer
                                                       );

                    configuration["dns"] = new JObject(
                                               new JProperty("servers",     new JArray(
                                                   NameServerToLearn,
                                                   new JObject(
                                                       new JProperty("address",              "127.0.0.1"),
                                                       new JProperty("port",                 TestPorts.Free()),
                                                       new JProperty("transport",            "UDP"),
                                                       new JProperty("queryTimeoutSeconds",  1)
                                                   )
                                               )),
                                               new JProperty("maxRetries",  0)
                                           );
                    break;

            }

            return configuration;

        }

        #endregion

        #region (protected) SilentNameServerPort

        /// <summary>
        /// The port of the name server that never answers, in a test with
        /// <see cref="NodeSetup.SilentNameServer"/>.
        /// </summary>
        protected UInt16 SilentNameServerPort

            => silentNameServer?.Port
                   ?? throw new InvalidOperationException("This test has no silent name server - it needs [WithNode(NodeSetup.SilentNameServer)].");

        #endregion

        #region (private static) BaseURLOf(Node) / Remove(Directory)

        private static String BaseURLOf(WWCPNode Node)
        {

            var url = Node.WebInterfaceURL.ToString();

            return url.EndsWith('/') ? url : url + "/";

        }

        /// <summary>
        /// Take a test's directory away again. A directory that survives a
        /// failed run is untidy and nothing more, so this never throws: failing
        /// a teardown over it would hide the failure that matters.
        /// </summary>
        private static void Remove(String? Directory)
        {

            try
            {
                if (Directory is not null && System.IO.Directory.Exists(Directory))
                    System.IO.Directory.Delete(Directory, true);
            }
            catch (IOException)
            { }
            catch (UnauthorizedAccessException)
            { }

        }

        #endregion


        #region (protected) Anonymous() / SignedIn() / SignedInAs(Login, Password) / WithPassword(Login, Password)

        /// <summary>
        /// A browser that has not signed in, keeping whatever cookie it is
        /// given.
        /// </summary>
        protected HttpClient Anonymous()

            => ClientOf(BaseURL);

        /// <summary>
        /// A browser that has signed in with the password the node made up,
        /// carrying the session cookie from here on.
        /// </summary>
        protected Task<HttpClient> SignedIn()

            => SignedInAs(AdminLogin, Password);

        /// <summary>
        /// A browser that has signed in as somebody in particular.
        /// </summary>
        protected async Task<HttpClient> SignedInAs(String  Login,
                                                    String  Password)
        {

            var http      = Anonymous();

            var response  = await http.PostAsync(SignInPath, SignInBody(Login, Password));

            Assert.That(response.IsSuccessStatusCode, Is.True,
                        $"Signing in as '{Login}' failed with {(Int32) response.StatusCode}, and every assertion below it would say so instead.");

            return http;

        }

        /// <summary>
        /// A client that says who it is with a password on every request, as a
        /// script does, and never signs in.
        /// </summary>
        protected HttpClient WithPassword(String  Login,
                                          String  Password)
        {

            var http = ClientOf(BaseURL);

            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                           "Basic",
                                                           Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Login}:{Password}"))
                                                       );

            return http;

        }

        /// <summary>
        /// A client of the web interface at the given address, with a cookie
        /// jar of its own.
        /// </summary>
        protected static HttpClient ClientOf(String BaseURL)

            => new (new HttpClientHandler { CookieContainer = new CookieContainer(), UseCookies = true }) {
                   BaseAddress  = new Uri(BaseURL),
                   Timeout      = TimeSpan.FromSeconds(30)
               };

        #endregion

        #region (protected static) JSONBody(...) / GetJSON(HTTP, Path) / Send(HTTP, Method, Path, JSON)

        /// <summary>
        /// A request body, as the web interface sends one.
        /// </summary>
        protected static StringContent JSONBody(params JProperty[] Properties)

            => new (new JObject(Properties).ToString(),
                    Encoding.UTF8,
                    "application/json");

        /// <summary>
        /// One GET, with the answer parsed and the status checked - so that a
        /// test which is about what a resource says does not also have to say
        /// what a 500 looks like.
        /// </summary>
        protected static async Task<JObject> GetJSON(HttpClient  HTTP,
                                                     String      Path)
        {

            var response = await HTTP.GetAsync(Path);

            Assert.That(response.IsSuccessStatusCode, Is.True,
                        $"GET {Path} answered {(Int32) response.StatusCode}.");

            return JObject.Parse(await response.Content.ReadAsStringAsync());

        }

        /// <summary>
        /// One request with a JSON body or none, and its answer: the status, and
        /// the body where there is one to read.
        /// </summary>
        protected static async Task<(HttpStatusCode Status, JObject JSON)> Send(HttpClient  HTTP,
                                                                               HttpMethod  Method,
                                                                               String      Path,
                                                                               JObject?    JSON = null)
        {

            using var request   = new HttpRequestMessage(Method, Path);

            if (JSON is not null)
                request.Content = new StringContent(JSON.ToString(), Encoding.UTF8, "application/json");

            using var response  = await HTTP.SendAsync(request);
            var text            = await response.Content.ReadAsStringAsync();

            return (response.StatusCode,
                    text.TrimStart().StartsWith('{') ? JObject.Parse(text) : new JObject());

        }

        #endregion

        #region (protected) AccountIn(Name, Role, Password)

        /// <summary>
        /// An account of the given name and password, in the group of the given
        /// role - made the way the node makes its first one, in its
        /// organization, so that it may sign in.
        /// </summary>
        protected async Task<IUser> AccountIn(String  Name,
                                              String  Role,
                                              String  Password)
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
            Assert.That(Node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group) && group is UserGroup,
                        Is.True, $"The {Node.Kind.Name} has no group '{Role}'.");

            await Node.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            return stored!;

        }

        #endregion

    }

}
