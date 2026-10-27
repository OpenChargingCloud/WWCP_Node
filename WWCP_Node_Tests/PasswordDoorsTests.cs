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
using System.Diagnostics;
using System.Net.Http.Headers;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using IPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The doors to an account's password besides the web interface's sign-in
    /// (POI3-ISSUES.md S22): SSH's password, counted against the sign-in's own
    /// ration of guesses, per client and per account, a name that opens
    /// nothing costing a hash all the same; and the HTTPExt API's legacy
    /// SET /ext/users/{id}/password, whose current password is rationed as
    /// POST /ext/auth/password rations it.
    /// </summary>
    [TestFixture]
    public class PasswordDoorsTests
    {

        #region Data

        private          String          directory  = "";
        private readonly List<WWCPNode>  nodes      = [];

        private static readonly IPAddress Guesser   = IPAddress.Parse("192.0.2.7");

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-password-doors-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helpers) Started() / Send(Node, Method, Path, Headers, Body) / SignIn(Node, Password)

        /// <summary>
        /// A node with the JSON API every node has, started on fresh ports.
        /// </summary>
        private async Task<WWCPNode> Started()
        {

            var node = await TestPorts.StartedOnFreshPorts(() => {

                var home        = Directory.CreateDirectory(Path.Combine(directory, "node" + nodes.Count)).FullName;
                var configFile  = Path.Combine(home, WWCPConfigFile.DefaultFileName);

                File.WriteAllText(configFile, """{ "nts": { "groups": { "legal": { "enabled": false } } } }""");

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

        /// <summary>
        /// A sign-in of the administrator at the web interface's door.
        /// </summary>
        private static Task<HttpResponseMessage> SignIn(WWCPNode  Node,
                                                        String    Password)

            => Send(Node,
                    HttpMethod.Post,
                    "ext/login",
                    [],
                    new FormUrlEncodedContent([
                        new KeyValuePair<String, String>("login",     WWCPNode.DefaultAdminUser),
                        new KeyValuePair<String, String>("password",  Password)
                    ]));

        /// <summary>
        /// The session cookie of a sign-in that worked, as a Cookie header sends it.
        /// </summary>
        private static String SessionOf(WWCPNode             Node,
                                        HttpResponseMessage  SignedIn)
        {

            Assert.That((Int32) SignedIn.StatusCode, Is.InRange(200, 399), "the sign-in");

            var cookie = SignedIn.Headers.TryGetValues("Set-Cookie", out var cookies)
                             ? cookies.FirstOrDefault(cookie => cookie.StartsWith($"{Node.ExtAPI.SessionCookieName}=", StringComparison.Ordinal))
                             : null;

            Assert.That(cookie, Is.Not.Null, "no session cookie");

            return cookie!.Split(';')[0];

        }

        /// <summary>
        /// SET ext/users/root/password with the given current password and a new one.
        /// </summary>
        private static Task<HttpResponseMessage> SetPassword(WWCPNode  Node,
                                                             String    Session,
                                                             String    CurrentPassword,
                                                             String    NewPassword)
        {

            var body = new StringContent(
                           new Newtonsoft.Json.Linq.JObject(
                               new Newtonsoft.Json.Linq.JProperty("currentPassword",  CurrentPassword),
                               new Newtonsoft.Json.Linq.JProperty("newPassword",      NewPassword)
                           ).ToString()
                       );

            body.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-8");

            return Send(Node, new HttpMethod("SET"), $"ext/users/{WWCPNode.DefaultAdminUser}/password", [ ("Cookie", Session) ], body);

        }

        #endregion


        #region SSHPasswordGuessesShareTheSignInsRationPerClient()

        /// <summary>
        /// Ten wrong SSH passwords from one address use up its ration: the right
        /// password from there opens nothing - not over SSH, and not at the web
        /// interface's sign-in either, which counts against the same ration -
        /// while from another address it opens the account at once.
        /// </summary>
        [Test]
        public async Task SSHPasswordGuessesShareTheSignInsRationPerClient()
        {

            var node           = await Started();
            var authenticator  = new NodeSSHAuthenticator(node, Passwords: true);

            // Another account's name, so that only the client's ration is used
            // up and not the administrator's.
            var guesses = new List<Boolean>();

            for (var guess = 1; guess <= 10; guess++)
                guesses.Add(await authenticator.AuthorizePasswordAsync("nobody", $"Not-The-Password-{guess}", IPAddress.Loopback));

            var sshAfter     = await authenticator.AuthorizePasswordAsync(WWCPNode.DefaultAdminUser, node.GeneratedPassword!, IPAddress.Loopback);
            using var web    = await SignIn(node, node.GeneratedPassword!);
            var otherClient  = await authenticator.AuthorizePasswordAsync(WWCPNode.DefaultAdminUser, node.GeneratedPassword!, Guesser);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(guesses,         Has.All.False);
                Assert.That(sshAfter,        Is.False,                                "the guesser's address may guess no more");
                Assert.That(web.StatusCode,  Is.EqualTo(HttpStatusCode.TooManyRequests), "the web sign-in counts against the same ration");
                Assert.That(otherClient,     Is.True,                                 "another address signs in");
            }

        }

        #endregion

        #region SSHPasswordGuessesAreRationedPerAccount()

        /// <summary>
        /// Ten wrong SSH passwords for one account, each from an address of its
        /// own, use up the account's ration: the right password opens it from no
        /// address for now, while another account's door stays open.
        /// </summary>
        [Test]
        public async Task SSHPasswordGuessesAreRationedPerAccount()
        {

            var node           = await Started();
            var authenticator  = new NodeSSHAuthenticator(node, Passwords: true);

            for (var guess = 1; guess <= 10; guess++)
                Assert.That(await authenticator.AuthorizePasswordAsync(WWCPNode.DefaultAdminUser, $"Not-The-Password-{guess}", IPAddress.Parse($"198.51.100.{guess}")), Is.False);

            Assert.That(await authenticator.AuthorizePasswordAsync(WWCPNode.DefaultAdminUser, node.GeneratedPassword!, IPAddress.Parse("203.0.113.9")),
                        Is.False,
                        "the account may be guessed at no more");

        }

        #endregion

        #region SSHPasswordsOffOpenNothingAndCountNothing()

        /// <summary>
        /// Where the node does not let passwords open SSH, the right one opens
        /// nothing - and costs nothing of anybody's ration.
        /// </summary>
        [Test]
        public async Task SSHPasswordsOffOpenNothingAndCountNothing()
        {

            var node   = await Started();
            var off    = new NodeSSHAuthenticator(node, Passwords: false);

            for (var guess = 1; guess <= 12; guess++)
                Assert.That(await off.AuthorizePasswordAsync(WWCPNode.DefaultAdminUser, node.GeneratedPassword!, IPAddress.Loopback), Is.False);

            using var web = await SignIn(node, node.GeneratedPassword!);

            Assert.That((Int32) web.StatusCode, Is.InRange(200, 399), "the web sign-in was rationed by SSH that is off");

        }

        #endregion

        #region AnUnknownNameCostsAHashAsWell()

        /// <summary>
        /// A name that opens no account costs a hash all the same, so that how
        /// long the answer takes does not say whether the account is there. The
        /// hash is 600 000 rounds of PBKDF2: without it, the answer would come
        /// back in well under a hundredth of the time.
        /// </summary>
        [Test]
        public async Task AnUnknownNameCostsAHashAsWell()
        {

            var node           = await Started();
            var authenticator  = new NodeSSHAuthenticator(node, Passwords: true);

            async Task<TimeSpan> Timed(String Username, Int32 Address)
            {

                var watch = Stopwatch.StartNew();

                Assert.That(await authenticator.AuthorizePasswordAsync(Username, "Not-The-Password", IPAddress.Parse($"203.0.113.{Address}")), Is.False);

                return watch.Elapsed;

            }

            // One of each first, so that neither pays for warming up.
            await Timed(WWCPNode.DefaultAdminUser, 1);
            await Timed("nobody",                  2);

            var known    = (await Timed(WWCPNode.DefaultAdminUser, 3)) + (await Timed(WWCPNode.DefaultAdminUser, 4)) + (await Timed(WWCPNode.DefaultAdminUser, 5));
            var unknown  = (await Timed("nobody",                  6)) + (await Timed("nobody",                  7)) + (await Timed("nobody",                  8));

            Assert.That(unknown, Is.GreaterThan(known / 4), $"an unknown name took {unknown.TotalMilliseconds:0} ms, a known one {known.TotalMilliseconds:0} ms");

        }

        #endregion

        #region TheLegacyPasswordChangeIsRationed()

        /// <summary>
        /// SET ext/users/{id}/password tells a wrong current password with 403,
        /// ten times; the eleventh time, the right one is told to wait with 429
        /// and changes nothing: a session is no way to guess the password behind
        /// it at the speed of the hash.
        /// </summary>
        [Test]
        public async Task TheLegacyPasswordChangeIsRationed()
        {

            var node     = await Started();
            var session  = SessionOf(node, await SignIn(node, node.GeneratedPassword!));

            var answers  = new List<HttpStatusCode>();

            for (var guess = 1; guess <= 10; guess++)
            {
                using var wrong = await SetPassword(node, session, $"Not-The-Password-{guess}", "Correct-Horse-Battery-Staple-9!");
                answers.Add(wrong.StatusCode);
            }

            using var right = await SetPassword(node, session, node.GeneratedPassword!, "Correct-Horse-Battery-Staple-9!");

            using (Assert.EnterMultipleScope())
            {
                Assert.That(answers,                                                                            Has.All.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(right.StatusCode,                                                                   Is.EqualTo(HttpStatusCode.TooManyRequests));
                Assert.That(node.ExtAPI.VerifyPassword(User_Id.Parse(WWCPNode.DefaultAdminUser), node.GeneratedPassword!),  Is.True, "the password was changed");
            }

        }

        #endregion

        #region TheLegacyPasswordChangeStillChanges()

        /// <summary>
        /// With the right current password, SET ext/users/{id}/password changes
        /// it as before; with a wrong one, it says so and changes nothing.
        /// </summary>
        [Test]
        public async Task TheLegacyPasswordChangeStillChanges()
        {

            var node     = await Started();
            var session  = SessionOf(node, await SignIn(node, node.GeneratedPassword!));
            var userId   = User_Id.Parse(WWCPNode.DefaultAdminUser);

            using var wrong  = await SetPassword(node, session, "Not-The-Password", "Correct-Horse-Battery-Staple-9!");
            var unchanged    = node.ExtAPI.VerifyPassword(userId, node.GeneratedPassword!);

            using var right  = await SetPassword(node, session, node.GeneratedPassword!, "Correct-Horse-Battery-Staple-9!");

            using (Assert.EnterMultipleScope())
            {
                Assert.That(wrong.StatusCode,                                                       Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(await wrong.Content.ReadAsStringAsync(),                                Does.Contain("The password is wrong."));
                Assert.That(unchanged,                                                              Is.True);
                Assert.That(right.StatusCode,                                                       Is.EqualTo(HttpStatusCode.OK), await right.Content.ReadAsStringAsync());
                Assert.That(node.ExtAPI.VerifyPassword(userId, "Correct-Horse-Battery-Staple-9!"),  Is.True);
            }

        }

        #endregion

    }

}
