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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// Who may ask the node anything, and what happens to everybody else.
    /// </summary>
    public abstract partial class NodeConformanceTests
    {

        #region TheAPIRefusesWithoutASession()

        [Test]
        public async Task TheAPIRefusesWithoutASession()
        {

            using var http = Anonymous();

            var response = await http.GetAsync("api/v1/status");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

        }

        #endregion

        #region EveryMethodBelowTheAPIIsAnsweredWithAJSON404(Method)

        /// <summary>
        /// The JSON API lives in its own HTTPAPI so that a mistyped API path
        /// never falls through to the single-page-application stub - a browser
        /// that asked for JSON and got HTML with status 200 has no way to tell
        /// what went wrong. For every method: one kind of node answered PATCH
        /// with the stub.
        /// </summary>
        [TestCase("GET")]
        [TestCase("POST")]
        [TestCase("PUT")]
        [TestCase("PATCH")]
        [TestCase("DELETE")]
        public async Task EveryMethodBelowTheAPIIsAnsweredWithAJSON404(String Method)
        {

            using var http     = await SignedIn();

            using var request  = new HttpRequestMessage(new HttpMethod(Method), "api/v1/nothing/here");

            if (Method is not ("GET" or "DELETE"))
                request.Content = JSONBody();

            using var response = await http.SendAsync(request);
            var json           = JObject.Parse(await response.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                              Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(response.Content.Headers.ContentType?.MediaType,  Is.EqualTo("application/json"));
                Assert.That(json.Value<String>("error"),                      Is.EqualTo("Unknown API path"), "not the web interface's page");
            });

        }

        #endregion

        #region AnUnknownAPIPathAnswersJSONEvenWithoutASession()

        /// <summary>
        /// And without anybody signed in: a path that is not there is not
        /// there for anybody, and asking who is asking first would tell a
        /// stranger which paths are.
        /// </summary>
        [Test]
        public async Task AnUnknownAPIPathAnswersJSONEvenWithoutASession()
        {

            using var http = Anonymous();

            var response = await http.GetAsync("api/v1/nonsense");

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                              Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(response.Content.Headers.ContentType?.MediaType,  Is.EqualTo("application/json"));
            });

        }

        #endregion

        #region TheJSONAPIHasNoSignIn()

        /// <summary>
        /// The one door that can check a password is the HTTPExt API's, and
        /// the JSON API has no second one onto the same credentials.
        /// </summary>
        [Test]
        public async Task TheJSONAPIHasNoSignIn()
        {

            using var http = Anonymous();

            var response = await http.PostAsync("api/v1/auth/login", SignInBody(AdminLogin, Password));

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                              Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(response.Content.Headers.ContentType?.MediaType,  Is.EqualTo("application/json"));
            });

        }

        #endregion

        #region EveryRoleHasItsGroup()

        /// <summary>
        /// One user group per role, made at every start - because a role is
        /// that group, and nothing else.
        /// </summary>
        /// <remarks>
        /// The failure that does not announce itself: AddUserGroup answers with
        /// a result rather than throwing, and the HTTPExt API's floor for a
        /// group identification is four characters - so a role called "cpo"
        /// was refused its group and simply did not exist, and the pages that
        /// asked for it refused everybody, correct password and all.
        /// </remarks>
        [Test]
        public void EveryRoleHasItsGroup()
        {

            Assert.Multiple(() => {

                foreach (var role in Node.Access.Roles)
                    Assert.That(Node.ExtAPI.TryGetUserGroup(role.GroupId, out _), Is.True,
                                $"The '{role.Name}' role has no user group, so nobody can ever hold it.");

            });

        }

        #endregion

        #region AWrongPasswordIsRefused() / AWrongLoginIsRefused()

        [Test]
        public async Task AWrongPasswordIsRefused()
        {

            using var http = Anonymous();

            var response = await http.PostAsync(SignInPath, SignInBody(AdminLogin, "not the password"));

            Assert.Multiple(() => {

                Assert.That(response.IsSuccessStatusCode, Is.False);

                // And nothing was let in on the strength of it: the cookie is
                // what a sign-in hands out, and a refusal that still handed one
                // out would pass the status check above and open the door.
                Assert.That(http.GetAsync("api/v1/status").Result.StatusCode,
                            Is.EqualTo(HttpStatusCode.Unauthorized));

            });

        }

        [Test]
        public async Task AWrongLoginIsRefused()
        {

            using var http = Anonymous();

            var response = await http.PostAsync(SignInPath, SignInBody("somebody-else", Password));

            Assert.Multiple(() => {

                Assert.That(response.IsSuccessStatusCode, Is.False);

                Assert.That(http.GetAsync("api/v1/status").Result.StatusCode,
                            Is.EqualTo(HttpStatusCode.Unauthorized));

            });

        }

        #endregion

        #region TheGeneratedPasswordSignsIn()

        /// <summary>
        /// The password the node made up at its first start, shown once on the
        /// console and kept nowhere but in its hash, opens the web interface.
        /// </summary>
        [Test]
        public async Task TheGeneratedPasswordSignsIn()
        {

            using var http = await SignedIn();

            var me = await GetJSON(http, "api/v1/auth/me");

            Assert.That(me.Value<String>("username"), Is.EqualTo(AdminLogin));

        }

        #endregion

        #region TheAccountSurvivesARestart()

        /// <summary>
        /// The accounts are read back at the next start, so the password
        /// somebody wrote down still works - and no second first account is
        /// made up beside the first.
        /// </summary>
        /// <remarks>
        /// The one that would not announce itself: without reading them back
        /// the store is empty at every start, the first start happens for ever,
        /// and the password on the console changes while the one in somebody's
        /// notebook stops working.
        /// </remarks>
        [Test]
        public async Task TheAccountSurvivesARestart()
        {

            var users = Node.ExtAPI.Users.Count();

            // Stopped rather than disposed: TearDown disposes this one.
            await Node.Stop();

            var again = NewNode(Directory, (JObject) Configuration.DeepClone());

            try
            {

                await again.Start();

                Assert.That(again.GeneratedPassword, Is.Null,
                            "A second password was made up, so the accounts of the first start were not read back.");

                using var http   = ClientOf(BaseURLOf(again));

                var       signIn = await http.PostAsync(SignInPath, SignInBody(AdminLogin, Password));

                Assert.That(signIn.IsSuccessStatusCode, Is.True,
                            $"The password from the first start no longer opens the {again.Kind.Name}.");

                var me = await GetJSON(http, "api/v1/auth/me");

                Assert.Multiple(() => {
                    Assert.That(again.ExtAPI.Users.Count(),          Is.EqualTo(users),  "the accounts of the first start, and no more");
                    Assert.That(me["roles"]?.Values<String>(),       Does.Contain(WWCPNode.AdminRole));
                });

            }
            finally
            {
                await again.DisposeAsync();
            }

        }

        #endregion

        #region TheFirstAccountMayDoEverything()

        /// <summary>
        /// A first start signs in as the node's administrator, because there is
        /// nobody else yet to hand the rest to. What the browser is told is a
        /// copy of what the node enforces and not the enforcement itself; this
        /// is the copy - every operation on every resource of this kind of
        /// node, spelt out.
        /// </summary>
        [Test]
        public async Task TheFirstAccountMayDoEverything()
        {

            using var http = await SignedIn();

            var me          = await GetJSON(http, "api/v1/auth/me");

            var roles       = me["roles"]?.      Values<String>().ToArray() ?? [];
            var permissions = me["permissions"]?.Values<String>().ToArray() ?? [];

            Assert.Multiple(() => {
                Assert.That(roles,       Does.Contain(WWCPNode.AdminRole));
                Assert.That(permissions, Is.EquivalentTo(from resource  in Node.Access.Resources
                                                         from operation in new[] { "read", "edit", "run" }
                                                         select $"{resource}:{operation}"));
                Assert.That(me.Properties().Select(property => property.Name).Take(3),
                            Is.EqualTo(new[] { "username", "roles", "permissions" }),
                            "what every node says comes first, and what the kind adds after it");
            });

        }

        #endregion

        #region SigningOutEndsTheSession()

        [Test]
        public async Task SigningOutEndsTheSession()
        {

            using var http = await SignedIn();

            Assert.That((await http.GetAsync("api/v1/auth/me")).IsSuccessStatusCode, Is.True,
                        "The session was not live before it was ended.");

            var logout = await http.PostAsync("api/v1/auth/logout", null);

            Assert.Multiple(() => {
                Assert.That(logout.StatusCode,                 Is.EqualTo(HttpStatusCode.NoContent));
                Assert.That(Node.ExtAPI.Sessions.Count(),      Is.EqualTo(0),
                            "The session was only forgotten by this browser, not ended where it lives.");
            });

            Assert.That((await http.GetAsync("api/v1/auth/me")).StatusCode,
                        Is.EqualTo(HttpStatusCode.Unauthorized),
                        $"The cookie still opened the {Node.Kind.Name} after signing out.");

        }

        #endregion

        #region SigningOutExpiresTheCookieIn1970()

        /// <summary>
        /// The browser is told to drop the cookie, rather than merely not being
        /// given a new one.
        /// </summary>
        /// <remarks>
        /// The HTTPExt API sets its cookies inside its own handlers and has
        /// nothing to hand one out, so the expiry is written on this side -
        /// which is why it is worth a test on this side.
        /// </remarks>
        [Test]
        public async Task SigningOutExpiresTheCookieIn1970()
        {

            using var http = await SignedIn();

            var logout  = await http.PostAsync("api/v1/auth/logout", null);

            var cookie  = logout.Headers.TryGetValues("Set-Cookie", out var values)
                              ? values.FirstOrDefault(value => value.StartsWith(Node.ExtAPI.SessionCookieName.ToString(), StringComparison.Ordinal))
                              : null;

            Assert.That(cookie, Is.Not.Null, "Signing out did not tell the browser to drop the cookie.");

            Assert.Multiple(() => {
                Assert.That(cookie, Does.Contain("Expires=Thu, 01 Jan 1970"));
                Assert.That(cookie, Does.Contain("Path=/"));
                Assert.That(cookie, Does.Contain("HttpOnly"));
            });

        }

        #endregion

        #region ACrossSiteChangeIsRefused() / ASameOriginChangeIsNotRefused()

        /// <summary>
        /// The session cookie is SameSite=strict, so a cross-site request would
        /// arrive without a session anyway. This is the second lock on the same
        /// door: browsers say where a request came from, and a state-changing
        /// request from anywhere but this origin is refused before it is read.
        /// </summary>
        [Test]
        public async Task ACrossSiteChangeIsRefused()
        {

            using var http = await SignedIn();

            var request = new HttpRequestMessage(HttpMethod.Put, "api/v1/configuration/dns") {
                              Content = JSONBody(new Newtonsoft.Json.Linq.JProperty("useCache", false))
                          };

            request.Headers.Add("Sec-Fetch-Site", "cross-site");

            var response = await http.SendAsync(request);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,       Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(Node.DNSClient.UseCache,   Is.True, "The refused request changed something anyway.");
            });

        }

        /// <summary>
        /// The other half of the test above: the header the node looks at is
        /// the one a browser sets for its own page, and that one has to go
        /// through - or the lock is on the wrong door.
        /// </summary>
        [Test]
        public async Task ASameOriginChangeIsNotRefused()
        {

            using var http = await SignedIn();

            var request = new HttpRequestMessage(HttpMethod.Put, "api/v1/configuration/dns") {
                              Content = JSONBody(new Newtonsoft.Json.Linq.JProperty("useCache", false))
                          };

            request.Headers.Add("Sec-Fetch-Site", "same-origin");

            var response = await http.SendAsync(request);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccessStatusCode,  Is.True);
                Assert.That(Node.DNSClient.UseCache,       Is.False);
            });

        }

        #endregion

    }

}
