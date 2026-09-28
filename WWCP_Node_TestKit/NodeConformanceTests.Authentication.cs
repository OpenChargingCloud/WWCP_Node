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

        #region TheAPIRefusesWithoutASession(Path)

        /// <summary>
        /// What the node says of itself is for somebody signed in: every one of
        /// the reads every node has answers 401 to a browser that is not.
        /// </summary>
        [TestCase("api/v1/status")]
        [TestCase("api/v1/auth/me")]
        [TestCase("api/v1/clock")]
        [TestCase("api/v1/configuration")]
        [TestCase("api/v1/configuration/dns")]
        [TestCase("api/v1/configuration/nts")]
        [TestCase("api/v1/logs")]
        [TestCase("api/v1/certificates")]
        public async Task TheAPIRefusesWithoutASession(String Path)
        {

            using var http = Anonymous();

            var response = await http.GetAsync(Path);

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
                Assert.That(json.Value<String>("path"),                       Does.EndWith("api/v1/nothing/here"), "and which path that was");
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

        #region AnUnknownLoginIsAnsweredAsAWrongPassword()

        /// <summary>
        /// Whether an account exists is not told at the sign-in to somebody who
        /// does not know its password: a login nobody has is answered as a
        /// wrong password is, word for word.
        /// </summary>
        /// <remarks>
        /// It was 404 "Unknown login!" for the one and 401 "Invalid password!"
        /// for the other - and the first at once, the second after a hash
        /// (Hermod e646766f).
        /// </remarks>
        [Test]
        public async Task AnUnknownLoginIsAnsweredAsAWrongPassword()
        {

            using var http     = Anonymous();

            using var unknown  = await http.PostAsync(SignInPath, SignInBody("somebody-else", "Not-The-Password-1"));
            using var wrong    = await http.PostAsync(SignInPath, SignInBody(AdminLogin,      "Not-The-Password-1"));

            var unknownSaid    = await unknown.Content.ReadAsStringAsync();
            var wrongSaid      = await wrong.  Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(unknown.StatusCode,  Is.EqualTo(wrong.StatusCode),  $"{(Int32) unknown.StatusCode} {unknownSaid} / {(Int32) wrong.StatusCode} {wrongSaid}");
                Assert.That(unknownSaid,         Is.EqualTo(wrongSaid),         "the same words");
            });

        }

        #endregion

        #region APasswordOpensTheAPIAsTheSameAccount()

        /// <summary>
        /// The same account through the other door. Hermod offers cookies,
        /// HTTP Basic auth and API keys, and which one was used must not change
        /// what somebody may do: the permissions hang off the account and its
        /// groups, not off the way it arrived.
        /// </summary>
        /// <remarks>
        /// This is the shape that a membership compared by reference rather
        /// than by identification got wrong - the same account came out as the
        /// administrator through Basic auth and as nobody through a cookie - so
        /// the roles are asserted and not only the status.
        /// </remarks>
        [Test]
        public async Task APasswordOpensTheAPIAsTheSameAccount()
        {

            using var withPassword  = WithPassword(AdminLogin, Password);
            using var signedIn      = await SignedIn();

            var byPassword          = await GetJSON(withPassword, "api/v1/auth/me");
            var bySession           = await GetJSON(signedIn,     "api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(byPassword.Value<String>("username"),       Is.EqualTo(AdminLogin));
                Assert.That(byPassword["roles"]?.Values<String>(),      Is.EquivalentTo(bySession["roles"]?.Values<String>() ?? []));
                Assert.That(byPassword["roles"]?.Values<String>(),      Does.Contain(WWCPNode.AdminRole));
                Assert.That(byPassword["permissions"]?.Values<String>(),Is.EquivalentTo(bySession["permissions"]?.Values<String>() ?? []));
            });

        }

        #endregion

        #region APasswordSentWithEveryRequestIsNotRationedLikeAGuess()

        /// <summary>
        /// A client that sends the password with every request - a script, a
        /// probe, somebody else's back office - is let in every time.
        /// </summary>
        /// <remarks>
        /// Guessing a password over Basic auth is rationed: ten attempts per
        /// address and ten per account, then one every six seconds. The right
        /// password drew on that ration as well, so the eleventh request of a
        /// minute was answered 401. A password that was checked is believed
        /// again without being checked, or rationed, again.
        /// </remarks>
        [Test]
        public async Task APasswordSentWithEveryRequestIsNotRationedLikeAGuess()
        {

            using var http = WithPassword(AdminLogin, Password);

            var answered = new List<HttpStatusCode>();

            for (var request = 0; request < 25; request++)
            {
                using var response = await http.GetAsync("api/v1/auth/me");
                answered.Add(response.StatusCode);
            }

            Assert.That(answered, Is.All.EqualTo(HttpStatusCode.OK),
                        String.Join(", ", answered.Select(status => (Int32) status)));

        }

        #endregion

        #region GuessingAtTheSignInIsRationed()

        /// <summary>
        /// The sign-in lets ten guesses a minute through, and no more - not even
        /// the right password after them - and says so in a sentence the
        /// sign-in page shows.
        /// </summary>
        /// <remarks>
        /// The form verified every password it was sent, as fast as they came:
        /// fifteen wrong ones in three seconds, each answered "Invalid
        /// password!", while guessing over Basic auth was rationed.
        /// </remarks>
        [Test]
        public async Task GuessingAtTheSignInIsRationed()
        {

            using var http = Anonymous();

            var guesses = new List<HttpStatusCode>();

            for (var guess = 1; guess <= 10; guess++)
            {
                using var response = await http.PostAsync(SignInPath, SignInBody(AdminLogin, $"Not-The-Password-{guess}"));
                guesses.Add(response.StatusCode);
            }

            using var right  = await http.PostAsync(SignInPath, SignInBody(AdminLogin, Password));
            var said         = await right.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(guesses,           Is.All.EqualTo(HttpStatusCode.Unauthorized),
                            String.Join(", ", guesses.Select(status => (Int32) status)));
                Assert.That(right.StatusCode,  Is.EqualTo(HttpStatusCode.TooManyRequests),
                            "after ten guesses the right password waits like any other: " + said);
                Assert.That(said,              Does.Contain("\"description\""),
                            "what the sign-in page shows");
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
