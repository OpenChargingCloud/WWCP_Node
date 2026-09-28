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
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// What happened inside the node, as a browser reads it: a snapshot of
    /// what led up to now, and then everything from now on over one
    /// Server-Sent Events stream - for as long as whoever opened it would
    /// still be let in.
    /// </summary>
    public abstract partial class NodeConformanceTests
    {

        #region (private) ShortHeartbeat()

        /// <summary>
        /// Make the event stream say something whenever it has been silent for
        /// 300 milliseconds, so that a test of what it does when nothing is
        /// logged does not wait fifteen seconds for it.
        /// </summary>
        private void ShortHeartbeat()
        {

            Assert.That(Node.JSONAPI, Is.Not.Null, $"This {Node.Kind.Name} has no JSON API.");

            Node.JSONAPI!.EventStreamHeartbeat = TimeSpan.FromMilliseconds(300);

        }

        #endregion


        #region TheSnapshotCarriesWhatHappened()

        [Test]
        public async Task TheSnapshotCarriesWhatHappened()
        {

            using var http = await SignedIn();

            Node.Log.Notice("A line written by a test.", "test");

            var page     = await GetJSON(http, "api/v1/logs?limit=500");
            var entries  = page["entries"] as JArray ?? [];

            Assert.Multiple(() => {

                Assert.That(entries.Count,                 Is.GreaterThan(0));
                Assert.That(page.Value<UInt64>("lastId"),  Is.GreaterThan(0));

                Assert.That(entries.Any(entry => entry.Value<String>("message") == "A line written by a test."),
                            Is.True,
                            "The line this test wrote is not in the snapshot it asked for.");

                // Every tag seen since the start, so that the Logs page can
                // offer them instead of asking somebody to guess.
                Assert.That(page["tags"]?.Values<String>(), Does.Contain("test"));

            });

        }

        #endregion

        #region ATagFiltersTheLog()

        /// <summary>
        /// The level counts as a tag, which is how "critical" and "ocpp" can be
        /// typed into the same filter box.
        /// </summary>
        [Test]
        public async Task ATagFiltersTheLog()
        {

            using var http = await SignedIn();

            Node.Log.Notice ("The first of two.",  "marked");
            Node.Log.Warning("The second of two.", "marked");
            Node.Log.Info   ("Not one of them.",   "elsewhere");

            var byTag   = await GetJSON(http, "api/v1/logs?tag=marked");
            var byLevel = await GetJSON(http, "api/v1/logs?tag=warning");

            var newestOnThePage = (byTag["entries"] as JArray)?.Max(entry => entry.Value<UInt64>("id")) ?? 0;

            Assert.Multiple(() => {

                Assert.That((byTag["entries"] as JArray)?.Count, Is.EqualTo(2));

                Assert.That((byLevel["entries"] as JArray)?.Any(entry => entry.Value<String>("message") == "The second of two."),
                            Is.True,
                            "Filtering by a level found nothing, so the level is not counting as a tag.");

                // The whole log's last id and not the newest entry of this
                // page: a page filtered by a tag would otherwise make the
                // browser ask again for everything between the two. The
                // unmatched line above was written after both matches, so the
                // two numbers have to differ.
                Assert.That(byTag.Value<UInt64>("lastId"), Is.GreaterThan(newestOnThePage),
                            "The page reports its own newest entry as the last id of the log.");

            });

        }

        #endregion

        #region AnImpossiblePageSizeIsRefused()

        [Test]
        public async Task AnImpossiblePageSizeIsRefused()
        {

            using var http = await SignedIn();

            var response = await http.GetAsync("api/v1/logs?limit=0");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));

        }

        #endregion


        #region TheEventStreamNeedsASession()

        [Test]
        public async Task TheEventStreamNeedsASession()
        {

            using var http = Anonymous();

            using var response = await http.GetAsync("api/v1/events", HttpCompletionOption.ResponseHeadersRead);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

        }

        #endregion

        #region TheEventStreamDeliversWhatHappensNext()

        /// <summary>
        /// The stream is what makes the Logs page a live one. A browser loads
        /// the snapshot, which says how far it reaches, and then applies
        /// everything from the stream with a greater id.
        /// </summary>
        [Test]
        public async Task TheEventStreamDeliversWhatHappensNext()
        {

            using var http   = await SignedIn();
            using var stream = await EventStream.Open(http);

            // Written after the stream is open, so that it is the stream
            // delivering it and not the cache of events being replayed to a
            // client that has just connected.
            const String message = "A line that has to arrive over the stream.";

            Node.Log.Notice(message, "test");

            Assert.That(await stream.ReadUntil(message), Is.True,
                        $"'{message}' did not arrive over the event stream within {EventStream.Timeout.TotalSeconds} seconds.");

        }

        #endregion

        #region TheStreamAsksAProxyNotToBufferIt()

        /// <summary>
        /// "X-Accel-Buffering: no" on the event stream.
        /// </summary>
        /// <remarks>
        /// nginx buffers what it passes on unless it is told otherwise, and a
        /// buffered event stream reached a browser as nothing at all - not even
        /// its header - until nginx gave up on it after 60 silent seconds.
        /// </remarks>
        [Test]
        public async Task TheStreamAsksAProxyNotToBufferIt()
        {

            using var http      = await SignedIn();
            using var response  = await http.GetAsync("api/v1/events", HttpCompletionOption.ResponseHeadersRead);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                                                 Is.EqualTo(HttpStatusCode.OK));
                Assert.That(response.Content.Headers.ContentType?.MediaType,                     Is.EqualTo("text/event-stream"));
                Assert.That(response.Headers.TryGetValues("X-Accel-Buffering", out var values),  Is.True, "the header is there");
                Assert.That(values,                                                              Is.EqualTo(new[] { "no" }));
            });

        }

        #endregion

        #region ASilentStreamSaysSoAndThenCarriesOn()

        /// <summary>
        /// A comment whenever the stream has been silent for the heartbeat, and
        /// the next entry after it as if nothing had happened.
        /// </summary>
        /// <remarks>
        /// nginx gives up on an upstream that has sent nothing for 60 seconds,
        /// and a node nobody is using says nothing for longer than that. The
        /// second half is the one that could go wrong: the stream waits for the
        /// next entry across the heartbeat instead of asking for it again, and
        /// an entry that arrived during one must neither be lost nor come twice.
        /// </remarks>
        [Test]
        public async Task ASilentStreamSaysSoAndThenCarriesOn()
        {

            ShortHeartbeat();

            using var http    = await SignedIn();
            using var stream  = await EventStream.Open(http);

            // Each step is judged as soon as it is taken, and not with the
            // rest: a read that waited in vain has closed the connection under
            // the reader, and the next read would fail with an exception that
            // says nothing about why.
            Assert.That(await stream.ReadUntil(": keep-alive"), Is.True,
                        $"No comment came down the stream in the {EventStream.Timeout.TotalSeconds} seconds nothing was logged.");

            var marker        = "A line for the event stream " + Guid.NewGuid().ToString("N")[..8];
            Node.Log.Info(marker, "test");

            Assert.That(await stream.ReadUntil(marker), Is.True,
                        $"The entry logged after the heartbeat did not come down the stream within {EventStream.Timeout.TotalSeconds} seconds.");

            // And the one after it, to be sure the stream is still waiting for
            // entries and not only for the heartbeat.
            var second        = marker + " (second)";
            Node.Log.Info(second, "test");

            var secondEntry   = await stream.ReadUntil(second);

            Assert.Multiple(() => {
                Assert.That(secondEntry,                    Is.True,        "the entry logged after that one arrived too");
                Assert.That(stream.Count($"\"{marker}\""),  Is.EqualTo(1),  "once");
            });

        }

        #endregion

        #region AStreamEndsWithTheSessionThatOpenedIt()

        /// <summary>
        /// Signed out, a stream opened with that session ends - and a line
        /// logged after the sign-out does not come down it first.
        /// </summary>
        /// <remarks>
        /// Measured before this was so: signed out, the Logs page went on
        /// saying "live" and showing every line the node wrote for as long as
        /// it was watched. A stream is a request that is answered for hours,
        /// and it was asked about its session once, when it opened.
        /// </remarks>
        [Test]
        public async Task AStreamEndsWithTheSessionThatOpenedIt()
        {

            ShortHeartbeat();

            using var http    = await SignedIn();
            using var stream  = await EventStream.OpenAndSettle(Node, http);

            Assert.That((await http.PostAsync("api/v1/auth/logout", null)).StatusCode,
                        Is.EqualTo(HttpStatusCode.NoContent));

            var afterwards    = "Logged after the sign-out " + Guid.NewGuid().ToString("N")[..8];
            Node.Log.Info(afterwards, "test");

            var ended         = await stream.EndsWithin(TimeSpan.FromSeconds(5));

            Assert.Multiple(() => {
                Assert.That(ended,                     Is.True,        "the stream went on after its session had ended");
                Assert.That(stream.Count(afterwards),  Is.EqualTo(0),  "a line logged after the sign-out was sent to the session that had signed out");
            });

        }

        #endregion

        #region AQuietStreamEndsWithItsSessionToo()

        /// <summary>
        /// And a stream nothing is logged into ends at its next heartbeat, not
        /// whenever the next line happens to be written - however the session
        /// ended. Here all of an account's sessions are taken back at once, the
        /// way a new password takes them, which logs nothing at all.
        /// </summary>
        [Test]
        public async Task AQuietStreamEndsWithItsSessionToo()
        {

            ShortHeartbeat();

            using var http    = await SignedIn();
            using var stream  = await EventStream.OpenAndSettle(Node, http);

            var session       = Node.ExtAPI.Sessions.Single();

            Assert.That(Node.ExtAPI.Sessions.RemoveAllForUser(session.UserId), Is.EqualTo(1));

            Assert.That(await stream.EndsWithin(TimeSpan.FromSeconds(3)), Is.True,
                        "a stream nothing was logged into went on after its session had ended");

        }

        #endregion

        #region AStreamOfAnotherSessionGoesOn()

        /// <summary>
        /// Only the stream of the session that ended ends: a second browser,
        /// signed in on its own, goes on being sent the log.
        /// </summary>
        [Test]
        public async Task AStreamOfAnotherSessionGoesOn()
        {

            using var mine    = await SignedIn();
            using var theirs  = await SignedIn();
            using var ending  = await EventStream.OpenAndSettle(Node, mine);
            using var going   = await EventStream.OpenAndSettle(Node, theirs);

            Assert.That((await mine.PostAsync("api/v1/auth/logout", null)).StatusCode,
                        Is.EqualTo(HttpStatusCode.NoContent));

            var afterwards    = "Logged after one of two signed out " + Guid.NewGuid().ToString("N")[..8];
            Node.Log.Info(afterwards, "test");

            var arrived       = await going. ReadUntil  (afterwards);
            var ended         = await ending.EndsWithin (TimeSpan.FromSeconds(5));

            Assert.Multiple(() => {
                Assert.That(arrived,                   Is.True,        "the stream of the session still signed in stopped too");
                Assert.That(ended,                     Is.True,        "the stream of the session that signed out went on");
                Assert.That(ending.Count(afterwards),  Is.EqualTo(0),  "a line logged after the sign-out was sent to the session that had signed out");
            });

        }

        #endregion

        #region (private) WithAPIKey(NotAfter = null)

        /// <summary>
        /// A client that opens the node with an API key of its first account,
        /// and nothing else: no session, no password.
        /// </summary>
        private async Task<(HttpClient HTTP, APIKey Key)> WithAPIKey(DateTimeOffset? NotAfter = null)
        {

            var key   = new APIKey(APIKey_Id.Parse("event-stream-" + Guid.NewGuid().ToString("N")),
                                   User_Id.Parse(AdminLogin),
                                   NotAfter: NotAfter);

            await Node.ExtAPI.AddAPIKey(key);

            Assert.That(Node.ExtAPI.TryGetAPIKey(key.Id, out _), Is.True,
                        "The API key was not added, so a test of taking it back would pass for the wrong reason.");

            var http  = Anonymous();

            http.DefaultRequestHeaders.Add("API-Key", key.Id.ToString());

            return (http, key);

        }

        #endregion

        #region AStreamOpenedWithAnAPIKeyEndsWithTheKey()

        /// <summary>
        /// A stream opened with an API key ends when the key is taken back -
        /// and a line logged afterwards does not come down it first.
        /// </summary>
        /// <remarks>
        /// Such a stream has no session that could end, and was held to its
        /// account alone: a key that was revoked went on being sent the log for
        /// as long as the account it belonged to was there.
        /// </remarks>
        [Test]
        public async Task AStreamOpenedWithAnAPIKeyEndsWithTheKey()
        {

            ShortHeartbeat();

            var (http, key)   = await WithAPIKey();

            using var client  = http;
            using var stream  = await EventStream.OpenAndSettle(Node, client);

            await Node.ExtAPI.RemoveAPIKey(key);

            Assert.That(Node.ExtAPI.TryGetAPIKey(key.Id, out _), Is.False, "the API key is gone");

            var afterwards    = "Logged after the key was taken back " + Guid.NewGuid().ToString("N")[..8];
            Node.Log.Info(afterwards, "test");

            var ended         = await stream.EndsWithin(TimeSpan.FromSeconds(5));

            Assert.Multiple(() => {
                Assert.That(ended,                     Is.True,        "the stream went on after its API key had been taken back");
                Assert.That(stream.Count(afterwards),  Is.EqualTo(0),  "a line logged after the key was taken back was sent over it");
            });

        }

        #endregion

        #region AStreamEndsWhenItsAPIKeyRunsOut()

        /// <summary>
        /// And one whose key runs out ends at the next heartbeat after, with
        /// nothing logged and nobody taking anything back.
        /// </summary>
        [Test]
        public async Task AStreamEndsWhenItsAPIKeyRunsOut()
        {

            ShortHeartbeat();

            // Long enough for the stream to settle before the key runs out.
            var runsOut       = DateTimeOffset.UtcNow.AddSeconds(5);
            var (http, _)     = await WithAPIKey(runsOut);

            using var client  = http;
            using var stream  = await EventStream.OpenAndSettle(Node, client);

            var ended         = await stream.EndsWithin(runsOut - DateTimeOffset.UtcNow + TimeSpan.FromSeconds(3));
            var endedAt       = DateTimeOffset.UtcNow;

            Assert.Multiple(() => {
                Assert.That(ended,    Is.True,                                                "the stream went on after its API key had run out");
                Assert.That(endedAt,  Is.GreaterThanOrEqualTo(runsOut.AddMilliseconds(-100)),  "the stream ended before its API key ran out, so something else ended it");
            });

        }

        #endregion

        #region AStreamOpenedWithAPasswordEndsWithANewPassword()

        /// <summary>
        /// A stream opened with a password is asked about the password before
        /// every entry, as a new request with it is: changed, the stream ends,
        /// and what is logged after the change is not sent down it. Held to the
        /// account alone, as it was on every kind of node, it went on.
        /// </summary>
        [Test]
        public async Task AStreamOpenedWithAPasswordEndsWithANewPassword()
        {

            ShortHeartbeat();

            var password        = "A-Reader-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
            var reader          = await AccountIn("reader1", Role.Viewer.Name, password);

            using var http      = WithPassword("reader1", password);
            using var stream    = await EventStream.OpenAndSettle(Node, http);

            var changed         = await Node.ExtAPI.ChangePassword(reader,
                                                                   "A-New-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)),
                                                                   password,
                                                                   SuppressNotifications: true);

            Assert.That(changed.Result, Is.EqualTo(CommandResult.Success), $"the password could not be changed: {changed.Description}");

            var afterwards      = "Logged after the new password " + Guid.NewGuid().ToString("N")[..8];
            Node.Log.Info(afterwards, "test");

            var ended           = await stream.EndsWithin(TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {
                Assert.That(ended,                     Is.True,        "a stream opened with the old password went on after it was changed");
                Assert.That(stream.Count(afterwards),  Is.EqualTo(0),  "the entry logged after the new password was sent to a stream opened with the old one");
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

            var password        = "A-Reader-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

            await AccountIn("reader2", Role.Viewer.Name, password);

            using var http      = WithPassword("reader2", password);
            using var stream    = await EventStream.OpenAndSettle(Node, http);

            var line            = "Line of fifteen " + Guid.NewGuid().ToString("N")[..8];

            for (var number = 1; number <= 15; number++)
                Node.Log.Info($"{line}: {number}", "test");

            Assert.That(await stream.ReadUntil($"{line}: 15"), Is.True,
                        "the stream ended before the fifteenth entry, so asking about the password was rationed like a guess");

        }

        #endregion

    }

}
