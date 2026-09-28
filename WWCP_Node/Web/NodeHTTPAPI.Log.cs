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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The part of the JSON API that is about the log: its snapshot, and the
    /// event stream that carries every entry after it.
    /// </summary>
    public partial class NodeHTTPAPI
    {

        #region (private) RegisterLogRoutes()

        private void RegisterLogRoutes()
        {

            AddHandler(HTTPPath.Root + "v1/logs",          GetLogs,           HTTPMethod.GET);

            AddHandler(HTTPMethod.GET,
                       HTTPPath.Root + "v1/events",
                       HTTPContentType.Text.EVENTSTREAM,
                       StreamEvents);

        }

        #endregion


        #region (protected virtual) ToReadTheLog

        /// <summary>
        /// What reading the log and its event stream needs beyond being signed
        /// in, or null for nothing more.
        /// </summary>
        /// <remarks>
        /// Nothing more by default: a page that cannot hear the event stream
        /// cannot show anything happening. A kind of node whose accounts include
        /// people the log is not for - the drivers of an e-mobility provider -
        /// asks for a permission they do not have.
        /// </remarks>
        protected virtual Permission? ToReadTheLog
            => null;

        #endregion

        #region (private) TryGetLogReader(Request, out Reader, out Refused)

        /// <summary>
        /// Who is asking for the log, when they may read it - or the answer
        /// that says why not.
        /// </summary>
        private Boolean TryGetLogReader(HTTPRequest                             Request,
                                        [NotNullWhen(true)]  out IUser?         Reader,
                                        [NotNullWhen(false)] out HTTPResponse?  Refused)
        {

            if (ToReadTheLog is Permission required)
                return TryAuthorize(Request, required, false, out Reader, out Refused);

            return TryGetUser(Request, out Reader, out Refused);

        }

        #endregion

        #region (private) MayReadTheLog(User)

        /// <summary>
        /// Whether the given account may still read the log - asked of an
        /// event stream before every entry, as its sign-in is.
        /// </summary>
        private Boolean MayReadTheLog(IUser User)

            => ToReadTheLog is not Permission required ||
               Node.IsAllowed(User, [ required ]);

        #endregion


        #region (private) GetLogs         (Request)

        /// <summary>
        /// GET /api/v1/logs?limit=&amp;after=&amp;tag=: what happened, oldest
        /// of the returned entries first.
        /// </summary>
        /// <remarks>
        /// This is the snapshot a browser loads before it starts following the
        /// event stream; "lastId" says how far it reaches, and everything the
        /// stream delivers with a greater id is new.
        /// </remarks>
        private Task<HTTPResponse> GetLogs(HTTPRequest Request)
        {

            if (!TryGetLogReader(Request, out _, out var refused))
                return Task.FromResult(refused);

            var limit    = Request.QueryString.GetInt32 ("limit") ?? DefaultLogPageSize;
            var after    = Request.QueryString.GetUInt64("after");
            var tag      = Request.QueryString.GetString("tag");

            if (limit < 1 || limit > MaxLogPageSize)
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'limit' must be between 1 and {MaxLogPageSize}.")
                       );

            var entries  = Log.Recent(limit, after, tag).ToArray();

            return Task.FromResult(
                       JSONResponse(
                           Request,
                           HTTPStatusCode.OK,
                           new JObject(
                               // The whole log's last id and not the last of
                               // this page: a page filtered by a tag would
                               // otherwise make the browser ask again for
                               // everything between the two.
                               new JProperty("lastId",   Log.LastId),
                               new JProperty("capacity", Log.Capacity),
                               new JProperty("tags",     new JArray(Log.KnownTags)),
                               new JProperty("entries",  new JArray(entries.Select(entry => entry.ToJSON())))
                           )
                       )
                   );

        }

        #endregion

        #region (private) StreamEvents    (Request)

        /// <summary>
        /// GET /api/v1/events: the Server-Sent Events stream every browser
        /// hangs on - see <see cref="EventStreamOf"/>.
        /// </summary>
        private Task<HTTPResponse> StreamEvents(HTTPRequest Request)
        {

            if (!TryGetLogReader(Request, out var reader, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       EventStreamOf(Request, Events, reader, MayReadTheLog)
                   );

        }

        #endregion

        #region (protected) EventStreamOf(Request, Source, Reader, MayStillRead = null)

        /// <summary>
        /// An event stream of the given source, carried for as long as whoever
        /// opened it would still be let in. Modelled on Hermod's
        /// MapEventSource, with the reader checked before every event and at
        /// every heartbeat, and without opening the stream to other origins.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The log's stream is one of these, and so is any stream a kind of node
        /// has of its own - the traffic a roaming hub passes on, say - which is
        /// why the source and what else the reader has to be allowed are
        /// parameters.
        /// </para>
        /// <para>
        /// Two things in here are for a proxy in front of the node, and both
        /// were learned from nginx as it comes - by the vehicle, whose Logs page
        /// stayed empty behind one.
        /// </para>
        /// <para>
        /// "X-Accel-Buffering: no", because nginx buffers what it passes on,
        /// and a buffered event stream reaches the browser as nothing at all -
        /// not even its header - until a buffer is full or the node has been
        /// silent long enough for nginx to give up on it. The browser never
        /// sees the stream open, so the Logs page says "reconnecting ..." and
        /// does not ask for its snapshot either: behind nginx the vehicle's
        /// header came after 72 seconds, and its stream ended 98 ms later.
        /// </para>
        /// <para>
        /// And a comment whenever the stream has been silent for
        /// <see cref="EventStreamHeartbeat"/>, because the 60 seconds after
        /// which nginx gives up are an ordinary pause for a node nobody is
        /// using.
        /// </para>
        /// </remarks>
        /// <param name="Request">The request that opens the stream.</param>
        /// <param name="Source">The events to carry.</param>
        /// <param name="Reader">Who it was let in as.</param>
        /// <param name="MayStillRead">What else the reader has to be allowed, asked with the sign-in; nothing more when null.</param>
        protected HTTPResponse EventStreamOf(HTTPRequest                Request,
                                             HTTPEventSource<JObject>   Source,
                                             IUser                      Reader,
                                             Func<IUser, Boolean>?      MayStillRead   = null)
        {

            var clientId    = Request.RemoteSocket.ToString();

            // Asked before every event and at every heartbeat - see StillLetIn().
            var stillLetIn  = StillLetIn(Request, Reader, MayStillRead);

            return new HTTPResponse.Builder(Request) {

                       HTTPStatusCode  = HTTPStatusCode.OK,
                       Server          = HTTPServer.HTTPServerName,
                       ContentType     = HTTPContentType.Text.EVENTSTREAM,
                       CacheControl    = "no-cache",
                       Connection      = ConnectionType.KeepAlive,

                       HTTPSSEWorker   = async (response, stream) => {

                           // Either the browser going away or this node
                           // shutting down ends the stream. The second one is
                           // not something the request's own token knows
                           // about - see CloseEventStreams().
                           using var ending = CancellationTokenSource.CreateLinkedTokenSource(
                                                  Request.CancellationToken,
                                                  shutdown.Token
                                              );

                           try
                           {

                               await stream.WriteAsync("retry: ");
                               await stream.WriteAsync(((UInt32) Source.RetryInterval.TotalMilliseconds).ToString());
                               await stream.WriteAsync("\n\n");

                               // The preamble has to leave the buffer now, not
                               // with the first event: on a quiet node the
                               // browser would otherwise wait for its first byte
                               // until its own read timeout expired.
                               await stream.FlushAsync(ending.Token);

                               var heartbeat  = EventStreamHeartbeat > TimeSpan.Zero
                                                    ? EventStreamHeartbeat
                                                    : Timeout.InfiniteTimeSpan;

                               await using var events = Source.GetAllEventsGreater(
                                                            clientId,
                                                            Request.GetHeaderField(HTTPRequestHeaderField.LastEventId),
                                                            ending.Token
                                                        ).GetAsyncEnumerator(ending.Token);

                               // The next event is waited for across heartbeats
                               // rather than asked for again: an enumerator takes
                               // one question at a time.
                               var next = events.MoveNextAsync().AsTask();

                               // Set when the stream ends because its sign-in did.
                               var signedOut = false;

                               try
                               {

                                   while (true)
                                   {

                                       try
                                       {
                                           if (!await next.WaitAsync(heartbeat, ending.Token))
                                               break;
                                       }
                                       catch (TimeoutException)
                                       {

                                           // A quiet stream is asked as well, or one
                                           // whose session ended would go on for as
                                           // long as nothing was logged.
                                           if (!stillLetIn())
                                           {
                                               signedOut = true;
                                               break;
                                           }

                                           await stream.WriteHeartbeat(CancellationToken: ending.Token);
                                           continue;

                                       }

                                       // Asked before the event is written, not after:
                                       // what was logged after the sign-out is not
                                       // sent to the session that signed out.
                                       if (!stillLetIn())
                                       {
                                           signedOut = true;
                                           break;
                                       }

                                       var httpEvent = events.Current;

                                       await stream.WriteAsync(httpEvent.SerializedHeader);
                                       await stream.WriteAsync(httpEvent.SerializedData);
                                       await stream.WriteAsync("\n\n");
                                       await stream.FlushAsync(ending.Token);

                                       next = events.MoveNextAsync().AsTask();

                                   }

                               }
                               finally
                               {
                                   // However the loop ended, the enumerator may
                                   // still be waiting for the next event - a
                                   // heartbeat that could not be written leaves it
                                   // so - and it cannot be disposed before it has
                                   // stopped. Cancelling stops it.
                                   ending.Cancel();

                                   try
                                   {
                                       await next;
                                   }
                                   catch
                                   { }
                               }

                               // Its sign-in over, the reader is told the one way a
                               // stream can tell anybody anything: it ends, and the
                               // browser's retry is answered with a 401.
                               if (signedOut)
                                   await Source.Unsubscribe(clientId);

                           }
                           catch (OperationCanceledException)
                           {
                               await Source.Unsubscribe(clientId);
                           }
                           catch (ObjectDisposedException)
                           {
                               await Source.Unsubscribe(clientId);
                           }
                           catch (Exception e)
                           {
                               await Source.Unsubscribe(clientId);

                               // Not through the event log: an event stream that
                               // ends because the browser went away is the normal
                               // end of one, and logging it here would publish an
                               // event to the very streams that are closing.
                               System.Diagnostics.Debug.WriteLine($"The event stream of {clientId} ended: {e.Message}");
                           }

                       }

                   }.Set("X-Accel-Buffering", "no").
                     WithCommonSecurityHeaders().
                     AsImmutable;

        }

        #endregion

        #region (protected) StillLetIn(Request, Reader, MayStillRead = null)

        /// <summary>
        /// Whether whoever opened an event stream would still be let in -
        /// asked before every event the stream is sent, and at every heartbeat.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A stream is one request that is answered for hours, and it used to
        /// be asked about its sign-in once, when it opened. Measured: signed
        /// out, the Logs page went on saying "live" and showing every line the
        /// node wrote, for as long as it was watched.
        /// </para>
        /// <para>
        /// A stream opened with a session is asked whether that session is
        /// still there and its account still one that may sign in - what a new
        /// request with the same cookie is asked. The session is looked at and
        /// not taken through Sessions.TryGet, which counts as a use: with an
        /// idle timeout, a Logs page left open would keep its session alive for
        /// ever, one line of the log at a time. Among the few sessions a node
        /// has, looking costs nothing.
        /// </para>
        /// <para>
        /// One opened with a password is asked about the password again, as a
        /// new request with it is. Hermod believes Basic credentials it has
        /// verified for a while without running PBKDF2 again or rationing them
        /// like a guess, and forgets them when the password changes (Hermod
        /// f4aa17db) - so the question costs an HMAC a line, and the stream
        /// ends with a new password. Held to its account alone, as it was, it
        /// outlived one: the e-mobility provider's node found it first. It needs
        /// that Hermod: an older one would run 600 000 rounds of PBKDF2 and a
        /// turn of the sign-in's rate limit for every line of the log. A
        /// password is asked before a key here because Hermod asks it first.
        /// </para>
        /// <para>
        /// One opened with an API key is asked about the key - still there,
        /// inside its window, not disabled, its owner still one that may sign
        /// in - which is what a new request with it is asked, and costs a
        /// lookup. Held to its account alone, a stream went on being sent the
        /// log after its key had been revoked or had run out.
        /// </para>
        /// <para>
        /// And whatever else the reader has to be allowed, with each of them:
        /// an account that lost the role the stream needs is let go as one that
        /// signed out is.
        /// </para>
        /// </remarks>
        /// <param name="Request">The request that opened the stream.</param>
        /// <param name="Reader">Who it was let in as.</param>
        /// <param name="MayStillRead">What else the reader has to be allowed; nothing more when null.</param>
        protected Func<Boolean> StillLetIn(HTTPRequest            Request,
                                           IUser                  Reader,
                                           Func<IUser, Boolean>?  MayStillRead   = null)
        {

            var mayRead = MayStillRead ?? (_ => true);

            if (Request.Cookies is not null                                                      &&
                Request.Cookies.TryGet(ExtAPI.SessionCookieName, out var cookie)                 &&
                cookie is not null                                                               &&
                SecurityToken_Id.TryParse(cookie.FirstOrDefault().Key, out var securityTokenId) &&
                LiveSession(securityTokenId) is not null)
            {
                return () => LiveSession(securityTokenId) is Session session  &&
                             ExtAPI.TryGetUser(session.UserId, out var user)   &&
                             HTTPExtAPI.CanAuthenticate(user)                  &&
                             mayRead(user);
            }

            if (Request.Authorization is HTTPBasicAuthentication)
            {
                return () => ExtAPI.TryGetHTTPUser(Request, out var user) &&
                             user is not null                              &&
                             mayRead(user);
            }

            if (Request.API_Key.HasValue &&
                ExtAPI.CheckHTTPAPIKey(Request) is not null)
            {
                return () => ExtAPI.CheckHTTPAPIKey(Request) is IUser user &&
                             mayRead(user);
            }

            var readerId = Reader.Id;

            return () => ExtAPI.TryGetUser(readerId, out var user) &&
                         HTTPExtAPI.CanAuthenticate(user)           &&
                         mayRead(user);


            Session? LiveSession(SecurityToken_Id Token)
            {

                var now = ExtAPI.Sessions.TimeProvider.GetUtcNow();

                return ExtAPI.Sessions.FirstOrDefault(session => session.Token == Token &&
                                                                 !session.IsExpired(now));

            }

        }

        #endregion

        #region CloseEventStreams()

        /// <summary>
        /// End every open event stream, so that the HTTP server can stop.
        /// </summary>
        /// <remarks>
        /// Called by the node before the server is stopped, and not by the
        /// server itself: an event stream is a request that has been answered
        /// and is still being written to, and Hermod waits for every request it
        /// started before it reports itself stopped. Closing the socket
        /// underneath one does not wake it, because it is waiting for the next
        /// log entry and not for the network - so without this, a node with one
        /// browser on its Logs page never finishes shutting down.
        ///
        /// The browsers see the connection end and reconnect by themselves;
        /// that is what the retry interval of the stream is for.
        /// </remarks>
        public void CloseEventStreams()
        {

            if (!shutdown.IsCancellationRequested)
                shutdown.Cancel();

        }

        #endregion

    }

}
