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
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The JSON API every kind of node has, registered at "/api": signing out
    /// and who is signed in, the status and the clock, the configuration, name
    /// resolution and the time servers, the certificate store, the log, and
    /// one Server-Sent Events stream that carries everything that happens -
    /// and a JSON 404 for everything else below it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A kind of node derives its own API from this one and registers what only
    /// it has: the vehicle its charging, the charging station its EVSEs, the
    /// local controller its CSMS and its stations. What every node has is here,
    /// once. It used to be in each of them - eight copies of the same routes
    /// and helpers, which had begun to differ: the clock at two paths, one 404
    /// without PATCH, a stream that outlived a sign-out, an input checked in one
    /// and taken as it came in another.
    /// </para>
    /// <para>
    /// It lives in its own HTTPAPI so that unknown API paths never reach the
    /// single-page-application fallback of the web interface at "/": Hermod
    /// dispatches a request to the most specific HTTPAPI first. Within it, a
    /// route of the kind of node registered after the JSON 404 is still found:
    /// Hermod matches a path segment by segment, and a parameter that takes the
    /// rest of the path only where no segment matched.
    /// </para>
    /// <para>
    /// Everything below /api/v1 needs somebody signed in - the event stream
    /// included, which is why the stream is opened here by hand rather than
    /// through Hermod's MapEventSource. Signing in itself happens at the
    /// HTTPExt API's own "/ext/login"; this API only reads what that door set.
    /// </para>
    /// </remarks>
    public partial class NodeHTTPAPI : HTTPAPI
    {

        #region Data

        /// <summary>
        /// The identification of the Server-Sent Events source.
        /// </summary>
        public const           String    EventSourceName      = "events";

        /// <summary>
        /// The sub-event every log entry travels as.
        /// </summary>
        public const           String    LogEventName         = "log";

        /// <summary>
        /// How long an event stream stays silent before a comment is sent down
        /// it instead.
        /// </summary>
        /// <remarks>
        /// Silence is how an event stream waits, and a proxy in front of the
        /// node cannot tell it from a node that has gone: nginx gives up on an
        /// upstream that has sent nothing for 60 seconds. Fifteen seconds is
        /// what the HTML standard suggests for exactly this, and a browser skips
        /// a comment.
        /// </remarks>
        public static readonly TimeSpan  DefaultEventStreamHeartbeat = TimeSpan.FromSeconds(15);

        /// <summary>
        /// The most log entries one request may ask for.
        /// </summary>
        public const           Int32     MaxLogPageSize       = 2_000;

        /// <summary>
        /// How many log entries a request brings back when it does not say.
        /// </summary>
        public const           Int32     DefaultLogPageSize   = 500;

        private readonly DateTimeOffset  startedAt;

        /// <summary>
        /// Cancelled when this node is shutting down, so that the event
        /// streams end.
        /// </summary>
        /// <remarks>
        /// A browser on the Logs page holds a request open that is not waiting
        /// on its socket but on the next log entry, so closing the socket under
        /// it does not end it - and an HTTP server that waits for every request
        /// it started would then never finish stopping. This is what ends them
        /// instead; see <see cref="CloseEventStreams"/>.
        /// </remarks>
        private readonly CancellationTokenSource  shutdown = new ();

        #endregion

        #region Properties

        /// <summary>
        /// The node this API speaks for.
        /// </summary>
        public WWCPNode                  Node        { get; }

        /// <summary>
        /// Everything that happens inside this node.
        /// </summary>
        public EventLog                  Log         { get; }

        /// <summary>
        /// Who may open the web interface: the accounts, and the groups whose
        /// membership carries this node's roles.
        /// </summary>
        public HTTPExtAPI                ExtAPI      { get; }

        /// <summary>
        /// The version reported by the status resource.
        /// </summary>
        public String                    Version     { get; }

        /// <summary>
        /// The Server-Sent Events source every browser hangs on (/api/v1/events).
        /// </summary>
        public HTTPEventSource<JObject>  Events      { get; }

        /// <summary>
        /// How long an event stream stays silent before a comment is sent down
        /// it; <see cref="DefaultEventStreamHeartbeat"/> unless set, and never
        /// when set to zero.
        /// </summary>
        public TimeSpan                  EventStreamHeartbeat { get; set; } = DefaultEventStreamHeartbeat;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create and register the JSON API of a node within the given HTTP
        /// server.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server.</param>
        /// <param name="Node">The node this API speaks for.</param>
        /// <param name="ExtAPI">The accounts and the groups they are in.</param>
        /// <param name="Log">Everything that happens inside this node.</param>
        /// <param name="APIPath">The root path of the API, the node's own by default.</param>
        /// <param name="Version">The version reported by the status resource, the node's own by default.</param>
        public NodeHTTPAPI(HTTPServer  HTTPServer,
                           WWCPNode    Node,
                           HTTPExtAPI  ExtAPI,
                           EventLog    Log,
                           HTTPPath?   APIPath   = null,
                           String?     Version   = null)

            : base(HTTPServer,
                   RootPath:     APIPath ?? Node.HTTPRootPath,
                   Description:  I18NString.Create($"The JSON API of this {Node.Kind.Name}"))

        {

            this.Node        = Node;
            this.ExtAPI      = ExtAPI;
            this.Log         = Log;
            this.startedAt   = Node.TimeProvider.GetUtcNow();
            this.Version     = Version ?? Node.Version;

            // Hermod caches the last events and replays them to a new client.
            // The browser ignores everything older than the snapshot it loaded,
            // so a replay costs nothing but bytes; what it buys is that a
            // browser which reconnects after a hiccup gets what it missed.
            this.Events      = this.AddJSONEventSource(
                                 HTTPEventSource_Id.Parse(EventSourceName),
                                 MaxNumberOfCachedEvents:  500,
                                 RetryInterval:            TimeSpan.FromSeconds(2),
                                 EnableLogging:            false
                             );

            this.Log.OnLogged += entry => Publish(LogEventName, entry.ToJSON());

            RegisterNodeRoutes();

        }

        #endregion


        #region (private) RegisterNodeRoutes()

        private void RegisterNodeRoutes()
        {

            // No sign-in route here. Signing in happens at the HTTPExt API's
            // own "/ext/login", which is the only place that can check a
            // password: the check reads a store this API has no access to, and
            // a second door onto the same credentials is a second door to get
            // wrong. What this API does is read the cookie that door sets.
            AddHandler(HTTPPath.Root + "v1/auth/logout",   Logout,            HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/auth/me",       Me,                HTTPMethod.GET);

            AddHandler(HTTPPath.Root + "v1/status",        GetStatus,         HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/clock",         GetClock,          HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration", GetConfiguration,  HTTPMethod.GET);

            RegisterNameAndTimeRoutes();
            RegisterCertificateStoreRoutes();
            RegisterLogRoutes();

            // Everything else below /api answers with a JSON 404 instead of
            // the single-page-application stub of the web interface - with
            // PATCH among the methods, which one copy of this had left out.
            foreach (var method in new[] { HTTPMethod.GET, HTTPMethod.HEAD, HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE })
                AddHandler(HTTPPath.Root + "{path..}", UnknownPath, method);

        }

        #endregion


        #region (private) Logout          (Request)

        /// <summary>
        /// POST /api/v1/auth/logout: ends the session and expires the cookie.
        /// </summary>
        private Task<HTTPResponse> Logout(HTTPRequest Request)
        {

            if (RefuseCrossSite(Request) is HTTPResponse refused)
                return Task.FromResult(refused);

            // The session is ended where it lives, and not only forgotten by
            // this browser: a cookie that is merely expired is still a valid
            // token to whoever copied it.
            if (Request.Cookies is not null                                                      &&
                Request.Cookies.TryGet(ExtAPI.SessionCookieName, out var cookie)                 &&
                cookie is not null                                                               &&
                SecurityToken_Id.TryParse(cookie.FirstOrDefault().Key, out var securityTokenId))
            {

                ExtAPI.Sessions.Remove(securityTokenId);

                Log.Notice($"A session was ended from {Request.RemoteSocket}.", "web", "auth");

            }

            return Task.FromResult(
                       new HTTPResponse.Builder(Request) {
                           HTTPStatusCode  = HTTPStatusCode.NoContent,
                           CacheControl    = "no-store",
                           SetCookie       = ExpiredSessionCookie()
                       }.WithCommonSecurityHeaders().AsImmutable
                   );

        }

        #endregion

        #region (private) Me              (Request)

        /// <summary>
        /// GET /api/v1/auth/me: who is signed in, or 401.
        /// </summary>
        private Task<HTTPResponse> Me(HTTPRequest Request)

            => Task.FromResult(
                   TryGetUser(Request, out var user, out var unauthorized)
                       ? JSONResponse(Request, HTTPStatusCode.OK, MeJSON(user))
                       : unauthorized
               );

        #endregion


        #region (private) GetStatus       (Request)

        /// <summary>
        /// GET /api/v1/status: how this node is doing right now.
        /// </summary>
        /// <remarks>
        /// "service" is what the node is called after "OpenChargingCloud" - its
        /// kind's product - so that the answer of a vehicle and of a local
        /// controller can be told apart without knowing which was asked.
        /// </remarks>
        private Task<HTTPResponse> GetStatus(HTTPRequest Request)
        {

            if (!TryGetUser(Request, out _, out var unauthorized))
                return Task.FromResult(unauthorized);

            var now    = Node.TimeProvider.GetUtcNow();

            var status = new JObject(
                             new JProperty("service",    Node.Kind.Product),
                             new JProperty("version",    Version)
                         );

            foreach (var property in ProductStatus())
                status.Add(property);

            status.Add(new JProperty("hermod",     typeof(HTTPServer).Assembly.GetName().Version?.ToString(3)));
            status.Add(new JProperty("timestamp",  now.ToString("o")));
            status.Add(new JProperty("startedAt",  startedAt.ToString("o")));
            status.Add(new JProperty("uptime",     (now - startedAt).ToString(@"d\.hh\:mm\:ss")));
            status.Add(new JProperty("sessions",   ExtAPI.Sessions.Count()));
            status.Add(new JProperty("log",        new JObject(
                                                       new JProperty("entries",   Log.Count),
                                                       new JProperty("capacity",  Log.Capacity),
                                                       new JProperty("lastId",    Log.LastId),
                                                       new JProperty("tags",      new JArray(Log.KnownTags))
                                                   )));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, status)
                   );

        }

        #endregion

        #region (protected virtual) ProductStatus()

        /// <summary>
        /// What the status of this kind of node says beyond what every node's
        /// says - the identity a local controller has towards its CSMS, say -
        /// after "version".
        /// </summary>
        protected virtual IEnumerable<JProperty> ProductStatus()
            => [];

        #endregion

        #region (private) GetConfiguration(Request)

        /// <summary>
        /// GET /api/v1/configuration: what this node is made of.
        /// </summary>
        private Task<HTTPResponse> GetConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Configuration), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.ConfigurationJSON())
                   );

        }

        #endregion


        #region (private) UnknownPath     (Request)

        private Task<HTTPResponse> UnknownPath(HTTPRequest Request)

            => Task.FromResult(
                   JSONResponse(
                       Request,
                       HTTPStatusCode.NotFound,
                       new JObject(
                           new JProperty("error",  "Unknown API path"),
                           new JProperty("path",   Request.Path.ToString())
                       )
                   )
               );

        #endregion

        #region (protected) Publish(SubEvent, JSON)

        /// <summary>
        /// Hands an event to every browser. Fire-and-forget on purpose: this is
        /// called from inside whatever wrote the log entry, and none of those
        /// should wait for a slow browser.
        /// </summary>
        protected void Publish(String   SubEvent,
                               JObject  JSON)
        {

            Events.SubmitEvent(SubEvent, JSON).
                   ContinueWith(task => System.Diagnostics.Debug.WriteLine($"Publishing a '{SubEvent}' event failed: {task.Exception?.GetBaseException().Message}"),
                                TaskContinuationOptions.OnlyOnFaulted);

        }

        #endregion


        #region (protected) TryGetUser(Request, out User, out Unauthorized)

        /// <summary>
        /// Who is behind the request, or the 401 response - which also expires
        /// a stale cookie, so that the browser stops sending it.
        /// </summary>
        protected Boolean TryGetUser(HTTPRequest                             Request,
                                     [NotNullWhen(true)]  out IUser?         User,
                                     [NotNullWhen(false)] out HTTPResponse?  Unauthorized)
        {

            // Cookie, HTTP Basic auth or an API key - whichever of the three
            // the caller used. Which one it was does not change what they may
            // do: the groups do that, and they hang off the account rather than
            // off the door it came through.
            if (ExtAPI.TryGetHTTPUser(Request, out User) && User is not null)
            {
                Unauthorized = null;
                return true;
            }

            var builder = new HTTPResponse.Builder(Request) {
                              HTTPStatusCode  = HTTPStatusCode.Unauthorized,
                              ContentType     = HTTPContentType.Application.JSON_UTF8,
                              Content         = Encoding.UTF8.GetBytes(new JObject(new JProperty("error", "Sign in required.")).ToString(Formatting.None)),
                              CacheControl    = "no-store"
                          };

            if (Request.Cookies is not null &&
                Request.Cookies.TryGet(ExtAPI.SessionCookieName, out _))
            {
                builder.SetCookie = ExpiredSessionCookie();
            }

            Unauthorized = builder.WithCommonSecurityHeaders().AsImmutable;
            return false;

        }

        #endregion

        #region (protected) TryAuthorize(Request, Required, StateChanging, out User, out Refused)

        /// <summary>
        /// Who is behind the request, when they are allowed to do this - or
        /// the response that says why not.
        /// </summary>
        /// <remarks>
        /// Three refusals, in the order they have to happen: a request from
        /// another site is turned away before it is read at all, a request
        /// without a session is a 401 that also expires a stale cookie, and a
        /// request from somebody signed in who may not do this is a 403 naming
        /// what they are short of and the roles that carry it. The difference
        /// between the last two matters to a browser: 401 means sign in again,
        /// 403 means signing in again will not help.
        ///
        /// What the account may do is the node's to answer - see
        /// <see cref="WWCPNode.IsAllowed(IUser, IEnumerable{Permission})"/> -
        /// so that a role in the configuration file means here what it means
        /// on every other node.
        /// </remarks>
        /// <param name="Request">The request.</param>
        /// <param name="Required">What this request needs to be allowed: an operation on a resource.</param>
        /// <param name="StateChanging">Whether it changes something, and is therefore also checked for being cross-site.</param>
        /// <param name="User">Who is behind it.</param>
        /// <param name="Refused">The response to send instead.</param>
        protected Boolean TryAuthorize(HTTPRequest                             Request,
                                       Permission                              Required,
                                       Boolean                                 StateChanging,
                                       [NotNullWhen(true)]  out IUser?         User,
                                       [NotNullWhen(false)] out HTTPResponse?  Refused)

            => TryAuthorize(Request, [ Required ], StateChanging, out User, out Refused);


        /// <summary>
        /// Who is behind the request, when they are allowed to do all of this -
        /// or the response that says why not.
        /// </summary>
        /// <remarks>
        /// All of it or nothing: a change that is several kinds at once needs
        /// every one of them, each carried by whichever role of the account
        /// carries it.
        /// </remarks>
        protected Boolean TryAuthorize(HTTPRequest                             Request,
                                       IReadOnlyCollection<Permission>         Required,
                                       Boolean                                 StateChanging,
                                       [NotNullWhen(true)]  out IUser?         User,
                                       [NotNullWhen(false)] out HTTPResponse?  Refused)
        {

            User = null;

            if (StateChanging && RefuseCrossSite(Request) is HTTPResponse crossSite)
            {
                Refused = crossSite;
                return false;
            }

            if (!TryGetUser(Request, out User, out Refused))
                return false;

            if (!Node.IsAllowed(User, Required))
            {
                Refused  = RefusePermission(Request, User, Required, null);
                User     = null;
                return false;
            }

            Refused = null;
            return true;

        }

        #endregion

        #region (protected) RefusePermission(Request, User, Required, Because)

        /// <summary>
        /// The 403 for somebody signed in who may not do this, naming the roles
        /// that carry what they are short of.
        /// </summary>
        /// <remarks>
        /// Its own method because it is needed twice: once before a request is
        /// read, and once after - a change that is several kinds at once cannot
        /// be judged until it has been compared with what the node has, so that
        /// refusal happens with the body already parsed. Both say the same
        /// sentence, and both leave the same line in the log.
        /// </remarks>
        /// <param name="Because">What it was about this particular request, when the route alone does not say.</param>
        protected HTTPResponse RefusePermission(HTTPRequest                      Request,
                                                IUser                            User,
                                                IReadOnlyCollection<Permission>  Required,
                                                String?                          Because)
        {

            // Only roles that could do all of it on their own: nobody is named
            // who could only do half of it. The administrators can always do
            // all of it, so the sentence never runs out of roles.
            var allowed = Node.Access.RolesAllowing(Required).
                                      Select(role => role.Name);

            Log.Warning(
                $"'{User.Id}' was refused {String.Join(", ", Required)} on {Request.HTTPMethod} {Request.Path}; " +
                $"signed in as {String.Join(", ", Node.RolesOf(User).Select(role => role.Name))}." +
                (Because is null ? "" : $" {Because}"),
                "web", "auth"
            );

            return ErrorJSON(
                       Request,
                       HTTPStatusCode.Forbidden,
                       (Because is null ? "" : Because + " ") +
                       $"This needs the {String.Join(" or ", allowed)} role."
                   );

        }

        #endregion

        #region (protected static) RefuseCrossSite(Request)

        /// <summary>
        /// The 403 for a request that another site made the browser send, or
        /// null when the request is our own page's.
        /// </summary>
        /// <remarks>
        /// The cookie is SameSite=strict, so a cross-site request would arrive
        /// without a session anyway. This is the second lock on the same door:
        /// browsers say where a request came from (Sec-Fetch-Site, Origin), and
        /// a state-changing request from anywhere but this origin is refused
        /// before it is even read.
        /// </remarks>
        protected static HTTPResponse? RefuseCrossSite(HTTPRequest Request)
        {

            var site = Request.GetHeaderField("Sec-Fetch-Site");

            if (site is not null && site is not ("same-origin" or "none"))
                return ErrorJSON(Request, HTTPStatusCode.Forbidden, "Cross-site requests are refused.");

            var origin = Request.GetHeaderField("Origin");

            if (origin is not null && origin != "null")
            {

                var host = Request.GetHeaderField("Host") ?? "";

                if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
                    !uri.Authority.Equals(host, StringComparison.OrdinalIgnoreCase))
                {
                    return ErrorJSON(Request, HTTPStatusCode.Forbidden, "Cross-site requests are refused.");
                }

            }

            return null;

        }

        #endregion

        #region (protected static) TryParseJSONObject(Request, out JSON, out ErrorResponse)

        /// <summary>
        /// The request body as a JSON object, or the 400 response describing
        /// what is wrong with it.
        /// </summary>
        protected static Boolean TryParseJSONObject(HTTPRequest                             Request,
                                                    [NotNullWhen(true)]  out JObject?       JSON,
                                                    [NotNullWhen(false)] out HTTPResponse?  ErrorResponse)
        {

            JSON           = null;
            ErrorResponse  = null;

            var text = Request.HTTPBodyAsUTF8String;

            if (String.IsNullOrWhiteSpace(text))
            {
                ErrorResponse = ErrorJSON(Request, HTTPStatusCode.BadRequest, "The request body must be a JSON object!");
                return false;
            }

            try
            {
                JSON = JObject.Parse(text);
                return true;
            }
            catch (JsonException e)
            {
                ErrorResponse = ErrorJSON(Request, HTTPStatusCode.BadRequest, $"Invalid JSON: {e.Message}");
                return false;
            }

        }

        #endregion

        #region (private) MeJSON(User)

        /// <summary>
        /// Who is signed in, and what they may do.
        /// </summary>
        /// <remarks>
        /// The permissions travel to the browser so that a page can grey out
        /// what this person may not do, rather than offering it and letting
        /// them find out by being refused - spelt out resource by resource,
        /// "dns:edit", so that no page has to know what "*" is. They are a copy
        /// of what the node enforces and not the enforcement: every request is
        /// checked again on arrival, so a browser that edits this list gains
        /// nothing but a button that answers 403.
        /// </remarks>
        private JObject MeJSON(IUser User)

            => new (
                   new JProperty("username",     User.Id.ToString()),
                   new JProperty("roles",        new JArray(Node.RolesOf(User).Select(role => role.Name))),
                   new JProperty("permissions",  new JArray(Node.PermissionsOf(User).Select(permission => permission.ToString())))
               );

        #endregion

        #region (private) ExpiredSessionCookie()

        /// <summary>
        /// The Set-Cookie of a sign-out: the HTTPExt API's session cookie,
        /// expired in 1970, so that the browser drops it.
        /// </summary>
        /// <remarks>
        /// Written here rather than asked of the HTTPExt API, which sets its
        /// cookies inside its own handlers and has nothing to hand one out.
        /// One HTTPCookie parsed as one: HTTPCookies.Parse(String) is made for
        /// the Cookie header of a request, where a semicolon separates cookies,
        /// and would turn "Path=/" and "HttpOnly" into cookies of their own.
        /// </remarks>
        private HTTPCookies ExpiredSessionCookie()

            => new (HTTPCookie.Parse(
                        String.Concat(ExtAPI.SessionCookieName, "=",
                                      "; Expires=", DateTimeOffset.UnixEpoch.ToRFC1123(),
                                      "; Path=/",
                                      "; SameSite=strict",
                                      "; HttpOnly")
                    ));

        #endregion

        #region (protected static) ErrorJSON(...) / JSONResponse(...)

        /// <summary>
        /// An answer that says what is wrong, as {"error"}.
        /// </summary>
        protected static HTTPResponse ErrorJSON(HTTPRequest     Request,
                                                HTTPStatusCode  StatusCode,
                                                String          Message)

            => JSONResponse(
                   Request,
                   StatusCode,
                   new JObject(new JProperty("error", Message))
               );

        /// <summary>
        /// An answer in JSON, never cached.
        /// </summary>
        protected static HTTPResponse JSONResponse(HTTPRequest     Request,
                                                   HTTPStatusCode  StatusCode,
                                                   JToken          JSON)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode  = StatusCode,
                   ContentType     = HTTPContentType.Application.JSON_UTF8,
                   Content         = Encoding.UTF8.GetBytes(JSON.ToString(Formatting.None)),
                   CacheControl    = "no-store"
               }.WithCommonSecurityHeaders().AsImmutable;

        #endregion

    }

}
