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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The part of the JSON API that is about name resolution, the time
    /// servers and the clock.
    /// </summary>
    public partial class NodeHTTPAPI
    {

        #region (private) RegisterNameAndTimeRoutes()

        private void RegisterNameAndTimeRoutes()
        {

            AddHandler(HTTPPath.Root + "v1/configuration/dns",        GetDNSConfiguration,   HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/dns",        PutDNSConfiguration,   HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/configuration/dns/query",  PostDNSQuery,          HTTPMethod.POST);

            AddHandler(HTTPPath.Root + "v1/configuration/nts",        GetNTSConfiguration,   HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/nts",        PutNTSConfiguration,   HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/configuration/nts/sync",   PostNTSSync,           HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/nts/test",   PostNTSTest,           HTTPMethod.POST);

        }

        #endregion


        #region (private) GetDNSConfiguration(Request) / PutDNSConfiguration(Request)

        /// <summary>
        /// GET /api/v1/configuration/dns: how this node resolves names.
        /// </summary>
        private Task<HTTPResponse> GetDNSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.DNS), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.DNSConfigurationJSON())
                   );

        }

        /// <summary>
        /// PUT /api/v1/configuration/dns: change what may be changed about it.
        /// Answers with the whole configuration as it now stands, so that the
        /// page does not have to ask again to find out what it got.
        /// </summary>
        /// <remarks>
        /// Who changed it is in the log, as it is for the time source and the
        /// certificate store: the node says what changed, and only the request
        /// knows who. Of a device whose readings are evidence, which name
        /// servers it asked and who told it to is part of the evidence.
        /// </remarks>
        private Task<HTTPResponse> PutDNSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.DNS), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!Node.TryUpdateDNSConfiguration(json, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            Log.Notice($"'{user.Id}' changed the name resolution of this {Node.Kind.Name}.", "dns", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.DNSConfigurationJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/dns/query with {"name", "recordTypes"}
        /// and an optional {"server"}: make this node look a name up and say
        /// what came back.
        /// </summary>
        /// <remarks>
        /// A POST although it changes nothing here, because it makes this node
        /// send traffic to a host somebody named - which is not something to
        /// leave sitting in a URL that a browser may repeat, prefetch or put in
        /// a history.
        ///
        /// The server is the place of one of the configured name servers in
        /// the list, counted from 0, and asks that one and nothing else, and
        /// without the cache. Left out, the question is put the way this node
        /// resolves anything: to the servers in turn, until one answers. A place
        /// with no server at it is said in the answer; one that is not a place
        /// at all is refused here, rather than read as "all of them" - or, as
        /// the copies that took it as it came did, thrown out of as a 500.
        /// </remarks>
        private async Task<HTTPResponse> PostDNSQuery(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run (NodeResources.DNS), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var name = json.Value<String>("name")?.Trim();

            if (String.IsNullOrEmpty(name))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "A 'name' to look up is required.");

            if (!WWCPNode.TryParseRecordTypes(json["recordTypes"], out var recordTypes, out var problem))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, problem);

            Int32? server = null;

            if (json["server"] is JToken serverToken && serverToken.Type != JTokenType.Null)
            {

                if (serverToken.Type != JTokenType.Integer ||
                    serverToken.Value<Int64>() is < 0 or > Int32.MaxValue)
                {
                    return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     "'server' must be the place of a name server in the list, counted from 0.");
                }

                server = serverToken.Value<Int32>();

            }

            Log.Info($"'{user.Id}' asked this {Node.Kind.Name} to resolve '{name}'.", "dns", "test", "web");

            return JSONResponse(
                       Request,
                       HTTPStatusCode.OK,
                       await Node.ResolveAsync(name, recordTypes, server, Request.CancellationToken)
                   );

        }

        #endregion

        #region (private) GetNTSConfiguration(Request) / PutNTSConfiguration(Request) / PostNTSSync(Request)

        /// <summary>
        /// GET /api/v1/configuration/nts: where this node gets the time from.
        /// </summary>
        private Task<HTTPResponse> GetNTSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.NTS), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.NTSConfigurationJSON())
                   );

        }

        /// <summary>
        /// PUT /api/v1/configuration/nts: change what may be changed about it.
        /// </summary>
        private Task<HTTPResponse> PutNTSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.NTS), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!Node.TryUpdateNTSConfiguration(json, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            Log.Notice($"'{user.Id}' changed the time source of this {Node.Kind.Name}.", "nts", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.NTSConfigurationJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/nts/sync: one key exchange and one
        /// authenticated NTP request, with every step in the log.
        /// </summary>
        /// <remarks>
        /// Answers with the whole NTS configuration and not only with the
        /// result, because an exchange moves the cookie pool, the key material
        /// and the record of the last exchange - all of which the page is
        /// showing while it waits.
        /// </remarks>
        private async Task<HTTPResponse> PostNTSSync(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run (NodeResources.NTS), true, out var user, out var refused))
                return refused;

            Log.Info($"'{user.Id}' asked this {Node.Kind.Name} to synchronise its time.", "nts", "test", "web");

            var result = await Node.SyncTimeAsync(Request.CancellationToken);

            var json   = Node.NTSConfigurationJSON();

            json["result"] = result;

            return JSONResponse(Request, HTTPStatusCode.OK, json);

        }

        #endregion

        #region (private) PostNTSTest(Request)

        /// <summary>
        /// POST /api/v1/configuration/nts/test with an optional {"host"}: ask
        /// one time server everything there is to ask, and say where it got
        /// to.
        /// </summary>
        /// <remarks>
        /// "Sync now" says whether the group has a time; this says where one
        /// server got to - the name, the TCP connection, the TLS handshake and
        /// the certificate it presented, the key exchange, the authenticated
        /// request - each step timed and in the answer, so that a server that
        /// is merely slow can be told from one that is refusing.
        ///
        /// The host is optional and names the server to ask; left out, or
        /// empty, it is the configured one. The key exchange may name NTP
        /// servers other than itself, which is the other reason this takes a
        /// host at all. A host that is not a string is refused here, rather
        /// than thrown out of as a 500.
        ///
        /// At the diagnostics permission, with the other tests. Like "Sync
        /// now", it does not step the clock.
        /// </remarks>
        private async Task<HTTPResponse> PostNTSTest(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run (NodeResources.NTS), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (json["host"] is JToken hostToken && hostToken.Type is not (JTokenType.String or JTokenType.Null))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "'host' must be the name or the address of a time server.");

            var host = json.Value<String>("host")?.Trim();

            if (host?.Length == 0)
                host = null;

            Log.Info($"'{user.Id}' asked this {Node.Kind.Name} to test {(host is null ? "its time server" : $"the time server '{host}'")}.",
                     "nts", "test", "web");

            return JSONResponse(
                       Request,
                       HTTPStatusCode.OK,
                       await Node.TestTimeServerAsync(host, Request.CancellationToken)
                   );

        }

        #endregion


        #region (private) GetClock        (Request)

        /// <summary>
        /// GET /api/v1/clock: what time it is here, and what that is worth.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Separate from the NTS configuration although it is the same subject,
        /// because it answers a different question and is asked at a different
        /// rate: the configuration says where the time comes from and is read
        /// when somebody opens a page, this says whether the clock is currently
        /// worth anything and is read by whatever wants to keep saying so.
        /// </para>
        /// <para>
        /// At /v1/clock on every node. It was at /v1/configuration/time on five
        /// kinds of node and at /v1/clock on three; the clock is not a setting
        /// that is read and written, it is a resource of its own.
        /// </para>
        /// <para>
        /// For anybody signed in, as the log and the event stream are - see
        /// <see cref="ToReadTheClock"/> for a kind of node that asks more.
        /// </para>
        /// </remarks>
        private Task<HTTPResponse> GetClock(HTTPRequest Request)
        {

            if (ToReadTheClock is Permission required)
            {
                if (!TryAuthorize(Request, required, false, out _, out var refused))
                    return Task.FromResult(refused);
            }
            else if (!TryGetUser(Request, out _, out var unauthorized))
                return Task.FromResult(unauthorized);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.ClockJSON())
                   );

        }

        #endregion

        #region (protected virtual) ToReadTheClock

        /// <summary>
        /// What reading the clock needs beyond being signed in, or null for
        /// nothing more.
        /// </summary>
        /// <remarks>
        /// Nothing more by default: the clock is none of the resources a role
        /// is about, and whether the time here is worth anything is what
        /// everybody looking at a page needs.
        /// </remarks>
        protected virtual Permission? ToReadTheClock
            => null;

        #endregion

    }

}
