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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.KeyPins;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The part of the HTTP API of a node about its connections: what it
    /// connects to and is connected by, what they prove themselves with, the
    /// keys and certificates it holds up, the state of each connection, and
    /// the test of one. Every node with a connection store has the same
    /// routes - a charging station and a local controller as a CSMS, a PKI or
    /// a grid operator -, registered by <see cref="RegisterConnectionRoutes"/>.
    /// </summary>
    public partial class NodeHTTPAPI
    {

        #region Data

        /// <summary>
        /// The resource a user needs a right to for reading, changing and
        /// testing the connections; null until the routes are registered.
        /// </summary>
        private String? connectionsResource;

        #endregion

        #region (protected) RegisterConnectionRoutes(ConnectionsResource)

        /// <summary>
        /// The routes of the connections of this node, at the given resource.
        /// </summary>
        /// <param name="ConnectionsResource">The resource a user needs a right to for the connections.</param>
        protected void RegisterConnectionRoutes(String ConnectionsResource)
        {

            this.connectionsResource = ConnectionsResource;

            AddHandler(HTTPPath.Root + "v1/status/connections", GetConnectionStates, HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/authentications",        GetConnectionsAndAuth,     HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/authentications",        PostAuthentication,        HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/authentications/update", PostUpdateAuthentication,  HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/authentications/remove", PostRemoveAuthentication,  HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/connections",            GetConnectionsAndAuth,     HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/connections",            PostConnection,            HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/connections/update",     PostUpdateConnection,      HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/connections/remove",     PostRemoveConnection,      HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/connections/test",       PostTestConnection,        HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/connections/pinSetSigners",         PostPinSetSigner,        HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/connections/pinSetSigners/remove",  PostRemovePinSetSigner,  HTTPMethod.POST);

            // The keys the node signs in with over SSH, beside its own:
            // made and removed at what making a key in the certificate
            // store asks, because that is what they are - who the node is.
            AddHandler(HTTPPath.Root + "v1/configuration/sshKeys",                PostSshKey,                HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/sshKeys/remove",         PostRemoveSshKey,          HTTPMethod.POST);

        }

        #endregion


        /// <summary>
        /// The whole picture both pages work from: the credentials, the
        /// connections, and the client certificates a connection may name.
        /// </summary>
        /// <remarks>
        /// One answer for two pages rather than two answers, because the
        /// Connections page needs the credentials in order to offer them and
        /// the Authentication page needs the connections in order to say which
        /// ones would break. Two routes returning it is a convenience for
        /// whoever reads the API; they are deliberately the same handler, so
        /// the two pages can never come to disagree about what exists.
        ///
        /// The passwords and shared secrets are not in here. What is in here
        /// is whether each set of credentials has one - see
        /// <see cref="AuthenticationEntry.ToJSON"/>, which leaves them out
        /// unless it is writing the file itself.
        /// </remarks>
        protected Task<HTTPResponse> GetConnectionsAndAuth(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(connectionsResource!), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON())
                   );

        }

        /// <summary>
        /// GET /api/v1/status/connections: where each connection this node
        /// made stands.
        /// </summary>
        /// <remarks>
        /// Asked again and again by the Connections page while it is open, so
        /// that a connection lost or back again is seen without a reload -
        /// which is why it is its own route and not the whole configuration
        /// every few seconds. At the permission that reads the configuration,
        /// because what it says - the addresses, what the back end answered -
        /// is the configuration's.
        /// </remarks>
        protected Task<HTTPResponse> GetConnectionStates(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(connectionsResource!), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ConnectionStatesJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/authentications with
        /// {"description", "kind", "login", "secret", ...}: one set of
        /// credentials this node can prove itself with.
        /// </summary>
        /// <remarks>
        /// At the permission that changes how this node reaches the outside
        /// world, the same as the certificates and the name servers: a login
        /// for a back end is a statement about how this node gets to one,
        /// and nothing about what the equipment is or what it measures.
        /// </remarks>
        protected Task<HTTPResponse> PostAuthentication(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, wrongDescription, false));

            var kind         = json.Value<String>("kind");
            var login        = User_Id.TryParse(json.Value<String>("login"));
            var secret       = json.Value<String>("secret");

            String? id       = null;
            String? error;
            var notSaved     = false;

            var added        = kind?.Trim().ToLowerInvariant() switch {

                                   "basic"  => Node.Connections.TryAddBasicAuthentication(login, secret, description,
                                                                                               out id, out error, out notSaved),

                                   "totp"   => Node.Connections.TryAddTOTPAuthentication (login, secret, description,
                                                                                               out id, out error, out notSaved,
                                                                                               json.Value<Double?> ("validitySeconds"),
                                                                                               json.Value<UInt32?> ("length"),
                                                                                               json.Value<String>  ("alphabet"),
                                                                                               json.Value<String>  ("hashAlgorithm"),
                                                                                               json.Value<Boolean?>("tlsChannelBinding")),

                                   "token"  => Node.Connections.TryAddTokenAuthentication(secret, description,
                                                                                               out id, out error, out notSaved),

                                   _        => NotAKind(kind, out error)

                               };

            if (!added)
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error ?? "The credentials were not written down.", notSaved));
            }

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.Created,
                                    new JObject(
                                        new JProperty("id",          id),
                                        new JProperty("connections", ConnectionsJSON())
                                    ))
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/authentications/update with {"id", ...}.
        /// </summary>
        /// <remarks>
        /// A secret left out means the one already there stays. That is what
        /// makes it possible to correct a description without being shown the
        /// password - and being shown it is exactly what this node never
        /// does.
        /// </remarks>
        protected Task<HTTPResponse> PostUpdateAuthentication(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var id           = json.Value<String>("id");
            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, wrongDescription, false));

            var kind         = json.Value<String>("kind");
            var login        = User_Id.TryParse(json.Value<String>("login"));
            var secret       = json.Value<String>("secret");

            String? error;
            var notSaved     = false;

            var changed      = kind?.Trim().ToLowerInvariant() switch {

                                   "basic"  => Node.Connections.TryUpdateBasicAuthentication(id, login, secret, description,
                                                                                                  out error, out notSaved),

                                   "totp"   => Node.Connections.TryUpdateTOTPAuthentication (id, login, secret, description,
                                                                                                  out error, out notSaved,
                                                                                                  json.Value<Double?> ("validitySeconds"),
                                                                                                  json.Value<UInt32?> ("length"),
                                                                                                  json.Value<String>  ("alphabet"),
                                                                                                  json.Value<String>  ("hashAlgorithm"),
                                                                                                  json.Value<Boolean?>("tlsChannelBinding")),

                                   "token"  => Node.Connections.TryUpdateTokenAuthentication(id, secret, description,
                                                                                                  out error, out notSaved),

                                   _        => NotAKind(kind, out error)

                               };

            if (!changed)
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error ?? "The credentials were not changed.", notSaved));
            }

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON())
                   );

        }

        /// <summary>
        /// Why credentials of the given kind are not taken: it is not one of
        /// "basic", "totp" and "token".
        /// </summary>
        private Boolean NotAKind(String? Kind, out String? Error)
        {
            Error = $"'{Kind}' is not a kind of authentication this {Node.NodeNoun} knows.";
            return false;
        }

        /// <summary>
        /// POST /api/v1/configuration/authentications/remove with {"id"}.
        /// </summary>
        /// <remarks>
        /// Refused while a connection is using it, and the refusal names the
        /// connection: the alternative leaves a station that cannot connect home
        /// and tells nobody why.
        /// </remarks>
        protected Task<HTTPResponse> PostRemoveAuthentication(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!Node.Connections.TryRemoveAuthentication(json.Value<String>("id"), out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/connections with
        /// {"description", "url", "connectionType", ...}: one place this
        /// station connects to.
        /// </summary>
        protected async Task<HTTPResponse> PostConnection(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (!TryPinsOf(json, out var pins, out var wrongPins))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongPins, false);

            if (!ConnectionIdentity.TryParse(json["identities"], out var identities, out var wrongIdentities))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongIdentities, false);

            if (!TryURLOf(json, out var url, out var wrongURL))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongURL, false);

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongDescription, false);

            if (!Node.Connections.TryAddConnection(description,
                                                       url,
                                                       json.Value<String>("connectionType"),
                                                       json.Value<Boolean?>("autoConnect"),
                                                       json.Value<String>("authenticationId"),
                                                       json.Value<String>("certificateId"),
                                                       out var id,
                                                       out var error,
                                                       out var notSaved,
                                                       json.Value<String>("ocppVersion"),
                                                       json.Value<String>("sshHostKey"),
                                                       ConnectionFields.SshTrustOf(json),
                                                       ConnectionFields.KeyPinsOf(json, ConnectionEntry.ClientKeyPinsKey) ?? ConnectionFields.KeyPinsOf(json, "serverKeyPins"),
                                                       ConnectionFields.KeyPinTrustOf(json),
                                                       pins,
                                                       json.Value<String>(ConnectionEntry.HTTPVersionKey),
                                                       json.Value<String>(ConnectionEntry.EncodingKey),
                                                       json.Value<String>(ConnectionEntry.SignatureFormatsKey),
                                                       json["identities"] is null ? null : identities,
                                                       json.Value<Boolean?>(ConnectionEntry.InboundKey),
                                                       json.Value<String>(ConnectionEntry.RemoteNodeIdKey),
                                                       OCPIVersion:     json.Value<String>(ConnectionEntry.OCPIVersionKey),
                                                       OpenADRBinding:  json.Value<String>(ConnectionEntry.OpenADRBindingKey),
                                                       VEN:             json.Value<String>(ConnectionEntry.VENKey)))
            {
                return NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved);
            }

            await SshKeyIfNeeded(id, Request.CancellationToken);

            return JSONResponse(Request, HTTPStatusCode.Created,
                                new JObject(
                                    new JProperty("id",          id),
                                    new JProperty("connections", ConnectionsJSON())
                                ));

        }

        /// <summary>
        /// POST /api/v1/configuration/connections/update with {"id", ...}.
        /// </summary>
        /// <remarks>
        /// The host key as the page showed it comes back beside the one in the
        /// form: where somebody left it as it was, the one there is now stays -
        /// written down meanwhile by the first connection, perhaps. The same
        /// for the key pins of a wss:// connection, which a signed pin set may
        /// have replaced meanwhile.
        /// </remarks>
        protected async Task<HTTPResponse> PostUpdateConnection(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (!TryPinsOf(json, out var pins, out var wrongPins))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongPins, false);

            if (!ConnectionIdentity.TryParse(json["identities"], out var identities, out var wrongIdentities))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongIdentities, false);

            if (!TryURLOf(json, out var url, out var wrongURL))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongURL, false);

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return NotChanged(Request, HTTPStatusCode.BadRequest, wrongDescription, false);

            if (!Node.Connections.TryUpdateConnection(json.Value<String>("id"),
                                                          description,
                                                          url,
                                                          json.Value<String>("connectionType"),
                                                          json.Value<Boolean?>("autoConnect"),
                                                          json.Value<String>("authenticationId"),
                                                          json.Value<String>("certificateId"),
                                                          out var error,
                                                          out var notSaved,
                                                          json.Value<String>("ocppVersion"),
                                                          json.Value<String>("sshHostKey"),
                                                          json.Value<String>("sshHostKeyAsShown"),
                                                          ConnectionFields.SshTrustOf(json),
                                                          ConnectionFields.KeyPinsOf(json, "serverKeyPins"),
                                                          ConnectionFields.KeyPinsOf(json, "serverKeyPinsAsShown"),
                                                          ConnectionFields.KeyPinTrustOf(json),
                                                          pins,
                                                          json.Value<String>(ConnectionEntry.HTTPVersionKey),
                                                          json.Value<String>(ConnectionEntry.EncodingKey),
                                                          json.Value<String>(ConnectionEntry.SignatureFormatsKey),
                                                          json["identities"] is null ? null : identities,
                                                          json.Value<Boolean?>(ConnectionEntry.InboundKey),
                                                          json.Value<String>(ConnectionEntry.RemoteNodeIdKey),
                                                          OCPIVersion:     json.Value<String>(ConnectionEntry.OCPIVersionKey),
                                                          OpenADRBinding:  json.Value<String>(ConnectionEntry.OpenADRBindingKey),
                                                          VEN:             json.Value<String>(ConnectionEntry.VENKey)))
            {
                return NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved);
            }

            await SshKeyIfNeeded(json.Value<String>("id"), Request.CancellationToken);

            return JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON());

        }

        /// <summary>
        /// POST /api/v1/configuration/connections/remove with {"id"}.
        /// </summary>
        /// <remarks>
        /// The credentials it was using stay behind: they are frequently the
        /// ones whatever replaces it will use.
        /// </remarks>
        protected Task<HTTPResponse> PostRemoveConnection(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!Node.Connections.TryRemoveConnection(json.Value<String>("id"), out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/connections/test with the fields of a
        /// connection: make it once, and say everything that happened.
        ///
        /// The fields rather than an identification, because the page offers
        /// this beside a connection being written down for the first time as
        /// well as beside one that already exists - and in both cases what
        /// somebody means by "test it" is what is on the screen. Nothing is
        /// stored either way.
        /// </summary>
        /// <remarks>
        /// At the diagnostics permission and not at the one that reads the
        /// configuration, for the same reason the name server and time server
        /// tests are: this makes the station open a connection to a host and
        /// show it a credential. That is more than it sounds like to hand to
        /// everybody who may look at a page, and it is less than changing what
        /// the station is configured to do - which is why it is not the
        /// network-settings permission either.
        ///
        /// It holds the request open for as long as the test takes, which is
        /// the connection plus about two seconds. The page's own deadline for
        /// a write is comfortably longer.
        /// </remarks>
        protected async Task<HTTPResponse> PostTestConnection(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run(connectionsResource!), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            Log.Info($"'{user.Id}' asked this node to test a connection.", "ocpp", "connections", "test", "web");

            // With "ocppRequest" for what is asked in OCPP once it is
            // connected: "heartbeat", which it is where nothing is said, or "none".
            return JSONResponse(
                       Request,
                       HTTPStatusCode.OK,
                       await Node.TestConnection(json, Request.CancellationToken)
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/connections/pinSetSigners with
        /// {"publicKey", "description"}: a key a pin set for a connection over
        /// SSH is believed of - the CSMS's signing anchor.
        /// </summary>
        protected Task<HTTPResponse> PostPinSetSigner(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!Node.Connections.TryAddPinSetSigner(json.Value<String>("publicKey"), json.Value<String>("description"), out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, ConnectionsJSON()));

        }

        /// <summary>
        /// POST /api/v1/configuration/connections/pinSetSigners/remove with
        /// {"publicKey"}: no pin set signed by it is believed any more.
        /// </summary>
        protected Task<HTTPResponse> PostRemovePinSetSigner(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(connectionsResource!), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!Node.Connections.TryRemovePinSetSigner(json.Value<String>("publicKey"), out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON()));

        }

        /// <summary>
        /// Where a connection goes, as it was sent under "url" - or null, where
        /// nothing was sent.
        /// </summary>
        /// <remarks>
        /// What is wrong with the URL as it was typed is said here. That there
        /// is none is said by the store, after what is wrong with the
        /// description, and so in the same order as before there was a URL.
        /// </remarks>
        protected static Boolean TryURLOf(JObject                           JSON,
                                          out URL?                          URL,
                                          [NotNullWhen(false)] out String?  Error)
        {

            URL    = null;
            Error  = null;

            var text = JSON.Value<String>("url");

            if (String.IsNullOrWhiteSpace(text))
                return true;

            if (!ConnectionEntry.TryParseURL(text, out var url, out Error))
                return false;

            URL = url;
            return true;

        }

        /// <summary>
        /// What the server of a wss:// connection checked by its CA is held to,
        /// as it was sent under "pins" - with what the page showed it held to,
        /// under "pinsAsShown", where it says so - or null, where neither was
        /// sent, to keep what it is held to.
        /// </summary>
        /// <remarks>
        /// Whether it is a wss:// connection at all is asked where the URL is
        /// known. What is read here is whether the words are ones a server can
        /// be held to: the same ones, and refused with the same sentences, as
        /// those of a time server, a name server and a meter.
        /// </remarks>
        protected static Boolean TryPinsOf(JObject                           JSON,
                                         out ServerPinsChange?        Pins,
                                         [NotNullWhen(false)] out String?  Error)
        {

            Pins   = null;
            Error  = null;

            // What the client certificate of the other end of a connection it
            // is connected to by was held to, while the connection said it: the
            // other end signs in with its WebSocket login now.
            if (JSON[ConnectionEntry.ClientPinsKey]    is JToken { Type: not JTokenType.Null } ||
                JSON[ConnectionEntry.ClientKeyPinsKey] is JToken { Type: not JTokenType.Null })
            {
                Error = $"'{ConnectionEntry.ClientKeyPinsKey}' and '{ConnectionEntry.ClientPinsKey}' are no more: the other end of a connection it makes " +
                         "signs in with the WebSocket login of the name it comes under - its key pins are said there, and the chains its " +
                         "certificate may lead to under Accepted chains.";
                return false;
            }

            var sentKey    = ConnectionEntry.PinsKey;
            var shownKey   = ConnectionEntry.PinsAsShownKey;

            var sent   = JSON[sentKey];
            var shown  = JSON[shownKey];

            if (sent is null && shown is null)
                return true;

            if (!TryServerPins(sent,  sentKey,  out var sentPins,  out Error) ||
                !TryServerPins(shown, shownKey, out var shownPins, out Error))
            {
                return false;
            }

            Pins = new ServerPinsChange(sentPins, shownPins, shown is not null);
            return true;

        }

        protected static Boolean TryServerPins(JToken?                                              JSON,
                                             String                                               Path,
                                             out protocols.WWCP.Node.Configuration.ServerPins?    Pins,
                                             [NotNullWhen(false)] out String?                     Error)
        {

            Pins   = null;
            Error  = null;

            if (JSON is null || JSON.Type == JTokenType.Null)
                return true;

            if (JSON is not JObject entry)
            {
                Error = $"'{Path}' is no object: it holds what the server is held to under 'certificateFingerprints', 'rootFingerprints', 'rootGroup', 'onMismatch' and 'trustOnFirstUse'.";
                return false;
            }

            return protocols.WWCP.Node.Configuration.ServerPins.TryParse(entry, Path, out Pins, out Error);

        }

        /// <summary>
        /// What both pages are handed, in one place.
        /// </summary>
        protected JObject ConnectionsJSON()
        {

            var json = Node.Connections.ToJSON();

            // How many charging stations each peer gets, where this node
            // forwards them: by their targets, and now.
            if (Node.StationsByPeer() is IReadOnlyDictionary<String, PeerStations> stationsByPeer)
                foreach (var peer in json["peers"]?.OfType<JObject>() ?? [])
                    if (peer.Value<String>("id") is String peerId &&
                        stationsByPeer.TryGetValue(peerId, out var stations))
                    {
                        peer.Add(new JProperty("stations", stations.ToJSON()));
                    }

            // What this node made of the certificate the server of each
            // wss:// connection checked by its CA showed last: what its page
            // offers to hold it to, and says it came to.
            foreach (var connection in json["connections"]?.OfType<JObject>() ?? [])
            {

                // Which version of HTTP the WebSocket it has now was opened
                // over: where the server chose, the entry does not say.
                if (URL.TryParse(connection.Value<String>("url") ?? "", out var connectedTo) &&
                    Node.HTTPVersionInUseAt(connectedTo) is String httpVersionInUse)
                {
                    connection.Add(new JProperty("httpVersionInUse", httpVersionInUse));
                }

                // Which subprotocol it agreed on, and so how its messages are
                // written: where the back end chose, the entry does not say.
                // Over a WebSocket and over ssh:// alike.
                if (connection.Value<String>("id") is String connectionId &&
                    Node.Connections.Connections.FirstOrDefault(entry => entry.Id == connectionId) is ConnectionEntry itsEntry &&
                    Node.SubprotocolInUseOf(itsEntry) is String subprotocolInUse)
                {
                    connection.Add(new JProperty("subprotocolInUse", subprotocolInUse));
                }

                if (connection.Value<Boolean?>("secure")    != true ||
                    connection.Value<Boolean?>("keyPinned") == true ||
                    !URL.TryParse(connection.Value<String>("url") ?? "", out var url))
                {
                    continue;
                }

                if (Node.LastJudgementOf(Node.ConnectionsCertificateUsage, url.Host.ToString()) is { } judgement)
                    connection.Add(new JProperty("judgement", judgement.ToJSON()));

            }

            // Which certificates a connection may point at. Read from the
            // certificate store rather than remembered here, so that one
            // removed on the page next door is gone from this list too.
            // The key this node signs in with over SSH, for the line that
            // goes into a server's authorized_keys - null until the first
            // ssh:// connection made it.
            json.Add(new JProperty("sshClientKey", Node.SshKey.ToJSON()));

            // Every key it signs in with over SSH: its own first - named
            // whether it was made yet or not, since a connection that names
            // none signs in with it - and the ones somebody made.
            json.Add(new JProperty("sshKeys", Node.SshKeys.ToJSON()));

            // Who this node is as a client: the identities of its
            // certificate store, which is where they are looked after - one
            // that is switched off or has run out is still named, with why
            // it cannot be shown.
            json.Add(
                new JProperty("certificates",
                    new JArray(
                        Node.Certificates.ByKind(CertificateKind.TLSIdentity).Select(entry =>
                            new JObject(
                                new JProperty("id",              entry.Id),
                                new JProperty("label",           entry.Label),
                                new JProperty("subject",         entry.Subject),
                                new JProperty("algorithm",       entry.KeyAlgorithm),
                                new JProperty("notAfter",        entry.NotAfter.UtcDateTime),
                                new JProperty("active",          entry.IsActive),
                                new JProperty("hasCertificate",  true),
                                new JProperty("canBeHeldUp",     entry.HasPrivateKey && entry.IsUsable)
                            )))));

            // Where each connection stands, so that the page does not first
            // draw every connection without it and then again with it.
            json.Merge(ConnectionStatesJSON());

            return json;

        }

        /// <summary>
        /// Where each connection this node made stands, by
        /// identification, and what time it is here.
        /// </summary>
        /// <remarks>
        /// The time, because the page says how long ago and how soon, and the
        /// clock it would otherwise ask is the browser's - which is not this
        /// station's, and on a laptop in a car park not always right either.
        /// </remarks>
        protected JObject ConnectionStatesJSON()

            => new (
                   new JProperty("timestamp",  Node.TimeProvider.GetUtcNow().UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                   new JProperty("states",     new JObject(
                       Node.ConnectionStates.Select(entry => new JProperty(entry.Key, entry.Value.ToJSON()))
                   ))
               );

        /// <summary>
        /// POST /api/v1/configuration/sshKeys with {"label"}: make a key this
        /// node signs in with over SSH, beside its own.
        /// </summary>
        /// <remarks>
        /// At what making a key in the certificate store asks, and not at the
        /// permission to change the connections: a key is who the node is,
        /// and which connection shows it is another matter. What comes back
        /// is its public half - the private one never leaves its file.
        /// </remarks>
        protected async Task<HTTPResponse> PostSshKey(HTTPRequest Request)
        {

            if (!TryAuthorizeKeys(Request, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var (entry, error) = await Node.SshKeys.MakeAsync(json.Value<String>("label"), Request.CancellationToken);

            if (entry is null)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, error ?? "The key could not be made.");

            Log.Info($"'{user.Id}' made the SSH key '{entry.Label}' ({entry.Key.Fingerprint}).", "ocpp", "connections", "ssh", "web");

            return JSONResponse(Request, HTTPStatusCode.Created,
                                new JObject(
                                    new JProperty("id",          entry.Id),
                                    new JProperty("connections", ConnectionsJSON())
                                ));

        }

        /// <summary>
        /// POST /api/v1/configuration/sshKeys/remove with {"id"}: take a key
        /// somebody made away, for good.
        /// </summary>
        /// <remarks>
        /// Not from under a connection that signs in with it, and never the
        /// node's own.
        /// </remarks>
        protected Task<HTTPResponse> PostRemoveSshKey(HTTPRequest Request)
        {

            if (!TryAuthorizeKeys(Request, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var id      = ConnectionEntry.Named(json.Value<String>("id")) ?? "";

            var naming  = Node.Connections.Connections.
                              Where (connection => connection.IsSSH && connection.Identities.Any(identity => identity.Id == id)).
                              Select(connection => $"'{connection.Description.FirstText()}'").
                              ToArray();

            if (naming.Length > 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 (naming.Length == 1
                                                      ? $"The connection {naming[0]} signs in with it"
                                                      : $"{naming.Length} connections sign in with it ({String.Join(", ", naming)})") +
                                                 ". Choose another key for it on the Connections page first."));

            if (!Node.SshKeys.TryRemove(id, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            Log.Info($"'{user.Id}' removed the SSH key '{id}'.", "ocpp", "connections", "ssh", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ConnectionsJSON())
                   );

        }

        /// <summary>
        /// The key this node signs in with over SSH, made where the
        /// connection just written down is an ssh:// one: its public half is
        /// what somebody has to hand the server before the first connection,
        /// and the page that just saved it is where it is shown.
        /// </summary>
        /// <remarks>
        /// A key that cannot be made does not undo what was written down: the
        /// connection stands, and says why when it is made.
        /// </remarks>
        protected async Task SshKeyIfNeeded(String? ConnectionId, CancellationToken CancellationToken)
        {

            if (Node.SshKey.Key is not null ||
                !Node.Connections.Connections.Any(entry => entry.Id == ConnectionId && entry.IsSSH))
                return;

            try
            {
                await Node.SshKey.MakeIfNeeded(CancellationToken);
            }
            catch (Exception e)
            {
                Log.Warning($"The key this node signs in with over SSH could not be made: {e.Message}", "ocpp", "connections", "ssh");
            }

        }

    }
}
