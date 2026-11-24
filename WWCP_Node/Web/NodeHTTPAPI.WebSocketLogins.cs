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

using cloud.charging.open.protocols.WWCP.Node.Logins;
using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    #region WebSocketLoginMark

    /// <summary>
    /// What a login may be marked as beside its group, true or false - for
    /// OCPP, a local controller's or a gateway's login.
    /// </summary>
    /// <param name="Name">The name of the mark in the JSON: "localController".</param>
    /// <param name="Noun">What a login so marked is: "a local controller".</param>
    /// <param name="Possessive">Whose a login so marked is: "a local controller's".</param>
    /// <param name="TrySet">Mark a login of the given logins, or take the mark away.</param>
    public sealed record WebSocketLoginMark(String                        Name,
                                            String                        Noun,
                                            String                        Possessive,
                                            WebSocketLoginMark.SetMark    TrySet)
    {

        /// <summary>
        /// Mark a login, or take the mark away: the error where it is refused.
        /// </summary>
        public delegate Boolean SetMark(WebSocketLogins                   Logins,
                                        User_Id                           Login,
                                        Boolean                           Marked,
                                        [NotNullWhen(false)] out String?  Error,
                                        out Boolean                       NotSaved);

        /// <summary>
        /// The login of a local controller, which may send in the name of the
        /// charging stations behind it.
        /// </summary>
        public static WebSocketLoginMark LocalController { get; }

            = new ("localController", "a local controller", "a local controller's",
                   (WebSocketLogins logins, User_Id login, Boolean marked, [NotNullWhen(false)] out String? error, out Boolean notSaved)
                       => logins.TrySetLocalController(login, marked, out error, out notSaved));

        /// <summary>
        /// The login of a gateway, which may send in the name of the charging
        /// stations behind it.
        /// </summary>
        public static WebSocketLoginMark Gateway { get; }

            = new ("gateway", "a gateway", "a gateway's",
                   (WebSocketLogins logins, User_Id login, Boolean marked, [NotNullWhen(false)] out String? error, out Boolean notSaved)
                       => logins.TrySetGateway(login, marked, out error, out notSaved));

    }

    #endregion

    #region WebSocketLoginRoutes

    /// <summary>
    /// The routes of a WebSocket server's logins: where they are, what they
    /// change, who may, and what a login is called there.
    /// </summary>
    /// <param name="Root">Where the routes are: "v1/configuration/ocpp-server", say.</param>
    /// <param name="Logins">The logins.</param>
    /// <param name="Trust">The chains a client certificate may lead to.</param>
    /// <param name="Resource">The resource a user needs a right to for the logins and their groups.</param>
    /// <param name="LoginNoun">What a login is: "charging station", "registration authority".</param>
    /// <param name="LogTags">What the log says of each change, beside "auth" and "web".</param>
    /// <param name="LoginRemoved">What else is forgotten with a login, said as the end of a sentence; null for nothing.</param>
    /// <param name="Marks">What a login may be marked as beside its group, of which a login is one at most; null for nothing.</param>
    public sealed record WebSocketLoginRoutes(HTTPPath                             Root,
                                              Func<WebSocketLogins>                Logins,
                                              Func<ClientTrustStore>               Trust,
                                              String                               Resource,
                                              String                               LoginNoun,
                                              IReadOnlyList<String>                LogTags,
                                              Func<User_Id, String>?               LoginRemoved  = null,
                                              IReadOnlyList<WebSocketLoginMark>?   Marks         = null);

    #endregion


    /// <summary>
    /// The part of the HTTP API of a node about who may sign in at a WebSocket
    /// server of it - and over SSH: the logins, what they sign in with, the
    /// groups that decide what they may do, and the chains a client
    /// certificate may lead to. The same routes for the charging stations of a
    /// CSMS and for the registration authorities of a PKI, registered by
    /// <see cref="RegisterWebSocketLoginRoutes"/>.
    /// </summary>
    /// <remarks>
    /// A credential is shown once: a password is kept as a hash, and a shared
    /// secret of TOTP that was made up here is handed out in the answer that
    /// made it, and never put into the list the pages read.
    /// </remarks>
    public partial class NodeHTTPAPI
    {

        #region (protected) RegisterWebSocketLoginRoutes(Routes)

        /// <summary>
        /// The routes of the logins of a WebSocket server of this node.
        /// </summary>
        protected void RegisterWebSocketLoginRoutes(WebSocketLoginRoutes Routes)
        {

            var root = Routes.Root;

            AddHandler(root + "trust",                                 request => GetTrust            (request, Routes),  HTTPMethod.GET);
            AddHandler(root + "trust",                                 request => PostTrust           (request, Routes),  HTTPMethod.POST);
            AddHandler(root + "trust/{id}",                            request => PutTrust            (request, Routes),  HTTPMethod.PUT);
            AddHandler(root + "trust/{id}",                            request => DeleteTrust         (request, Routes),  HTTPMethod.DELETE);

            AddHandler(root + "groups",                                request => PostLoginGroup      (request, Routes),  HTTPMethod.POST);
            AddHandler(root + "groups/{id}",                           request => PutLoginGroup       (request, Routes),  HTTPMethod.PUT);
            AddHandler(root + "groups/{id}",                           request => DeleteLoginGroup    (request, Routes),  HTTPMethod.DELETE);

            AddHandler(root + "logins",                                request => GetLogins           (request, Routes),  HTTPMethod.GET);
            AddHandler(root + "logins",                                request => PostLogin           (request, Routes),  HTTPMethod.POST);
            AddHandler(root + "logins/{login}",                        request => PutLogin            (request, Routes),  HTTPMethod.PUT);
            AddHandler(root + "logins/{login}",                        request => DeleteLogin         (request, Routes),  HTTPMethod.DELETE);

            AddHandler(root + "logins/{login}/totp",                   request => PutLoginTOTP        (request, Routes),  HTTPMethod.PUT);
            AddHandler(root + "logins/{login}/totp",                   request => DeleteLoginTOTP     (request, Routes),  HTTPMethod.DELETE);
            AddHandler(root + "logins/{login}/totp/binding",           request => PutLoginTOTPBinding (request, Routes),  HTTPMethod.PUT);
            AddHandler(root + "logins/{login}/password",               request => DeleteLoginPassword (request, Routes),  HTTPMethod.DELETE);

            AddHandler(root + "logins/{login}/sshKeys",                request => PostLoginSSHKey     (request, Routes),  HTTPMethod.POST);
            AddHandler(root + "logins/{login}/sshKeys/{fingerprint}",  request => DeleteLoginSSHKey   (request, Routes),  HTTPMethod.DELETE);

            AddHandler(root + "logins/{login}/keyPins",                request => PostLoginKeyPin     (request, Routes),  HTTPMethod.POST);
            AddHandler(root + "logins/{login}/keyPins/{pin}",          request => DeleteLoginKeyPin   (request, Routes),  HTTPMethod.DELETE);

        }

        #endregion


        #region (private) The chains a client certificate may lead to

        /// <summary>
        /// GET .../trust: which certificate authorities a client may be
        /// vouched for by.
        /// </summary>
        private Task<HTTPResponse> GetTrust(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Trust().ToJSON()));

        }

        /// <summary>
        /// POST .../trust with {"pem", "name"}: accept clients whose certificate
        /// leads to the one in this file.
        /// </summary>
        private Task<HTTPResponse> PostTrust(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var pem = json.Value<String>("pem") ?? "";

            if (pem.Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "A 'pem' with the certificate authority in it is required."));

            if (!Routes.Trust().TryAdd(pem, json.Value<String>("name"), out var id, out var warnings, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));

            Log.Notice($"'{user.Id}' added the accepted chain '{id}'.", [ .. Routes.LogTags, "tls", "trust", "web" ]);

            return Task.FromResult(
                       JSONResponse(
                           Request,
                           HTTPStatusCode.Created,
                           new JObject(
                               new JProperty("id",        id),
                               new JProperty("warnings",  new JArray(warnings))
                           )
                       )
                   );

        }

        /// <summary>
        /// PUT .../trust/{id} with {"enabled"} and/or {"name"}: switch a chain
        /// off without losing it, or give it another name.
        /// </summary>
        private Task<HTTPResponse> PutTrust(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryIdOfPath(Request, out var id, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var trust = Routes.Trust();

            if (json.Value<String>("name") is { Length: > 0 } name &&
                !trust.TryRename(id, name, out var renameError, out var renameNotSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, renameError, renameNotSaved));

            if (json.Value<Boolean?>("enabled") is Boolean enabled &&
                !trust.TrySetEnabled(id, enabled, out var enableError, out var enableNotSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, enableError, enableNotSaved));

            Log.Info($"'{user.Id}' changed the accepted chain '{id}'.", [ .. Routes.LogTags, "tls", "trust", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, trust.ToJSON()));

        }

        /// <summary>
        /// DELETE .../trust/{id}: stop accepting clients that lead to it.
        /// </summary>
        private Task<HTTPResponse> DeleteTrust(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryIdOfPath(Request, out var id, out var badRequest))
                return Task.FromResult(badRequest);

            if (!Routes.Trust().TryRemove(id, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));

            Log.Notice($"'{user.Id}' removed the accepted chain '{id}'.", [ .. Routes.LogTags, "tls", "trust", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Trust().ToJSON()));

        }

        #endregion

        #region (private) The logins

        /// <summary>
        /// GET .../logins: who may sign in.
        /// </summary>
        private Task<HTTPResponse> GetLogins(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Read(Routes.Resource), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON()));

        }

        /// <summary>
        /// POST .../logins with {"login", "password", "group", "description"}:
        /// add a login, or give one a new password.
        /// </summary>
        /// <remarks>
        /// The password is given: none is made up here. It is kept only as a
        /// hash, so whoever sets it has to know it to type it in at the other
        /// end.
        /// </remarks>
        private Task<HTTPResponse> PostLogin(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (User_Id.TryParse(json.Value<String>("login")) is not User_Id login)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, $"A {Routes.LoginNoun} needs a login."));

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, wrongDescription));

            var logins = Routes.Logins();

            if (!logins.TrySetPasswordAuthentication(
                     login,
                     json.Value<String>("password"),
                     json.Value<String>("group"),
                     description,
                     out var error,
                     out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            Log.Notice($"'{user.Id}' set the password of the {Routes.LoginNoun} '{login}'.", [ .. Routes.LogTags, "auth", "web" ]);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("login",   login.ToString()),
                           new JProperty("logins",  logins.ToJSON())
                       ))
                   );

        }

        /// <summary>
        /// PUT .../logins/{login} with {"enabled"}, {"group"} and/or one of the
        /// marks: let a login in, stop letting it in, move it to another group,
        /// or mark it - without losing what it signs in with. A login has one
        /// mark at most: two of them true is refused.
        /// </summary>
        private Task<HTTPResponse> PutLogin(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var marks    = Routes.Marks ?? [];
            var enabled  = json.Value<Boolean?>("enabled");
            var group    = json.Value<String>("group");
            var marked   = new List<(WebSocketLoginMark Mark, Boolean Marked)>();

            foreach (var mark in marks)
            {

                var token = json[mark.Name];

                if (token is not null && token.Type is not (JTokenType.Boolean or JTokenType.Null))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'{mark.Name}' is true or false."));

                if (token?.Type == JTokenType.Boolean)
                    marked.Add((mark, token.Value<Boolean>()));

            }

            if (enabled is null && group is null && marked.Count == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 marks.Count == 0
                                                     ? "An 'enabled' of true or false, or a 'group', is required."
                                                     : $"An 'enabled' of true or false, a 'group', or a {String.Join(" or a ", marks.Select(mark => $"'{mark.Name}'"))} of true or false, is required."));

            if (marked.Count(said => said.Marked) > 1)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"A login is {String.Join(" or ", marks.Select(mark => mark.Possessive))}, not both."));

            var logins   = Routes.Logins();

            if (group is not null &&
                !logins.TrySetGroup(login, group, out var groupError, out var groupNotSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, groupError, groupNotSaved));
            }

            if (enabled is Boolean wanted &&
                !logins.TrySetEnabled(login, wanted, out var error, out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));
            }

            // In the order of the marks: marking the one takes the other away,
            // and two of them true was refused above.
            foreach (var (mark, isMarked) in marked)
                if (!mark.TrySet(logins, login, isMarked, out var markError, out var markNotSaved))
                    return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, markError, markNotSaved));

            foreach (var (mark, isMarked) in marked)
                Log.Notice(isMarked
                               ? $"'{user.Id}' marked '{login}' as {mark.Noun}."
                               : $"'{user.Id}' took the mark of {mark.Noun} from '{login}'.",
                           [ .. Routes.LogTags, "security", "web" ]);

            if (group is not null)
                Log.Info($"'{user.Id}' moved the {Routes.LoginNoun} '{login}' into the login group '{group}'.", [ .. Routes.LogTags, "auth", "web" ]);

            if (enabled is Boolean said)
                Log.Info($"'{user.Id}' {(said ? "let in" : "shut out")} the {Routes.LoginNoun} '{login}'.", [ .. Routes.LogTags, "auth", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, logins.ToJSON()));

        }

        /// <summary>
        /// PUT .../logins/{login}/totp with {"sharedSecret", "validitySeconds",
        /// "length", "alphabet", "hashAlgorithm", "group", "description"}: let a
        /// login in with a one-time token.
        /// </summary>
        /// <remarks>
        /// An empty shared secret means "make one up", and it comes back in
        /// this response - and only here: it is never put into the list the
        /// pages read.
        /// </remarks>
        private Task<HTTPResponse> PutLoginTOTP(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            TOTPHashAlgorithm? hash = null;

            if (json.Value<String>("hashAlgorithm")?.Trim() is { Length: > 0 } hashText)
            {

                hash = hashText.ToUpperInvariant() switch {
                           "SHA256"  => TOTPHashAlgorithm.SHA256,
                           "SHA384"  => TOTPHashAlgorithm.SHA384,
                           "SHA512"  => TOTPHashAlgorithm.SHA512,
                           _         => null
                       };

                if (hash is null)
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                     $"'{hashText}' is not a TOTP hash algorithm; there are SHA256, SHA384 and SHA512."));

            }

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, wrongDescription));

            var logins        = Routes.Logins();
            var seconds       = json.Value<Double?>("validitySeconds");
            var sharedSecret  = json.Value<String>("sharedSecret");

            if (!logins.TrySetTOTPAuthentication(
                     login,
                     sharedSecret,
                     seconds.HasValue ? TimeSpan.FromSeconds(seconds.Value) : null,
                     json.Value<UInt32?>("length"),
                     json.Value<String>("alphabet"),
                     hash,
                     json.Value<String>("group"),
                     description,
                     out var error,
                     out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            Log.Notice($"'{user.Id}' set the TOTP configuration of the {Routes.LoginNoun} '{login}'.", [ .. Routes.LogTags, "auth", "web" ]);

            var response = new JObject(
                               new JProperty("login",   login.ToString()),
                               new JProperty("logins",  logins.ToJSON())
                           );

            // None was sent, so one was made up: shown once here.
            if (String.IsNullOrWhiteSpace(sharedSecret) &&
                logins.TryGet(login, out var entry) &&
                entry.TOTP is TOTPSettings totp)
            {
                response.Add("sharedSecret", totp.SharedSecret);
            }

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, response));

        }

        /// <summary>
        /// PUT .../logins/{login}/totp/binding with {"tlsChannelBinding": true
        /// or false}: whether the one-time token of a login has to be bound to
        /// the TLS session of its connection.
        /// </summary>
        /// <remarks>
        /// Its own request, so that it leaves the shared secret alone: the
        /// secret cannot be read back, and setting the token anew to change
        /// this would mean carrying a new secret to the other end.
        /// </remarks>
        private Task<HTTPResponse> PutLoginTOTPBinding(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (json["tlsChannelBinding"] is not JValue { Type: JTokenType.Boolean } binding)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 "Say whether the token has to be bound: { \"tlsChannelBinding\": true } or false."));

            var bound = binding.Value<Boolean>();

            if (!Routes.Logins().TrySetTOTPBinding(login, bound, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));

            Log.Notice($"'{user.Id}' {(bound ? "asked for" : "no longer asks for")} the one-time token of the {Routes.LoginNoun} '{login}' to be bound to its connection.",
                       [ .. Routes.LogTags, "auth", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON()));

        }

        /// <summary>
        /// DELETE .../logins/{login}/totp: stop letting a login in with a
        /// one-time token.
        /// </summary>
        private Task<HTTPResponse> DeleteLoginTOTP(HTTPRequest Request, WebSocketLoginRoutes Routes)

            => Task.FromResult(TakeCredentialAway(Request, Routes, Routes.Logins().TryClearTOTP, "TOTP configuration"));

        /// <summary>
        /// DELETE .../logins/{login}/password: stop letting a login in with a
        /// password.
        /// </summary>
        private Task<HTTPResponse> DeleteLoginPassword(HTTPRequest Request, WebSocketLoginRoutes Routes)

            => Task.FromResult(TakeCredentialAway(Request, Routes, Routes.Logins().TryClearPassword, "password"));

        /// <summary>
        /// POST .../logins/{login}/sshKeys with {"line", "label", "group",
        /// "description"}: give a login an SSH key, adding the login where it
        /// is not listed yet.
        /// </summary>
        /// <remarks>
        /// Refused for the name of an account of this node: both would sign in
        /// over SSH under one name, and a name that is both is let in as
        /// neither.
        /// </remarks>
        private Task<HTTPResponse> PostLoginSSHKey(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, wrongDescription));

            if (ExtAPI.TryGetUser(login, out _))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest,
                                                  $"'{login}' is an account of this {Node.NodeNoun}. A {Routes.LoginNoun} of the same name could not sign in over SSH: " +
                                                   "both would sign in under one name, and a name that is both is let in as neither.",
                                                  false));

            var logins = Routes.Logins();

            if (!logins.TryAddSSHKey(
                     login,
                     json.Value<String>("line"),
                     json.Value<String>("label"),
                     json.Value<String>("group"),
                     description,
                     user.Id.ToString(),
                     out var key,
                     out var error,
                     out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            Log.Notice($"'{user.Id}' gave the {Routes.LoginNoun} '{login}' the SSH key {key}.", [ .. Routes.LogTags, "auth", "ssh", "web" ]);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("login",        login.ToString()),
                           new JProperty("fingerprint",  key.Fingerprint),
                           new JProperty("logins",       logins.ToJSON())
                       ))
                   );

        }

        /// <summary>
        /// DELETE .../logins/{login}/sshKeys/{fingerprint}: take an SSH key away
        /// from a login. A session it opened ends.
        /// </summary>
        /// <remarks>
        /// The fingerprint as OpenSSH writes it, "SHA256:...", escaped - or
        /// without its "SHA256:" and in the URL-safe Base64 alphabet, as the
        /// pages send it.
        /// </remarks>
        private Task<HTTPResponse> DeleteLoginSSHKey(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (Request.ParsedURLParameters.ElementAtOrDefault(1)?.Trim() is not { Length: > 0 } fingerprintText)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "The fingerprint of the key is required."));

            var fingerprint = UserSSHKey.FingerprintFromURL(fingerprintText);

            if (!Routes.Logins().TryRemoveSSHKey(login, fingerprint, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));

            Log.Notice($"'{user.Id}' took the SSH key {fingerprint} of the {Routes.LoginNoun} '{login}' away.", [ .. Routes.LogTags, "auth", "ssh", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON()));

        }

        /// <summary>
        /// POST .../logins/{login}/keyPins with {"pin", "label", "group",
        /// "description"}: let a login in by the key pin of its TLS client key,
        /// adding the login where it is not listed yet.
        /// </summary>
        /// <remarks>
        /// The pin is SHA-256 over the public key - 64 hexadecimal digits, with
        /// or without colons, or "sha256//" and base64. Nothing about it is
        /// secret.
        /// </remarks>
        private Task<HTTPResponse> PostLoginKeyPin(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!ConnectionFields.TryDescriptionOf(json, out var description, out var wrongDescription))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, wrongDescription));

            var logins = Routes.Logins();

            if (!logins.TryAddKeyPin(
                     login,
                     json.Value<String>("pin"),
                     json.Value<String>("label"),
                     json.Value<String>("group"),
                     description,
                     user.Id.ToString(),
                     out var keyPin,
                     out var error,
                     out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            Log.Notice($"'{user.Id}' gave the {Routes.LoginNoun} '{login}' the key pin {keyPin.Pin}.", [ .. Routes.LogTags, "auth", "tls", "web" ]);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("login",   login.ToString()),
                           new JProperty("keyPin",  keyPin.Pin.ToHex()),
                           new JProperty("logins",  logins.ToJSON())
                       ))
                   );

        }

        /// <summary>
        /// DELETE .../logins/{login}/keyPins/{pin}: stop letting a login in by
        /// a key pin. A connection it opened stays open; the next one is
        /// refused.
        /// </summary>
        /// <remarks>
        /// The pin as 64 hexadecimal digits, which is what the pages send: the
        /// other notations hold a '/' or ':', which a path is better without.
        /// </remarks>
        private Task<HTTPResponse> DeleteLoginKeyPin(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (Request.ParsedURLParameters.ElementAtOrDefault(1)?.Trim() is not { Length: > 0 } pin)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "The key pin is required."));

            if (!Routes.Logins().TryRemoveKeyPin(login, pin, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));

            Log.Notice($"'{user.Id}' took the key pin {pin} of the {Routes.LoginNoun} '{login}' away.", [ .. Routes.LogTags, "auth", "tls", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON()));

        }

        /// <summary>
        /// What taking a password or a TOTP away have in common.
        /// </summary>
        private HTTPResponse TakeCredentialAway(HTTPRequest           Request,
                                                WebSocketLoginRoutes  Routes,
                                                TryClearCredential    Clear,
                                                String                What)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return refused;

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return badRequest;

            if (!Clear(login, out var error, out var notSaved))
                return NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved);

            Log.Notice($"'{user.Id}' took the {What} of the {Routes.LoginNoun} '{login}' away.", [ .. Routes.LogTags, "auth", "web" ]);

            return JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON());

        }

        /// <summary>
        /// One of the store's "take this credential away" methods, with what
        /// they promise: the error where they refuse.
        /// </summary>
        private delegate Boolean TryClearCredential(User_Id                           Login,
                                                    [NotNullWhen(false)] out String?  Error,
                                                    out Boolean                       NotSaved);

        /// <summary>
        /// DELETE .../logins/{login}: forget a login.
        /// </summary>
        private Task<HTTPResponse> DeleteLogin(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryLoginOfPath(Request, Routes, out var login, out var badRequest))
                return Task.FromResult(badRequest);

            if (!Routes.Logins().TryRemove(login, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));

            // What the kind of node forgets with it - a CSMS, the certificates
            // it knows of the station.
            var alsoForgotten = Routes.LoginRemoved?.Invoke(login) ?? "";

            Log.Notice($"'{user.Id}' removed the {Routes.LoginNoun} '{login}'{alsoForgotten}.", [ .. Routes.LogTags, "auth", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON()));

        }

        #endregion

        #region (private) The groups that decide what a login may do

        /// <summary>
        /// POST .../groups with {"id", "name", "enabled", "authMethods",
        /// "clientAuthentication", "sshChannels", "description"}: make a login
        /// group.
        /// </summary>
        private Task<HTTPResponse> PostLoginGroup(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            // Asked before the body is looked at: somebody who may not change
            // anything should be told that and not what this node thinks of
            // their JSON.
            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            return Task.FromResult(WriteLoginGroup(Request, Routes, json.Value<String>("id"), json));

        }

        /// <summary>
        /// PUT .../groups/{id}: change what a login group allows.
        /// </summary>
        private Task<HTTPResponse> PutLoginGroup(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryIdOfPath(Request, out var id, out var badRequest))
                return Task.FromResult(badRequest);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            return Task.FromResult(WriteLoginGroup(Request, Routes, id, json));

        }

        /// <summary>
        /// Making a group and changing one are the same write; only where the
        /// identification comes from differs.
        /// </summary>
        /// <remarks>
        /// Everything about a group is replaced, not merged. A form that offers
        /// the whole group sends the whole group, and merging would make
        /// clearing the last authentication method impossible - which is
        /// exactly the move somebody makes to shut a group out.
        /// </remarks>
        private HTTPResponse WriteLoginGroup(HTTPRequest           Request,
                                             WebSocketLoginRoutes  Routes,
                                             String?               Id,
                                             JObject               JSON)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return refused;

            #region The ways in it accepts

            var methods = new List<AuthMethod>();

            if (JSON["authMethods"] is JArray methodArray)
                foreach (var token in methodArray)
                {

                    var method = AuthMethodExtensions.TryParseAuthMethod(token.Value<String>());

                    if (method is null)
                        return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                         $"'{token}' is not a way of signing in that this {Node.NodeNoun} knows; " +
                                          "there are basic, totp, certificate, sshkey and keypin.");

                    methods.Add(method.Value);

                }

            #endregion

            #region How its members may authenticate

            // What a group said of the transport before: refused rather than
            // passed over, which would leave its members with nothing.
            if (JSON.ContainsKey("securityProfiles"))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 "'securityProfiles' of a login group is no more: say how its members may authenticate in 'clientAuthentication', " +
                                 $"by {String.Join(", ", WebSocketClientAuthentications.Names.Select(name => $"\"{name}\""))}.");

            var authentications = new List<WebSocketClientAuthentication>();

            if (JSON["clientAuthentication"] is JArray authenticationArray)
                foreach (var token in authenticationArray)
                {

                    if (token.Type != JTokenType.String ||
                        !WebSocketClientAuthentications.TryParse(token.Value<String>(), out var authentication))
                        return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                         $"'{token}' is no way a client may authenticate; they are {String.Join(", ", WebSocketClientAuthentications.Names)}.");

                    authentications.Add(authentication);

                }

            #endregion

            #region What its members have over SSH besides their own subsystem

            // Replaced like everything else about a group: a form that sends
            // none of it takes it away.
            var channels = new List<String>();

            if (JSON["sshChannels"] is JToken said)
            {

                if (said is not JArray channelArray ||
                    channelArray.Any(token => token.Type != JTokenType.String))
                    return ErrorJSON(Request, HTTPStatusCode.BadRequest, "'sshChannels' must be a list of the names of SSH subsystems.");

                channels.AddRange(channelArray.Select(token => token.Value<String>()!));

            }

            #endregion

            if (!ConnectionFields.TryDescriptionOf(JSON, out var description, out var wrongDescription))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, wrongDescription);

            if (!Routes.Logins().TryAddOrUpdateGroup(
                     Id,
                     JSON.Value<String>("name"),
                     JSON.Value<Boolean?>("enabled") ?? true,
                     methods,
                     authentications,
                     description,
                     channels,
                     out var error,
                     out var notSaved))
            {
                return NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved);
            }

            Log.Notice($"'{user.Id}' wrote the login group '{Id}'.", [ .. Routes.LogTags, "auth", "web" ]);

            return JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON());

        }

        /// <summary>
        /// DELETE .../groups/{id}: forget a login group nobody is in.
        /// </summary>
        private Task<HTTPResponse> DeleteLoginGroup(HTTPRequest Request, WebSocketLoginRoutes Routes)
        {

            if (!TryAuthorize(Request, Permission.Edit(Routes.Resource), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryIdOfPath(Request, out var id, out var badRequest))
                return Task.FromResult(badRequest);

            if (!Routes.Logins().TryRemoveGroup(id, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.Conflict, error, notSaved));

            Log.Notice($"'{user.Id}' removed the login group '{id}'.", [ .. Routes.LogTags, "auth", "web" ]);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, Routes.Logins().ToJSON()));

        }

        #endregion

        #region (private static) TryLoginOfPath(Request, Routes, out Login, out ErrorResponse) / TryIdOfPath(Request, out Id, out ErrorResponse)

        /// <summary>
        /// The login out of the path, or the 400 that says there was none.
        /// </summary>
        private static Boolean TryLoginOfPath(HTTPRequest           Request,
                                              WebSocketLoginRoutes  Routes,
                                              out User_Id           Login,
                                              out HTTPResponse      ErrorResponse)
        {

            ErrorResponse = default!;

            if (User_Id.TryParse(Request.ParsedURLParameters.FirstOrDefault()) is User_Id login)
            {
                Login = login;
                return true;
            }

            Login          = default;
            ErrorResponse  = ErrorJSON(Request, HTTPStatusCode.BadRequest, $"The login of a {Routes.LoginNoun} is required.");
            return false;

        }

        /// <summary>
        /// The identification out of the path, or the 400 that says there was
        /// none.
        /// </summary>
        private static Boolean TryIdOfPath(HTTPRequest       Request,
                                           out String        Id,
                                           out HTTPResponse  ErrorResponse)
        {

            Id             = Request.ParsedURLParameters.FirstOrDefault()?.Trim() ?? "";
            ErrorResponse  = default!;

            if (Id.Length == 0)
            {
                ErrorResponse = ErrorJSON(Request, HTTPStatusCode.BadRequest, "An identification is required.");
                return false;
            }

            return true;

        }

        #endregion

    }

}
