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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The part of the JSON API that is about the server keys of this node's
    /// listeners: keys its clients may pin, the current and the announced
    /// next one, and the switch from the one to the other.
    /// </summary>
    /// <remarks>
    /// Below /v1/certificates, because a server key is shown in identities of
    /// the store - its carrier, and whatever was issued for it - and whoever
    /// may read the store may read which of them is which. Making a key and
    /// switching to the next one change what the clients of a listener are
    /// shown, which is changing the store: at "certificates:edit".
    /// </remarks>
    public partial class NodeHTTPAPI
    {

        #region (private) RegisterServerKeyRoutes()

        /// <summary>
        /// Everything under /v1/certificates/serverKeys.
        /// </summary>
        private void RegisterServerKeyRoutes()
        {

            var root = HTTPPath.Root + "v1/certificates/serverKeys";

            AddHandler(root,                        GetAllServerKeys,     HTTPMethod.GET);
            AddHandler(root + "/{listener}",        GetServerKeys,        HTTPMethod.GET);
            AddHandler(root + "/{listener}",        PostServerKey,        HTTPMethod.POST);
            AddHandler(root + "/{listener}/switch", PostServerKeySwitch,  HTTPMethod.POST);

        }

        #endregion


        #region (private) GetAllServerKeys(Request) / GetServerKeys(Request)

        /// <summary>
        /// GET /api/v1/certificates/serverKeys: the server keys of every
        /// listener that has one, or that keeps serving the last.
        /// </summary>
        private Task<HTTPResponse> GetAllServerKeys(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            var listeners = Node.Certificates.ServerKeyListeners.
                                 Concat  (Node.ListenerCertificates.KeepServingLastOn).
                                 Distinct().
                                 OrderBy (listener => listener.ToString(), StringComparer.Ordinal);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                                    new JObject(
                                        new JProperty("listeners", new JArray(listeners.Select(ServerKeysJSON)))
                                    ))
                   );

        }

        /// <summary>
        /// GET /api/v1/certificates/serverKeys/{listener}: the server keys of
        /// one listener - each with its key pin, whether it is the current or
        /// the next one, its carrier and whatever was issued for it - and what
        /// the listener shows now.
        /// </summary>
        /// <remarks>
        /// At the reading permission, as the store is: a key pin is what is
        /// handed to the clients, and no secret.
        /// </remarks>
        private Task<HTTPResponse> GetServerKeys(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryListener(Request, out var listener, out var wrong))
                return Task.FromResult(wrong);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ServerKeysJSON(listener))
                   );

        }

        #endregion

        #region (private) PostServerKey(Request) / PostServerKeySwitch(Request)

        /// <summary>
        /// POST /api/v1/certificates/serverKeys/{listener} with {"algorithm",
        /// "asNext"}: a new server key of the listener - the current one where
        /// the listener shows nothing yet, or the announced next one.
        /// </summary>
        /// <remarks>
        /// A key that would take the place of what is shown is refused rather
        /// than made: see <see cref="CertificateStore.TryCreateServerKey(String, String?, Boolean, out ServerKey?, out String?)"/>.
        /// </remarks>
        private Task<HTTPResponse> PostServerKey(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryListener(Request, out var listener, out var wrong))
                return Task.FromResult(wrong);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (json["asNext"] is JToken asNextToken && asNextToken.Type is not (JTokenType.Boolean or JTokenType.Null))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "\"asNext\" is true or false."));

            if (!Node.Certificates.TryCreateServerKey(listener.ToString(),
                                                      json.Value<String>("algorithm"),
                                                      json.Value<Boolean?>("asNext") ?? false,
                                                      out var key,
                                                      out var error,
                                                      out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            Log.Notice($"'{user.Id}' made the {(key.IsNext ? "next " : "")}server key '{key.Id}' of the listener '{listener}', with the key pin {key.KeyPin.ToHex()}.",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.Created,
                                    new JObject(
                                        new JProperty("key",         ServerKeyJSON(key, key.IsNext ? "next" : "current")),
                                        new JProperty("serverKeys",  ServerKeysJSON(listener))
                                    ))
                   );

        }

        /// <summary>
        /// POST /api/v1/certificates/serverKeys/{listener}/switch with
        /// {"ifNextKeyPinIs"}: show the listener's announced next key from now
        /// on - where it is still the key with that key pin, when one is given.
        /// </summary>
        /// <remarks>
        /// 409 where the announced next key is not the one named: whoever
        /// handed a key pin out gets that key or nothing, and is told which
        /// key is announced instead.
        /// </remarks>
        private Task<HTTPResponse> PostServerKeySwitch(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryListener(Request, out var listener, out var wrong))
                return Task.FromResult(wrong);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            KeyPin? ifNextKeyPinIs = null;

            if (json.Value<String>("ifNextKeyPinIs") is String pinText &&
                !KeyPin.TryParse(pinText, out ifNextKeyPinIs))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 "\"ifNextKeyPinIs\" is a key pin: 64 hexadecimal digits, or 'sha256//' and the base64 of 32 bytes."));
            }

            var before = Node.Certificates.GetCurrentAndNextKey(listener, out var next);

            if (!Node.Certificates.TrySwitchToNextKey(listener.ToString(),
                                                      ifNextKeyPinIs,
                                                      out var key,
                                                      out var error,
                                                      out var notSaved))
            {
                return Task.FromResult(NotChanged(Request,
                                                  ifNextKeyPinIs is not null && next is not null && next.KeyPin != ifNextKeyPinIs
                                                      ? HTTPStatusCode.Conflict
                                                      : HTTPStatusCode.BadRequest,
                                                  error,
                                                  notSaved));
            }

            Log.Notice($"'{user.Id}' switched the listener '{listener}' to its server key '{key.Id}' with the key pin {key.KeyPin.ToHex()}.",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                                    new JObject(
                                        new JProperty("key",         ServerKeyJSON(key, "current")),
                                        new JProperty("before",      before?.KeyPin.ToHex()),
                                        new JProperty("serverKeys",  ServerKeysJSON(listener))
                                    ))
                   );

        }

        #endregion


        #region (private) TryListener(Request, out Listener, out Refused)

        /// <summary>
        /// The listener the address names, or a refusal for a name that is none.
        /// </summary>
        private Boolean TryListener(HTTPRequest            Request,
                                    out CertificateUsage   Listener,
                                    out HTTPResponse       Refused)
        {

            var name  = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : "";

            Refused   = null!;

            if (CertificateUsage.TryParse(name, out Listener))
                return true;

            Refused   = ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                  $"'{name}' is not a listener name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.");

            return false;

        }

        #endregion

        #region (private) ServerKeysJSON(Listener) / ServerKeyJSON(Key, State)

        /// <summary>
        /// The server keys of one listener and what it shows now, as the JSON
        /// API answers.
        /// </summary>
        private JObject ServerKeysJSON(CertificateUsage Listener)
        {

            var store     = Node.Certificates;
            var current   = store.GetCurrentAndNextKey(Listener, out var next);
            var keeps     = Node.ListenerCertificates.KeepServingLastOn.Contains(Listener);

            // What a listener of the node shows, as it chooses; where nothing
            // asked for one yet, as it would choose - and let go of again.
            ShownCertificate? shown;

            if (Node.ListenerCertificates.Listeners.Contains(Listener))
                shown = Node.ListenerCertificates.For(Listener).Choose();

            else
            {
                using var asIf = new ListenerCertificate(store, Listener, Node.Log, KeepServingLast: keeps);
                shown = asIf.Choose();
            }

            return new JObject(
                       new JProperty("listener",          Listener.ToString()),
                       new JProperty("keepsServingLast",  keeps),
                       new JProperty("current",           current?.KeyPin.ToHex()),
                       new JProperty("next",              next?.   KeyPin.ToHex()),
                       new JProperty("shown",             shown is null
                                                              ? null
                                                              : new JObject(
                                                                    new JProperty("id",           shown.Entry.Id),
                                                                    new JProperty("label",        shown.Entry.Label),
                                                                    new JProperty("presentedAs",  shown.PresentedAs),
                                                                    new JProperty("keptOn",       shown.IsKeptOn)
                                                                )),
                       new JProperty("keys",              new JArray(
                                                              store.ServerKeys(Listener).Select(key => ServerKeyJSON(
                                                                  key,
                                                                  key.KeyPin == current?.KeyPin ? "current"
                                                                      : key.IsNext              ? "next"
                                                                      : "former"))
                                                          ))
                   );

        }

        /// <summary>
        /// One server key as the JSON API answers: its key pin and state, its
        /// carrier and whatever was issued for it, each as the store says it.
        /// </summary>
        private JObject ServerKeyJSON(ServerKey  Key,
                                      String     State)
        {

            var store  = Node.Certificates;
            var now    = store.Clock.GetUtcNow();

            return new JObject(
                       new JProperty("id",            Key.Id),
                       new JProperty("keyPin",        Key.KeyPin.ToHex()),
                       new JProperty("keyPinCurl",    Key.KeyPin.ToCurl()),
                       new JProperty("algorithm",     Key.Algorithm),
                       new JProperty("createdAt",     Key.CreatedAt.ToString("o")),
                       new JProperty("state",         State),
                       new JProperty("currentSince",  Key.CurrentSince?.ToString("o")),
                       new JProperty("carrier",       store.CarrierOf(Key)?.ToJSON(WithDiagnostics: true, now)),
                       new JProperty("issued",        new JArray(store.IssuedFor(Key).Select(entry => entry.ToJSON(WithDiagnostics: true, now))))
                   );

        }

        #endregion

    }

}
