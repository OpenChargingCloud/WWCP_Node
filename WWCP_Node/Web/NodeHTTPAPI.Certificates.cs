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

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The part of the JSON API that is about this node's own certificate
    /// store: the roots of the servers it connects to, their certificates, and
    /// what it presents in TLS itself.
    /// </summary>
    /// <remarks>
    /// Addressed as a collection and not under "configuration/": what is in
    /// the store is not a setting that is read and written whole, it is a set
    /// of things that are added, switched and removed one at a time.
    /// </remarks>
    public partial class NodeHTTPAPI
    {

        #region (private) RegisterCertificateStoreRoutes()

        /// <summary>
        /// Everything under /v1/certificates.
        /// </summary>
        private void RegisterCertificateStoreRoutes()
        {

            var root = HTTPPath.Root + "v1/certificates";

            AddHandler(root,               GetStoreCertificates,        HTTPMethod.GET);
            AddHandler(root,               PostStoreCertificate,        HTTPMethod.POST);
            AddHandler(root + "/reload",   PostStoreCertificateReload,  HTTPMethod.POST);
            AddHandler(root + "/{id}",     GetStoreCertificate,         HTTPMethod.GET);
            AddHandler(root + "/{id}",     PatchStoreCertificate,       HTTPMethod.PATCH);
            AddHandler(root + "/{id}",     DeleteStoreCertificate,      HTTPMethod.DELETE);

        }

        #endregion


        #region (private) GetStoreCertificates(Request) / PostStoreCertificate(Request)

        /// <summary>
        /// GET /api/v1/certificates: everything in this node's store.
        /// </summary>
        /// <remarks>
        /// At the reading permission: what certificates a node holds is not a
        /// secret from anybody who may look at it at all, and the private keys
        /// are not in the answer. Changing any of it needs "certificates:edit",
        /// which only the administrators have unless the configuration file
        /// says otherwise.
        /// </remarks>
        private Task<HTTPResponse> GetStoreCertificates(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.CertificatesJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/certificates with {"kind", "content", "password", "label",
        /// "usages"}: put a certificate into the store.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The kind has to be one this store keeps, and a refusal names those -
        /// not every kind there is, which a node that keeps three would list as
        /// eleven.
        /// </para>
        /// <para>
        /// The file arrives as base64 in <c>content</c>, which is what an
        /// upload from the browser turns into. The password is what opens it if
        /// it is a protected PKCS#12, is used once here, and is not kept: the
        /// store writes what it holds without one.
        /// </para>
        /// <para>
        /// Answered with 200 rather than 201 when the certificate was already
        /// there. Importing the same file twice is the same entry - the id is
        /// its fingerprint - so the second import created nothing.
        /// </para>
        /// <para>
        /// <c>usages</c> says what a certificate of a kind that is told what it
        /// is for is for - ["dns", "nts"] - and is left out, or null, for every
        /// use.
        /// </para>
        /// </remarks>
        private Task<HTTPResponse> PostStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!CertificateKindExtensions.TryParseKind(json.Value<String>("kind"), out var kind) ||
                !Node.Certificates.Kinds.Contains(kind))
            {
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     "'kind' has to be one of " +
                                     String.Join(", ", Node.Certificates.Kinds.Select(one => one.AsText())) + ".")
                       );
            }

            var content = json.Value<String>("content")?.Trim();

            if (content is null or { Length: 0 })
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     "'content' has to be the certificate file, base64-encoded.")
                       );

            Byte[] bytes;

            try
            {
                bytes = Convert.FromBase64String(content);
            }
            catch (FormatException)
            {
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest, "'content' is not valid base64.")
                       );
            }

            if (!TryReadUsages(json, out var usages, out var usagesError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError));

            var existed = Node.Certificates.Entries.Count;

            if (!Node.Certificates.Import(bytes,
                                          kind,
                                          json.Value<String>("password"),
                                          json.Value<String>("label"),
                                          usages,
                                          out var entry,
                                          out var error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            Log.Notice($"'{user.Id}' put '{entry.Label}' into the certificate store as {entry.Kind.WithArticle()} ({entry.Id}).",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(
                           Request,
                           Node.Certificates.Entries.Count > existed
                               ? HTTPStatusCode.Created
                               : HTTPStatusCode.OK,
                           entry.ToJSON(WithDiagnostics: true)
                       )
                   );

        }

        #endregion

        #region (private) GetStoreCertificate(Request) / PatchStoreCertificate(Request) / DeleteStoreCertificate(Request)

        /// <summary>
        /// GET /api/v1/certificates/{id}: one certificate.
        /// </summary>
        private Task<HTTPResponse> GetStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            var entry = Node.Certificates.Get(HandleOf(Request));

            return Task.FromResult(
                       entry is null
                           ? ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no such certificate in this store.")
                           : JSONResponse(Request, HTTPStatusCode.OK, entry.ToJSON(WithDiagnostics: true))
                   );

        }

        /// <summary>
        /// PATCH /api/v1/certificates/{id} with {"active"}, {"label"} and/or
        /// {"usages"}: switch a certificate on or off, rename it, or say what
        /// it is for.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Three things in one request because they are the only three things
        /// about a stored certificate that can be changed at all - everything
        /// else about it is read out of the file and is not somebody's to edit.
        /// "usages" set to null is every use again; left out, it is left alone.
        /// </para>
        /// <para>
        /// Whatever can refuse the change is asked before any of it is made:
        /// whether "active" is true or false, whether the store would keep the
        /// usages, and whether the node would be left without a certificate it
        /// needs - see <see cref="WWCPNode.WhatWouldLose"/>, a 409 in the
        /// node's own sentence. Asked one after the other, as they were made, a
        /// request refused for its "active" had renamed the certificate first.
        /// </para>
        /// </remarks>
        private Task<HTTPResponse> PatchStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var handle = HandleOf(Request);

            if (Node.Certificates.Get(handle) is not CertificateEntry entry)
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no such certificate in this store.")
                       );

            Boolean? active = null;

            if (json.TryGetValue("active", out var activeToken))
            {

                if (activeToken.Type != JTokenType.Boolean)
                    return Task.FromResult(
                               ErrorJSON(Request, HTTPStatusCode.BadRequest, "'active' has to be true or false.")
                           );

                active = activeToken.Value<Boolean>();

            }

            // Present, even as null, is something to set: null is every use.
            var                     newUsages  = json.ContainsKey("usages");
            IReadOnlyList<String>?  usages     = null;

            if (newUsages)
            {

                if (!TryReadUsages(json, out var given, out var usagesError))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError));

                if (!Node.Certificates.TrySettleUsages(entry.Kind, given, out usages, out var usagesRefused))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesRefused));

            }

            if (Node.WhatWouldLose(entry,
                                   active ?? entry.IsActive,
                                   newUsages ? usages : entry.Usages) is String wouldLose)
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, wouldLose));
            }

            if (json.TryGetValue("label", out var label) && label.Type != JTokenType.Undefined)
            {
                if (!Node.Certificates.Relabel(handle, label.Value<String>(), out _, out var relabelError))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, relabelError));
            }

            if (active is Boolean on && !Node.Certificates.SetActive(handle, on, out _, out var activeError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, activeError));

            if (newUsages && !Node.Certificates.SetUsages(handle, usages, out _, out var usagesNotSet))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesNotSet));

            var changed = Node.Certificates.Get(handle) ?? entry;

            Log.Notice($"'{user.Id}' changed the certificate '{changed.Label}' ({changed.Id}) in the certificate store.",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, changed.ToJSON(WithDiagnostics: true))
                   );

        }

        /// <summary>
        /// DELETE /api/v1/certificates/{id}: take a certificate out of the
        /// store and delete its file.
        /// </summary>
        /// <remarks>
        /// Refused with 409, in the node's own sentence, while something of
        /// the node names it - see <see cref="WWCPNode.WhatUses"/>: the CSMS
        /// connection of a local controller, the session of a vehicle - and
        /// while something would be left without a certificate it needs, as
        /// switching it off would leave it - see
        /// <see cref="WWCPNode.WhatWouldLose"/>: a listener of a meter.
        /// </remarks>
        private Task<HTTPResponse> DeleteStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            var handle = HandleOf(Request);

            if (Node.WhatUses(handle) is String inUse)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, inUse));

            var entry = Node.Certificates.Get(handle);

            if (entry is not null &&
                Node.WhatWouldLose(entry, false, entry.Usages) is String wouldLose)
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, wouldLose));
            }

            if (!Node.Certificates.Remove(handle, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, error));

            Log.Notice($"'{user.Id}' took the certificate '{entry?.Label}' ({handle}) out of the certificate store.",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.CertificatesJSON())
                   );

        }

        #endregion

        #region (private) PostStoreCertificateReload(Request)

        /// <summary>
        /// POST /api/v1/certificates/reload: read the store directory again.
        /// </summary>
        /// <remarks>
        /// What the store does at every start, on demand: certificates somebody
        /// copied into the directory are adopted, and entries whose files are
        /// gone are dropped. It exists because putting a file in a directory is
        /// a perfectly good way to install a certificate on a machine somebody
        /// already has a shell on, and having to restart the node to be noticed
        /// would make it a worse one.
        /// </remarks>
        private Task<HTTPResponse> PostStoreCertificateReload(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            Node.Certificates.Reload();

            Log.Notice($"'{user.Id}' had the certificate store read again from its directory.",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.CertificatesJSON())
                   );

        }

        #endregion


        #region (protected static) TryReadUsages(JSON, out Usages, out Error)

        /// <summary>
        /// The "usages" of a request: absent or null for every use, or a list
        /// of usages - or why not.
        /// </summary>
        /// <remarks>
        /// Whether each of them is a usage the store knows is the store's to
        /// say, and it says so in a sentence that names the ones it knows.
        /// </remarks>
        protected static Boolean TryReadUsages(JObject                           JSON,
                                               out IReadOnlyList<String>?        Usages,
                                               [NotNullWhen(false)] out String?  Error)
        {

            Usages  = null;
            Error   = null;

            if (!JSON.TryGetValue("usages", out var token) || token.Type == JTokenType.Null)
                return true;

            if (token is not JArray array || array.Any(usage => usage.Type != JTokenType.String))
            {
                Error = "'usages' has to be a list of usages, such as [\"dns\", \"nts\"], or null for every use.";
                return false;
            }

            Usages = [.. array.Select(usage => usage.Value<String>()!)];
            return true;

        }

        #endregion

        #region (protected static) HandleOf(Request)

        /// <summary>
        /// The certificate handle out of the request's path, as the store
        /// spells handles: in lower case.
        /// </summary>
        /// <remarks>
        /// Hex digits, which somebody may have copied out of a tool that writes
        /// them in capitals - asked for that way, a certificate in the store was
        /// not found. The meter's copy of this spelt it; the others did not.
        /// </remarks>
        protected static String HandleOf(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? Request.ParsedURLParameters[0].Trim().ToLowerInvariant()
                   : "";

        #endregion

    }

}
