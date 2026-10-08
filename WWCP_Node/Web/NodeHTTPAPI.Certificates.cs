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
            AddHandler(root + "/inspect",  PostStoreCertificateInspect, HTTPMethod.POST);
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

            if (json.ContainsKey("kinds"))
                return Task.FromResult(PostStoreCertificates(Request, json, user.Id.ToString()));

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
                                          out var error,
                                          out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
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

        /// <summary>
        /// POST /api/v1/certificates with {"kinds": [{"kind", "group", "usages"}],
        /// "content" or "pem", "password", "label"}: put every certificate in a
        /// file or a text into the store as every kind given.
        /// </summary>
        /// <remarks>
        /// <para>
        /// What the page's upload sends: a text that may hold several
        /// certificates and their keys, and the kinds ticked for it. Each
        /// certificate in it is one import - see <see cref="CertificateStore.InspectFor"/>
        /// - put in as all the kinds given or as none, and each is answered on
        /// its own: {"imported": [...], "refused": [{"id", "label", "error"}]}.
        /// Refused as a whole, with 400, where nothing went in.
        /// </para>
        /// <para>
        /// A kind is one the store keeps, or one somebody makes up here: a name
        /// it does not know, with the group it is in - "trustAnchor",
        /// "credential" or "recognised". A label is taken only where the text
        /// holds one certificate; several each keep their own names.
        /// </para>
        /// </remarks>
        private HTTPResponse PostStoreCertificates(HTTPRequest  Request,
                                                   JObject      JSON,
                                                   String       UserId)
        {

            if (JSON["kinds"] is not JArray kindsArray || kindsArray.Count == 0 || kindsArray.Any(token => token is not JObject))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 "'kinds' has to be a list of the kinds to keep the certificates as, such as [{\"kind\": \"tlsRoot\"}].");

            var registrations = new List<CertificateRegistration>();

            foreach (var token in kindsArray.Cast<JObject>())
            {

                var name   = token.Value<String>("kind");
                var group  = CertificateKind.TryParseGroup(token.Value<String>("group"), out var said) ? said : (CertificateGroup?) null;

                // A kind the store keeps - one made up among them, once a
                // certificate is kept as it - is named without its group, as
                // the page names it; a kind defined in code anywhere is known
                // too, and one nobody knows is made up where its group is said.
                var kept   = Node.Certificates.KindsKept.FirstOrDefault(one => String.Equals(one.AsText(), name?.Trim(), StringComparison.OrdinalIgnoreCase));
                var kind   = kept.IsNotNullOrEmpty ? kept : (CertificateKind?) null;

                if (kind is null &&
                    !CertificateKind.TryParse(name, null, out kind) &&
                    !(token.ContainsKey("group") && CertificateKind.TryParse(name, group, out kind)))
                {
                    return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     CertificateKind.IsKindName(name?.Trim())
                                         ? $"'{name}' is no kind this {Node.Kind.Name} knows. To make it up, say which group it is in: " +
                                            "\"trustAnchor\", \"credential\" or \"recognised\"."
                                         : $"'{name}' is not a kind name: a letter, then letters, digits, '-' or '_', at most {CertificateKind.MaxLength} characters.");
                }

                if (!Node.Certificates.Keeps(kind.Value))
                    return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     "'kinds' has to name kinds of " +
                                     String.Join(", ", Node.Certificates.Kinds.Select(one => one.AsText())) + ", or kinds made up.");

                if (!TryReadUsages(token, out var usages, out var usagesError))
                    return ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError);

                registrations.Add(new CertificateRegistration(kind.Value, usages));

            }

            if (!TryReadContent(JSON, out var bytes, out var contentError))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, contentError);

            var password    = JSON.Value<String>("password");
            var inspection  = Node.Certificates.InspectFor(bytes, password);

            if (inspection.Error is not null)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, inspection.Error,
                                 inspection.PasswordWanted ? new JProperty("passwordWanted", true) : null);

            var label     = inspection.Certificates.Count == 1 ? JSON.Value<String>("label") : null;
            var imported  = new JArray();
            var refused   = new JArray();
            var created   = false;

            foreach (var certificate in inspection.Certificates)
            {

                var before = Node.Certificates.Registrations(certificate.Id).Count;

                if (!Node.Certificates.Import(System.Text.Encoding.ASCII.GetBytes(certificate.Pem),
                                              null,
                                              label,
                                              registrations,
                                              out var entries,
                                              out var error,
                                              out var notSaved))
                {

                    if (notSaved)
                        return NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved);

                    refused.Add(new JObject(
                                    new JProperty("id",     certificate.Id),
                                    new JProperty("label",  certificate.CommonName),
                                    new JProperty("error",  error)
                                ));

                    continue;

                }

                created |= Node.Certificates.Registrations(certificate.Id).Count > before;

                foreach (var entry in entries)
                    imported.Add(entry.ToJSON(WithDiagnostics: true));

                Log.Notice($"'{UserId}' put '{entries[0].Label}' into the certificate store as " +
                           $"{String.Join(" and ", entries.Select(entry => entry.Kind.WithArticle()))} ({entries[0].Id}).",
                           "certificates", "web");

            }

            var answer = new JObject(
                             new JProperty("imported", imported),
                             new JProperty("refused",  refused)
                         );

            if (imported.Count == 0)
            {
                answer.Add("error", refused.Count == 1
                                        ? refused[0]!.Value<String>("error")
                                        : $"None of the {refused.Count} certificates went in.");
                return JSONResponse(Request, HTTPStatusCode.BadRequest, answer);
            }

            return JSONResponse(Request,
                                created ? HTTPStatusCode.Created : HTTPStatusCode.OK,
                                answer);

        }

        /// <summary>
        /// POST /api/v1/certificates/inspect with {"content" or "pem",
        /// "password"}: what a file or a text holds, certificate by certificate,
        /// without putting anything anywhere.
        /// </summary>
        /// <remarks>
        /// <para>
        /// For a page that is dropped a file on: each certificate with its PEM -
        /// the certificates above it that came with it, and its private key
        /// where it came with one - the kinds the store keeps it as already, and
        /// why it cannot be each kind it cannot be. {"certificates": [...],
        /// "pem"}: the whole as one text, for the box it was dropped on.
        /// </para>
        /// <para>
        /// At the permission to change the store, because what comes back holds
        /// the private keys that were sent: what somebody may only look at the
        /// store with is not something to read keys out of, even their own.
        /// </para>
        /// </remarks>
        private Task<HTTPResponse> PostStoreCertificateInspect(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!TryReadContent(json, out var bytes, out var contentError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, contentError));

            var inspection = Node.Certificates.InspectFor(bytes, json.Value<String>("password"));

            if (inspection.Error is not null)
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest, inspection.Error,
                                     inspection.PasswordWanted ? new JProperty("passwordWanted", true) : null)
                       );

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("certificates", new JArray(inspection.Certificates.Select(certificate =>
                                                                        certificate.ToJSON(Node.Certificates.Unsuitable(certificate))))),
                           new JProperty("pem",          inspection.Pem)
                       ))
                   );

        }

        #endregion

        #region (protected static) TryReadContent(JSON, out Content, out Error)

        /// <summary>
        /// The file of a request: "content", base64 - what an upload from the
        /// browser turns into - or "pem", a text as it was pasted.
        /// </summary>
        protected static Boolean TryReadContent(JObject                           JSON,
                                                out Byte[]                        Content,
                                                [NotNullWhen(false)] out String?  Error)
        {

            Content = [];
            Error   = null;

            if (JSON.Value<String>("pem") is String pem && pem.Trim().Length > 0)
            {
                Content = System.Text.Encoding.UTF8.GetBytes(pem);
                return true;
            }

            var content = JSON.Value<String>("content")?.Trim();

            if (content is null or { Length: 0 })
            {
                Error = "'content' has to be the certificate file, base64-encoded - or 'pem' the text of one.";
                return false;
            }

            try
            {
                Content = Convert.FromBase64String(content);
                return true;
            }
            catch (FormatException)
            {
                Error = "'content' is not valid base64.";
                return false;
            }

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
                           : JSONResponse(Request, HTTPStatusCode.OK, WithKinds(entry))
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

            if (!TryReadKindOf(json.Value<String>("kind"), out var kind, out var kindError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, kindError));

            var registrations = Node.Certificates.Registrations(handle).Where(one => kind is null || one.Kind == kind.Value).ToList();

            if (registrations.Count == 0)
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no such certificate in this store.")
                       );

            var entry = registrations[0];

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
            IReadOnlyList<CertificateUsage>?  usages  = null;

            if (newUsages)
            {

                if (!TryReadUsages(json, out var given, out var usagesError))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError));

                if (registrations.Count > 1)
                    return Task.FromResult(
                               ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                         $"'{entry.Label}' is kept as {String.Join(" and ", registrations.Select(one => one.Kind.WithArticle()))}. " +
                                          "Say as which of them it is told what it is for, with 'kind'.")
                           );

                if (!Node.Certificates.TrySettleUsages(entry.Kind, given, out usages, out var usagesRefused))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesRefused));

            }

            foreach (var registration in registrations)
            {
                if (Node.WhatWouldLose(registration,
                                       active ?? registration.IsActive,
                                       newUsages ? usages : registration.Usages) is String wouldLose)
                {
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, wouldLose));
                }
            }

            // Each of the three is written into the index, and put back where
            // that cannot be done - answered with 500, where it had been
            // answered as done and was gone at the next start.
            if (json.TryGetValue("label", out var label) && label.Type != JTokenType.Undefined)
            {
                if (!Node.Certificates.Relabel(handle, label.Value<String>(), out _, out var relabelError, out var relabelNotSaved))
                    return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, relabelError, relabelNotSaved));
            }

            if (active is Boolean on && !Node.Certificates.SetActive(handle, kind, on, out _, out var activeError, out var activeNotSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, activeError, activeNotSaved));

            if (newUsages && !Node.Certificates.SetUsages(handle, entry.Kind, usages?.Select(usage => usage.ToString()), out _, out var usagesNotSet, out var usagesNotSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, usagesNotSet, usagesNotSaved));

            var changed = Node.Certificates.Get(handle, entry.Kind) ?? entry;

            Log.Notice($"'{user.Id}' changed the certificate '{changed.Label}' ({changed.Id}) in the certificate store.",
                       "certificates", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, WithKinds(changed))
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

            if (!TryReadKindOf(Request.QueryString.GetString("kind"), out var kind, out var kindError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, kindError));

            var registrations = Node.Certificates.Registrations(handle).Where(one => kind is null || one.Kind == kind.Value).ToList();
            var entry         = registrations.FirstOrDefault();

            // What names a certificate names it whichever kinds it is kept as,
            // as far as a kind of node says: taken out as one kind of several,
            // it is asked all the same.
            if (Node.WhatUses(handle) is String inUse)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, inUse));

            foreach (var registration in registrations)
            {
                if (Node.WhatWouldLose(registration, false, registration.Usages) is String wouldLose)
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, wouldLose));
            }

            if (!Node.Certificates.Remove(handle, kind, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.NotFound, error, notSaved));

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


        #region (private) WithKinds(Entry) / TryReadKindOf(Text, out Kind, out Error)

        /// <summary>
        /// One certificate as one kind it is kept as, with every kind it is kept as.
        /// </summary>
        private JObject WithKinds(CertificateEntry Entry)
        {

            var json = Entry.ToJSON(WithDiagnostics: true);

            json.Add("kinds", new JArray(Node.Certificates.Registrations(Entry.Id).Select(entry => entry.Kind.AsText())));

            return json;

        }

        /// <summary>
        /// The kind a request names a certificate as - a kind the store keeps,
        /// or one made up - or none, where it names none.
        /// </summary>
        private Boolean TryReadKindOf(String?                           Text,
                                      out CertificateKind?              Kind,
                                      [NotNullWhen(false)] out String?  Error)
        {

            Kind   = null;
            Error  = null;

            if (Text is null || Text.Trim().Length == 0)
                return true;

            var known = Node.Certificates.KindsKept.FirstOrDefault(kept => String.Equals(kept.AsText(), Text.Trim(), StringComparison.OrdinalIgnoreCase));

            if (known.IsNotNullOrEmpty)
            {
                Kind = known;
                return true;
            }

            Error = $"'kind' has to be one of {String.Join(", ", Node.Certificates.KindsKept.Select(kept => kept.AsText()))}.";
            return false;

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
