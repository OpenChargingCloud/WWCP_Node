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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// Refuses, with 403, every request below the given path that is not a read
    /// and that brings a read-only API key - before any handler of the HTTPExt
    /// API reads it.
    /// </summary>
    /// <remarks>
    /// The HTTPExt API lets an API key in as its account, whatever the key's
    /// rights, and its routes - the account, its API keys and SSH keys, the
    /// password - are Hermod's and many (POI3-ISSUES.md S37). The JSON API holds
    /// such a key to reading in NodeHTTPAPI.TryAuthorize; this is the same rule
    /// at "/ext", in one place every request passes before it reaches a handler.
    /// Hermod itself is left as it is: a key made there is read-only unless said
    /// otherwise, and its other programs write with such keys.
    /// </remarks>
    /// <param name="RootPath">The path of the HTTPExt API, "/ext".</param>
    /// <param name="ExtAPI">The HTTPExt API whose API keys are judged.</param>
    /// <param name="OnRefused">Told of every request refused, e.g. to log it.</param>
    public sealed class ReadOnlyAPIKeyPipeline(HTTPPath              RootPath,
                                               HTTPExtAPI            ExtAPI,
                                               Action<HTTPRequest>?  OnRefused   = null) : AHTTPPipeline()
    {

        #region Data

        /// <summary>
        /// What a refused request is told.
        /// </summary>
        public const String Refusal = "The API key used is read-only and may only read.";

        #endregion

        #region Properties

        /// <summary>
        /// The path below which requests are judged.
        /// </summary>
        public HTTPPath  RootPath    { get; } = RootPath;

        #endregion


        #region (static) BringsAReadOnlyAPIKey(ExtAPI, Request)

        /// <summary>
        /// Whether the given request brings an API key of the given HTTPExt API
        /// that is valid and read-only. The cookie and HTTP Basic auth of the web
        /// interface carry no such key, so they are unaffected; a programmatic
        /// caller sending a read-only API key is held to reading, even when it
        /// also sends other credentials (then the strictest wins).
        /// </summary>
        public static Boolean BringsAReadOnlyAPIKey(HTTPExtAPI   ExtAPI,
                                                    HTTPRequest  Request)

            => Request.API_Key is not null &&
               ExtAPI.TryGetValidAPIKey(Request.API_Key, out var apiKey) &&
               apiKey is not null &&
               apiKey.AccessRights == APIKeyRights.ReadOnly;

        #endregion

        #region (override) ProcessHTTPRequest(Request, CancellationToken = default)

        /// <summary>
        /// The 403 for a request below the root path that is not a read and that
        /// brings a read-only API key; nothing for every other request.
        /// </summary>
        public override Task<(HTTPRequest, HTTPResponse?)> ProcessHTTPRequest(HTTPRequest        Request,
                                                                               CancellationToken  CancellationToken = default)
        {

            if (CrossSite.IsARead(Request) ||
                !CrossSitePipeline.IsBelow(RootPath, Request.Path) ||
                !BringsAReadOnlyAPIKey(ExtAPI, Request))
            {
                return Task.FromResult<(HTTPRequest, HTTPResponse?)>((Request, null));
            }

            OnRefused?.Invoke(Request);

            return Task.FromResult<(HTTPRequest, HTTPResponse?)>((
                       Request,
                       new HTTPResponse.Builder(Request) {
                           HTTPStatusCode  = HTTPStatusCode.Forbidden,
                           ContentType     = HTTPContentType.Application.JSON_UTF8,
                           Content         = new JObject(new JProperty("description", Refusal)).ToString(Formatting.None).ToUTF8Bytes(),
                           CacheControl    = "no-store",
                           Connection      = ConnectionType.KeepAlive
                       }.WithCommonSecurityHeaders().AsImmutable
                   ));

        }

        #endregion

    }

}
