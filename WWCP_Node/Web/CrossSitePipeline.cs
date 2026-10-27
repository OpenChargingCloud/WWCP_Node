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
    /// and that another site made a browser send - before any handler of the
    /// HTTPExt API reads it.
    /// </summary>
    /// <remarks>
    /// The HTTPExt API's routes - the sign-in, the account, its API keys and SSH
    /// keys, the password - read their bodies whatever they are said to be, and
    /// one of the forms another site may make a browser send without asking
    /// first is a POST of "text/plain" that reads as JSON (POI3-ISSUES.md S23).
    /// The session cookie is SameSite=strict, but Basic auth and an address an
    /// API key is bound to go with such a request as well. One place for all of
    /// them, since the routes are Hermod's and many: a pipeline of the HTTP
    /// server, which every request passes before it reaches a handler.
    /// </remarks>
    /// <param name="RootPath">The path of the HTTPExt API, "/ext".</param>
    /// <param name="HostAskedFor">What a trusted proxy in front of the node says the browser asked for, or null where none says it.</param>
    public sealed class CrossSitePipeline(HTTPPath                     RootPath,
                                          Func<HTTPRequest, String?>?  HostAskedFor = null) : AHTTPPipeline()
    {

        #region Properties

        /// <summary>
        /// The path below which requests are judged.
        /// </summary>
        public HTTPPath  RootPath    { get; } = RootPath;

        #endregion


        #region (override) ProcessHTTPRequest(Request, CancellationToken = default)

        /// <summary>
        /// The 403 for a request below the root path that is not a read and that
        /// another site made a browser send; nothing for every other request.
        /// </summary>
        public override Task<(HTTPRequest, HTTPResponse?)> ProcessHTTPRequest(HTTPRequest        Request,
                                                                               CancellationToken  CancellationToken = default)
        {

            if (CrossSite.IsARead(Request) ||
                !IsBelowRootPath(Request.Path) ||
                !CrossSite.IsCrossSite(Request, HostAskedFor?.Invoke(Request)))
            {
                return Task.FromResult<(HTTPRequest, HTTPResponse?)>((Request, null));
            }

            return Task.FromResult<(HTTPRequest, HTTPResponse?)>((
                       Request,
                       new HTTPResponse.Builder(Request) {
                           HTTPStatusCode  = HTTPStatusCode.Forbidden,
                           ContentType     = HTTPContentType.Application.JSON_UTF8,
                           Content         = new JObject(new JProperty("description", CrossSite.Refusal)).ToString(Formatting.None).ToUTF8Bytes(),
                           CacheControl    = "no-store",
                           Connection      = ConnectionType.KeepAlive
                       }.WithCommonSecurityHeaders().AsImmutable
                   ));

        }

        #endregion

        #region (private) IsBelowRootPath(Path)

        private Boolean IsBelowRootPath(HTTPPath Path)
        {

            var root = RootPath.ToString().TrimEnd('/');
            var path = Path.    ToString();

            return path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(root + "/", StringComparison.OrdinalIgnoreCase);

        }

        #endregion

    }

}
