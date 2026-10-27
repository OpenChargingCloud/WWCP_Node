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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// Whether a request is one that another site made a browser send: what the
    /// JSON API refuses of every request that changes something, and the
    /// HTTPExt API at "/ext" of every request that is not a read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Browsers say where a request came from. Sec-Fetch-Site says it outright,
    /// and anything but "same-origin" - or "none", for what somebody typed into
    /// the address bar - is another site's. Where a browser does not send it,
    /// the Origin has to be the node's own: the host and port the request was
    /// sent to, or what a trusted proxy in front says the browser asked for -
    /// see Hermod's SameOrigin. An Origin of "null" is let through here, as it
    /// always was on the JSON API: a page of the node's own sent with a
    /// Referrer-Policy of "no-referrer" says it, and a browser that sends it for
    /// another site's page sends Sec-Fetch-Site as well.
    /// </para>
    /// <para>
    /// Programs that are no browsers say neither, and are let through: what
    /// they may do, their credentials say.
    /// </para>
    /// </remarks>
    public static class CrossSite
    {

        #region Data

        /// <summary>
        /// What a refused request is told.
        /// </summary>
        public const String Refusal = "Cross-site requests are refused.";

        #endregion


        #region IsCrossSite(Request, HostAskedFor = null)

        /// <summary>
        /// Whether the given request is one another site made a browser send.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        /// <param name="HostAskedFor">What a trusted proxy in front of the node says the browser asked for, or null where none says it.</param>
        public static Boolean IsCrossSite(HTTPRequest  Request,
                                          String?      HostAskedFor   = null)
        {

            var site = Request.GetHeaderField("Sec-Fetch-Site");

            if (site is not null && site is not ("same-origin" or "none"))
                return true;

            var origin = Request.GetHeaderField("Origin");

            return origin is not null &&
                   origin != "null" &&
                  !Request.IsSameOrigin(origin, HostAskedFor);

        }

        #endregion

        #region IsARead(Request)

        /// <summary>
        /// Whether the given request only reads: GET, HEAD or OPTIONS - which
        /// nothing that changes something is registered for.
        /// </summary>
        public static Boolean IsARead(HTTPRequest Request)

            => Request.HTTPMethod == HTTPMethod.GET  ||
               Request.HTTPMethod == HTTPMethod.HEAD ||
               Request.HTTPMethod == HTTPMethod.OPTIONS;

        #endregion

    }

}
