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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The "hsts" of the "web" section: whether the answers that reached a
    /// browser over HTTPS tell it to come back over HTTPS only
    /// (Strict-Transport-Security, RFC 6797), for how long, and whether for
    /// the names below this one as well.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sent wherever a browser was reached over HTTPS - by the node's own TLS,
    /// or by a trusted proxy that says so - and nowhere else: the field says
    /// something about the browser's own leg, and a browser ignores it over
    /// plain HTTP anyway. On by default, for a year, because a node that speaks
    /// HTTPS and does not say so leaves the next "http://" somebody types to
    /// go out in the clear, cookie and all.
    /// </para>
    /// <para>
    /// Behind nginx it does no harm where nginx sends one of its own: a browser
    /// takes the first. <c>false</c> leaves it to the proxy altogether; a
    /// "maxAge" of 0 tells a browser to forget what it was told before, which
    /// is the way back from HTTPS.
    /// </para>
    /// </remarks>
    /// <param name="Enabled">Whether it is sent at all; yes where absent.</param>
    /// <param name="MaxAge">For how long, in seconds; <see cref="DefaultMaxAge"/> where absent.</param>
    /// <param name="IncludeSubDomains">Whether for every name below the node's as well; no where absent.</param>
    public sealed record HSTSConfiguration(Boolean   Enabled            = true,
                                           UInt32?   MaxAge             = null,
                                           Boolean?  IncludeSubDomains  = null)
    {

        #region Data

        /// <summary>
        /// The name of this part of the "web" section.
        /// </summary>
        public const String  Name           = "hsts";

        /// <summary>
        /// A year, in seconds: what the browsers' preload list asks at least,
        /// and long enough that a browser that came once a month never forgets.
        /// </summary>
        public const UInt32  DefaultMaxAge  = 31_536_000;

        /// <summary>
        /// Two years, in seconds: the longest a node may say.
        /// </summary>
        public const UInt32  MaxMaxAge      = 63_072_000;

        #endregion

        #region Properties

        /// <summary>
        /// What is sent where nothing is said.
        /// </summary>
        public static HSTSConfiguration Default { get; } = new ();

        /// <summary>
        /// The field as it is sent, or null where none is.
        /// </summary>
        public String? HeaderValue

            => Enabled
                   ? $"max-age={MaxAge ?? DefaultMaxAge}{(IncludeSubDomains == true ? "; includeSubDomains" : "")}"
                   : null;

        #endregion


        #region (static) TryParse(JSON, Path, out Configuration, out Error)

        /// <summary>
        /// The "hsts" of the "web" section - false, or an object - or the one
        /// sentence that says what is wrong with it.
        /// </summary>
        /// <param name="JSON">The value of "hsts".</param>
        /// <param name="Path">Where it is in the document: "web.hsts".</param>
        /// <param name="Configuration">What it says.</param>
        /// <param name="Error">What is wrong with it.</param>
        public static Boolean TryParse(JToken                                      JSON,
                                       String                                      Path,
                                       [NotNullWhen(true)]  out HSTSConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?             Error)
        {

            Configuration  = null;
            Error          = null;

            if (JSON.Type == JTokenType.Boolean)
            {
                Configuration = JSON.Value<Boolean>()
                                    ? Default
                                    : new HSTSConfiguration(Enabled: false);
                return true;
            }

            if (JSON is not JObject hsts)
            {
                Error = $"'{Path}' must be false, or {{ \"maxAge\": <seconds>, \"includeSubDomains\": true or false }}.";
                return false;
            }

            if (!WebTLSConfiguration.OnlyThese(hsts, Path, [ "maxAge", "includeSubDomains" ], out Error) ||
                !ConfigurationReader.TryReadUInt32 (hsts, "maxAge",             Path, 0, MaxMaxAge, out var maxAge,             out Error) ||
                !ConfigurationReader.TryReadBoolean(hsts, "includeSubDomains",  Path,               out var includeSubDomains,  out Error))
                return false;

            Configuration = new HSTSConfiguration(true, maxAge, includeSubDomains);

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The "hsts" as it is written to the file: false, or what it says.
        /// </summary>
        public JToken ToJSON()
        {

            if (!Enabled)
                return false;

            var json = new JObject();

            if (MaxAge            is not null)  json.Add("maxAge",             MaxAge.Value);
            if (IncludeSubDomains is not null)  json.Add("includeSubDomains",  IncludeSubDomains.Value);

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => HeaderValue is String value
                   ? $"HSTS {value}"
                   : "no HSTS";

        #endregion

    }

}
