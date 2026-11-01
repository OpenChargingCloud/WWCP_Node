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

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Who or what changed the configuration of a node, as a log line and an
    /// event name it: "web:root", "cli:root", "ocpp:CSMS1" - or "start" and
    /// "tofu" for what the node does by itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A plain text rather than a type, because it is read by people in the
    /// log as much as by code, and because a node does not know every way it
    /// can be reached: a station's bridge to OCPP is not the node's to name.
    /// What comes after the colon is that way's own name for whoever it was -
    /// an account, a CSMS.
    /// </para>
    /// <para>
    /// The white papers on time and on name resolution want every change
    /// written down, and as evidence who made it: a change of the legal time
    /// group nobody can attribute is one nobody can answer for.
    /// </para>
    /// </remarks>
    public static class ChangeOrigin
    {

        #region Data

        /// <summary>
        /// What the node put into effect as it started, from its file and its
        /// command line.
        /// </summary>
        public const String  Start       = "start";

        /// <summary>
        /// What the node wrote down by itself on trust on first use: a pin
        /// learned from the first certificate a server was believed with.
        /// </summary>
        public const String  TOFU        = "tofu";

        /// <summary>
        /// The beginning of a change made on the web interface, or through its
        /// JSON API.
        /// </summary>
        public const String  WebPrefix   = "web:";

        /// <summary>
        /// The beginning of a change made at the command line.
        /// </summary>
        public const String  CLIPrefix   = "cli:";

        /// <summary>
        /// The beginning of a change a CSMS made through OCPP.
        /// </summary>
        public const String  OCPPPrefix  = "ocpp:";

        #endregion


        #region (static) Web(Account)

        /// <summary>
        /// A change an account made on the web interface or through the JSON
        /// API: "web:root".
        /// </summary>
        /// <param name="Account">The account, by its login.</param>
        public static String Web(String Account)

            => WebPrefix + Account;

        #endregion

        #region (static) CLI(Account)

        /// <summary>
        /// A change an account made at the command line: "cli:root".
        /// </summary>
        /// <param name="Account">The account, by its login.</param>
        public static String CLI(String Account)

            => CLIPrefix + Account;

        #endregion

        #region (static) OCPP(Id)

        /// <summary>
        /// A change a CSMS made through OCPP: "ocpp:CSMS1".
        /// </summary>
        /// <param name="Id">The CSMS, by the name its connection has.</param>
        public static String OCPP(String Id)

            => OCPPPrefix + Id;

        #endregion

        #region (static) IsOCPP(Origin)

        /// <summary>
        /// Whether a change came from a CSMS through OCPP - which a bridge to
        /// OCPP tells apart from a local change without reading the text.
        /// </summary>
        /// <param name="Origin">Who or what made the change, or null where nobody said.</param>
        public static Boolean IsOCPP(String? Origin)

            => Origin?.StartsWith(OCPPPrefix, StringComparison.Ordinal) == true;

        #endregion

        #region (internal static) By(Origin)

        /// <summary>
        /// The end of a log line that names who made a change - " (by web:root)"
        /// - or nothing where nobody said, so that such a line reads as it did
        /// before there were origins.
        /// </summary>
        /// <param name="Origin">Who or what made the change, or null.</param>
        internal static String By(String? Origin)

            => Origin is null
                   ? ""
                   : $" (by {Origin})";

        #endregion

    }

}
