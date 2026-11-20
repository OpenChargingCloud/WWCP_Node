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
    /// How the node treats those who sign in wrong, at every door it has:
    /// the section "signIns".
    /// </summary>
    /// <param name="MaxFailedPerMinute">How many wrong sign-ins of one address are let through within a minute before it is told to wait; 0 for no brake, nothing for <see cref="SignInBrake.DefaultMaxFailedPerMinute"/>.</param>
    public sealed record SignInsConfiguration(UInt32? MaxFailedPerMinute = null)
    {

        #region Data

        /// <summary>
        /// The name of the section in the configuration file.
        /// </summary>
        public const String  SectionName           = "signIns";

        /// <summary>
        /// The most wrong sign-ins a minute that may be let through.
        /// </summary>
        public const UInt32  MaxMaxFailedPerMinute  = 10000;

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// Read the section "signIns".
        /// </summary>
        public static Boolean TryParse(JObject                                       JSON,
                                       [NotNullWhen(true)]  out SignInsConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?                Error)
        {

            Configuration = null;

            if (!ConfigurationReader.TryReadUInt32(JSON, "maxFailedPerMinute", SectionName, 0, MaxMaxFailedPerMinute, out var maxFailedPerMinute, out Error))
                return false;

            Configuration = new SignInsConfiguration(maxFailedPerMinute);
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (MaxFailedPerMinute.HasValue)
                json.Add("maxFailedPerMinute", MaxFailedPerMinute.Value);

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => MaxFailedPerMinute switch {
                   null  => "sign-ins as by default",
                   0     => "no brake on sign-ins",
                   var n => $"at most {n} wrong sign-ins a minute"
               };

        #endregion

    }

}
