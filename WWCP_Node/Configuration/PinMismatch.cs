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

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// What a key exchange comes to whose certificate is not the one its time
    /// server is held to.
    /// </summary>
    /// <remarks>
    /// Either way it is written into the metrological log. The difference is
    /// whether the time the server gives is used.
    /// </remarks>
    public enum PinMismatch
    {

        /// <summary>
        /// Refused: the key exchange ends, and the server is not asked for the
        /// time. What a pin is for, and so what a pin means unless it says
        /// otherwise.
        /// </summary>
        Refuse,

        /// <summary>
        /// Used, and written down: for watching what a server shows before
        /// holding it to anything - a certificate about to be renewed, a root
        /// about to change - without losing its time in the meantime.
        /// </summary>
        Record

    }


    /// <summary>
    /// What a <see cref="PinMismatch"/> is called in the configuration file.
    /// </summary>
    public static class PinMismatchExtensions
    {

        /// <summary>
        /// The word the configuration file uses: "refuse" or "record".
        /// </summary>
        public static String AsText(this PinMismatch Mismatch)

            => Mismatch switch {
                   PinMismatch.Record  => "record",
                   _                   => "refuse"
               };

        /// <summary>
        /// The word as somebody wrote it, in any case.
        /// </summary>
        public static Boolean TryParse(String?          Text,
                                       out PinMismatch  Mismatch)
        {

            switch (Text?.Trim().ToLowerInvariant())
            {

                case "refuse":
                    Mismatch = PinMismatch.Refuse;
                    return true;

                case "record":
                    Mismatch = PinMismatch.Record;
                    return true;

                default:
                    Mismatch = default;
                    return false;

            }

        }

    }

}
