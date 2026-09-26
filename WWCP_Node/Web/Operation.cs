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

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// What somebody may do to a resource of a node.
    /// </summary>
    /// <remarks>
    /// Three, and a closed set on purpose, while the resources are not: "may
    /// read" has to mean the same on a vehicle's DNS settings and on a charging
    /// station's EVSEs, or a role written for one kind of node would say
    /// something else on the next. What a kind of node adds is things to be
    /// read, edited or run - not new ways of touching them.
    /// </remarks>
    public enum Operation
    {

        /// <summary>
        /// Look at it, and change nothing.
        /// </summary>
        Read,

        /// <summary>
        /// Change it: what is written into the configuration file, or into the
        /// certificate store, and stays changed.
        /// </summary>
        Edit,

        /// <summary>
        /// Make it do something now - ask a name server, a time server or the
        /// link below a charging cable, or run a charging session - without
        /// changing how it is set up.
        /// </summary>
        /// <remarks>
        /// Its own operation and not a kind of reading: it sends traffic from
        /// the node to somebody else, and for a session it draws power.
        /// </remarks>
        Run

    }


    /// <summary>
    /// What an <see cref="Operation"/> is called where it is written down.
    /// </summary>
    public static class OperationExtensions
    {

        /// <summary>
        /// The word the configuration file and the web interface use: "read",
        /// "edit" or "run".
        /// </summary>
        public static String AsText(this Operation Operation)

            => Operation switch {
                   Operation.Edit  => "edit",
                   Operation.Run   => "run",
                   _               => "read"
               };

        /// <summary>
        /// The operation named by the given word, in any case.
        /// </summary>
        public static Boolean TryParse(String?        Text,
                                       out Operation  Operation)
        {

            switch (Text?.Trim().ToLowerInvariant())
            {

                case "read":
                    Operation = Operation.Read;
                    return true;

                case "edit":
                    Operation = Operation.Edit;
                    return true;

                case "run":
                    Operation = Operation.Run;
                    return true;

                default:
                    Operation = default;
                    return false;

            }

        }

    }

}
