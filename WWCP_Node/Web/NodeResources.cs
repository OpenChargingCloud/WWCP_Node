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
    /// The resources every node has, by the names a role writes them under.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The node serves none of them itself - it has no JSON API of its own -
    /// but every kind of node that puts them behind a route of its own asks
    /// for them under these names, so that a role written for a vehicle's DNS
    /// settings means the same on a charging station's.
    /// </para>
    /// <para>
    /// The clock, the log and the event stream are none of them: they are for
    /// anybody signed in, as they have always been, because a screen that
    /// shows the time has to be able to say what it is worth and a page that
    /// cannot hear the event stream cannot show anything happening.
    /// </para>
    /// </remarks>
    public static class NodeResources
    {

        /// <summary>
        /// What a node is made of, as the Configuration page shows it: its web
        /// server, its accounts, its log and its time.
        /// </summary>
        public const String  Configuration  = "configuration";

        /// <summary>
        /// How a node resolves names: reading the settings, changing them, and
        /// asking a name server something to find out whether it can.
        /// </summary>
        public const String  DNS            = "dns";

        /// <summary>
        /// Where a node reads the time: reading the settings, changing them,
        /// and asking a time server something to find out whether it can.
        /// </summary>
        public const String  NTS            = "nts";

        /// <summary>
        /// The certificate store: seeing what is in it, and putting
        /// certificates in, taking them out and switching them on and off.
        /// </summary>
        /// <remarks>
        /// Both halves of the store behind one resource, because both are
        /// decisions about trust: somebody who can add a root can make the node
        /// believe a server nobody else would.
        /// </remarks>
        public const String  Certificates   = "certificates";

        /// <summary>
        /// All of them.
        /// </summary>
        public static readonly IReadOnlyList<String>  All = [ Configuration, DNS, NTS, Certificates ];

    }

}
