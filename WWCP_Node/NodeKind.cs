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
    /// What kind of node one is: how it names itself in its own log, and what
    /// it calls the things it makes for itself.
    /// </summary>
    /// <remarks>
    /// Five names rather than one, because they are read in five places and
    /// spelt for each. <see cref="Name"/> is read in a sentence - "The
    /// electric vehicle is shutting down.", "The clock of this charging
    /// station will be checked ..." - and is lower case for that reason; it
    /// is what the node calls itself in everything it says. <see cref="Tag"/>
    /// is the word in square brackets on every entry about the node itself.
    /// <see cref="Product"/> follows "OpenChargingCloud" in the name the HTTP
    /// server and the accounts go by: what the Configuration page shows as
    /// the server's name, and what the few answers Hermod gives by itself -
    /// the accounts' refusals among them - carry as their Server header. The
    /// node's own answers, the web interface and a kind's JSON API, carry
    /// none.
    /// <see cref="LogFilePrefix"/> is what the day's log file is called
    /// before its date. And <see cref="Organization"/> is the identifier of
    /// the one organization the accounts are in, which is written into the
    /// accounts file at the first start and read back at every start after
    /// it - so it is the one of the five that must never change once a node
    /// has run.
    /// </remarks>
    /// <param name="Name">The node as a sentence names it, in lower case: "electric vehicle".</param>
    /// <param name="Tag">The tag on the log entries about the node itself: "vehicle".</param>
    /// <param name="Product">What it is called after "OpenChargingCloud": "EV".</param>
    /// <param name="Organization">The one organization of its accounts: "Vehicle".</param>
    /// <param name="LogFilePrefix">What a day's log file is called before its date: "ev", for "ev-2026-09-24.log".</param>
    public sealed record NodeKind(String  Name,
                                  String  Tag,
                                  String  Product,
                                  String  Organization,
                                  String  LogFilePrefix)
    {

        #region Data

        /// <summary>
        /// A node of no particular kind: what this assembly is on its own, and
        /// what its tests construct.
        /// </summary>
        public static readonly NodeKind  Default  = new ("WWCP node", "node", "WWCP Node", "Node", "node");

        #endregion

        #region Properties

        /// <summary>
        /// The name as a sentence begins with it: "Electric vehicle".
        /// </summary>
        public String CapitalisedName
            => Name.Length > 0
                   ? Char.ToUpperInvariant(Name[0]) + Name[1..]
                   : Name;

        #endregion

        #region (override) ToString()

        public override String ToString()
            => Name;

        #endregion

    }

}
