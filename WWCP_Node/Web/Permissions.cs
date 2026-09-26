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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// What somebody signed in to this node is allowed to do.
    /// </summary>
    /// <remarks>
    /// Flags rather than a list, because a permission is asked about one at a
    /// time and answered by a single test - and because the set a role grants
    /// is then a constant instead of a collection to be built and searched.
    /// </remarks>
    [Obsolete("Roles are data now: Role, Permission and Operation, asked through WWCPNode.Access and WWCPNode.IsAllowed. This stays until every kind of node using it has moved over.")]
    [Flags]
    public enum Permissions : UInt32
    {

        /// <summary>
        /// Nothing at all. What an unknown role would grant.
        /// </summary>
        None                   = 0,

        /// <summary>
        /// See how this node is configured.
        /// </summary>
        ReadConfiguration      = 1,

        /// <summary>
        /// Change how this node reaches the network: its name resolution and
        /// where it reads the time.
        /// </summary>
        /// <remarks>
        /// Separate from the charging settings below because it is reversible
        /// and it complains: a wrong name server makes the node say so, and
        /// the next change puts it right.
        /// </remarks>
        ChangeNetworkSettings  = 2,

        /// <summary>
        /// Make this node ask a name server or a time server something - or,
        /// for a vehicle, the link below the charging cable - to find out
        /// whether it can.
        /// </summary>
        /// <remarks>
        /// Its own permission and not part of reading: a diagnostic sends
        /// traffic from this node to a host somebody names - or, in the
        /// case of SDP, to every host on the link at once - which is more than
        /// it sounds like to hand to everybody who may look at a page.
        /// </remarks>
        RunDiagnostics         = 4,

        /// <summary>
        /// Change what this vehicle asks a station for: the battery it says it
        /// has, the power it wants, and when it is leaving.
        /// </summary>
        /// <remarks>
        /// Day-to-day, and the one thing a driver actually changes. Everything
        /// it can be set to is something a station may refuse, so the worst a
        /// wrong figure does is a session that charges slower than it could.
        /// </remarks>
        ChangeChargingSettings = 8,

        /// <summary>
        /// Run a session on the wire below the charging cable: discover a
        /// station, pair over SLAC, charge.
        /// </summary>
        /// <remarks>
        /// Separate from the diagnostics above, which only ask questions. This
        /// one draws power - or, against a station that is not a simulator,
        /// occupies an outlet somebody else is queueing for.
        /// </remarks>
        RunSessions            = 16,

        /// <summary>
        /// Put certificates on this node and take them off, switch them on
        /// and off, and say which of them a session uses.
        /// </summary>
        /// <remarks>
        /// Both halves of the certificate store, because both are decisions
        /// about trust. The credentials are the whole of who this node is
        /// and who pays for what it takes; the roots are the whole of whose
        /// word it takes for a station, a contract and an OEM - and somebody
        /// who can add a root can make this node believe a station nobody
        /// else would. That is why this is the one permission not even the
        /// owner gets by default.
        /// </remarks>
        ManageCredentials      = 32

    }

}
