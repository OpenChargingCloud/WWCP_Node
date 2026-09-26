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

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What somebody signed in to a node may do: the roles they hold, and what
    /// those let them do.
    /// </summary>
    /// <remarks>
    /// Asked here and not by every kind of node for itself, so that a role
    /// means the same wherever it is asked about. Who somebody is - a cookie,
    /// an API key, a password - is the HTTPExt API's to answer; which groups
    /// they are in hangs off the account rather than off the door it came
    /// through, and so does everything below.
    /// </remarks>
    public partial class WWCPNode
    {

        #region RolesOf(User)

        /// <summary>
        /// The roles the given account holds: the groups of this node's roles
        /// it is a member of.
        /// </summary>
        /// <remarks>
        /// Asked of the groups on every request rather than remembered at
        /// sign-in, so that taking somebody out of a group takes effect on
        /// their next request instead of at their next sign-in. A role revoked
        /// that still works until a browser is closed is not revoked.
        /// </remarks>
        public IReadOnlyList<Role> RolesOf(IUser? User)

              // IsMember compares the account by identification, which is what
              // makes this safe to ask with whatever instance authenticated the
              // request: a cookie brings one rebuilt from what the cookie holds
              // rather than the one the membership was made with. It compared by
              // reference until 2026-09-18, and the same account then came out as
              // systemadmin through Basic auth and as nobody through a cookie.
            => User is null
                   ? []
                   : [.. Access.Roles.Where(role => ExtAPI.IsMember(User, role.GroupId))];

        #endregion

        #region PermissionsOf(User)

        /// <summary>
        /// Everything the given account may do, spelt out resource by resource -
        /// what a web interface is told so that it can grey out the rest.
        /// </summary>
        /// <remarks>
        /// A copy of what this node enforces and not the enforcement: every
        /// request is asked again when it arrives.
        /// </remarks>
        public IReadOnlyList<Permission> PermissionsOf(IUser? User)

            => Access.PermissionsOf(RolesOf(User));

        #endregion

        #region IsAllowed(User, Resource, Operation)

        /// <summary>
        /// Whether the given account may do the given operation on the given
        /// resource.
        /// </summary>
        public Boolean IsAllowed(IUser?     User,
                                 String     Resource,
                                 Operation  Operation)

            => IsAllowed(User, [ new Permission(Resource, Operation) ]);

        #endregion

        #region IsAllowed(User, Required)

        /// <summary>
        /// Whether the given account may do all of the given - each of them by
        /// whichever of its roles carries it.
        /// </summary>
        /// <remarks>
        /// All of them or nothing: a request that changes two things at once
        /// needs both, and one that is let in for half of what it does has been
        /// let in for all of it.
        /// </remarks>
        public Boolean IsAllowed(IUser?                   User,
                                 IEnumerable<Permission>  Required)

            => User is not null &&
               AccessControl.Allows(RolesOf(User), Required);

        #endregion

    }

}
