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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{


    /// <summary>
    /// What a set of roles adds up to.
    /// </summary>
    [Obsolete("Roles are data now: Role, Permission and Operation, asked through WWCPNode.Access and WWCPNode.IsAllowed. This stays until every kind of node using it has moved over.")]
    public static class UserRoleExtensions
    {

        #region PermissionsOf(this Roles)

        /// <summary>
        /// Everything the given roles grant together.
        /// </summary>
        public static Permissions PermissionsOf(this IEnumerable<UserRole> Roles)
        {

            var permissions = Permissions.None;

            foreach (var role in Roles)
                permissions |= role.Permissions;

            return permissions;

        }

        #endregion

        #region Names(this Permissions)

        /// <summary>
        /// The permissions as the web interface reads them, so that a page can
        /// grey out what this browser may not do instead of finding out by
        /// being refused.
        /// </summary>
        /// <remarks>
        /// What the browser is told is a copy of what the node enforces, and
        /// not the enforcement: every request is checked again on arrival. A
        /// greyed-out button is a courtesy, not a lock.
        /// </remarks>
        public static IEnumerable<String> Names(this Permissions Permissions)

            => Enum.GetValues<Permissions>().
                    Where (permission => permission != Permissions.None && Permissions.HasFlag(permission)).
                    Select(permission => Char.ToLowerInvariant(permission.ToString()[0]) + permission.ToString()[1..]);

        #endregion

    }


    /// <summary>
    /// A role somebody signs in as: a name, and the permissions it carries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A closed set, and deliberately so: a role this node has never heard
    /// of is a role it cannot enforce. So a group whose name is not one of
    /// these grants nothing, rather than quietly granting something - or, far
    /// worse, being taken for a known one because it looks similar.
    /// </para>
    /// <para>
    /// Each role is a user group in the HTTPExt API, under the same name, and
    /// membership of that group is what carries the permissions below. The
    /// permissions stay here because they are this node's own vocabulary:
    /// the HTTPExt API knows users, groups and organizations, and has no
    /// opinion about what "may start a charging session" means. So it answers
    /// who somebody is and this answers what that lets them do.
    /// </para>
    /// </remarks>
    /// <param name="Name">The role, and the name of the user group that carries it.</param>
    /// <param name="Permissions">What it grants.</param>
    [Obsolete("Roles are data now: Role, Permission and Operation, asked through WWCPNode.Access and WWCPNode.IsAllowed. This stays until every kind of node using it has moved over.")]
    public sealed record UserRole(String       Name,
                                  Permissions  Permissions)
    {

        #region Properties

        /// <summary>
        /// The user group in the HTTPExt API whose members hold this role.
        /// </summary>
        public UserGroup_Id  GroupId
            => UserGroup_Id.Parse(Name);

        #endregion


        #region Data

        /// <summary>
        /// May look at this node, and do nothing to it.
        /// </summary>
        public static readonly UserRole  Viewer       = new ("viewer",
                                                             Permissions.ReadConfiguration);

        /// <summary>
        /// Whoever drives this vehicle: may say what the battery wants and
        /// when the car is leaving, may plug it in, and may ask whether the
        /// network works - but may not repoint it at other name and time
        /// servers, and may not touch the certificates it is known by.
        /// </summary>
        public static readonly UserRole  Driver       = new ("driver",
                                                             Permissions.ReadConfiguration      |
                                                             Permissions.RunDiagnostics         |
                                                             Permissions.ChangeChargingSettings |
                                                             Permissions.RunSessions);

        /// <summary>
        /// Whoever commissions this vehicle: everything the driver may do, and
        /// on top of it where it resolves names and reads the time.
        /// </summary>
        /// <remarks>
        /// The network settings sit here rather than with the driver because a
        /// vehicle that cannot resolve a name fails in a way that reads like a
        /// broken station, and working that out is a garage's job.
        /// </remarks>
        public static readonly UserRole  Service      = new ("service",
                                                             Permissions.ReadConfiguration      |
                                                             Permissions.ChangeNetworkSettings  |
                                                             Permissions.RunDiagnostics         |
                                                             Permissions.ChangeChargingSettings |
                                                             Permissions.RunSessions);

        /// <summary>
        /// Everything this node can be told, by whoever is trusted with all
        /// of it at once.
        /// </summary>
        public static readonly UserRole  SystemAdmin  = new (WWCPNode.AdminRole,
                                                             Permissions.ReadConfiguration      |
                                                             Permissions.ChangeNetworkSettings  |
                                                             Permissions.RunDiagnostics         |
                                                             Permissions.ChangeChargingSettings |
                                                             Permissions.RunSessions            |
                                                             Permissions.ManageCredentials);

        /// <summary>
        /// Every role this node knows.
        /// </summary>
        public static readonly IReadOnlyList<UserRole>  All = [ Viewer, Driver, Service, SystemAdmin ];

        #endregion


        #region (static) TryParse(Text, out Role, out Error)

        /// <summary>
        /// A role by the name the login file writes it under, in any case.
        /// </summary>
        public static Boolean TryParse(String?                             Text,
                                       [NotNullWhen(true)]  out UserRole?  Role,
                                       [NotNullWhen(false)] out String?    Error)
        {

            Role   = All.FirstOrDefault(role => String.Equals(role.Name, Text?.Trim(), StringComparison.OrdinalIgnoreCase));

            Error  = Role is null
                         ? $"\"{Text}\" is not a role known here. Known roles: {String.Join(", ", All.Select(role => role.Name))}."
                         : null;

            return Role is not null;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()
            => Name;

        #endregion

    }

}
