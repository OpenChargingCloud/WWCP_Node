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

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The "roles" section of the configuration file: roles beside the ones the
    /// node and its kind bring, and what a role they brought may do instead.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One entry per role, its name and its permissions:
    /// </para>
    /// <code>
    /// "roles": {
    ///   "support": [ "dns:read", "nts:read" ]
    /// }
    /// </code>
    /// <para>
    /// A name the node does not know yet is a role of its own, and gets its
    /// group at the next start like every other. A name it knows - "viewer",
    /// or one a kind of node brings - is that role with these permissions
    /// instead of its own. "systemadmin" is refused: it may do everything
    /// there is, and a file that could narrow it could leave nobody able to
    /// put the file right.
    /// </para>
    /// <para>
    /// Whether a resource named here exists is not asked here: the kind of
    /// node adds its own, and only the node knows the whole list. It asks
    /// when it starts, and a role naming a resource it does not have is a
    /// start refused - a typo in "dns" would otherwise be a role that quietly
    /// grants nothing.
    /// </para>
    /// </remarks>
    /// <param name="Roles">The roles, in the order the file names them.</param>
    public sealed record RolesConfiguration(IReadOnlyList<Role> Roles)
    {

        #region Data

        /// <summary>
        /// The name of this section in the configuration file.
        /// </summary>
        public const String  SectionName        = "roles";

        /// <summary>
        /// The most roles the section may name.
        /// </summary>
        public const Int32   MaxRoles           = 64;

        /// <summary>
        /// The most permissions one role may be given.
        /// </summary>
        public const Int32   MaxPermissions     = 256;

        /// <summary>
        /// The longest one permission may be written.
        /// </summary>
        public const Int32   MaxPermissionText  = Permission.MaxResourceLength + 8;

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The "roles" section, or the one sentence that says what is wrong
        /// with it.
        /// </summary>
        /// <remarks>
        /// A role set to null is a role the file says nothing about, as a null
        /// is everywhere else in the file; a role set to an empty list is a
        /// role that may do nothing, which is something to say.
        /// </remarks>
        public static Boolean TryParse(JObject                                      JSON,
                                       [NotNullWhen(true)]  out RolesConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?              Error)
        {

            Configuration  = null;
            Error          = null;

            var roles      = new List<Role>();

            foreach (var property in JSON.Properties())
            {

                if (property.Value.Type == JTokenType.Null)
                    continue;

                var name = property.Name.Trim();

                if (!Role.IsRoleName(name))
                {
                    Error = $"'{SectionName}' names '{property.Name}', which is not a role name: a letter, then letters, digits, '-' or '_', {Role.MinNameLength} to {Role.MaxNameLength} characters.";
                    return false;
                }

                // Told apart regardless of case, as the accounts tell groups
                // apart: two entries for one group would be two answers to one
                // question, and the file would not say which one it meant.
                if (roles.Any(role => String.Equals(role.Name, name, StringComparison.OrdinalIgnoreCase)))
                {
                    Error = $"'{SectionName}' names the role '{name}' twice.";
                    return false;
                }

                if (roles.Count == MaxRoles)
                {
                    Error = $"'{SectionName}' may name at most {MaxRoles} roles.";
                    return false;
                }

                if (!ConfigurationReader.TryReadStrings(JSON, property.Name, SectionName, MaxPermissions, MaxPermissionText, out var texts, out Error))
                    return false;

                var permissions = new List<Permission>();

                foreach (var text in texts ?? [])
                {

                    if (!Permission.TryParse(text, out var permission, out var problem))
                    {
                        Error = $"'{SectionName}.{name}': {problem}";
                        return false;
                    }

                    permissions.Add(permission);

                }

                roles.Add(new Role(name, permissions));

            }

            Configuration = new RolesConfiguration(roles);

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as it is written to the file.
        /// </summary>
        public JObject ToJSON()

            => new (
                   Roles.Select(role => new JProperty(
                                            role.Name,
                                            new JArray(role.Permissions.Select(permission => permission.ToString()))
                                        ))
               );

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Roles.Count == 0
                   ? "no roles"
                   : $"roles {String.Join(", ", Roles.Select(role => role.Name))}";

        #endregion

    }

}
