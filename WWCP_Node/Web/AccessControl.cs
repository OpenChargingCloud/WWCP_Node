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

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// Who may do what on a node: the resources it has, and the roles that
    /// may touch them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Put together once, when the node is made, from three places in this
    /// order: the node's own - the resources every node has, the viewer and
    /// the administrators - then what the kind of node brings, then what the
    /// configuration file says. Each may add, and the later ones may say
    /// differently what a role of an earlier one may do; nobody but the node
    /// says what the administrators may do, which is everything.
    /// </para>
    /// <para>
    /// A kind of node that still enforces roles of its own may hand in their
    /// names alone. Their groups are made like every other, and the node
    /// knows no permissions for them: what they let somebody do is that
    /// kind's own business, as it was before roles were data.
    /// </para>
    /// </remarks>
    public sealed class AccessControl
    {

        #region Properties

        /// <summary>
        /// Every resource a role may name: the node's, and its kind's.
        /// </summary>
        public IReadOnlyList<String>  Resources    { get; }

        /// <summary>
        /// Every role, as it came out of the node, its kind and its
        /// configuration file - the viewer first and the administrators last.
        /// </summary>
        public IReadOnlyList<Role>    Roles        { get; }

        /// <summary>
        /// The roles known here by their names alone: what they let somebody
        /// do is enforced by the kind of node that named them, and not known
        /// to the node.
        /// </summary>
        public IReadOnlySet<String>   NamedOnly    { get; }

        #endregion

        #region Constructor(s)

        private AccessControl(IReadOnlyList<String>  Resources,
                              IReadOnlyList<Role>    Roles,
                              IReadOnlySet<String>   NamedOnly)
        {

            this.Resources  = Resources;
            this.Roles      = Roles;
            this.NamedOnly  = NamedOnly;

        }

        #endregion


        #region (static) TryCombine(KindResources, KindRoles, RoleNames, Configured, NodeName, out Access, out Notes, out Error)

        /// <summary>
        /// The node's resources and roles, its kind's, and the configuration
        /// file's, put together - or the one sentence that says what is wrong
        /// with the file.
        /// </summary>
        /// <remarks>
        /// What the kind of node hands in is code, and a mistake in it is a
        /// mistake in the program: that throws. What the configuration file
        /// says is somebody's writing, and a mistake in it is answered with a
        /// sentence that names the entry.
        /// </remarks>
        /// <param name="KindResources">The resources the kind of node adds.</param>
        /// <param name="KindRoles">The roles the kind of node brings, each with what it may do.</param>
        /// <param name="RoleNames">The roles of a kind of node that enforces them itself, by name alone.</param>
        /// <param name="Configured">What the configuration file says.</param>
        /// <param name="NodeName">What the node calls itself in a sentence: "electric vehicle".</param>
        /// <param name="Access">The resources and roles.</param>
        /// <param name="Notes">What the configuration file changed, one sentence each, for the log.</param>
        /// <param name="Error">What is wrong with the configuration file.</param>
        public static Boolean TryCombine(IEnumerable<String>?                        KindResources,
                                         IEnumerable<Role>?                          KindRoles,
                                         IEnumerable<String>?                        RoleNames,
                                         RolesConfiguration?                         Configured,
                                         String                                      NodeName,
                                         [NotNullWhen(true)]  out AccessControl?     Access,
                                         out IReadOnlyList<String>                   Notes,
                                         [NotNullWhen(false)] out String?            Error)
        {

            Access  = null;
            Error   = null;

            var notes = new List<String>();
            Notes     = notes;

            #region The resources: the node's, and its kind's

            var resources = new List<String>(NodeResources.All);

            foreach (var resource in KindResources ?? [])
            {

                var name = resource?.Trim().ToLowerInvariant() ?? "";

                if (!Permission.IsResourceName(name))
                    throw new ArgumentException($"'{resource}' is not a resource name: a letter, then letters, digits, '-' or '_'.",
                                                nameof(KindResources));

                if (!resources.Contains(name))
                    resources.Add(name);

            }

            #endregion

            #region The roles: the viewer, the kind's, the ones known by name, the administrators

            var roles = new List<Role> { Role.Viewer };

            foreach (var role in KindRoles ?? [])
            {

                if (role.IsSystemAdmin)
                    throw new ArgumentException($"What '{WWCPNode.AdminRole}' may do is not a kind of node's to say: it may do everything there is.",
                                                nameof(KindRoles));

                if (UnknownResource(role, resources) is String unknown)
                    throw new ArgumentException($"The role '{role.Name}' names the resource '{unknown}', which is neither the node's nor handed in as one of its kind's.",
                                                nameof(KindRoles));

                var index = IndexOf(roles, role.Name);

                // The node's viewer is a default, and a kind of node that means
                // something else by "viewer" says so by bringing its own.
                if (index >= 0 && ReferenceEquals(roles[index], Role.Viewer))
                    roles[index] = role;

                else if (index >= 0)
                    throw new ArgumentException($"The role '{role.Name}' is handed in twice.",
                                                nameof(KindRoles));

                else
                    roles.Add(role);

            }

            var namedOnly = new HashSet<String>(StringComparer.OrdinalIgnoreCase);

            foreach (var name in RoleNames ?? [])
            {

                var trimmed = name?.Trim() ?? "";

                if (String.Equals(trimmed, WWCPNode.AdminRole, StringComparison.OrdinalIgnoreCase) ||
                    IndexOf(roles, trimmed) >= 0)
                {
                    continue;
                }

                // A role this node knows nothing about but its name: its
                // group is made, and what it lets somebody do is enforced by
                // the kind of node that named it.
                roles.Add(new Role(trimmed, []));
                namedOnly.Add(trimmed);

            }

            roles.Add(Role.SystemAdmin);

            #endregion

            #region What the configuration file says

            // A kind of node that names its roles and brings none of them as
            // data asks nobody but itself what a role may do - so a role in the
            // file would be a group that grants whatever that kind grants its
            // members, which is to say nothing it was written to grant.
            if (Configured?.Roles.Count > 0 && RoleNames?.Any() == true && KindRoles?.Any() != true)
            {
                Error = $"'{RolesConfiguration.SectionName}' cannot be heard by this {NodeName}: it decides by itself what its roles may do, so a role written here would be one nobody enforces.";
                return false;
            }

            foreach (var role in Configured?.Roles ?? [])
            {

                if (role.IsSystemAdmin)
                {
                    Error = $"'{RolesConfiguration.SectionName}' may not say what '{WWCPNode.AdminRole}' may do: it may do everything there is, and a file that narrowed it could leave nobody able to put the file right.";
                    return false;
                }

                if (UnknownResource(role, resources) is String unknown)
                {
                    Error = $"'{RolesConfiguration.SectionName}.{role.Name}' names the resource '{unknown}', which this {NodeName} does not have. " +
                            $"Its resources are: {String.Join(", ", resources)} - or \"*\" for all of them.";
                    return false;
                }

                var permissions  = role.Permissions.Count == 0
                                       ? "nothing"
                                       : String.Join(", ", role.Permissions);

                var index        = IndexOf(roles, role.Name);

                if (index >= 0)
                {
                    roles[index] = roles[index].WithPermissions(role.Permissions);
                    notes.Add($"The configuration file lets the role '{roles[index].Name}' do {permissions}, instead of what this {NodeName} lets it do.");
                }

                else
                {
                    // Before the administrators, who stay last: that is where a
                    // sentence naming the roles that may do something reads
                    // best, "the driver, the support or the systemadmin role".
                    roles.Insert(roles.Count - 1, role);
                    notes.Add($"The configuration file adds the role '{role.Name}', which may do {permissions}.");
                }

            }

            #endregion

            Access = new AccessControl(resources, roles, namedOnly);
            return true;

        }

        #endregion


        #region RoleNamed(Name)

        /// <summary>
        /// The role of the given name, in any case, or null.
        /// </summary>
        public Role? RoleNamed(String? Name)

            => Roles.FirstOrDefault(role => String.Equals(role.Name, Name?.Trim(), StringComparison.OrdinalIgnoreCase));

        #endregion

        #region RolesAllowing(Required)

        /// <summary>
        /// The roles that let somebody do all of the given, each of them on its
        /// own - what a refusal names as the roles to ask for.
        /// </summary>
        /// <remarks>
        /// Each on its own, because a refusal that named a role which could
        /// only do half of what was asked would send somebody to ask for the
        /// wrong one.
        /// </remarks>
        public IReadOnlyList<Role> RolesAllowing(IEnumerable<Permission> Required)
        {

            var required = Required.ToArray();

            return [.. Roles.Where(role => required.All(permission => role.Allows(permission.Resource, permission.Operation)))];

        }

        #endregion

        #region Allows(Roles, Required)

        /// <summary>
        /// Whether somebody holding the given roles may do all of the given -
        /// each of them by whichever of the roles carries it.
        /// </summary>
        public static Boolean Allows(IEnumerable<Role>        Roles,
                                     IEnumerable<Permission>  Required)
        {

            var roles = Roles.ToArray();

            return Required.All(permission => roles.Any(role => role.Allows(permission.Resource, permission.Operation)));

        }

        #endregion

        #region PermissionsOf(Roles)

        /// <summary>
        /// Everything the given roles let somebody do, spelt out resource by
        /// resource: "*" is written as every resource there is.
        /// </summary>
        /// <remarks>
        /// Spelt out for whoever reads it - a web interface that greys out what
        /// it may not do asks "dns:edit" and should not have to know that "*"
        /// means that too.
        /// </remarks>
        public IReadOnlyList<Permission> PermissionsOf(IEnumerable<Role> Roles)
        {

            var permissions = new List<Permission>();
            var order       = Resources.Select((resource, index) => (resource, index)).
                                        ToDictionary(pair => pair.resource, pair => pair.index);

            foreach (var permission in Roles.SelectMany(role => role.Permissions))
            {

                if (permission.IsAnyResource)
                    permissions.AddRange(Resources.Select(resource => new Permission(resource, permission.Operation)));

                else
                    permissions.Add(permission);

            }

            return [.. permissions.Distinct().
                                   OrderBy(permission => order.TryGetValue(permission.Resource, out var index) ? index : Int32.MaxValue).
                                   ThenBy (permission => permission.Resource, StringComparer.Ordinal).
                                   ThenBy (permission => permission.Operation)];

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// Every role and what it may do, as the Configuration page reads it.
        /// </summary>
        /// <remarks>
        /// A role known by its name alone says null rather than an empty list:
        /// it may well do a great deal, and what it may do is not the node's
        /// to show.
        /// </remarks>
        public JArray ToJSON()

            => new (Roles.Select(role => NamedOnly.Contains(role.Name)
                                             ? new JObject(
                                                   new JProperty("name",         role.Name),
                                                   new JProperty("permissions",  JValue.CreateNull()),
                                                   new JProperty("description",  "what it may do is enforced by this kind of node itself")
                                               )
                                             : role.ToJSON()));

        #endregion


        #region (private static) IndexOf(Roles, Name)

        private static Int32 IndexOf(List<Role>  Roles,
                                     String      Name)

            => Roles.FindIndex(role => String.Equals(role.Name, Name, StringComparison.OrdinalIgnoreCase));

        #endregion

        #region (private static) UnknownResource(Role, Resources)

        /// <summary>
        /// The first resource the given role names that is not among the given
        /// ones, or null.
        /// </summary>
        private static String? UnknownResource(Role                   Role,
                                               IReadOnlyList<String>  Resources)

            => Role.Permissions.
                    Where (permission => !permission.IsAnyResource && !Resources.Contains(permission.Resource)).
                    Select(permission => permission.Resource).
                    FirstOrDefault();

        #endregion

    }

}
