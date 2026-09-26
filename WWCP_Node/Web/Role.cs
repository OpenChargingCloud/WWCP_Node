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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// A role somebody signs in as: a name, and the permissions it carries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Data rather than vocabulary. The node brings two - the administrators',
    /// who may do everything, and the viewer, who may look at everything - a
    /// kind of node brings its own, and the configuration file may add more or
    /// say differently what one of them may do. Nothing about a role is
    /// compiled into the routes that ask for it: a route asks for a permission,
    /// and whichever roles carry it are let in.
    /// </para>
    /// <para>
    /// Each role is a user group in the HTTPExt API, under the same name, and
    /// membership of that group is what carries the permissions. The HTTPExt
    /// API knows users, groups and organizations and has no opinion about
    /// what "may edit the DNS settings" means; it answers who somebody is, and
    /// the node answers what that lets them do.
    /// </para>
    /// </remarks>
    public sealed record Role
    {

        #region Data

        /// <summary>
        /// The shortest a role may be called.
        /// </summary>
        public const Int32  MinNameLength  = 2;

        /// <summary>
        /// The longest a role may be called.
        /// </summary>
        public const Int32  MaxNameLength  = 64;

        /// <summary>
        /// Everything this node can be told, by whoever is trusted with all of
        /// it at once.
        /// </summary>
        /// <remarks>
        /// Every operation on every resource, the ones a kind of node adds
        /// included, and not the configuration file's to narrow: the first
        /// account is put in this role, and a file that took something away
        /// from it could leave nobody able to put that right.
        /// </remarks>
        public static readonly Role  SystemAdmin  = new (WWCPNode.AdminRole,
                                                         [ Permission.Read(Permission.AnyResource),
                                                           Permission.Edit(Permission.AnyResource),
                                                           Permission.Run (Permission.AnyResource) ],
                                                         "may do everything");

        /// <summary>
        /// Somebody who may look at everything, and do nothing to it.
        /// </summary>
        public static readonly Role  Viewer       = new ("viewer",
                                                         [ Permission.Read(Permission.AnyResource) ],
                                                         "may look at everything, and change nothing");

        #endregion

        #region Properties

        /// <summary>
        /// The role, and the name of the user group that carries it.
        /// </summary>
        public String                      Name           { get; }

        /// <summary>
        /// What it lets somebody do.
        /// </summary>
        public IReadOnlyList<Permission>   Permissions    { get; }

        /// <summary>
        /// What it is for, in a few words, or null.
        /// </summary>
        public String?                     Description    { get; }

        /// <summary>
        /// The user group in the HTTPExt API whose members hold this role.
        /// </summary>
        public UserGroup_Id                GroupId
            => UserGroup_Id.Parse(Name);

        /// <summary>
        /// Whether this is the administrators' role.
        /// </summary>
        public Boolean                     IsSystemAdmin
            => String.Equals(Name, WWCPNode.AdminRole, StringComparison.OrdinalIgnoreCase);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A role: a name, and what it lets somebody do.
        /// </summary>
        /// <param name="Name">The role, and the name of the user group that carries it.</param>
        /// <param name="Permissions">What it lets somebody do; the same permission twice counts once.</param>
        /// <param name="Description">What it is for, in a few words.</param>
        public Role(String                   Name,
                    IEnumerable<Permission>  Permissions,
                    String?                  Description = null)
        {

            var name = Name?.Trim() ?? "";

            if (!IsRoleName(name))
                throw new ArgumentException($"'{Name}' is not a role name: a letter, then letters, digits, '-' or '_', {MinNameLength} to {MaxNameLength} characters.",
                                            nameof(Name));

            this.Name         = name;
            this.Permissions  = [.. Permissions.Distinct()];
            this.Description  = Description?.Trim() is { Length: > 0 } description
                                    ? description
                                    : null;

        }

        #endregion


        #region (static) IsRoleName(Text)

        /// <summary>
        /// Whether the given text may name a role: a letter, then letters,
        /// digits, '-' or '_'.
        /// </summary>
        /// <remarks>
        /// Narrower than what a user group of the HTTPExt API may be called,
        /// which is anything that is not empty: a role is also written into
        /// the configuration file and read out in a sentence, and a name with
        /// a space or a comma in it would read as two roles in both.
        /// </remarks>
        public static Boolean IsRoleName(String? Text)
        {

            if (String.IsNullOrEmpty(Text) || Text.Length < MinNameLength || Text.Length > MaxNameLength)
                return false;

            if (!Char.IsAsciiLetter(Text[0]))
                return false;

            foreach (var character in Text)
                if (!Char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))
                    return false;

            return true;

        }

        #endregion


        #region Allows(Resource, Operation)

        /// <summary>
        /// Whether this role lets somebody do the given operation on the given
        /// resource.
        /// </summary>
        public Boolean Allows(String     Resource,
                              Operation  Operation)

            => Permissions.Any(permission => permission.Covers(Resource, Operation));

        #endregion

        #region WithPermissions(Permissions, Description = null)

        /// <summary>
        /// The same role, letting somebody do something else: what the
        /// configuration file makes of a role a node or a kind of node brought.
        /// </summary>
        public Role WithPermissions(IEnumerable<Permission>  Permissions,
                                    String?                  Description = null)

            => new (Name, Permissions, Description ?? this.Description);

        #endregion

        #region ToJSON()

        /// <summary>
        /// The role as the Configuration page reads it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("name",         Name),
                   new JProperty("permissions",  new JArray(Permissions.Select(permission => permission.ToString()))),
                   new JProperty("description",  Description)
               );

        #endregion

        #region (override) ToString()

        /// <summary>
        /// The name, which is how a role is read out in a sentence.
        /// </summary>
        public override String ToString()
            => Name;

        #endregion

    }

}
