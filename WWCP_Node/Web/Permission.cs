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
    /// One thing a role lets somebody do: an operation on a resource, written
    /// "dns:edit".
    /// </summary>
    /// <remarks>
    /// <para>
    /// A resource is a name and nothing more - "dns", "certificates",
    /// "session" - and it is whoever serves the resource that says what it is
    /// called: the node for what every node has, a kind of node for what it
    /// adds. So a vehicle's roles and a charging station's are written in the
    /// same form about different things, and a role in the configuration file
    /// can name either.
    /// </para>
    /// <para>
    /// "*" is every resource there is, the ones a kind of node adds included:
    /// "*:read" is somebody who may look at everything, whatever the node
    /// turns out to have.
    /// </para>
    /// </remarks>
    public readonly record struct Permission
    {

        #region Data

        /// <summary>
        /// The resource that stands for every resource.
        /// </summary>
        public const String  AnyResource        = "*";

        /// <summary>
        /// The longest a resource may be called.
        /// </summary>
        public const Int32   MaxResourceLength  = 64;

        #endregion

        #region Properties

        /// <summary>
        /// What may be touched, in lower case, or <see cref="AnyResource"/>.
        /// </summary>
        public String     Resource    { get; }

        /// <summary>
        /// How it may be touched.
        /// </summary>
        public Operation  Operation   { get; }

        /// <summary>
        /// Whether this is about every resource.
        /// </summary>
        public Boolean    IsAnyResource
            => Resource == AnyResource;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// An operation on a resource.
        /// </summary>
        /// <param name="Resource">The resource, in any case, or <see cref="AnyResource"/>.</param>
        /// <param name="Operation">The operation.</param>
        public Permission(String     Resource,
                          Operation  Operation)
        {

            var resource = Resource?.Trim().ToLowerInvariant() ?? "";

            if (!IsResourceName(resource) && resource != AnyResource)
                throw new ArgumentException($"'{Resource}' is not a resource name: a letter, then letters, digits, '-' or '_', at most {MaxResourceLength} characters.",
                                            nameof(Resource));

            this.Resource   = resource;
            this.Operation  = Operation;

        }

        #endregion


        #region (static) Read(Resource) / Edit(Resource) / Run(Resource)

        /// <summary>
        /// Reading the given resource.
        /// </summary>
        public static Permission Read(String Resource)
            => new (Resource, Operation.Read);

        /// <summary>
        /// Editing the given resource.
        /// </summary>
        public static Permission Edit(String Resource)
            => new (Resource, Operation.Edit);

        /// <summary>
        /// Running the given resource.
        /// </summary>
        public static Permission Run(String Resource)
            => new (Resource, Operation.Run);

        #endregion

        #region (static) IsResourceName(Text)

        /// <summary>
        /// Whether the given text may name a resource: a letter, then letters,
        /// digits, '-' or '_' - lower case, which is what a resource is
        /// compared in.
        /// </summary>
        /// <remarks>
        /// Narrow on purpose. A resource is written after a role in the
        /// configuration file and before a colon in the web interface, so a
        /// name with a colon, a space or a star in it would be read as
        /// something else in one of the two.
        /// </remarks>
        public static Boolean IsResourceName(String? Text)
        {

            if (String.IsNullOrEmpty(Text) || Text.Length > MaxResourceLength)
                return false;

            if (Text[0] is < 'a' or > 'z')
                return false;

            foreach (var character in Text)
                if (character is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_'))
                    return false;

            return true;

        }

        #endregion

        #region (static) TryParse(Text, out Permission, out Error)

        /// <summary>
        /// A permission written the way the configuration file and the web
        /// interface write it - "dns:edit", "*:read" - in any case.
        /// </summary>
        public static Boolean TryParse(String?                           Text,
                                       out Permission                    Permission,
                                       [NotNullWhen(false)] out String?  Error)
        {

            Permission  = default;
            Error       = null;

            var text    = Text?.Trim() ?? "";
            var colon   = text.IndexOf(':');

            if (colon < 0 || colon != text.LastIndexOf(':'))
            {
                Error = $"'{Text}' is not a permission: it is a resource and an operation, as in \"dns:read\".";
                return false;
            }

            var resource = text[..colon].Trim().ToLowerInvariant();

            if (resource != AnyResource && !IsResourceName(resource))
            {
                Error = $"'{text[..colon].Trim()}' in '{Text}' is not a resource name: a letter, then letters, digits, '-' or '_', or \"*\" for every resource.";
                return false;
            }

            if (!OperationExtensions.TryParse(text[(colon + 1)..], out var operation))
            {
                Error = $"'{text[(colon + 1)..].Trim()}' in '{Text}' is not an operation. Known operations: read, edit, run.";
                return false;
            }

            Permission = new Permission(resource, operation);
            return true;

        }

        #endregion


        #region Covers(Resource, Operation)

        /// <summary>
        /// Whether this lets somebody do the given operation on the given
        /// resource.
        /// </summary>
        public Boolean Covers(String     Resource,
                              Operation  Operation)

            => this.Operation == Operation &&
               (IsAnyResource || String.Equals(this.Resource, Resource, StringComparison.OrdinalIgnoreCase));

        #endregion

        #region (override) ToString()

        /// <summary>
        /// "dns:edit".
        /// </summary>
        public override String ToString()
            => $"{Resource}:{Operation.AsText()}";

        #endregion

    }

}
