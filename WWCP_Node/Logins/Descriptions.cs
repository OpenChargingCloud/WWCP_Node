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

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Logins
{

    /// <summary>
    /// What logins, their groups, connections, their peers and credentials say
    /// of themselves: a description, in as many languages as it is said in.
    /// </summary>
    internal static class Descriptions
    {

        #region Normalized(Description)

        /// <summary>
        /// A description with its texts trimmed and those that say nothing left
        /// out - none where none is left.
        /// </summary>
        /// <param name="Description">The description as it was given.</param>
        public static I18NString? Normalized(I18NString? Description)
        {

            var texts = (Description ?? I18NString.Empty).
                            Select (pair => new I18NPair(pair.Language, pair.Text.Trim())).
                            Where  (pair => pair.Text.Length > 0).
                            ToArray();

            return texts.Length > 0
                       ? new I18NString(texts)
                       : null;

        }

        #endregion

        #region TryCheck        (Description, MaxLength,          out Checked, out Error)

        /// <summary>
        /// A description, <see cref="Normalized">normalized</see>, and refused
        /// where a text is longer than the given length.
        /// </summary>
        /// <param name="Description">The description as it was given.</param>
        /// <param name="MaxLength">The longest a text may be, in each language.</param>
        /// <param name="Checked">The description as it is kept.</param>
        /// <param name="Error">Why it was refused.</param>
        public static Boolean TryCheck(I18NString?                       Description,
                                       Int32                             MaxLength,
                                       out I18NString?                   Checked,
                                       [NotNullWhen(false)] out String?  Error)
        {

            Checked  = Normalized(Description);
            Error    = null;

            if (Checked is not null && Checked.Any(pair => pair.Text.Length > MaxLength))
            {
                Checked  = null;
                Error    = $"A description may be at most {MaxLength} characters long, in each language.";
                return false;
            }

            return true;

        }

        #endregion

        #region TryCheckRequired(Description, MaxLength, Missing, out Checked, out Error)

        /// <summary>
        /// A description that has to say something, checked as by
        /// <see cref="TryCheck"/>.
        /// </summary>
        /// <param name="Description">The description as it was given.</param>
        /// <param name="MaxLength">The longest a text may be, in each language.</param>
        /// <param name="Missing">What is said where it says nothing.</param>
        /// <param name="Checked">The description as it is kept.</param>
        /// <param name="Error">Why it was refused.</param>
        public static Boolean TryCheckRequired(I18NString?                                    Description,
                                               Int32                                          MaxLength,
                                               String                                         Missing,
                                               [NotNullWhen(true)]  out I18NString?           Checked,
                                               [NotNullWhen(false)] out String?               Error)
        {

            if (!TryCheck(Description, MaxLength, out Checked, out Error))
                return false;

            if (Checked is null)
            {
                Error = Missing;
                return false;
            }

            return true;

        }

        #endregion

    }

}
