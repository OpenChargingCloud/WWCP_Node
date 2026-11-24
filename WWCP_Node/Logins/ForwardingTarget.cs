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
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Logins
{

    /// <summary>
    /// Where what a charging station sends up is forwarded to: the back ends
    /// of this node - its peers - in the order they are tried. The first of
    /// them that is connected gets it; where none is, the station is told so,
    /// and nothing goes to a back end that is not in the list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A list even where it holds one peer: a CSMS and the one taking over
    /// from it, or a CSMS and its standby, are one target of a station, and
    /// the station is not moved by hand when the first one is down.
    /// </para>
    /// <para>
    /// A peer is a back end, with however many endpoints it has: the peer
    /// tries its endpoints, the target tries its peers.
    /// </para>
    /// <para>
    /// A charging station whose login names no target goes to the back end in
    /// charge of this node, as every station did before there were targets.
    /// </para>
    /// </remarks>
    /// <param name="Id">What the target is called, in the file and in every login that names it.</param>
    /// <param name="PeerIds">The peers it forwards to, in the order they are tried.</param>
    /// <param name="AddedAt">When it was made.</param>
    /// <param name="Description">What it is for, for whoever reads the list later - in as many languages as it is said in.</param>
    public sealed partial record ForwardingTarget(String                 Id,
                                                  IReadOnlyList<String>  PeerIds,
                                                  DateTimeOffset         AddedAt,
                                                  I18NString?            Description)
    {

        #region Data

        /// <summary>
        /// The longest a target identification may be.
        /// </summary>
        public const Int32  MaxIdLength           = 32;

        /// <summary>
        /// How many peers one target may try.
        /// </summary>
        public const Int32  MaxPeers              = 8;

        /// <summary>
        /// The longest a description of a target may be, in each language.
        /// </summary>
        public const Int32  MaxDescriptionLength  = 200;

        /// <summary>
        /// How many targets may be listed.
        /// </summary>
        public const Int32  MaxTargets            = 100;

        [GeneratedRegex("^[a-z0-9][a-z0-9_-]*$")]
        private static partial Regex IdPattern();

        #endregion


        #region (static) TryCheckId(Text, out Id, out Error)

        /// <summary>
        /// A target identification as it is kept: trimmed, in lower case, of
        /// letters, digits, '-' and '_', and starting with a letter or digit.
        /// </summary>
        public static Boolean TryCheckId(String?                            Text,
                                         [NotNullWhen(true)]  out String?  Id,
                                         [NotNullWhen(false)] out String?  Error)
        {

            Id     = Text?.Trim().ToLowerInvariant();
            Error  = null;

            if (String.IsNullOrEmpty(Id) || Id.Length > MaxIdLength || !IdPattern().IsMatch(Id))
            {
                Error  = $"A target is named in 1 to {MaxIdLength} letters, digits, '-' and '_', starting with a letter or a digit.";
                Id     = null;
                return false;
            }

            return true;

        }

        #endregion

        #region (static) TryParse(JSON, out Target, out Error)

        /// <summary>
        /// One target, as it stands in the file.
        /// </summary>
        public static Boolean TryParse(JObject                                    JSON,
                                       [NotNullWhen(true)]  out ForwardingTarget? Target,
                                       [NotNullWhen(false)] out String?           Error)
        {

            Target = null;

            if (!TryCheckId(JSON.Value<String>("id"), out var id, out Error))
                return false;

            if (JSON["peers"] is not JArray peersJSON ||
                peersJSON.Any(peer => peer.Type != JTokenType.String || String.IsNullOrWhiteSpace(peer.Value<String>())))
            {
                Error = $"the target '{id}' needs 'peers', a JSON array of peer identifications.";
                return false;
            }

            var peers = peersJSON.Select(peer => peer.Value<String>()!.Trim()).ToArray();

            if (peers.Length == 0 || peers.Length > MaxPeers)
            {
                Error = $"the target '{id}' tries 1 to {MaxPeers} peers, not {peers.Length}.";
                return false;
            }

            if (peers.Distinct(StringComparer.Ordinal).Count() != peers.Length)
            {
                Error = $"the target '{id}' names a peer twice.";
                return false;
            }

            var addedAt = DateTimeOffset.MinValue;

            DateTimeOffset.TryParse(JSON.Value<String>("addedAt"),
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.RoundtripKind,
                                    out addedAt);

            Target = new ForwardingTarget(
                         id,
                         peers,
                         addedAt,
                         JSON["description"] is JObject descriptionJSON &&
                         I18NString.TryParse(descriptionJSON, out I18NString? description, out _) &&
                         description.IsNotNullOrEmpty()
                             ? description
                             : null
                     );

            return true;

        }

        #endregion

        #region ToJSON(Logins = null)

        /// <summary>
        /// This target - with how many logins name it, where that is asked.
        /// </summary>
        public JObject ToJSON(Int32? Logins = null)
        {

            var json = new JObject(
                           new JProperty("id",       Id),
                           new JProperty("peers",    new JArray(PeerIds)),
                           new JProperty("addedAt",  AddedAt.ToString("o"))
                       );

            if (Description.IsNotNullOrEmpty())
                json.Add("description", Description.ToJSON());

            if (Logins.HasValue)
                json.Add("logins", Logins.Value);

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()
            => $"{Id}: {String.Join(" > ", PeerIds)}";

        #endregion

    }

}
