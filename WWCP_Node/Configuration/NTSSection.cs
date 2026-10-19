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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The "nts" section of the configuration file as a whole: every group of
    /// time servers of a node, by its name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Written as <c>"nts": { "groups": { "legal": { ... }, "local": { ... } } }</c>,
    /// each group in the shape the section had when there was only one - see
    /// <see cref="NTSConfiguration"/>. The white paper's NTP client groups are
    /// instances of any name; "legal" and "local" are the well-known ones.
    /// </para>
    /// <para>
    /// The flat section every file had before there were groups is read as the
    /// legal group, and stays as it is until something is saved into it: then
    /// it is moved into "groups.legal" as a whole - see
    /// <see cref="WithGroup"/>. A file the node only reads is never rewritten
    /// behind somebody's back.
    /// </para>
    /// <para>
    /// No section at all is the legal group as the node makes it, the PTB's
    /// four. "groups" holding no "legal" is a node without legal time, which is
    /// what a country without the idea for charging stations has; and
    /// <c>"groups": { }</c> is a node that checks its clock against nobody.
    /// </para>
    /// </remarks>
    public sealed class NTSSection
    {

        #region Data

        /// <summary>
        /// The key the groups are kept under.
        /// </summary>
        public const String  GroupsKey    = "groups";

        /// <summary>
        /// The longest a group's name may be.
        /// </summary>
        public const Int32   MaxIdLength  = 32;

        /// <summary>
        /// What only the legal group may say: who stands behind its time, and
        /// how close and how recent a check has to be for it to count.
        /// </summary>
        public static readonly IReadOnlyList<String> LegalOnlyKeys = [
                                                         "legalTimeAuthority",
                                                         "legalTimeToleranceSeconds",
                                                         "legalTimeMaxAgeSeconds"
                                                     ];

        private static readonly Regex groupId = new ("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant);

        #endregion

        #region Properties

        /// <summary>
        /// Every group the section names, in the order it names them.
        /// </summary>
        public IReadOnlyList<KeyValuePair<String, NTSConfiguration>>  Groups  { get; }

        /// <summary>
        /// Whether the section was written the way it was before there were
        /// groups: one group, the legal one, without saying so.
        /// </summary>
        public Boolean                                                IsFlat  { get; }

        /// <summary>
        /// The group of the given name, or null where the section names none.
        /// </summary>
        public NTSConfiguration? this[String Id]

            => Groups.FirstOrDefault(group => group.Key == Id).Value;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The "nts" section as a whole.
        /// </summary>
        /// <param name="Groups">Every group, by its name, in the order the section names them.</param>
        /// <param name="IsFlat">Whether it was written the way it was before there were groups.</param>
        public NTSSection(IEnumerable<KeyValuePair<String, NTSConfiguration>>  Groups,
                          Boolean                                              IsFlat = false)
        {
            this.Groups  = [.. Groups];
            this.IsFlat  = IsFlat;
        }

        #endregion


        #region (static) IsGroupId(Text)

        /// <summary>
        /// Whether a text can be the name of a group: lower-case letters, digits
        /// and hyphens, beginning with a letter - "legal", "local", "grid-a".
        /// </summary>
        /// <remarks>
        /// Narrow on purpose: the name is a key in the file, a part of a URL and
        /// a word in log lines, and what reads the same in all three is this.
        /// What people see is the display name.
        /// </remarks>
        public static Boolean IsGroupId(String? Text)

            => Text is not null &&
               Text.Length <= MaxIdLength &&
               groupId.IsMatch(Text);

        #endregion

        #region (static) PathOf(Id)

        /// <summary>
        /// Where a group is in the file, as a sentence about it names it:
        /// "nts.groups.local".
        /// </summary>
        public static String PathOf(String Id)

            => $"{NTSConfiguration.SectionName}.{GroupsKey}.{Id}";

        #endregion

        #region (static) TryParse(JSON, out Section, out Error)

        /// <summary>
        /// The "nts" section, in either of its forms, or the one sentence that
        /// says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JObject                                JSON,
                                       [NotNullWhen(true)]  out NTSSection?    Section,
                                       [NotNullWhen(false)] out String?        Error)
        {

            Section = null;

            #region The flat section of a file from before there were groups

            if (!JSON.TryGetValue(GroupsKey, out var groupsToken))
            {

                if (!NTSConfiguration.TryParse(JSON, out var legal, out Error))
                    return false;

                Section = new NTSSection([ new (NTSGroup.LegalId, legal) ], IsFlat: true);
                return true;

            }

            #endregion

            Error = null;

            // Both at once is a file half moved by hand: the settings beside
            // "groups" would belong to no group, and guessing which one they
            // meant would be guessing.
            var beside = JSON.Properties().Select(property => property.Name).Where(name => name != GroupsKey).ToArray();

            if (beside.Length > 0)
            {
                Error = $"'{NTSConfiguration.SectionName}' holds '{GroupsKey}' and also '{String.Join("', '", beside)}': with groups, every setting belongs to one of them - " +
                        $"move it into '{PathOf(NTSGroup.LegalId)}', or wherever it was meant for.";
                return false;
            }

            if (groupsToken is not JObject groupsJSON)
            {
                Error = $"'{NTSConfiguration.SectionName}.{GroupsKey}' must be an object of the groups by their names.";
                return false;
            }

            var groups = new List<KeyValuePair<String, NTSConfiguration>>();

            foreach (var (id, groupToken) in groupsJSON)
            {

                var path = PathOf(id);

                if (!IsGroupId(id))
                {
                    Error = $"'{path}': '{id}' cannot be the name of a group, which is lower-case letters, digits and hyphens, beginning with a letter, and at most {MaxIdLength} of them.";
                    return false;
                }

                if (groupToken is not JObject groupJSON)
                {
                    Error = $"'{path}' must be an object.";
                    return false;
                }

                if (!NTSConfiguration.TryParse(groupJSON, out var group, out Error, path))
                    return false;

                if (id != NTSGroup.LegalId)
                {

                    // Legal time rests on the legal group, and on nothing else: a
                    // "local" group saying "PTB" would be a claim nobody reads,
                    // and one somebody might believe.
                    var legalOnly = LegalOnlyKeys.FirstOrDefault(key => groupJSON.TryGetValue(key, out var value) && value.Type != JTokenType.Null);

                    if (legalOnly is not null)
                    {
                        Error = $"'{path}.{legalOnly}': only the group '{NTSGroup.LegalId}' carries legal time.";
                        return false;
                    }

                    // Switched on and asking nobody is a group that fails every
                    // check it makes. The legal group has the PTB's four when it
                    // names none; no other group has a default worth having.
                    if (group.Enabled == true && group.Servers is null && group.Hostname is null)
                    {
                        Error = $"'{path}' is switched on and names no time server: name one, or set '{path}.enabled' to false.";
                        return false;
                    }

                }

                groups.Add(new (id, group));

            }

            Section = new NTSSection(groups);
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as it is written to the file, in the form it was read
        /// in: flat where it was flat, with groups otherwise.
        /// </summary>
        public JObject ToJSON()

            => IsFlat && this[NTSGroup.LegalId] is NTSConfiguration legal
                   ? legal.ToJSON()
                   : new JObject(
                         new JProperty(GroupsKey, new JObject(
                             Groups.Select(group => new JProperty(group.Key, group.Value.ToJSON()))
                         ))
                     );

        #endregion

        #region (static) Grouped(Section)

        /// <summary>
        /// The section as it is written with groups, whichever way it was
        /// written: a copy, never the section itself.
        /// </summary>
        /// <remarks>
        /// The flat section becomes "groups.legal" as a whole, and no section at
        /// all becomes a legal group that says nothing - which is still the
        /// PTB's four, now said beside whatever group is added.
        /// </remarks>
        /// <param name="Section">The "nts" section of the file, or null where it has none.</param>
        public static JObject Grouped(JObject? Section)
        {

            if (Section?[GroupsKey] is JObject)
                return (JObject) Section.DeepClone();

            return new JObject(
                       new JProperty(GroupsKey, new JObject(
                           new JProperty(NTSGroup.LegalId, Section?.DeepClone() ?? new JObject())
                       ))
                   );

        }

        #endregion

        #region (static) WithGroup(Section, Id, Values, Removed)

        /// <summary>
        /// The section with the given fields written into one of its groups and
        /// the given keys taken out of it, leaving everything else alone - and
        /// written with groups from now on.
        /// </summary>
        /// <remarks>
        /// What saving a group does to the file. A section still written flat is
        /// moved into "groups.legal" first, by <see cref="Grouped"/>: the first
        /// save of anything is where a file changes its form, because a save is
        /// a moment somebody meant the file to be written. A group the section
        /// does not name yet is added after the others.
        ///
        /// Arrays are replaced rather than merged, as in every section: a list
        /// of servers is one value.
        /// </remarks>
        /// <param name="Section">The "nts" section of the file, or null where it has none.</param>
        /// <param name="Id">The group.</param>
        /// <param name="Values">The fields to write into it.</param>
        /// <param name="Removed">The keys to take out of it.</param>
        public static JObject WithGroup(JObject?             Section,
                                        String               Id,
                                        JObject              Values,
                                        IEnumerable<String>  Removed)
        {

            var grouped  = Grouped(Section);
            var groups   = (JObject) grouped[GroupsKey]!;

            if (groups[Id] is not JObject group)
            {
                group       = [];
                groups[Id]  = group;
            }

            group.Merge(
                Values,
                new JsonMergeSettings {
                    MergeArrayHandling = MergeArrayHandling.Replace
                }
            );

            foreach (var key in Removed)
                group.Remove(key);

            return grouped;

        }

        #endregion

        #region (static) WithoutGroup(Section, Id)

        /// <summary>
        /// The section without one of its groups, written with groups from now
        /// on - so that a legal group taken away stays away, and does not come
        /// back as the default at the next start.
        /// </summary>
        /// <param name="Section">The "nts" section of the file, or null where it has none.</param>
        /// <param name="Id">The group.</param>
        public static JObject WithoutGroup(JObject?  Section,
                                           String    Id)
        {

            var grouped = Grouped(Section);

            ((JObject) grouped[GroupsKey]!).Remove(Id);

            return grouped;

        }

        #endregion

    }

}
