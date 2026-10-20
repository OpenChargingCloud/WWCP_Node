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

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The "nts" section as a whole: its groups, the flat form of the files
    /// from before there were groups that it refuses, and what saving one
    /// group does to it.
    /// </summary>
    public class NTSSectionTests
    {

        #region (helper) Parsed(JSON)

        private static NTSSection Parsed(String JSON)
        {

            Assert.That(NTSSection.TryParse(JObject.Parse(JSON), out var section, out var error), Is.True, error);

            return section!;

        }

        #endregion

        #region (helper) Refusal(JSON)

        private static String Refusal(String JSON)
        {

            Assert.That(NTSSection.TryParse(JObject.Parse(JSON), out _, out var error), Is.False);

            return error!;

        }

        #endregion


        #region AFlatSectionIsRefusedAndToldWhereItBelongs()

        /// <summary>
        /// The section of the files from before there were groups is not read
        /// any more, nor guessed at: refused, with where its settings belong.
        /// </summary>
        [Test]
        public void AFlatSectionIsRefusedAndToldWhereItBelongs()
        {

            var one   = Refusal("""{ "enabled": false }""");
            var more  = Refusal("""{ "enabled": false, "hostname": "a.example" }""");

            Assert.Multiple(() => {
                Assert.That(one,   Does.Contain("'enabled'").And.Contain("move it into 'nts.groups.legal'"));
                Assert.That(more,  Does.Contain("'enabled', 'hostname'").And.Contain("move them into 'nts.groups.legal'"));
            });

        }

        #endregion

        #region AnEmptySectionIsTheLegalGroupAsTheNodeMakesIt()

        /// <summary>
        /// <c>"nts": { }</c> says nothing, and is as good as no section: the
        /// legal group, with the PTB's four.
        /// </summary>
        [Test]
        public void AnEmptySectionIsTheLegalGroupAsTheNodeMakesIt()
        {

            var section = Parsed("""{ }""");

            Assert.Multiple(() => {
                Assert.That(section.Groups.Select(group => group.Key),        Is.EqualTo(new[] { "legal" }));
                Assert.That(section["legal"]?.Servers,                        Is.Null, "the node's own four, not a list of its own");
                Assert.That(section.ToJSON().ToString(Newtonsoft.Json.Formatting.None),
                            Is.EqualTo("""{"groups":{"legal":{}}}"""));
            });

        }

        #endregion

        #region GroupsAreReadInTheOrderTheFileNamesThem()

        [Test]
        public void GroupsAreReadInTheOrderTheFileNamesThem()
        {

            var section = Parsed("""
                              { "groups": {
                                  "local": { "servers": [ "lc1.local" ], "enabled": false },
                                  "legal": { "minServers": 2 },
                                  "grid":  { "servers": [ "grid.example" ] }
                              } }
                              """);

            Assert.Multiple(() => {
                Assert.That(section.Groups.Select(group => group.Key),        Is.EqualTo(new[] { "local", "legal", "grid" }));
                Assert.That(section["local"]?.Enabled,                        Is.False);
                Assert.That(section["legal"]?.MinServers,                     Is.EqualTo(2));
                Assert.That(section["grid"]?.Servers?.Count(),                Is.EqualTo(1));
            });

        }

        #endregion

        #region GroupsWithoutALegalOneAreANodeWithoutLegalTime()

        /// <summary>
        /// A country without legal time for charging stations: "groups" naming
        /// no legal group, and nothing put in its place.
        /// </summary>
        [Test]
        public void GroupsWithoutALegalOneAreANodeWithoutLegalTime()
        {

            var some  = Parsed("""{ "groups": { "local": { "servers": [ "lc1.local" ] } } }""");
            var none  = Parsed("""{ "groups": { } }""");

            Assert.Multiple(() => {
                Assert.That(some["legal"],   Is.Null);
                Assert.That(none.Groups,     Is.Empty,  "no group at all: a node checking its clock against nobody");
            });

        }

        #endregion

        #region SettingsBesideTheGroupsAreRefused()

        /// <summary>
        /// A file half moved by hand: the settings beside "groups" would belong
        /// to no group.
        /// </summary>
        [Test]
        public void SettingsBesideTheGroupsAreRefused()
        {

            var error = Refusal("""{ "enabled": false, "groups": { "legal": { } } }""");

            Assert.Multiple(() => {
                Assert.That(error,  Does.Contain("'enabled'"));
                Assert.That(error,  Does.Contain("nts.groups.legal"),  "where it was most likely meant to go");
            });

        }

        #endregion

        #region GroupsMustBeAnObject()

        [Test]
        public void GroupsMustBeAnObject()
        {
            Assert.That(Refusal("""{ "groups": [ "legal" ] }"""),            Does.Contain("'nts.groups'"));
            Assert.That(Refusal("""{ "groups": { "local": "lc1.local" } }"""), Does.Contain("'nts.groups.local' must be an object"));
        }

        #endregion

        #region AGroupIsNamedInLowerCaseLettersDigitsAndHyphens(Id)

        [TestCase("Local")]
        [TestCase("1st")]
        [TestCase("grid_a")]
        [TestCase("grid a")]
        [TestCase("-grid")]
        [TestCase("")]
        [TestCase("abcdefghijklmnopqrstuvwxyzabcdefg")]
        public void AGroupIsNamedInLowerCaseLettersDigitsAndHyphens(String Id)
        {

            var error = Refusal(new JObject(new JProperty("groups", new JObject(new JProperty(Id, new JObject())))).ToString());

            Assert.That(error,  Does.Contain("cannot be the name of a group"));

        }

        [TestCase("legal")]
        [TestCase("local")]
        [TestCase("grid-a")]
        [TestCase("site2")]
        [TestCase("abcdefghijklmnopqrstuvwxyzabcdef")]
        public void TheseAreNamesOfGroups(String Id)

            => Assert.That(NTSSection.IsGroupId(Id),  Is.True);

        #endregion

        #region OnlyTheLegalGroupCarriesLegalTime(Key)

        /// <summary>
        /// A "local" group saying "PTB" would be a claim nobody reads, and one
        /// somebody might believe.
        /// </summary>
        [TestCase("legalTimeAuthority",         "\"PTB\"")]
        [TestCase("legalTimeToleranceSeconds",  "1")]
        [TestCase("legalTimeMaxAgeSeconds",     "600")]
        public void OnlyTheLegalGroupCarriesLegalTime(String Key, String Value)
        {

            var error = Refusal($$"""{ "groups": { "local": { "servers": [ "lc1.local" ], "{{Key}}": {{Value}} } } }""");

            Assert.Multiple(() => {
                Assert.That(error,  Does.Contain($"'nts.groups.local.{Key}'"));
                Assert.That(error,  Does.Contain("only the group 'legal'"));
            });

            Parsed($$"""{ "groups": { "legal": { "{{Key}}": {{Value}} } } }""");

        }

        #endregion

        #region AGroupSwitchedOnMustNameAServer()

        /// <summary>
        /// Only the legal group has a default worth asking - the PTB's four.
        /// Any other group switched on and naming nobody would fail every check
        /// it makes.
        /// </summary>
        [Test]
        public void AGroupSwitchedOnMustNameAServer()
        {

            Assert.Multiple(() => {
                Assert.That(Refusal("""{ "groups": { "local": { "enabled": true } } }"""),  Does.Contain("'nts.groups.local' is switched on and names no time server"));
                Assert.That(Parsed ("""{ "groups": { "local": { "enabled": false } } }""")["local"]?.Enabled,  Is.False,  "switched off, a group may name nobody yet");
                Assert.That(Parsed ("""{ "groups": { "local": { } } }""")["local"],        Is.Not.Null,      "and so may one that says nothing");
                Assert.That(Parsed ("""{ "groups": { "legal": { "enabled": true } } }""")["legal"]?.Enabled,  Is.True,  "the legal group has the PTB's four");
            });

        }

        #endregion

        #region ASentenceAboutAGroupNamesWhereItIs()

        [Test]
        public void ASentenceAboutAGroupNamesWhereItIs()
        {

            Assert.Multiple(() => {
                Assert.That(Refusal("""{ "groups": { "local": { "ntpPort": 0 } } }"""),                               Does.Contain("nts.groups.local.ntpPort"));
                Assert.That(Refusal("""{ "groups": { "local": { "servers": [ ] } } }"""),                              Does.Contain("'nts.groups.local.servers' is empty"));
                Assert.That(Refusal("""{ "groups": { "local": { "servers": [ "a.example" ], "minServers": 2 } } }"""), Does.Contain("'nts.groups.local.minServers' is 2"));
                Assert.That(Refusal("""{ "groups": { "grid": { "servers": [ { "priority": 1 } ] } } }"""),              Does.Contain("'nts.groups.grid.servers[0]' names no host"));
                Assert.That(Refusal("""{ "ntpPort": 0 }"""),                                                            Does.Contain("move it into 'nts.groups.legal'"),  "and the flat section is not read at all");
            });

        }

        #endregion


        #region ADisplayNameIsOneTextOrOneTextByLanguage()

        [Test]
        public void ADisplayNameIsOneTextOrOneTextByLanguage()
        {

            var one    = Parsed("""{ "groups": { "local": { "displayName": "  Local time  " } } }""")["local"]!;
            var many   = Parsed("""{ "groups": { "local": { "displayName": { "en": "Local time", "DE": "Lokale Zeit", "de-AT": " ", "fr": null } } } }""")["local"]!;
            var blank  = Parsed("""{ "groups": { "local": { "displayName": "" } } }""")["local"]!;

            Assert.Multiple(() => {

                Assert.That(one.DisplayName,              Is.EqualTo(new Dictionary<String, String> { [ "*" ] = "Local time" }),  "for every language, and trimmed");
                Assert.That(one.ToJSON()["displayName"],  Is.EqualTo(new JValue("Local time")),                              "written back as one text");

                Assert.That(many.DisplayName,             Is.EqualTo(new Dictionary<String, String> { [ "en" ] = "Local time", [ "de" ] = "Lokale Zeit" }),
                            "by language in lower case, without the blank ones");
                Assert.That(many.ToJSON()["displayName"]?.Value<String>("de"),  Is.EqualTo("Lokale Zeit"));

                Assert.That(blank.DisplayName,            Is.Null);
                Assert.That(blank.RemovesDisplayName,     Is.True,  "an emptied field takes the name away");
                Assert.That(blank.RemovedKeys,            Does.Contain("displayName"));

            });

        }

        #endregion

        #region ADisplayNameIsWrittenUnderALanguage()

        [Test]
        public void ADisplayNameIsWrittenUnderALanguage()
        {

            Assert.Multiple(() => {
                Assert.That(Refusal("""{ "groups": { "local": { "displayName": { "english": "Local time" } } } }"""),  Does.Contain("'english' is not a language"));
                Assert.That(Refusal("""{ "groups": { "local": { "displayName": { "en": 42 } } } }"""),                 Does.Contain("'nts.groups.local.displayName.en' must be a string"));
                Assert.That(Refusal("""{ "groups": { "local": { "displayName": [ "Local time" ] } } }"""),             Does.Contain("'nts.groups.local.displayName' must be a string"));
                Assert.That(Refusal($$"""{ "groups": { "local": { "displayName": "{{new String('x', NTSConfiguration.MaxDisplayNameLength + 1)}}" } } }"""),
                            Does.Contain($"longer than {NTSConfiguration.MaxDisplayNameLength}"));
            });

        }

        #endregion


        #region SavingIntoAFlatSectionMovesNothing()

        /// <summary>
        /// A save never moves a flat section into a group for anybody: it is
        /// left as it is, and what the save would write is refused the way the
        /// next start would refuse it.
        /// </summary>
        [Test]
        public void SavingIntoAFlatSectionMovesNothing()
        {

            var flat     = JObject.Parse("""{ "hostname": "a.example", "checkEverySeconds": 600, "enabled": true }""");
            var written  = NTSSection.WithGroup   (flat, "legal", new JObject(new JProperty("enabled", false)), []);
            var without  = NTSSection.WithoutGroup(flat, "legal");

            Assert.Multiple(() => {
                Assert.That(JToken.DeepEquals(written, flat),                       Is.True,   written.ToString());
                Assert.That(JToken.DeepEquals(without, flat),                       Is.True,   without.ToString());
                Assert.That(NTSSection.TryParse(written, out _, out var error),     Is.False);
                Assert.That(error,                                                  Does.Contain("move them into 'nts.groups.legal'"));
            });

        }

        #endregion

        #region SavingIntoNoSectionKeepsTheDefaultLegalGroup()

        /// <summary>
        /// No section at all is the legal group as the node makes it. A group
        /// added to such a file must not take it away by being the only one
        /// named.
        /// </summary>
        [Test]
        public void SavingIntoNoSectionKeepsTheDefaultLegalGroup()
        {

            var written = NTSSection.WithGroup(null, "local", JObject.Parse("""{ "enabled": false }"""), []);

            Assert.That(NTSSection.TryParse(written, out var section, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(section!.Groups.Select(group => group.Key),  Is.EqualTo(new[] { "legal", "local" }));
                Assert.That(section["legal"]?.Servers,                   Is.Null,  "saying nothing, which is still the PTB's four");
            });

        }

        #endregion

        #region SavingAGroupChangesThatGroupOnly()

        [Test]
        public void SavingAGroupChangesThatGroupOnly()
        {

            var section  = JObject.Parse("""
                               { "groups": {
                                   "legal": { "legalTimeAuthority": "PTB", "servers": [ "ptbtime1.ptb.de" ] },
                                   "local": { "servers": [ "lc1.local" ], "enabled": true }
                               } }
                               """);

            var written  = NTSSection.WithGroup(section, "legal", JObject.Parse("""{ "servers": [ "ptbtime2.ptb.de" ] }"""), [ "legalTimeAuthority" ]);

            Assert.Multiple(() => {
                Assert.That(written["groups"]?["legal"]?["servers"]?.Values<String>(),  Is.EqualTo(new[] { "ptbtime2.ptb.de" }),  "a list is replaced whole");
                Assert.That(written["groups"]?["legal"]?["legalTimeAuthority"],          Is.Null,                                   "what is taken away is gone");
                Assert.That(JToken.DeepEquals(written["groups"]?["local"], section["groups"]?["local"]),  Is.True,                   "and the other group is as it was");
            });

        }

        #endregion

        #region TakingAGroupAwayKeepsItAway()

        /// <summary>
        /// Without the legal group, no section would come back as the default
        /// at the next start; "groups" without it does not.
        /// </summary>
        [Test]
        public void TakingAGroupAwayKeepsItAway()
        {

            var written = NTSSection.WithoutGroup(null, "legal");

            Assert.Multiple(() => {
                Assert.That(JToken.DeepEquals(written, JObject.Parse("""{ "groups": { } }""")),  Is.True,  written.ToString());
                Assert.That(NTSSection.TryParse(written, out var section, out _) && section.Groups.Count == 0,  Is.True);
            });

        }

        #endregion

        #region ASectionIsWrittenWithItsGroups()

        [Test]
        public void ASectionIsWrittenWithItsGroups()
        {

            var grouped = Parsed("""{ "groups": { "legal": { "enabled": false }, "local": { "servers": [ "lc1.local" ] } } }""").ToJSON();

            Assert.Multiple(() => {
                Assert.That(grouped.Properties().Select(property => property.Name),         Is.EqualTo(new[] { "groups" }));
                Assert.That(grouped["groups"]?["legal"]?.Value<Boolean>("enabled"),        Is.False, grouped.ToString());
                Assert.That(grouped["groups"]?["local"]?["servers"]?[0]?.Value<String>(),  Is.EqualTo("lc1.local."));
            });

        }

        #endregion

    }

}
