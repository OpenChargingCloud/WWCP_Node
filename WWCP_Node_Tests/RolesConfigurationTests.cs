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

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The "roles" section of the configuration file: a role per entry, with
    /// the permissions it carries, written the way the web interface reads
    /// them.
    /// </summary>
    public class RolesConfigurationTests
    {

        #region ARoleIsANameAndItsPermissions()

        [Test]
        public void ARoleIsANameAndItsPermissions()
        {

            var json = JObject.Parse("""{ "support": [ "dns:read", "NTS:Read", "*:run" ] }""");

            Assert.That(RolesConfiguration.TryParse(json, out var configuration, out var error), Is.True, error);

            var support = configuration!.Roles.Single();

            Assert.Multiple(() => {
                Assert.That(support.Name,                               Is.EqualTo("support"));
                Assert.That(support.Permissions.Select(p => p.ToString()),  Is.EqualTo(new[] { "dns:read", "nts:read", "*:run" }));
            });

        }

        #endregion

        #region TheSectionTravelsInTheWholeDocument()

        [Test]
        public void TheSectionTravelsInTheWholeDocument()
        {

            var document = new WWCPConfiguration(
                               Roles: new RolesConfiguration([ new Role("support", [ Permission.Read("dns") ]) ])
                           ).ToJSON();

            Assert.That(WWCPConfiguration.TryParse(document, out var read, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(read!.Roles,                                                  Is.Not.Null);
                Assert.That(read!.Roles!.Roles.Single().Name,                              Is.EqualTo("support"));
                Assert.That(read!.Roles!.Roles.Single().Permissions.Single().ToString(),  Is.EqualTo("dns:read"));
                Assert.That(read!.IsEmpty,                                                Is.False);
            });

        }

        #endregion

        #region ARoleSetToNullIsOneTheFileSaysNothingAbout()

        /// <summary>
        /// A null is "the file does not say", everywhere in the file - and an
        /// empty list is a role that may do nothing, which is something to say.
        /// </summary>
        [Test]
        public void ARoleSetToNullIsOneTheFileSaysNothingAbout()
        {

            var json = JObject.Parse("""{ "support": null, "guest": [] }""");

            Assert.That(RolesConfiguration.TryParse(json, out var configuration, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(configuration!.Roles.Select(role => role.Name),  Is.EqualTo(new[] { "guest" }));
                Assert.That(configuration!.Roles.Single().Permissions,       Is.Empty);
            });

        }

        #endregion

        #region WhatIsNotARoleIsSaidSo(JSON, Expected)

        [TestCase("""{ "support": "dns:read" }""",                  "must be an array")]
        [TestCase("""{ "support": [ 42 ] }""",                     "nothing but strings")]
        [TestCase("""{ "support": [ "dns" ] }""",                  "is not a permission")]
        [TestCase("""{ "support": [ "dns:write" ] }""",            "is not an operation")]
        [TestCase("""{ "support": [ "d n s:read" ] }""",           "is not a resource name")]
        [TestCase("""{ "support team": [ "dns:read" ] }""",        "is not a role name")]
        [TestCase("""{ "support": [], "Support": [] }""",          "twice")]
        public void WhatIsNotARoleIsSaidSo(String JSON, String Expected)
        {

            Assert.That(RolesConfiguration.TryParse(JObject.Parse(JSON), out _, out var error), Is.False);
            Assert.That(error, Does.Contain(Expected));

        }

        #endregion

        #region ASectionOfTheWrongKindIsRefused()

        [Test]
        public void ASectionOfTheWrongKindIsRefused()
        {

            Assert.That(WWCPConfiguration.TryParse(
                            new JObject(new JProperty(RolesConfiguration.SectionName, new JArray("support"))),
                            out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("JSON object"));

        }

        #endregion

    }

}
