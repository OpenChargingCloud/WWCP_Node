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

using System.Net;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// Roles the configuration file adds: enforced by the node as the roles
    /// it and its kind bring are, and named where a refusal names who may.
    /// </summary>
    /// <remarks>
    /// A role is a list of permissions, each an operation on a resource, on
    /// every node - so the file can add one no kind of node ever heard of: a
    /// support desk that may look at the name resolution and nothing else,
    /// and one that may change it as well. The gateway and the charging
    /// station each asked this of their own; it is the node that reads the
    /// file, so it is asked of every kind here.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region (protected static) RolesTheFileAdds

        /// <summary>
        /// The "roles" section of <see cref="NodeSetup.RolesFromTheFile"/>.
        /// </summary>
        protected static JObject RolesTheFileAdds

            => new (
                   new JProperty("support",  new JArray("dns:read")),
                   new JProperty("dnsdesk",  new JArray("dns:read", "dns:edit"))
               );

        #endregion


        #region ARoleTheFileAddsIsOneOfTheNodesRoles()

        /// <summary>
        /// A role nobody compiled in: the file names it, and the start makes it
        /// a role of the node, with a group to put accounts into.
        /// </summary>
        [Test, WithNode(NodeSetup.RolesFromTheFile)]
        public void ARoleTheFileAddsIsOneOfTheNodesRoles()
        {

            Assert.Multiple(() => {

                Assert.That(Node.Roles,  Does.Contain("support").And.Contain("dnsdesk"));

                foreach (var role in new[] { "support", "dnsdesk" })
                    Assert.That(Node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(role), out _),
                                Is.True,
                                $"The {Node.Kind.Name} made no group for the role '{role}'.");

            });

        }

        #endregion

        #region ARoleTheFileAddsMayDoWhatItSaysAndNothingElse()

        /// <summary>
        /// Somebody in a role the file added may do what the file says it may
        /// - read the name resolution - and nothing else: not read the time
        /// source, not change what it may read. And it is told so, as a copy
        /// of what the node enforces.
        /// </summary>
        [Test, WithNode(NodeSetup.RolesFromTheFile)]
        public async Task ARoleTheFileAddsMayDoWhatItSaysAndNothingElse()
        {

            await AccountIn("supporter", "support", "Supporting-Only-1");

            using var http  = await SignedInAs("supporter", "Supporting-Only-1");

            var dns         = await http.GetAsync("api/v1/configuration/dns");
            var nts         = await http.GetAsync("api/v1/configuration/nts");
            var change      = await http.PutAsync("api/v1/configuration/dns", JSONBody());
            var me          = await GetJSON(http, "api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(dns.   StatusCode,                         Is.EqualTo(HttpStatusCode.OK),         "reading the name servers is what the role is for");
                Assert.That(nts.   StatusCode,                         Is.EqualTo(HttpStatusCode.Forbidden),  "the time source is none of its business");
                Assert.That(change.StatusCode,                         Is.EqualTo(HttpStatusCode.Forbidden),  "reading is not changing");
                Assert.That(me["roles"]?.      Values<String>(),       Is.EqualTo(new[] { "support" }));
                Assert.That(me["permissions"]?.Values<String>(),       Is.EqualTo(new[] { "dns:read" }));
            });

        }

        #endregion

        #region ARefusalNamesTheRolesTheFileAdds()

        /// <summary>
        /// A refusal names the roles that may, and a role the file added is one
        /// of them where it carries the permission - and is left out where it
        /// does not.
        /// </summary>
        [Test, WithNode(NodeSetup.RolesFromTheFile)]
        public async Task ARefusalNamesTheRolesTheFileAdds()
        {

            await AccountIn("supporter", "support", "Supporting-Only-1");

            using var http          = await SignedInAs("supporter", "Supporting-Only-1");

            var (refused, answer)   = await Send(http, HttpMethod.Put, "api/v1/configuration/dns", new JObject());
            var said                = answer.Value<String>("error");

            Assert.Multiple(() => {
                Assert.That(refused,  Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(said,     Does.StartWith("This needs the ").And.EndWith(" role."));
                Assert.That(said,     Does.Contain("dnsdesk"),      "the role the file gave the permission is not among the ones to ask for");
                Assert.That(said,     Does.Not.Contain("support"),  "the role the file did not give it is");
            });

        }

        #endregion

        #region WhatTheFileAddsIsSaidInTheLog()

        /// <summary>
        /// Who may do what is a matter of security, and a role the file adds is
        /// said as one - at the start, before anybody can sign in.
        /// </summary>
        [Test, WithNode(NodeSetup.RolesFromTheFile)]
        public void WhatTheFileAddsIsSaidInTheLog()
        {

            var said = Node.Log.Recent(500, Tag: "security").Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(said,  Has.Some.EqualTo("The configuration file adds the role 'support', which may do dns:read."),  String.Join(" | ", said));
                Assert.That(said,  Has.Some.StartsWith("The configuration file adds the role 'dnsdesk', which may do "),       String.Join(" | ", said));
            });

        }

        #endregion

    }

}
