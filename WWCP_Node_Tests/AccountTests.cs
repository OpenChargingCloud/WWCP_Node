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
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Who may sign in to a node: one user group per role its kind knows,
    /// made at every start, and the one account a first start makes, in
    /// systemadmin.
    /// </summary>
    /// <remarks>
    /// The roles are the kind's. A vehicle knows a driver, a charging station
    /// an operator and an installer; what the node knows is that each of them
    /// is a group of the same name, and that the first account goes into
    /// systemadmin, which every one of these programs names alike.
    ///
    /// These nodes are started, because the groups are made at a start - on a
    /// port nobody else has, with the time client switched off so that a
    /// start asks no time server anything.
    /// </remarks>
    public class AccountTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-accounts-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helper) StartedNode(Roles = null)

        /// <summary>
        /// A node of no particular kind, knowing the given roles, started.
        /// </summary>
        private async Task<WWCPNode> StartedNode(IEnumerable<String>? Roles = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "nts": { "enabled": false } }""");

            var node = new WWCPNode(
                           HTTPPort:          FreePort(),
                           AccountsPath:      Path.Combine(directory, "accounts"),
                           Roles:             Roles,
                           ConfigFile:        new WWCPConfigFile(configuration),
                           CertificatesPath:  Path.Combine(directory, "certificates"),
                           LogToConsole:      false,
                           BridgeDebugLog:    false
                       );

            await node.Start();

            return node;

        }

        #endregion

        #region (helper) FreePort()

        private static IPPort FreePort()
        {

            var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();

            var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();

            return IPPort.Parse((UInt16) port);

        }

        #endregion

        #region (helper) GroupsOf(Node)

        /// <summary>
        /// The groups the accounts of a node hold, by name.
        /// </summary>
        private static String[] GroupsOf(WWCPNode Node)

            => [.. Node.ExtAPI.UserGroups.Select(group => group.Id.ToString()).Order(StringComparer.Ordinal)];

        #endregion

        #region (helper) RootIsASystemAdmin(Node)

        /// <summary>
        /// Whether the account a first start makes is in systemadmin.
        /// </summary>
        private static Boolean RootIsASystemAdmin(WWCPNode Node)

            => Node.ExtAPI.TryGetUser(User_Id.Parse(WWCPNode.DefaultAdminUser), out var root) &&
               Node.ExtAPI.IsMember(root, UserGroup_Id.Parse(WWCPNode.AdminRole));

        #endregion


        #region ANodeOfNoParticularKindKnowsTheRolesItAlwaysHas()

        /// <summary>
        /// Told nothing, a node makes the groups it has always made - which are
        /// a vehicle's, having come here with the rest of the vehicle.
        /// </summary>
        [Test]
        public async Task ANodeOfNoParticularKindKnowsTheRolesItAlwaysHas()
        {

            await using var node = await StartedNode();

            Assert.Multiple(() => {
                Assert.That(node.Roles,              Is.EqualTo(UserRole.All.Select(role => role.Name)));
                Assert.That(GroupsOf(node),          Is.EqualTo(new[] { "driver", "service", "systemadmin", "viewer" }));
                Assert.That(RootIsASystemAdmin(node), Is.True);
            });

        }

        #endregion

        #region AKindOfNodeBringsItsOwnRoles()

        /// <summary>
        /// A kind of node that names its roles gets their groups, and none of
        /// the vehicle's beside them.
        /// </summary>
        /// <remarks>
        /// A charging station's, which is the kind that needed this: its
        /// operator and its installer have no group among the vehicle's four,
        /// so every page asking for either role refused everybody. And "cpo"
        /// is three characters, which is below the HTTPExt API's own floor
        /// for a group's identification - a group it refuses by a returned
        /// result rather than an exception, so the floor has to come from the
        /// roles actually handed in.
        /// </remarks>
        [Test]
        public async Task AKindOfNodeBringsItsOwnRoles()
        {

            await using var node = await StartedNode([ "viewer", "cpo", "installer", "systemadmin" ]);

            Assert.Multiple(() => {
                Assert.That(node.Roles,              Is.EqualTo(new[] { "viewer", "cpo", "installer", "systemadmin" }));
                Assert.That(GroupsOf(node),          Is.EqualTo(new[] { "cpo", "installer", "systemadmin", "viewer" }));
                Assert.That(RootIsASystemAdmin(node), Is.True);
            });

        }

        #endregion

        #region SystemAdminIsOneOfThemWhateverTheKindSays()

        /// <summary>
        /// The first account goes into systemadmin, so that group is made
        /// whether or not the kind of node named it.
        /// </summary>
        /// <remarks>
        /// Every one of these programs names its administrators alike, which
        /// is what lets one set of accounts shared between several of them
        /// have one kind of administrator. A kind that left the role out would
        /// otherwise have a first account in a group that was never made -
        /// with a password printed on the console that opens nothing.
        /// </remarks>
        [Test]
        public async Task SystemAdminIsOneOfThemWhateverTheKindSays()
        {

            await using var node = await StartedNode([ "viewer" ]);

            Assert.Multiple(() => {
                Assert.That(node.Roles,              Is.EqualTo(new[] { "viewer", "systemadmin" }));
                Assert.That(GroupsOf(node),          Is.EqualTo(new[] { "systemadmin", "viewer" }));
                Assert.That(RootIsASystemAdmin(node), Is.True);
            });

        }

        #endregion

    }

}
