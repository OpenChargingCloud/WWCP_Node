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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Who may do what on a node: permissions as an operation on a resource,
    /// roles as data - the node's, its kind's and its configuration file's -
    /// and an account that may do what the groups it is in may do.
    /// </summary>
    public class AccessTests
    {

        #region Data

        private String directory = "";

        /// <summary>
        /// What a vehicle adds, as a kind of node would hand it in.
        /// </summary>
        private static readonly String[]  VehicleResources  = [ "vehicle", "session" ];

        private static readonly Role      Driver            = new ("driver",
                                                                   [ Permission.Read(Permission.AnyResource),
                                                                     Permission.Edit("vehicle"),
                                                                     Permission.Run ("session") ]);

        private static readonly Role      Service           = new ("service",
                                                                   [ Permission.Read(Permission.AnyResource),
                                                                     Permission.Edit(NodeResources.DNS),
                                                                     Permission.Edit("vehicle"),
                                                                     Permission.Run ("session") ]);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-access-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Combine(KindResources = null, KindRoles = null, RoleNames = null, Configured = null)

        /// <summary>
        /// The resources and roles of a node, where nothing is expected to be
        /// wrong with the file.
        /// </summary>
        private static AccessControl Combine(IEnumerable<String>?  KindResources  = null,
                                             IEnumerable<Role>?    KindRoles      = null,
                                             IEnumerable<String>?  RoleNames      = null,
                                             String?               Configured     = null)
        {

            Assert.That(AccessControl.TryCombine(KindResources,
                                                 KindRoles,
                                                 RoleNames,
                                                 Roles(Configured),
                                                 "electric vehicle",
                                                 out var access,
                                                 out _,
                                                 out var error),
                        Is.True,
                        error);

            return access!;

        }

        #endregion

        #region (helper) Roles(JSON)

        /// <summary>
        /// A "roles" section, or none.
        /// </summary>
        private static RolesConfiguration? Roles(String? JSON)
        {

            if (JSON is null)
                return null;

            Assert.That(RolesConfiguration.TryParse(JObject.Parse(JSON), out var roles, out var error), Is.True, error);

            return roles;

        }

        #endregion

        #region (helper) Names(Roles)

        private static String[] Names(IEnumerable<Role> Roles)
            => [.. Roles.Select(role => role.Name)];

        #endregion

        #region (helper) StartedNode(Configuration)

        /// <summary>
        /// A node of no particular kind, started with the given configuration
        /// file - on a port nobody else has, and without asking a time server.
        /// </summary>
        private async Task<WWCPNode> StartedNode(String Configuration = """{ "nts": { "enabled": false } }""")
        {

            var node = NodeWith(Configuration);

            await node.Start();

            return node;

        }

        #endregion

        #region (helper) NodeWith(Configuration)

        private WWCPNode NodeWith(String Configuration)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, Configuration);

            return new WWCPNode(
                       HTTPPort:          FreePort(),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

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

        #region (helper) AccountIn(Node, Name, Role)

        /// <summary>
        /// An account of the given name, in the group of the given role - or in
        /// none, where no role is given.
        /// </summary>
        private static async Task<IUser> AccountIn(WWCPNode  Node,
                                                   String    Name,
                                                   String?   Role)
        {

            var added = await Node.ExtAPI.AddUser(
                                  new User(
                                      User_Id.Parse(Name),
                                      I18NString.Create(Languages.en, Name),
                                      SimpleEMailAddress.Parse($"{Name}@localhost")
                                  ),
                                  SkipDefaultNotifications:  true,
                                  SkipNewUserEMail:          true,
                                  SkipNewUserNotifications:  true
                              );

            Assert.That(Node.ExtAPI.TryGetUser(User_Id.Parse(Name), out var stored) && stored is User, Is.True,
                        $"The account '{Name}' was not made: {added.Result}");

            if (Role is not null)
            {

                Assert.That(Node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group) && group is UserGroup, Is.True,
                            $"The node has no group '{Role}'.");

                var joined = await Node.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

                Assert.That(joined.IsSuccess, Is.True, $"'{Name}' could not be put in '{Role}'.");

            }

            return stored!;

        }

        #endregion


        #region APermissionIsAnOperationOnAResource()

        [Test]
        public void APermissionIsAnOperationOnAResource()
        {

            Assert.That(Permission.TryParse(" DNS : Edit ", out var permission, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(permission.Resource,                       Is.EqualTo("dns"));
                Assert.That(permission.Operation,                      Is.EqualTo(Operation.Edit));
                Assert.That(permission.ToString(),                     Is.EqualTo("dns:edit"));
                Assert.That(permission.Covers("dns", Operation.Edit),  Is.True);
                Assert.That(permission.Covers("dns", Operation.Read),  Is.False, "editing is not reading: a role that may do both says both");
                Assert.That(permission.Covers("nts", Operation.Edit),  Is.False);
            });

        }

        #endregion

        #region EveryResourceIsWrittenAsAStar()

        [Test]
        public void EveryResourceIsWrittenAsAStar()
        {

            var anything = Permission.Read(Permission.AnyResource);

            Assert.Multiple(() => {
                Assert.That(anything.IsAnyResource,                       Is.True);
                Assert.That(anything.Covers("dns",     Operation.Read),   Is.True);
                Assert.That(anything.Covers("vehicle", Operation.Read),   Is.True, "every resource there is, a kind of node's included");
                Assert.That(anything.Covers("dns",     Operation.Edit),   Is.False);
            });

        }

        #endregion

        #region WhatIsNotAPermissionIsSaidSo(Text, Expected)

        [TestCase("dns",             "is not a permission")]
        [TestCase("dns:read:edit",   "is not a permission")]
        [TestCase(":read",           "is not a resource name")]
        [TestCase("1dns:read",       "is not a resource name")]
        [TestCase("dns:write",       "is not an operation")]
        [TestCase("dns:",            "is not an operation")]
        public void WhatIsNotAPermissionIsSaidSo(String Text, String Expected)
        {

            Assert.That(Permission.TryParse(Text, out _, out var error), Is.False);
            Assert.That(error, Does.Contain(Expected));

        }

        #endregion

        #region ARoleIsCalledWhatItCanBeCalledInASentence(Name, Valid)

        [TestCase("support",       true)]
        [TestCase("cpo",           true)]
        [TestCase("first-line_2",  true)]
        [TestCase("s",             false)]
        [TestCase("2nd-line",      false)]
        [TestCase("first line",    false)]
        [TestCase("admins,users",  false)]
        [TestCase("",              false)]
        public void ARoleIsCalledWhatItCanBeCalledInASentence(String Name, Boolean Valid)
        {

            Assert.That(Role.IsRoleName(Name), Is.EqualTo(Valid));

        }

        #endregion


        #region TheNodeBringsTheViewerAndTheAdministrators()

        /// <summary>
        /// Told nothing, a node has the resources every node has and the two
        /// roles every node has - and none of a vehicle's, which it used to
        /// have when its roles came with the rest of the vehicle.
        /// </summary>
        [Test]
        public void TheNodeBringsTheViewerAndTheAdministrators()
        {

            var access = Combine();

            Assert.Multiple(() => {
                Assert.That(access.Resources,                                                Is.EqualTo(NodeResources.All));
                Assert.That(Names(access.Roles),                                             Is.EqualTo(new[] { "viewer", WWCPNode.AdminRole }));
                Assert.That(access.RoleNamed("viewer")!.     Allows("dns", Operation.Read),  Is.True);
                Assert.That(access.RoleNamed("viewer")!.     Allows("dns", Operation.Edit),  Is.False);
                Assert.That(access.RoleNamed("SystemAdmin")!.Allows("dns", Operation.Edit),  Is.True, "a role is found in any case, as a group is");
            });

        }

        #endregion

        #region AKindOfNodeBringsResourcesAndRolesOfItsOwn()

        [Test]
        public void AKindOfNodeBringsResourcesAndRolesOfItsOwn()
        {

            var access = Combine(VehicleResources, [ Driver, Service ]);

            Assert.Multiple(() => {

                Assert.That(access.Resources,        Is.EqualTo(NodeResources.All.Concat(VehicleResources)));
                Assert.That(Names(access.Roles),     Is.EqualTo(new[] { "viewer", "driver", "service", WWCPNode.AdminRole }),
                            "the viewer first and the administrators last, which is how a sentence naming them reads best");

                Assert.That(access.RoleNamed("driver")!.Allows("session", Operation.Run),   Is.True);
                Assert.That(access.RoleNamed("driver")!.Allows("dns",     Operation.Edit),  Is.False);

                // "*" is every resource there is, and that includes what the kind
                // of node added after the administrators' role was written.
                Assert.That(access.RoleNamed(WWCPNode.AdminRole)!.Allows("session", Operation.Run),  Is.True);
                Assert.That(access.RoleNamed("viewer")!.          Allows("vehicle", Operation.Read), Is.True);

            });

        }

        #endregion

        #region AKindOfNodeThatMeansSomethingElseByViewerSaysSo()

        [Test]
        public void AKindOfNodeThatMeansSomethingElseByViewerSaysSo()
        {

            var viewer  = new Role("viewer", [ Permission.Read(NodeResources.Configuration) ]);
            var access  = Combine(KindRoles: [ viewer ]);

            Assert.Multiple(() => {
                Assert.That(Names(access.Roles),                                 Is.EqualTo(new[] { "viewer", WWCPNode.AdminRole }), "one viewer, not two");
                Assert.That(access.RoleNamed("viewer")!.Allows("dns", Operation.Read),  Is.False);
            });

        }

        #endregion

        #region WhatTheKindOfNodeGetsWrongIsAMistakeInTheProgram()

        /// <summary>
        /// What a kind of node hands in is code: a mistake in it throws, rather
        /// than being answered like a mistake in somebody's file.
        /// </summary>
        [Test]
        public void WhatTheKindOfNodeGetsWrongIsAMistakeInTheProgram()
        {

            Assert.Multiple(() => {

                Assert.That(() => Combine(KindRoles: [ new Role(WWCPNode.AdminRole, [ Permission.Read("dns") ]) ]),
                            Throws.ArgumentException.With.Message.Contains("not a kind of node's to say"));

                Assert.That(() => Combine(KindRoles: [ new Role("driver", [ Permission.Run("session") ]) ]),
                            Throws.ArgumentException.With.Message.Contains("'session'"),
                            "a role naming a resource nobody handed in");

                Assert.That(() => Combine(VehicleResources, [ Driver, Driver ]),
                            Throws.ArgumentException.With.Message.Contains("twice"));

            });

        }

        #endregion

        #region AKindThatEnforcesItsOwnRolesHandsInTheirNames()

        /// <summary>
        /// Names alone: their groups are made, and the node knows nothing of
        /// what they may do - the kind of node that named them enforces that.
        /// </summary>
        [Test]
        public void AKindThatEnforcesItsOwnRolesHandsInTheirNames()
        {

            var access = Combine(RoleNames: [ "viewer", "cpo", "installer", "systemadmin" ]);
            var shown  = access.ToJSON().Cast<JObject>().ToDictionary(role => role["name"]!.Value<String>()!);

            Assert.Multiple(() => {

                Assert.That(Names(access.Roles),                    Is.EqualTo(new[] { "viewer", "cpo", "installer", WWCPNode.AdminRole }));
                Assert.That(access.RoleNamed("cpo")!.Permissions,   Is.Empty);
                Assert.That(access.NamedOnly,                       Is.EquivalentTo(new[] { "cpo", "installer" }));

                // Not "may do nothing", which an empty list would say: what it
                // may do is not the node's to show.
                Assert.That(shown["cpo"]["permissions"]!.Type,      Is.EqualTo(JTokenType.Null));
                Assert.That(shown["viewer"]["permissions"]!.Type,   Is.EqualTo(JTokenType.Array));

            });

        }

        #endregion


        #region TheConfigurationFileAddsARole()

        [Test]
        public void TheConfigurationFileAddsARole()
        {

            Assert.That(AccessControl.TryCombine(VehicleResources, [ Driver ], null,
                                                 Roles("""{ "support": [ "dns:read", "nts:read" ] }"""),
                                                 "electric vehicle",
                                                 out var access, out var notes, out var error),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(Names(access!.Roles),                                   Is.EqualTo(new[] { "viewer", "driver", "support", WWCPNode.AdminRole }));
                Assert.That(access!.RoleNamed("support")!.Allows("dns", Operation.Read),  Is.True);
                Assert.That(access!.RoleNamed("support")!.Allows("dns", Operation.Edit),  Is.False);
                Assert.That(notes.Single(),                                          Does.Contain("adds the role 'support'").And.Contain("dns:read, nts:read"));
            });

        }

        #endregion

        #region TheConfigurationFileSaysDifferentlyWhatARoleMayDo()

        [Test]
        public void TheConfigurationFileSaysDifferentlyWhatARoleMayDo()
        {

            Assert.That(AccessControl.TryCombine(VehicleResources, [ Driver ], null,
                                                 Roles("""{ "Driver": [ "*:read" ] }"""),
                                                 "electric vehicle",
                                                 out var access, out var notes, out var error),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(Names(access!.Roles),                                          Is.EqualTo(new[] { "viewer", "driver", WWCPNode.AdminRole }),
                            "the same role, under the name its kind gave it");
                Assert.That(access!.RoleNamed("driver")!.Allows("session", Operation.Run),  Is.False);
                Assert.That(access!.RoleNamed("driver")!.Allows("session", Operation.Read), Is.True);
                Assert.That(notes.Single(),                                                 Does.Contain("lets the role 'driver' do *:read, instead of what this electric vehicle lets it do"));
            });

        }

        #endregion

        #region TheConfigurationFileMayNotNarrowTheAdministrators()

        [Test]
        public void TheConfigurationFileMayNotNarrowTheAdministrators()
        {

            Assert.That(AccessControl.TryCombine(null, null, null,
                                                 Roles("""{ "systemadmin": [ "*:read" ] }"""),
                                                 "electric vehicle",
                                                 out _, out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("may not say what 'systemadmin' may do"));

        }

        #endregion

        #region ARoleInTheFileNamingAResourceTheNodeDoesNotHaveIsRefused()

        /// <summary>
        /// A typo in "dns" would otherwise be a role that quietly grants
        /// nothing - so the sentence names the resource, and the ones there are.
        /// </summary>
        [Test]
        public void ARoleInTheFileNamingAResourceTheNodeDoesNotHaveIsRefused()
        {

            Assert.That(AccessControl.TryCombine(VehicleResources, null, null,
                                                 Roles("""{ "support": [ "dsn:read" ] }"""),
                                                 "electric vehicle",
                                                 out _, out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("'dsn'").
                               And.Contain("this electric vehicle does not have").
                               And.Contain("configuration, dns, nts, certificates, vehicle, session"));

        }

        #endregion


        #region ARoleInTheFileIsRefusedWhereTheKindEnforcesItsOwn()

        /// <summary>
        /// A kind of node that asks nobody but itself what its roles may do
        /// would make the group of a role in the file and grant it nothing it
        /// was written to grant - so the file is told, rather than obeyed in
        /// name only.
        /// </summary>
        [Test]
        public void ARoleInTheFileIsRefusedWhereTheKindEnforcesItsOwn()
        {

            Assert.That(AccessControl.TryCombine(null, null, [ "viewer", "cpo", "installer" ],
                                                 Roles("""{ "support": [ "dns:read" ] }"""),
                                                 "charging station",
                                                 out _, out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("cannot be heard by this charging station").
                               And.Contain("nobody enforces"));

        }

        #endregion

        #region WhatARoleMayDoIsSpeltOutResourceByResource()

        /// <summary>
        /// A web interface asks "dns:edit", and should not have to know that
        /// "*" means that too.
        /// </summary>
        [Test]
        public void WhatARoleMayDoIsSpeltOutResourceByResource()
        {

            var access = Combine(VehicleResources, [ Driver ]);

            Assert.That(access.PermissionsOf([ access.RoleNamed("driver")! ]).Select(permission => permission.ToString()),
                        Is.EqualTo(new[] { "configuration:read", "dns:read", "nts:read", "certificates:read",
                                           "vehicle:read", "vehicle:edit", "session:read", "session:run" }));

        }

        #endregion

        #region ARefusalNamesOnlyTheRolesThatCouldDoAllOfIt()

        /// <summary>
        /// A role that could do half of what was asked is the wrong one to ask
        /// for - but somebody holding two roles may do what the two carry
        /// between them.
        /// </summary>
        [Test]
        public void ARefusalNamesOnlyTheRolesThatCouldDoAllOfIt()
        {

            var access    = Combine(VehicleResources, [ Driver, Service ]);
            var required  = new[] { Permission.Edit(NodeResources.DNS), Permission.Run("session") };

            Assert.Multiple(() => {

                Assert.That(Names(access.RolesAllowing([ Permission.Run("session") ])),  Is.EqualTo(new[] { "driver", "service", WWCPNode.AdminRole }));
                Assert.That(Names(access.RolesAllowing(required)),                        Is.EqualTo(new[] { "service", WWCPNode.AdminRole }));

                var dnsOnly = new Role("dns-only", [ Permission.Edit(NodeResources.DNS) ]);

                Assert.That(AccessControl.Allows([ dnsOnly, access.RoleNamed("driver")! ], required),  Is.True,  "between them");
                Assert.That(AccessControl.Allows([ dnsOnly ],                               required),  Is.False, "half of it");

            });

        }

        #endregion


        #region AStartedNodeMakesTheGroupsOfTheRolesInItsFile()

        [Test]
        public async Task AStartedNodeMakesTheGroupsOfTheRolesInItsFile()
        {

            await using var node = await StartedNode("""
                                                     {
                                                       "nts":   { "enabled": false },
                                                       "roles": { "support": [ "dns:read", "nts:read" ] }
                                                     }
                                                     """);

            var groups = node.ExtAPI.UserGroups.Select(group => group.Id.ToString()).Order(StringComparer.Ordinal).ToArray();

            Assert.Multiple(() => {
                Assert.That(node.Roles,  Is.EqualTo(new[] { "viewer", "support", WWCPNode.AdminRole }));
                Assert.That(groups,      Is.EqualTo(new[] { "support", WWCPNode.AdminRole, "viewer" }));
                Assert.That(node.Log.Recent(500, Tag: "security").Any(entry => entry.Message.Contains("adds the role 'support'")),
                            Is.True,
                            "who may do what is a decision about trust, and one the file made: said at the start, tagged as such");
            });

        }

        #endregion

        #region ANodeWhoseFileNamesAResourceItDoesNotHaveDoesNotStart()

        [Test]
        public void ANodeWhoseFileNamesAResourceItDoesNotHaveDoesNotStart()
        {

            Assert.That(() => NodeWith("""{ "nts": { "enabled": false }, "roles": { "support": [ "dsn:read" ] } }"""),
                        Throws.InvalidOperationException.With.Message.Contains("'dsn'").
                                                          And.Message.Contains("Repair or remove"));

        }

        #endregion

        #region WhatAnAccountMayDoFollowsItsGroups()

        /// <summary>
        /// The groups hang off the account rather than off the door it came
        /// through, and so does what it may do: the first account may do
        /// everything, a viewer may look, and an account in no group may do
        /// nothing at all.
        /// </summary>
        [Test]
        public async Task WhatAnAccountMayDoFollowsItsGroups()
        {

            await using var node  = await StartedNode();

            Assert.That(node.ExtAPI.TryGetUser(User_Id.Parse(WWCPNode.DefaultAdminUser), out var root), Is.True);

            var alice             = await AccountIn(node, "alice", "viewer");
            var robert            = await AccountIn(node, "robert", null);

            Assert.Multiple(() => {

                Assert.That(node.IsAllowed(root,  NodeResources.Certificates, Operation.Edit),  Is.True);

                Assert.That(Names(node.RolesOf(alice)),                                          Is.EqualTo(new[] { "viewer" }));
                Assert.That(node.IsAllowed(alice, NodeResources.DNS,          Operation.Read),  Is.True);
                Assert.That(node.IsAllowed(alice, NodeResources.DNS,          Operation.Edit),  Is.False);
                Assert.That(node.PermissionsOf(alice).Select(permission => permission.ToString()),
                            Is.EqualTo(new[] { "configuration:read", "dns:read", "nts:read", "certificates:read" }));

                Assert.That(node.RolesOf(robert),                                                   Is.Empty);
                Assert.That(node.IsAllowed(robert, NodeResources.DNS,          Operation.Read),  Is.False);

                Assert.That(node.IsAllowed(null,  NodeResources.DNS,          Operation.Read),  Is.False, "nobody at all");

            });

        }

        #endregion

    }

}
