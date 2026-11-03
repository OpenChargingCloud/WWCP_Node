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
    /// What a change of the groups of time servers tells whoever listens, and
    /// who it says made it: once per group and save, after the change is in
    /// effect and the lock is let go - and several groups changed at once, all
    /// of them or none.
    /// </summary>
    /// <remarks>
    /// What a bridge to OCPP needs from the node: a CSMS told of what changed
    /// on the page, a change of its own told apart from the page's, and the
    /// variables of several groups set in one request without the station
    /// ending up half changed.
    /// </remarks>
    public class NTSChangeTests
    {

        #region Data

        private String directory = "";

        private String ConfigurationPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        private JObject OnDisk
            => JObject.Parse(File.ReadAllText(ConfigurationPath));

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-nts-changes-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Configuration = null)

        private WWCPNode Node(String? Configuration = null)
        {

            if (Configuration is not null)
                File.WriteAllText(ConfigurationPath, Configuration);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Added(Node, Id)

        private static NTSGroup Added(WWCPNode  Node,
                                      String    Id)
        {

            Assert.That(Node.TryAddNTSGroup(Id, null, out var group, out var error, out _),  Is.True,  error);

            return group!;

        }

        #endregion

        #region (helper) Recorded(Node)

        /// <summary>
        /// One change as a listener was told it.
        /// </summary>
        private sealed record Told(NTSGroup               Group,
                                   IReadOnlyList<String>  Changes,
                                   String?                Origin);

        /// <summary>
        /// Every change the node tells from now on, in the order it tells them.
        /// </summary>
        private static List<Told> Recorded(WWCPNode Node)
        {

            var told = new List<Told>();

            Node.OnNTSGroupChanged += (group, changes, origin) => {
                lock (told)
                    told.Add(new (group, changes, origin));
            };

            return told;

        }

        #endregion

        #region (helper) Said(Node, Since)

        private static String[] Said(WWCPNode  Node,
                                     UInt64    Since)

            => [.. Node.Log.Recent(100, Since, null).Select(entry => entry.Message)];

        #endregion


        #region ASaveIsToldOnceWithWhatChangedAndWhoChangedIt()

        [Test]
        public void ASaveIsToldOnceWithWhatChangedAndWhoChangedIt()
        {

            var node    = Node();
            var local   = Added(node, "local");
            var told    = Recorded(node);
            var before  = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "servers": [ "a.example", "b.example" ], "maxErrors": 20 }"""), out var error, out _, ChangeOrigin.Web("alice")),
                        Is.True,
                        error);

            Assert.Multiple(() => {

                Assert.That(told,              Has.Count.EqualTo(1));
                Assert.That(told[0].Group,     Is.SameAs(local));
                Assert.That(told[0].Changes,   Has.Some.StartsWith("time servers = "));
                Assert.That(told[0].Changes,   Has.Some.EqualTo("server ids = local-1, local-2"));
                Assert.That(told[0].Changes,   Has.Some.EqualTo("limited after 20 errors in a row"));
                Assert.That(told[0].Origin,    Is.EqualTo("web:alice"));

                Assert.That(Said(node, before), Has.Some.StartsWith("NTS group 'local' changed: ").And.EndsWith(" (by web:alice)."),
                            "the log line names who changed the group");

            });

        }

        #endregion

        #region ASaveThatChangesNothingTellsNothing()

        [Test]
        public void ASaveThatChangesNothingTellsNothing()
        {

            var node   = Node();
            var local  = Added(node, "local");
            var json   = """{ "servers": [ "a.example" ], "maxErrors": 20 }""";

            Assert.That(node.TryUpdateNTSConfiguration(local, JObject.Parse(json), out var error, out _),  Is.True,  error);

            var told   = Recorded(node);

            Assert.That(node.TryUpdateNTSConfiguration(local, JObject.Parse(json), out error, out _),      Is.True,  error);

            Assert.That(told, Is.Empty, "the same save again changed nothing");

        }

        #endregion

        #region AGroupMadeAndTakenAwayIsToldWithWhoDidIt()

        [Test]
        public async Task AGroupMadeAndTakenAwayIsToldWithWhoDidIt()
        {

            var node     = Node();
            var added    = new List<(NTSGroup Group, String? Origin)>();
            var removed  = new List<(NTSGroup Group, String? Origin)>();

            node.OnNTSGroupAdded   += (group, origin) => added.  Add((group, origin));
            node.OnNTSGroupRemoved += (group, origin) => removed.Add((group, origin));

            var before   = node.Log.LastId;

            Assert.That(node.TryAddNTSGroup("local", null, out var local, out var error, out _, ChangeOrigin.CLI("bob")),  Is.True,  error);

            var (taken, takenError, _) = await node.TryRemoveNTSGroupAsync("local", ChangeOrigin.OCPP("CSMS1"));

            Assert.That(taken, Is.True, takenError);

            Assert.Multiple(() => {

                Assert.That(added,    Is.EqualTo(new[] { (local!, (String?) "cli:bob") }));
                Assert.That(removed,  Is.EqualTo(new[] { (local!, (String?) "ocpp:CSMS1") }));
                Assert.That(removed[0].Group.IsDisposed,  Is.True,  "told once everything that ran for it has ended");

                Assert.That(Said(node, before), Has.Some.EqualTo("NTS group 'local' added, switched off (by cli:bob)."));
                Assert.That(Said(node, before), Has.Some.EqualTo("NTS group 'local' removed (by ocpp:CSMS1)."));

            });

        }

        #endregion

        #region AListenerMayChangeTheNodeInTurn()

        /// <summary>
        /// Told once the lock is let go: a listener that changes the node in
        /// turn - a bridge writing down the id of a server it was told of -
        /// would otherwise wait for the save that told it, and that save for
        /// the listener.
        /// </summary>
        [Test]
        public void AListenerMayChangeTheNodeInTurn()
        {

            var node      = Node();
            var local     = Added(node, "local");
            var answered  = new List<Boolean>();

            node.OnNTSGroupChanged += (group, changes, origin) => {
                if (origin == "web:alice")
                    answered.Add(node.TryUpdateNTSConfiguration(group, JObject.Parse("""{ "errorLogging": 3 }"""), out _, out _, "test:listener"));
            };

            var save = Task.Run(() => node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "maxErrors": 20 }"""), out _, out _, ChangeOrigin.Web("alice")));

            Assert.That(save.Wait(TimeSpan.FromSeconds(10)),  Is.True,  "the listener's change waited for the lock the save that told it still held");

            Assert.Multiple(() => {
                Assert.That(save.Result,         Is.True);
                Assert.That(answered,            Is.EqualTo(new[] { true }));
                Assert.That(local.ErrorLogging,  Is.EqualTo(3));
            });

        }

        #endregion

        #region AListenerThatFailsKeepsNoOtherFromHearing()

        [Test]
        public void AListenerThatFailsKeepsNoOtherFromHearing()
        {

            var node    = Node();
            var local   = Added(node, "local");

            node.OnNTSGroupChanged += (_, _, _) => throw new InvalidOperationException("listener down");

            var told    = Recorded(node);
            var before  = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "maxErrors": 20 }"""), out var error, out _),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(told,                Has.Count.EqualTo(1));
                Assert.That(local.MaxErrors,     Is.EqualTo(20),  "the save is not undone by a listener");
                Assert.That(Said(node, before),  Has.Some.Contains("NTS group 'local' changed failed: listener down"));
            });

        }

        #endregion


        #region SeveralGroupsAreChangedAtOnce()

        [Test]
        public void SeveralGroupsAreChangedAtOnce()
        {

            var node   = Node();
            var legal  = node.LegalTime;
            var local  = Added(node, "local");
            var told   = Recorded(node);

            Assert.That(node.TryUpdateNTSConfigurations([ (legal, JObject.Parse("""{ "maxErrors": 20 }""")),
                                                          (local, JObject.Parse("""{ "maxErrors": 30 }""")) ],
                                                        out var error,
                                                        out var refused,
                                                        out _,
                                                        ChangeOrigin.OCPP("CSMS1")),
                        Is.True,
                        error);

            Assert.Multiple(() => {

                Assert.That(refused,          Is.Null);
                Assert.That(legal.MaxErrors,  Is.EqualTo(20));
                Assert.That(local.MaxErrors,  Is.EqualTo(30));

                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?.Value<Int32>("maxErrors"),  Is.EqualTo(20));
                Assert.That(OnDisk["nts"]?["groups"]?["local"]?.Value<Int32>("maxErrors"),  Is.EqualTo(30));

                Assert.That(told.Select(change => change.Group),   Is.EqualTo(new[] { legal, local }),  "each group told on its own");
                Assert.That(told.Select(change => change.Origin),  Is.All.EqualTo("ocpp:CSMS1"));

            });

        }

        #endregion

        #region OneGroupRefusedChangesNoneOfThem(Local, Says)

        /// <summary>
        /// Refused where the part is read, and where it is checked against what
        /// is in effect, under the lock: either way the group before it in the
        /// list is not changed either - not in effect, and not in the file.
        /// </summary>
        [TestCase("""{ "maxErrors": 0 }""",   "maxErrors",   TestName = "Refused as it is read")]
        [TestCase("""{ "minServers": 5 }""",  "minServers",  TestName = "Refused against the servers in effect")]
        public void OneGroupRefusedChangesNoneOfThem(String  Local,
                                                     String  Says)
        {

            var node      = Node();
            var legal     = node.LegalTime;
            var local     = Added(node, "local");
            var told      = Recorded(node);
            var file      = File.ReadAllText(ConfigurationPath);

            Assert.That(node.TryUpdateNTSConfigurations([ (legal, JObject.Parse("""{ "maxErrors": 20 }""")),
                                                          (local, JObject.Parse(Local)) ],
                                                        out var error,
                                                        out var refused,
                                                        out var notSaved),
                        Is.False);

            Assert.Multiple(() => {

                Assert.That(refused,           Is.SameAs(local),  "the group whose part was the reason");
                Assert.That(error,             Does.Contain("nts.groups.local").And.Contain(Says));
                Assert.That(notSaved,          Is.False);

                Assert.That(legal.MaxErrors,   Is.EqualTo(10),    "the legal group was not changed either");
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(file),  "nor written down");
                Assert.That(told,              Is.Empty);

            });

        }

        #endregion

        #region AGroupNamedTwiceIsRefused()

        [Test]
        public void AGroupNamedTwiceIsRefused()
        {

            var node   = Node();
            var local  = Added(node, "local");

            Assert.That(node.TryUpdateNTSConfigurations([ (local, JObject.Parse("""{ "maxErrors": 20 }""")),
                                                          (local, JObject.Parse("""{ "maxErrors": 30 }""")) ],
                                                        out var error,
                                                        out var refused,
                                                        out _),
                        Is.False);

            Assert.Multiple(() => {
                Assert.That(refused,          Is.SameAs(local));
                Assert.That(error,            Does.Contain("twice"));
                Assert.That(local.MaxErrors,  Is.EqualTo(50),  "neither part was put into effect");
            });

        }

        #endregion

        #region TheGroupsAreCheckedTogetherAsTheNextStartReadsThem()

        /// <summary>
        /// Each part on its own is a group the next start would read, and the
        /// two together are not: a server's id names it in every group. Refused
        /// as a whole, with no group to blame.
        /// </summary>
        [Test]
        public void TheGroupsAreCheckedTogetherAsTheNextStartReadsThem()
        {

            var node   = Node();
            var legal  = node.LegalTime;
            var local  = Added(node, "local");
            var was    = legal.ServerIds;

            Assert.That(node.TryUpdateNTSConfigurations([ (legal, JObject.Parse("""{ "servers": [ { "id": "shared", "hostname": "a.example" } ] }""")),
                                                          (local, JObject.Parse("""{ "servers": [ { "id": "shared", "hostname": "b.example" } ] }""")) ],
                                                        out var error,
                                                        out var refused,
                                                        out var notSaved),
                        Is.False);

            Assert.Multiple(() => {
                Assert.That(refused,           Is.Null,  "both together, neither alone");
                Assert.That(error,             Does.Contain("'shared' is the id of"));
                Assert.That(notSaved,          Is.False);
                Assert.That(legal.ServerIds,   Is.EqualTo(was));
                Assert.That(local.ServerIds,   Is.Empty);
            });

        }

        #endregion

        #region AChangeIsMadeFromTheGroupsAsTheyAreUnderTheLock()

        /// <summary>
        /// A change made from the groups as they are is asked for its parts
        /// while nothing else can change them: a save from a page that comes
        /// in meanwhile waits until the change is in, and is made after it,
        /// rather than being written away by a list read before it.
        /// </summary>
        [Test]
        public async Task AChangeIsMadeFromTheGroupsAsTheyAreUnderTheLock()
        {

            var node        = Node();
            var local       = Added(node, "local");
            Task<Boolean>?  page = null;
            var pageWaited  = false;

            Assert.That(node.TryUpdateNTSConfigurations(groups => {

                                                            Assert.That(groups, Does.Contain(local), "asked with the groups as they are");

                                                            // A page saving a server of the same group at this moment.
                                                            page       = Task.Run(() => node.TryUpdateNTSConfiguration(local, JObject.Parse("""{ "servers": [ { "id": "a", "hostname": "a.example" }, { "id": "b", "hostname": "b.example" } ] }"""), out _, out _));
                                                            pageWaited = !page.Wait(TimeSpan.FromMilliseconds(300));

                                                            return [ (local, JObject.Parse("""{ "servers": [ { "id": "a", "hostname": "a.example" } ], "maxErrors": 30 }""")) ];

                                                        },
                                                        out var error,
                                                        out var refused,
                                                        out _,
                                                        ChangeOrigin.OCPP("CSMS1")),
                        Is.True,
                        error);

            Assert.That(await page!, Is.True, "the page's save is made after the change");

            Assert.Multiple(() => {
                Assert.That(pageWaited,        Is.True,  "the page waited for the change");
                Assert.That(refused,           Is.Null);
                Assert.That(local.MaxErrors,   Is.EqualTo(30));
                Assert.That(local.ServerIds,   Is.EqualTo(new[] { "a", "b" }), "the page's server is kept, saved after the change");
            });

        }

        #endregion

        #region AChangeThatSaysNoneChangesNothingAndTellsNothing()

        /// <summary>
        /// A change that finds nothing to do says so with null: nothing is
        /// written, and nothing is told.
        /// </summary>
        [Test]
        public void AChangeThatSaysNoneChangesNothingAndTellsNothing()
        {

            var node    = Node("{}");
            var told    = Recorded(node);
            var before  = File.ReadAllText(ConfigurationPath);

            Assert.That(node.TryUpdateNTSConfigurations(groups => null, out var error, out var refused, out var notSaved), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(refused,                              Is.Null);
                Assert.That(notSaved,                             Is.False);
                Assert.That(told,                                 Is.Empty);
                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before));
            });

        }

        #endregion

    }

}
