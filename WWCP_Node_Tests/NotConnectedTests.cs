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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A connection the node does not connect on purpose - because of
    /// something a kind of node knows of it beyond what is written of it, as
    /// a CSMS knows the login of the node at its other end - says so: not
    /// connected, and why, rather than that it could not be reached.
    /// </summary>
    public class NotConnectedTests
    {

        #region (class) ANodeThatMayNotDial

        /// <summary>
        /// A node that says of every connection why it is not connected -
        /// or, with no reason, nothing.
        /// </summary>
        private sealed class ANodeThatMayNotDial(String   Directory,
                                                 String?  Why)

            : WWCPNode(AccountsPath:      Path.Combine(Directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(Path.Combine(Directory, WWCPConfigFile.DefaultFileName)),
                       CertificateKinds:  [],
                       LogToConsole:      false,
                       BridgeDebugLog:    false)

        {

            public Int32 Asked { get; private set; }

            protected internal override String? WhyItIsNotConnected(ConnectionEntry Connection)
            {
                Asked++;
                return Why;
            }

            public Task DialIt(ConnectionEntry Connection)

                => Dial(Connection, CancellationToken.None);

            public void Keeps(ConnectionStore Store)

                => Connections = Store;

        }

        #endregion

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-not-connected-" + Guid.NewGuid().ToString("N")[..12]);
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
            catch
            { }
        }

        #endregion


        #region AConnection(Name)

        private ConnectionEntry AConnection(out String URL)
        {

            var store  = new ConnectionStore(Path.Combine(directory, "conn"));
            URL        = $"ws://127.0.0.1:{TestPorts.Free()}/cs001";

            Assert.That(store.TryAddConnection(I18NString.Create("The gateway below"), org.GraphDefined.Vanaheimr.Hermod.HTTP.URL.Parse(URL), "Gateway", true, null, null, out var id, out var error),
                        Is.True, error);

            return store.Connections.Single(connection => connection.Id == id);

        }

        #endregion


        #region AConnectionNotConnectedOnPurpose_SaysSo()

        /// <summary>
        /// A connection the node will not connect is not connected: it
        /// stands as not connected, says why, and does not say that it could
        /// not be reached - nothing was tried.
        /// </summary>
        [Test]
        public async Task AConnectionNotConnectedOnPurpose_SaysSo()
        {

            await using var node        = new ANodeThatMayNotDial(directory, "the login gw007 is marked as a local controller, not as a gateway");
            var             connection  = AConnection(out var url);

            var dialling = node.DialIt(connection);
            Assert.That(await Task.WhenAny(dialling, Task.Delay(TimeSpan.FromSeconds(30))), Is.SameAs(dialling), "Dialling did not end.");
            await dialling;

            var state = node.ConnectionStates[connection.Id];

            Assert.Multiple(() => {
                Assert.That(node.Asked,   Is.EqualTo(1));
                Assert.That(state.Status, Is.EqualTo(ConnectionStatus.NotConnected));
                Assert.That(state.Said,   Is.EqualTo($"Not connected: 'The gateway below' ({url}): the login gw007 is marked as a local controller, not as a gateway."));
                Assert.That(state.Said,   Does.Not.Contain("could not be reached"));
            });

        }

        #endregion

        #region AConnectionMissingSomethingHere_SaysWhyTheSameWay()

        /// <summary>
        /// A connection that is not connected because something it needs is
        /// missing here says it as one the kind of node refuses does: which
        /// one, and after a colon why.
        /// </summary>
        [Test]
        public async Task AConnectionMissingSomethingHere_SaysWhyTheSameWay()
        {

            await using var node   = new ANodeThatMayNotDial(directory, null);
            var             store  = new ConnectionStore(Path.Combine(directory, "conn"));
            var             url    = $"ws://127.0.0.1:{TestPorts.Free()}/cs001";

            node.Keeps(store);

            Assert.That(store.TryAddConnection(I18NString.Create("The back end"), URL.Parse(url), "CSMS", true, null, null, out var id, out var error),
                        Is.True, error);

            var connection = store.Connections.Single(one => one.Id == id);
            connection.AuthenticationId = "nobody";

            var dialling = node.DialIt(connection);
            Assert.That(await Task.WhenAny(dialling, Task.Delay(TimeSpan.FromSeconds(30))), Is.SameAs(dialling), "Dialling did not end.");
            await dialling;

            var state = node.ConnectionStates[connection.Id];

            Assert.Multiple(() => {
                Assert.That(state.Status, Is.EqualTo(ConnectionStatus.NotConnected));
                Assert.That(state.Said,   Is.EqualTo($"Not connected: 'The back end' ({url}): it names credentials that are not configured here."));
            });

        }

        #endregion

        #region AConnectionWithNothingAgainstIt_IsDialled()

        /// <summary>
        /// A connection the node has nothing against is dialled as before:
        /// where nothing listens, it could not be reached - and is not said
        /// to be not connected.
        /// </summary>
        [Test]
        public async Task AConnectionWithNothingAgainstIt_IsDialled()
        {

            await using var node        = new ANodeThatMayNotDial(directory, null);
            var             connection  = AConnection(out _);

            var dialling = node.DialIt(connection);
            Assert.That(await Task.WhenAny(dialling, Task.Delay(TimeSpan.FromSeconds(30))), Is.SameAs(dialling), "Dialling did not end.");
            await dialling;

            var state = node.ConnectionStates[connection.Id];

            Assert.Multiple(() => {
                Assert.That(node.Asked,   Is.EqualTo(1));
                Assert.That(state.Status, Is.Not.EqualTo(ConnectionStatus.NotConnected));
                Assert.That(state.Said,   Does.Not.StartWith("Not connected"));
            });

        }

        #endregion

    }

}
