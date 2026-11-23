/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.OpenADR;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A connection to a grid operator carries OpenADR, and so does one of a
    /// VEN, as the grid operator has it: a grid operator is connected to and
    /// connects to nothing, a VEN is what connects - in the binding of its
    /// JSON messages, or in that of the REST API in a tunnel - and a connection
    /// of a VEN names the VEN it is taken as.
    /// </summary>
    public class OpenADRConnectionTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-openadr-connections-" + Guid.NewGuid().ToString("N")[..12]);
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

        #region (private) AStore(Rules = null) / AGridOperatorsStore()

        private ConnectionStore AStore(ConnectionRules? Rules = null)

            => new (Path.Combine(directory, "connections")) {
                   Rules = Rules ?? new ConnectionRules()
               };

        private ConnectionStore AGridOperatorsStore()

            => AStore(new ConnectionRules {
                          Types                  = [ ConnectionType.VEN ],
                          Outbound               = false,
                          OCPP1_6                = false,
                          NamesTheNodeItLeadsTo  = false
                      });

        #endregion


        #region TheTypes_GridOperatorAndVEN_AreRead_AndCarryOpenADR(Text, Type)

        /// <summary>
        /// "gridoperator" and "ven" are kinds of what is at the other end, and
        /// carry OpenADR.
        /// </summary>
        [TestCase("gridoperator",  ConnectionType.GridOperator)]
        [TestCase("GridOperator",  ConnectionType.GridOperator)]
        [TestCase(" ven",          ConnectionType.VEN)]
        [TestCase("VEN",           ConnectionType.VEN)]
        public void TheTypes_GridOperatorAndVEN_AreRead_AndCarryOpenADR(String          Text,
                                                                       ConnectionType  Type)
        {

            Assert.That(ConnectionEntry.TryParseType(Text, out var type), Is.True);

            Assert.Multiple(() => {
                Assert.That(type,                                                  Is.EqualTo(Type));
                Assert.That(ConnectionEntry.UseOf(type),                           Is.EqualTo(ConnectionUse.OpenADR));
                Assert.That(ProtocolVersion.OpenADR(OpenADRBinding.REST).    ToString(), Is.EqualTo("OpenADR (REST)"));
                Assert.That(ProtocolVersion.OpenADR(OpenADRBinding.Messages).ToString(), Is.EqualTo("OpenADR"));
                Assert.That(ProtocolVersion.OpenADR(OpenADRBinding.REST),         Is.Not.EqualTo(ProtocolVersion.OpenADR(OpenADRBinding.Messages)));
            });

        }

        #endregion

        #region TheWireNames_OfBothBindings()

        /// <summary>
        /// Each binding has a WebSocket subprotocol and an SSH subsystem of its own.
        /// </summary>
        [Test]
        public void TheWireNames_OfBothBindings()
        {

            Assert.Multiple(() => {
                Assert.That(OpenADRWireNames.SubprotocolOf (OpenADRBinding.Messages),  Is.EqualTo("openadr3.1"));
                Assert.That(OpenADRWireNames.SubprotocolOf (OpenADRBinding.REST),      Is.EqualTo("openadr3.1-rest"));
                Assert.That(OpenADRWireNames.SshSubsystemOf(OpenADRBinding.Messages),  Is.EqualTo("openadr@open.charging.cloud"));
                Assert.That(OpenADRWireNames.SshSubsystemOf(OpenADRBinding.REST),      Is.EqualTo("openadr-rest@open.charging.cloud"));
                Assert.That(WWCPNode.GridOperatorTunnelURL.AbsolutePath,               Is.EqualTo(OpenADRWireNames.RestTunnelPath));
            });

        }

        #endregion

        #region EveryNode_ConnectsToAGridOperator_InEitherBinding(URL, Binding, Expected)

        /// <summary>
        /// Every node may connect to a grid operator, over ws://, wss:// and
        /// ssh://: it carries OpenADR - its JSON messages where nothing says
        /// otherwise -, and no OCPI version and no VEN.
        /// </summary>
        [TestCase("ws://127.0.0.1:2363/lc001",          null,        OpenADRBinding.Messages)]
        [TestCase("wss://grid.example.org:2363/lc001",  "rest",      OpenADRBinding.REST)]
        [TestCase("ssh://lc001@grid.example.org:2222",  "REST",      OpenADRBinding.REST)]
        [TestCase("ssh://lc001@grid.example.org:2222",  "messages",  OpenADRBinding.Messages)]
        public void EveryNode_ConnectsToAGridOperator_InEitherBinding(String          URL,
                                                                      String?         Binding,
                                                                      OpenADRBinding  Expected)
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The grid operator"), org.GraphDefined.Vanaheimr.Hermod.HTTP.URL.Parse(URL), "GridOperator", true, null, null,
                                               out var id, out var error,
                                               OpenADRBinding: Binding),
                        Is.True, error);

            var entry = store.Connections.Single(connection => connection.Id == id);

            Assert.Multiple(() => {
                Assert.That(entry.Use,             Is.EqualTo(ConnectionUse.OpenADR));
                Assert.That(entry.OpenADRBinding,  Is.EqualTo(Expected));
                Assert.That(entry.Protocol,        Is.EqualTo(ProtocolVersion.OpenADR(Expected)));
                Assert.That(entry.VEN,             Is.Null);
                Assert.That(entry.OCPIVersion,     Is.Null);
                Assert.That(entry.ToJSON()[ConnectionEntry.OpenADRBindingKey]?.Value<String>(), Is.EqualTo(ConnectionEntry.AsText(Expected)));
            });

        }

        #endregion

        #region AGridOperator_ConnectsToNothing_AndNamesNoVEN()

        /// <summary>
        /// A connection to a grid operator is one the node makes, names no node
        /// beyond it and no VEN; one the grid operator would make is refused,
        /// and so is a binding that is none.
        /// </summary>
        [Test]
        public void AGridOperator_ConnectsToNothing_AndNamesNoVEN()
        {

            var store = AStore();

            Assert.Multiple(() => {

                Assert.That(store.TryAddConnection(I18NString.Create("connecting"), URL.Parse("ws://127.0.0.1:2363/go01"), "GridOperator", true, null, null,
                                                   out _, out var inbound, Inbound: true),
                            Is.False);

                Assert.That(inbound, Does.Contain("connects to nothing"));

                Assert.That(store.TryAddConnection(I18NString.Create("a VEN"), URL.Parse("ws://127.0.0.1:2363/lc001"), "GridOperator", true, null, null,
                                                   out _, out var named, VEN: "lc-1"),
                            Is.False, "A connection to a grid operator named a VEN.");

                Assert.That(store.TryAddConnection(I18NString.Create("a node beyond"), URL.Parse("ws://127.0.0.1:2363/lc001"), "GridOperator", true, null, null,
                                                   out _, out var beyond, RemoteNodeId: "go01"),
                            Is.False, "A connection to a grid operator named a node beyond it.");

                Assert.That(store.TryAddConnection(I18NString.Create("soap"), URL.Parse("ws://127.0.0.1:2363/lc001"), "GridOperator", true, null, null,
                                                   out _, out var soap, OpenADRBinding: "soap"),
                            Is.False, "A binding that is none was taken.");

                Assert.That(store.TryAddConnection(I18NString.Create("a CSMS"), URL.Parse("ws://127.0.0.1:2351/lc001"), "CSMS", true, null, null,
                                                   out _, out var csms, OpenADRBinding: "rest"),
                            Is.False, "A connection of OCPP said a binding of OpenADR.");

            });

        }

        #endregion

        #region AGridOperator_WritesDownItsVENs_AndNothingElse()

        /// <summary>
        /// A grid operator writes down the VENs that connect - naming the VEN
        /// each is taken as -, keeps the binding and the VEN when a change does
        /// not say them, reads them back from its file, and refuses a VEN it
        /// would connect to and one that names no VEN.
        /// </summary>
        [Test]
        public void AGridOperator_WritesDownItsVENs_AndNothingElse()
        {

            var store = AGridOperatorsStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The controller"), URL.Parse("ssh://lc001@127.0.0.1:2222"), "VEN", true, null, null,
                                               out var id, out var error,
                                               Inbound:         true,
                                               OpenADRBinding:  "rest",
                                               VEN:             "lc-paradies"),
                        Is.True, error);

            var entry = store.Connections.Single(connection => connection.Id == id);

            Assert.Multiple(() => {
                Assert.That(entry.InboundName,     Is.EqualTo("lc001"));
                Assert.That(entry.VEN,             Is.EqualTo("lc-paradies"));
                Assert.That(entry.OpenADRBinding,  Is.EqualTo(OpenADRBinding.REST));
                Assert.That(entry.Protocol,        Is.EqualTo(ProtocolVersion.OpenADR(OpenADRBinding.REST)));
            });

            // A change of something else keeps both.
            Assert.That(store.TryUpdateConnection(id, I18NString.Create("The controller, renamed"), URL.Parse("ssh://lc001@127.0.0.1:2222"), "VEN", false, null, null,
                                                  out error, Inbound: true),
                        Is.True, error);

            entry = store.Connections.Single(connection => connection.Id == id);

            Assert.Multiple(() => {
                Assert.That(entry.VEN,             Is.EqualTo("lc-paradies"));
                Assert.That(entry.OpenADRBinding,  Is.EqualTo(OpenADRBinding.REST));
                Assert.That(entry.AutoConnect,     Is.False);
            });

            // Read back from the file as it was written.
            var again = AGridOperatorsStore();
            again.Reload();

            var read  = again.Connections.Single(connection => connection.Id == id);

            Assert.Multiple(() => {
                Assert.That(read.VEN,             Is.EqualTo("lc-paradies"));
                Assert.That(read.OpenADRBinding,  Is.EqualTo(OpenADRBinding.REST));
            });

            Assert.Multiple(() => {

                Assert.That(store.TryAddConnection(I18NString.Create("no VEN"), URL.Parse("ws://127.0.0.1:2363/lc002"), "VEN", true, null, null,
                                                   out _, out var noVEN, Inbound: true, OpenADRBinding: "rest"),
                            Is.False, "A connection of a VEN named no VEN.");

                Assert.That(noVEN, Does.Contain(ConnectionEntry.VENKey));

                Assert.That(store.TryAddConnection(I18NString.Create("two words"), URL.Parse("ws://127.0.0.1:2363/lc002"), "VEN", true, null, null,
                                                   out _, out var twoWords, Inbound: true, VEN: "lc paradies"),
                            Is.False, "A VEN name of two words was taken.");

                Assert.That(store.TryAddConnection(I18NString.Create("connected to"), URL.Parse("ws://lc.example.org/go01"), "VEN", true, null, null,
                                                   out _, out var outbound, VEN: "lc-nord"),
                            Is.False, "A grid operator connects to a VEN.");

            });

        }

        #endregion

    }

}
