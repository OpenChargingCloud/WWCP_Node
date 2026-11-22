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

using System.Collections.Concurrent;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Modbus;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A connection to an energy meter carries Modbus, and so does one of what
    /// reads a meter, as the meter has it: an energy meter is connected to and
    /// connects to nothing, and what reads it is what connects.
    /// </summary>
    public class ModbusConnectionTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-modbus-connections-" + Guid.NewGuid().ToString("N")[..12]);
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

        #region (private) AStore(Rules = null)

        private ConnectionStore AStore(ConnectionRules? Rules = null)

            => new (Path.Combine(directory, "connections")) {
                   Rules = Rules ?? new ConnectionRules()
               };

        #endregion


        #region TheTypes_EnergyMeterAndMeterReader_AreRead_AndCarryModbus(Text, Type)

        /// <summary>
        /// "energymeter" and "meterreader" are kinds of what is at the other end,
        /// and carry Modbus, which has no version.
        /// </summary>
        [TestCase("energymeter",  ConnectionType.EnergyMeter)]
        [TestCase("EnergyMeter",  ConnectionType.EnergyMeter)]
        [TestCase(" meterreader", ConnectionType.MeterReader)]
        [TestCase("MeterReader",  ConnectionType.MeterReader)]
        public void TheTypes_EnergyMeterAndMeterReader_AreRead_AndCarryModbus(String          Text,
                                                                              ConnectionType  Type)
        {

            Assert.That(ConnectionEntry.TryParseType(Text, out var type), Is.True);

            Assert.Multiple(() => {
                Assert.That(type,                         Is.EqualTo(Type));
                Assert.That(ConnectionEntry.UseOf(type),  Is.EqualTo(ConnectionUse.Modbus));
                Assert.That(ProtocolVersion.Modbus.ToString(), Is.EqualTo("Modbus"));
            });

        }

        #endregion

        #region EveryNode_ConnectsToAnEnergyMeter_OverWebSocketsAndSSH(URL)

        /// <summary>
        /// Every node may connect to an energy meter, over ws://, wss:// and
        /// ssh://: it carries Modbus, and no OCPI version.
        /// </summary>
        [TestCase("ws://127.0.0.1:2357/cs001")]
        [TestCase("wss://meter.example.org:2357/cs001")]
        [TestCase("ssh://cs001@meter.example.org:2222")]
        public void EveryNode_ConnectsToAnEnergyMeter_OverWebSocketsAndSSH(String URL)
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The meter"), org.GraphDefined.Vanaheimr.Hermod.HTTP.URL.Parse(URL), "EnergyMeter", true, null, null,
                                               out var id, out var error),
                        Is.True, error);

            var entry = store.Connections.Single(connection => connection.Id == id);

            Assert.Multiple(() => {
                Assert.That(entry.Use,          Is.EqualTo(ConnectionUse.Modbus));
                Assert.That(entry.Protocol,     Is.EqualTo(ProtocolVersion.Modbus));
                Assert.That(entry.OCPIVersion,  Is.Null);
            });

        }

        #endregion

        #region AnEnergyMeter_ConnectsToNothing()

        /// <summary>
        /// A connection to an energy meter is one the node makes: one the meter
        /// would make is refused.
        /// </summary>
        [Test]
        public void AnEnergyMeter_ConnectsToNothing()
        {

            Assert.That(AStore().TryAddConnection(I18NString.Create("The meter, connecting"), URL.Parse("ws://127.0.0.1:2357/em01"), "EnergyMeter", true, null, null,
                                                  out _, out var error,
                                                  Inbound: true),
                        Is.False);

            Assert.That(error, Does.Contain("connects to nothing"));

        }

        #endregion

        #region AMeter_WritesDownWhatReadsIt_AndNothingElse()

        /// <summary>
        /// A meter writes down what reads it - one the other end makes, over a
        /// WebSocket or over SSH - and refuses one it would make itself, or one
        /// that names a node or an OCPI version.
        /// </summary>
        [Test]
        public void AMeter_WritesDownWhatReadsIt_AndNothingElse()
        {

            var store = AStore(new ConnectionRules {
                                   Types     = [ ConnectionType.MeterReader ],
                                   Outbound  = false,
                                   OCPP1_6   = false
                               });

            Assert.That(store.TryAddConnection(I18NString.Create("The station"), URL.Parse("ssh://cs001@127.0.0.1:2222"), "MeterReader", true, null, null,
                                               out var inbound, out var error,
                                               Inbound: true),
                        Is.True, error);

            Assert.That(store.Connections.Single(connection => connection.Id == inbound).InboundName, Is.EqualTo("cs001"));

            Assert.That(store.TryAddConnection(I18NString.Create("The station, connected to"), URL.Parse("ws://cs.example.org/em01"), "MeterReader", true, null, null,
                                               out _, out error),
                        Is.False);

            Assert.That(store.TryAddConnection(I18NString.Create("The station, of OCPI"), URL.Parse("ws://127.0.0.1:2357/cs002"), "MeterReader", true, null, null,
                                               out _, out error,
                                               Inbound:      true,
                                               OCPIVersion:  "2.2.1"),
                        Is.False);

            Assert.That(error, Does.Contain("Modbus"));

        }

        #endregion

        #region AConnectionOfModbus_NamesNoNodeAtItsOtherEnd()

        /// <summary>
        /// Nothing is routed beyond a connection to an energy meter.
        /// </summary>
        [Test]
        public void AConnectionOfModbus_NamesNoNodeAtItsOtherEnd()
        {

            Assert.That(AStore().TryAddConnection(I18NString.Create("The meter"), URL.Parse("ws://127.0.0.1:2357/cs001"), "EnergyMeter", true, null, null,
                                                  out _, out var error,
                                                  RemoteNodeId: "em01"),
                        Is.False);

            Assert.That(error, Does.Contain("Modbus"));

        }

        #endregion


        #region AWebSocketMessageStream_ReadsAcrossMessages_AndSendsAWriteAsOneMessage()

        /// <summary>
        /// A WebSocket as a stream: what its binary messages carry is read one
        /// after the other, across their boundaries, and every write goes as one
        /// message; it ends when the WebSocket does.
        /// </summary>
        [Test]
        public async Task AWebSocketMessageStream_ReadsAcrossMessages_AndSendsAWriteAsOneMessage()
        {

            var sent    = new ConcurrentQueue<Byte[]>();
            var closed  = false;

            using var stream = new WebSocketMessageStream(
                                   (message, cancellationToken) => { sent.Enqueue(message); return Task.CompletedTask; },
                                   () => { closed = true; return Task.CompletedTask; }
                               );

            await stream.Deliver([ 1, 2, 3 ]);
            await stream.Deliver([ 4, 5 ]);

            var buffer  = new Byte[5];
            var read    = 0;

            while (read < buffer.Length)
                read += await stream.ReadAsync(buffer.AsMemory(read));

            await stream.WriteAsync(new Byte[] { 9, 8, 7, 6 });

            stream.End();

            var afterTheEnd = await stream.ReadAsync(new Byte[1]);

            stream.Dispose();

            await Task.Delay(50);

            Assert.Multiple(() => {
                Assert.That(buffer,         Is.EqualTo(new Byte[] { 1, 2, 3, 4, 5 }));
                Assert.That(sent,           Has.Count.EqualTo(1));
                Assert.That(sent.First(),   Is.EqualTo(new Byte[] { 9, 8, 7, 6 }));
                Assert.That(afterTheEnd,    Is.Zero, "The stream did not end with the WebSocket.");
                Assert.That(stream.HasEnded, Is.True);
                Assert.That(closed,         Is.True, "Disposing the stream did not close the WebSocket.");
            });

        }

        #endregion

    }

}
