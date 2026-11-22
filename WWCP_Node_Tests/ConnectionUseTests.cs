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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a connection carries: OCPP to a CSMS, a local controller, a gateway
    /// and a charging station, OCPI to an EMSP and a CPO - in the version of
    /// OCPI it says, which a connection of OCPI has to say and one of OCPP may
    /// not.
    /// </summary>
    public class ConnectionUseTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-connection-use-" + Guid.NewGuid().ToString("N")[..12]);
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

        /// <summary>
        /// A store of connections of its own, held to the given rules - to those
        /// of a CSMS that connects to an EMSP as well, where none are given.
        /// </summary>
        private ConnectionStore AStore(ConnectionRules? Rules = null)

            => new (Path.Combine(directory, "connections")) {
                   Rules = Rules ?? new ConnectionRules {
                                        Types = [ .. ConnectionRules.Every, ConnectionType.EMSP ]
                                    }
               };

        #endregion

        #region (private static) WithoutWarnings(JSON)

        /// <summary>
        /// A connection as JSON without what its store worked out about it: what
        /// is read back of it has none.
        /// </summary>
        private static Newtonsoft.Json.Linq.JObject WithoutWarnings(Newtonsoft.Json.Linq.JObject JSON)
        {
            var json = (Newtonsoft.Json.Linq.JObject) JSON.DeepClone();
            json.Remove("warnings");
            return json;
        }

        #endregion


        #region TheTypes_EMSPAndCPO_AreRead_AndCarryOCPI(Text, Type)

        /// <summary>
        /// "emsp" and "cpo" are kinds of what is at the other end, written as
        /// every kind is - and carry OCPI, where every other kind carries OCPP.
        /// </summary>
        [TestCase("emsp",             ConnectionType.EMSP,             ConnectionUse.OCPI)]
        [TestCase("EMSP",             ConnectionType.EMSP,             ConnectionUse.OCPI)]
        [TestCase(" cpo ",            ConnectionType.CPO,              ConnectionUse.OCPI)]
        [TestCase("CPO",              ConnectionType.CPO,              ConnectionUse.OCPI)]
        [TestCase("csms",             ConnectionType.CSMS,             ConnectionUse.OCPP)]
        [TestCase("chargingstation",  ConnectionType.ChargingStation,  ConnectionUse.OCPP)]
        [TestCase("gateway",          ConnectionType.Gateway,          ConnectionUse.OCPP)]
        public void TheTypes_EMSPAndCPO_AreRead_AndCarryOCPI(String          Text,
                                                             ConnectionType  Type,
                                                             ConnectionUse   Use)
        {

            Assert.That(ConnectionEntry.TryParseType(Text, out var type), Is.True);

            Assert.Multiple(() => {
                Assert.That(type,                           Is.EqualTo(Type));
                Assert.That(ConnectionEntry.UseOf(type),    Is.EqualTo(Use));
            });

        }

        #endregion

        #region AnOCPIVersion_IsReadAsOCPILabelsIt(Text, Version)

        /// <summary>
        /// An OCPI version is read as OCPI labels it, with "v" or "ocpi" in front
        /// of it as well - and nothing else is one.
        /// </summary>
        [TestCase("2.1.1",      "2.1.1")]
        [TestCase("2.2.1",      "2.2.1")]
        [TestCase(" 2.3.0 ",    "2.3.0")]
        [TestCase("v2.2.1",     "2.2.1")]
        [TestCase("ocpi2.2.1",  "2.2.1")]
        [TestCase("OCPI 2.3.0", "2.3.0")]
        [TestCase("2.2",        null)]
        [TestCase("2.0",        null)]
        [TestCase("ocpp2.1",    null)]
        [TestCase("",           null)]
        public void AnOCPIVersion_IsReadAsOCPILabelsIt(String   Text,
                                                       String?  Version)
        {

            Assert.That(ConnectionEntry.TryParseOCPIVersion(Text, out var version), Is.EqualTo(Version is not null));
            Assert.That(version,                                                    Is.EqualTo(Version));

        }

        #endregion


        #region AConnectionToAnEMSP_SaysItsOCPIVersion_AndRoundTrips()

        /// <summary>
        /// A connection to an EMSP is written down with its OCPI version: it
        /// carries OCPI, says "ocpiVersion" and no "ocppVersion" - and reads
        /// back as it was written, from the JSON and from the file.
        /// </summary>
        [Test]
        public void AConnectionToAnEMSP_SaysItsOCPIVersion_AndRoundTrips()
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The EMSP"), URL.Parse("wss://emsp.example.org:2359/csms01"), "EMSP", true, null, null,
                                               out var id, out var error,
                                               Encoding:     "cbor",
                                               OCPIVersion:  "v2.2.1"),
                        Is.True, error);

            var entry = store.Connections.Single(connection => connection.Id == id);
            var json  = entry.ToJSON();

            Assert.Multiple(() => {

                Assert.That(entry.ConnectionType,           Is.EqualTo(ConnectionType.EMSP));
                Assert.That(entry.Use,                      Is.EqualTo(ConnectionUse.OCPI));
                Assert.That(entry.OCPIVersion,              Is.EqualTo("2.2.1"));
                Assert.That(entry.Protocol,                 Is.EqualTo(ProtocolVersion.OCPI("2.2.1")));
                Assert.That(entry.Protocol.ToString(),      Is.EqualTo("OCPI 2.2.1"));

                Assert.That(json.Value<String>("connectionType"),             Is.EqualTo("EMSP"));
                Assert.That(json.Value<String>(ConnectionEntry.OCPIVersionKey), Is.EqualTo("2.2.1"));
                Assert.That(json.ContainsKey("ocppVersion"),                  Is.False, "A connection of OCPI says no OCPP version.");

            });

            Assert.That(ConnectionEntry.TryParse(json, out var parsed, out error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(parsed!.ConnectionType,  Is.EqualTo(ConnectionType.EMSP));
                Assert.That(parsed.OCPIVersion,      Is.EqualTo("2.2.1"));
                Assert.That(parsed.Encoding,         Is.EqualTo(entry.Encoding));
                Assert.That(parsed.ToJSON().ToString(), Is.EqualTo(WithoutWarnings(json).ToString()));
            });

            var again = AStore().Connections.Single(connection => connection.Id == id);

            Assert.That(again.OCPIVersion, Is.EqualTo("2.2.1"), "The OCPI version was not read back from the file.");

        }

        #endregion

        #region AConnectionOfOCPP_SaysNoOCPIVersion()

        /// <summary>
        /// A connection of OCPP says its OCPP version, as it always did, and no
        /// OCPI version - and one that is given one is refused.
        /// </summary>
        [Test]
        public void AConnectionOfOCPP_SaysNoOCPIVersion()
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The CSMS"), URL.Parse("ws://csms.example.org/cs01"), "CSMS", true, null, null,
                                               out var id, out var error),
                        Is.True, error);

            var json = store.Connections.Single(connection => connection.Id == id).ToJSON();

            Assert.Multiple(() => {
                Assert.That(json.Value<String>("ocppVersion"),                  Is.EqualTo("OCPP2.1"));
                Assert.That(json.ContainsKey(ConnectionEntry.OCPIVersionKey),   Is.False);
            });

            Assert.That(store.TryAddConnection(I18NString.Create("The CSMS again"), URL.Parse("ws://csms.example.org/cs02"), "CSMS", true, null, null,
                                               out _, out error,
                                               OCPIVersion: "2.2.1"),
                        Is.False);

            Assert.That(error, Does.Contain("OCPP"));

        }

        #endregion

        #region AConnectionOfOCPI_WithoutAVersion_OrWithAWrongOne_IsRefused(Version)

        /// <summary>
        /// A connection to an EMSP says which OCPI it carries, and one OCPI has.
        /// </summary>
        [TestCase(null)]
        [TestCase("")]
        [TestCase("2.2")]
        [TestCase("3.0.0")]
        public void AConnectionOfOCPI_WithoutAVersion_OrWithAWrongOne_IsRefused(String? Version)
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The EMSP"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                               out _, out var error,
                                               OCPIVersion: Version),
                        Is.False);

            Assert.That(error, Does.Contain("2.2.1"));

        }

        #endregion

        #region AConnectionOfOCPI_NamesNoNodeAtItsOtherEnd()

        /// <summary>
        /// Nothing is reached through a connection of OCPI: it names no node at
        /// its other end.
        /// </summary>
        [Test]
        public void AConnectionOfOCPI_NamesNoNodeAtItsOtherEnd()
        {

            Assert.That(AStore().TryAddConnection(I18NString.Create("The EMSP"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                                  out _, out var error,
                                                  RemoteNodeId:  "emsp01",
                                                  OCPIVersion:   "2.2.1"),
                        Is.False);

            Assert.That(error, Does.Contain("OCPI"));

        }

        #endregion

        #region AnEMSP_IsNoKindOfNode_OfEveryNode()

        /// <summary>
        /// An EMSP is no kind of node of the network of OCPP: a node that does
        /// not name it among what its connections lead to does not write one down.
        /// </summary>
        [Test]
        public void AnEMSP_IsNoKindOfNode_OfEveryNode()
        {

            Assert.That(AStore(new ConnectionRules()).TryAddConnection(I18NString.Create("The EMSP"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                                                       out _, out var error,
                                                                       OCPIVersion: "2.2.1"),
                        Is.False);

            Assert.That(error, Does.Contain("EMSP"));

        }

        #endregion

        #region ANodeThatOnlyLetsIn_WritesDownWhatConnects_AndNothingElse()

        /// <summary>
        /// A node that only lets the other end connect - an EMSP - writes down a
        /// CPO that connects to it, and refuses a connection it would make itself.
        /// </summary>
        [Test]
        public void ANodeThatOnlyLetsIn_WritesDownWhatConnects_AndNothingElse()
        {

            var store = AStore(new ConnectionRules {
                                   Types     = [ ConnectionType.CPO ],
                                   Outbound  = false
                               });

            Assert.That(store.TryAddConnection(I18NString.Create("A CPO, connecting"), URL.Parse("ws://127.0.0.1:2359/csms01"), "CPO", true, null, null,
                                               out var inbound, out var error,
                                               Inbound:      true,
                                               OCPIVersion:  "2.3.0"),
                        Is.True, error);

            Assert.That(store.Connections.Single(connection => connection.Id == inbound).Protocol, Is.EqualTo(ProtocolVersion.OCPI("2.3.0")));

            Assert.That(store.TryAddConnection(I18NString.Create("A CPO, connected to"), URL.Parse("ws://cpo.example.org/emsp01"), "CPO", true, null, null,
                                               out _, out error,
                                               OCPIVersion: "2.3.0"),
                        Is.False);

            Assert.That(error, Does.Contain("connects to nothing"));

        }

        #endregion

        #region TwoCPOs_OfOneName_AreTwo_WhereTheirVersionsDiffer()

        /// <summary>
        /// The name a connection the other end makes comes under is its own among
        /// the connections of its protocol and version: one of OCPI 2.2.1 and one
        /// of OCPI 2.3.0 may come under one name, as they come to two servers.
        /// </summary>
        [Test]
        public void TwoCPOs_OfOneName_AreTwo_WhereTheirVersionsDiffer()
        {

            var store = AStore(new ConnectionRules { Types = [ ConnectionType.CPO ] });

            Assert.That(store.TryAddConnection(I18NString.Create("2.2.1"), URL.Parse("ws://127.0.0.1:2359/csms01"), "CPO", true, null, null,
                                               out _, out var error, Inbound: true, OCPIVersion: "2.2.1"),
                        Is.True, error);

            Assert.That(store.TryAddConnection(I18NString.Create("2.3.0"), URL.Parse("ws://127.0.0.1:2359/csms01"), "CPO", true, null, null,
                                               out _, out error, Inbound: true, OCPIVersion: "2.3.0"),
                        Is.True, error);

            Assert.That(store.TryAddConnection(I18NString.Create("2.2.1 again"), URL.Parse("ws://127.0.0.1:2359/csms01"), "CPO", true, null, null,
                                               out _, out error, Inbound: true, OCPIVersion: "2.2.1"),
                        Is.False);

            Assert.That(error, Does.Contain("in OCPI 2.2.1"));

        }

        #endregion

        #region AConnectionOfOCPI_IsInChargeOfNothing()

        /// <summary>
        /// The peer of a connection of OCPI that connects by itself is an
        /// observer, and not the primary: it leads to no back end in charge of
        /// anything - and a connection of OCPP written down after it is the primary.
        /// </summary>
        [Test]
        public void AConnectionOfOCPI_IsInChargeOfNothing()
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The EMSP"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                               out var emsp, out var error, OCPIVersion: "2.2.1"),
                        Is.True, error);

            Assert.That(store.TryAddConnection(I18NString.Create("The CSMS"), URL.Parse("ws://csms.example.org/cs01"), "CSMS", true, null, null,
                                               out var csms, out error),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(store.PeerOf(emsp!)!.Role,  Is.EqualTo(PeerRole.Observer));
                Assert.That(store.PeerOf(csms!)!.Role,  Is.EqualTo(PeerRole.Primary));
            });

        }

        #endregion

        #region AChangeKeepsTheOCPIVersion_WhereItSaysNone()

        /// <summary>
        /// A change of a connection of OCPI that says no OCPI version keeps the
        /// one it has; one that says another changes it.
        /// </summary>
        [Test]
        public void AChangeKeepsTheOCPIVersion_WhereItSaysNone()
        {

            var store = AStore();

            Assert.That(store.TryAddConnection(I18NString.Create("The EMSP"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                               out var id, out var error, OCPIVersion: "2.1.1"),
                        Is.True, error);

            Assert.That(store.TryUpdateConnection(id, I18NString.Create("The EMSP, renamed"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                                  out error),
                        Is.True, error);

            Assert.That(store.Connections.Single(connection => connection.Id == id).OCPIVersion, Is.EqualTo("2.1.1"));

            Assert.That(store.TryUpdateConnection(id, I18NString.Create("The EMSP, renamed"), URL.Parse("ws://emsp.example.org/csms01"), "EMSP", true, null, null,
                                                  out error, OCPIVersion: "2.3.0"),
                        Is.True, error);

            Assert.That(store.Connections.Single(connection => connection.Id == id).OCPIVersion, Is.EqualTo("2.3.0"));

        }

        #endregion

    }

}
