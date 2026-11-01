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

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The id of a time server: what names it across every group, whatever its
    /// host name becomes - given by the file, or by the server's place in its
    /// list until somebody writes it down - and never the id of two servers.
    /// </summary>
    /// <remarks>
    /// To a CSMS it is the instance of the server's NTPClientController, which
    /// it asks for without saying which group it means.
    /// </remarks>
    public class NTSServerIdTests
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

            directory = Path.Combine(Path.GetTempPath(), "node-nts-ids-" + Guid.NewGuid().ToString("N")[..12]);

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


        #region (helper) Node(Configuration)

        private WWCPNode Node(String Configuration)
        {

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

        #region (helper) Group(JSON, Id = "local")

        private static NTSConfiguration Group(String  JSON,
                                              String  Id = "local")
        {

            Assert.That(NTSConfiguration.TryParse(JObject.Parse(JSON), out var group, out var error, NTSSection.PathOf(Id)),  Is.True,  error);

            return group!;

        }

        #endregion

        #region (helper) Refused(Section)

        private static String Refused(String Section)
        {

            Assert.That(NTSSection.TryParse(JObject.Parse(Section), out _, out var error),  Is.False);

            return error!;

        }

        #endregion


        #region AServerWithoutAnIdIsNamedByItsPlace()

        [Test]
        public void AServerWithoutAnIdIsNamedByItsPlace()
        {

            Assert.Multiple(() => {

                Assert.That(Group("""{ "servers": [ "a.example", "b.example" ] }""").ServerIdsIn("local"),
                            Is.EqualTo(new[] { "local-1", "local-2" }));

                Assert.That(Group("""{ "servers": [ "a.example", { "id": "local-1", "hostname": "b.example" }, "c.example" ] }""").ServerIdsIn("local"),
                            Is.EqualTo(new[] { "local-2", "local-1", "local-3" }),
                            "the next number not taken, where a server of the group has the one of its place");

                Assert.That(Group("""{ "hostname": "a.example" }""").ServerIdsIn("local"),
                            Is.EqualTo(new[] { "local-1" }),
                            "a lone hostname is a group of one");

                Assert.That(Group("""{ "maxErrors": 20 }""").ServerIdsIn("local"),
                            Is.Null,
                            "a section that says nothing about the servers keeps those there are");

            });

        }

        #endregion

        #region AnIdIsWrittenWithItsServer()

        [Test]
        public void AnIdIsWrittenWithItsServer()
        {

            var server  = new NTSServerConfiguration(DomainName.Parse("a.example"), Id: "ptb-a");
            var json    = server.ToJSON();

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out var read, out var error),  Is.True,  error);

            Assert.Multiple(() => {
                Assert.That(json.Type,                    Is.EqualTo(JTokenType.Object),  "a bare host name has no place for it");
                Assert.That(json.Value<String>("id"),     Is.EqualTo("ptb-a"));
                Assert.That(read!.Id,                     Is.EqualTo("ptb-a"));
            });

        }

        #endregion

        #region WhatCannotBeAServerIdIsRefused(Id)

        [TestCase("Legal-1")]
        [TestCase("1-legal")]
        [TestCase("legal_1")]
        [TestCase("legal 1")]
        [TestCase("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy")]
        public void WhatCannotBeAServerIdIsRefused(String Id)
        {

            var json = new JObject(new JProperty("id", Id), new JProperty("hostname", "a.example"));

            Assert.That(NTSServerConfiguration.TryParse(json, 0, out _, out var error, "nts.groups.local"),  Is.False);
            Assert.That(error,  Does.StartWith("'nts.groups.local.servers[0].id'"));

        }

        #endregion

        #region AnIdIsTheIdOfOneServer()

        [Test]
        public void AnIdIsTheIdOfOneServer()
        {

            Assert.That(NTSConfiguration.TryParse(JObject.Parse("""{ "servers": [ { "id": "x", "hostname": "a.example" }, { "id": "x", "hostname": "b.example" } ] }"""),
                                                  out _,
                                                  out var inAGroup,
                                                  "nts.groups.local"),
                        Is.False);

            Assert.Multiple(() => {

                Assert.That(inAGroup,
                            Is.EqualTo("'nts.groups.local.servers[1].id': 'x' is the id of 'nts.groups.local.servers[0]' already."));

                Assert.That(Refused("""{ "groups": { "legal": { "servers": [ { "id": "x", "hostname": "a.example" } ] }, "local": { "servers": [ { "id": "x", "hostname": "b.example" } ] } } }"""),
                            Is.EqualTo("'nts.groups.local.servers[0].id': 'x' is the id of 'nts.groups.legal.servers[0]' already: a server's id names it in every group."),
                            "across the groups as well");

                Assert.That(Refused("""{ "groups": { "legal": { }, "local": { "servers": [ { "id": "legal-2", "hostname": "b.example" } ] } } }"""),
                            Does.Contain("'legal-2' is the id of 'nts.groups.legal' already"),
                            "a legal group naming no server asks the PTB's four, legal-1 to legal-4");

                Assert.That(Refused("""{ "groups": { "legal": { "servers": [ { "id": "local-1", "hostname": "a.example" } ] }, "local": { "servers": [ "b.example" ] } } }"""),
                            Is.EqualTo("'nts.groups.local.servers[0]' has no id, and 'local-1', the one it would be given, is the id of 'nts.groups.legal.servers[0]' already: give it an id of its own."));

            });

        }

        #endregion


        #region TheNodeShowsEveryServerWithItsId()

        [Test]
        public void TheNodeShowsEveryServerWithItsId()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", { "id": "ptb-b", "hostname": "b.example" } ] } } } }""");
            var shown  = node.NTSConfigurationJSON(node.LegalTime)["timeSources"]?.Select(source => source.Value<String>("id"));

            Assert.Multiple(() => {
                Assert.That(node.LegalTime.ServerIds,  Is.EqualTo(new[] { "legal-1", "ptb-b" }));
                Assert.That(shown,                     Is.EqualTo(new[] { "legal-1", "ptb-b" }));
            });

        }

        #endregion

        #region AnIdWrittenDownAsItWasShownChangesNothing()

        /// <summary>
        /// A page sends back the ids it was shown, the given ones as well: they
        /// are in the file from then on, and nothing about the servers changed.
        /// </summary>
        [Test]
        public void AnIdWrittenDownAsItWasShownChangesNothing()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ "a.example", "b.example" ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "id": "legal-1", "hostname": "a.example" }, { "id": "legal-2", "hostname": "b.example" } ] }"""),
                                                       out var error,
                                                       out _),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(told,                                                                   Is.Empty);
                Assert.That(node.LegalTime.ServerIds,                                               Is.EqualTo(new[] { "legal-1", "legal-2" }));
                Assert.That(OnDisk["nts"]?["groups"]?["legal"]?["servers"]?.Select(server => server.Value<String>("id")),
                            Is.EqualTo(new[] { "legal-1", "legal-2" }),
                            "written down");
            });

        }

        #endregion

        #region AServerKeepsItsIdWhenAnotherGoes()

        /// <summary>
        /// Once written down, an id stays with its server: the first taken
        /// away, the second is still "legal-2" - and one added at the end is
        /// given the next number its place has free.
        /// </summary>
        [Test]
        public void AServerKeepsItsIdWhenAnotherGoes()
        {

            var node   = Node("""{ "nts": { "groups": { "legal": { "enabled": false, "servers": [ { "id": "legal-1", "hostname": "a.example" }, { "id": "legal-2", "hostname": "b.example" } ] } } } }""");
            var told   = new List<IReadOnlyList<String>>();

            node.OnNTSGroupChanged += (_, changes, _) => told.Add(changes);

            Assert.That(node.TryUpdateNTSConfiguration(node.LegalTime,
                                                       JObject.Parse("""{ "servers": [ { "id": "legal-2", "hostname": "b.example" }, "c.example" ] }"""),
                                                       out var error,
                                                       out _),
                        Is.True,
                        error);

            Assert.Multiple(() => {
                Assert.That(node.LegalTime.ServerIds,  Is.EqualTo(new[] { "legal-2", "legal-3" }));
                Assert.That(told.SingleOrDefault(),    Has.Some.EqualTo("server ids = legal-2, legal-3"),  "said with the change, as a CSMS loses a server and gains one");
            });

        }

        #endregion

    }

}
