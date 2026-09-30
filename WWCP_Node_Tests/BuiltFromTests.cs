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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a node was built from: one line per repository and none of them
    /// lost - and the kind of node's own assembly among them, whoever started
    /// the node. The kinds' copies brought their tests along: the local
    /// controller's and the hub's, and the CSMS's case of both at once.
    /// </summary>
    [TestFixture]
    public class BuiltFromTests
    {

        #region AssembliesOfOneRepositoryAreOneLine()

        /// <summary>
        /// Many assemblies out of one repository carry one commit, and are the
        /// one line the grouping exists for. Assemblies without a stamp are
        /// not ours and are left out.
        /// </summary>
        [Test]
        public void AssembliesOfOneRepositoryAreOneLine()
        {

            var lines = BuiltFrom.OnePerRepository([
                            new LoadedAssembly("WWCP_OCPPv2.1",     "1.0",  "WWCP_OCPP",  "4a8eb9e8b7ee13610a4c81f56af9a152690188d1"),
                            new LoadedAssembly("WWCP_OCPP_Common",  "1.0",  "WWCP_OCPP",  "4a8eb9e8b7ee13610a4c81f56af9a152690188d1"),
                            new LoadedAssembly("Hermod",            "1.0",  "Hermod",     "8801bcfee26a11b5ac4ac7af9486bf909b25d67c"),
                            new LoadedAssembly("Newtonsoft.Json",   "13.0", null,         null)
                        ]).ToArray();

            Assert.That(lines.Select(line => line.Repository), Is.EqualTo(new[] { "Hermod", "WWCP_OCPP" }));

        }

        #endregion

        #region TwoRepositoriesOfOneNameAreTwoLines()

        /// <summary>
        /// A repository is named after the directory it was cloned into, so a
        /// command line tool and its library can both be called
        /// "ModbusTLSEnergyMeter". Grouped by the name alone they were one
        /// line, whichever sorted first won, and the other commit was dropped
        /// without a word - in a report that exists to say which commits are
        /// running. One kind's copy still grouped that way.
        /// </summary>
        [Test]
        public void TwoRepositoriesOfOneNameAreTwoLines()
        {

            var lines = BuiltFrom.OnePerRepository([
                            new LoadedAssembly("ModbusTLSEnergyMeterCLI",  "1.0",    "ModbusTLSEnergyMeter",  "2222222222222222222222222222222222222222"),
                            new LoadedAssembly("ModbusTLSEnergyMeter",     "1.0",    "ModbusTLSEnergyMeter",  "1111111111111111111111111111111111111111"),
                            new LoadedAssembly("WWCP_ISO15118_2",          "1.0",    "WWCP_ISO15118",         "3333333333333333333333333333333333333333"),
                            new LoadedAssembly("WWCP_ISO15118_EXI",        "1.0",    "WWCP_ISO15118",         "3333333333333333333333333333333333333333"),
                            new LoadedAssembly("Newtonsoft.Json",          "13.0",   null,                    null)
                        ]).ToArray();

            Assert.That(lines.Select(line => $"{line.Repository} {line.Commit![..4]}"),
                        Is.EqualTo(new[] { "ModbusTLSEnergyMeter 1111", "ModbusTLSEnergyMeter 2222", "WWCP_ISO15118 3333" }));

        }

        #endregion

        #region TheNodesOwnAssemblyIsAmongThemWhoeverStartedIt()

        /// <summary>
        /// The kind of node's own assembly is walked from, beside the program
        /// that was started and this library: a test host starts neither the
        /// command line tool nor anything that references a kind of node, and
        /// this library references no kind either - the kind would be missing
        /// from its own report. This assembly stands in for a kind here.
        /// </summary>
        [Test]
        public void TheNodesOwnAssemblyIsAmongThemWhoeverStartedIt()
        {

            var builtFrom  = new BuiltFrom(typeof(BuiltFromTests).Assembly);
            var names      = builtFrom.Assemblies.Select(assembly => assembly.Name).ToArray();

            Assert.Multiple(() => {
                Assert.That(names, Does.Contain(typeof(BuiltFromTests).Assembly.GetName().Name), "the kind's own assembly is missing");
                Assert.That(names, Does.Contain(typeof(WWCPNode).      Assembly.GetName().Name), "the node's library is missing");
            });

        }

        #endregion

        #region TheNodesLibraryCarriesAStamp()

        /// <summary>
        /// This library says which commit it was built from - which is what says
        /// that Directory.Build.props reached it (the hub's test of its own).
        /// </summary>
        [Test]
        public void TheNodesLibraryCarriesAStamp()
        {

            var library = new BuiltFrom(typeof(WWCPNode).Assembly).
                              Assemblies.
                              Single(assembly => assembly.Name == typeof(WWCPNode).Assembly.GetName().Name);

            // Not by the repository's name, which is the directory it was
            // cloned into, and not this test's to decide.
            Assert.That(library.IsStamped, Is.True, "WWCP_Node carries no GitCommit: Directory.Build.props did not reach it");

        }

        #endregion

        #region ALineOfANameOfItsOwnNamesNoAssembly()

        /// <summary>
        /// A repository whose name no other line of the configuration has is
        /// said by that name alone, as the banner says it. The assembly beside
        /// it was the first one the node had found of the repository - "SDP"
        /// for all of ISO 15118's dozens - and said nothing of it (found by the
        /// vehicle).
        /// </summary>
        [Test]
        public async Task ALineOfANameOfItsOwnNamesNoAssembly()
        {

            var directory = TestNodes.TemporaryDirectory("built-from");

            try
            {

                await using var node = TestNodes.New(directory, TestNodes.Offline);

                var lines  = (node.ConfigurationJSON()["assemblies"] as JArray)?.OfType<JObject>().ToArray() ?? [];
                var names  = lines.Select(line => line.Value<String>("name")).ToArray();

                Assert.Multiple(() => {
                    Assert.That(lines, Is.Not.Empty, "the lines of the configuration");
                    Assert.That(lines.Where (line => names.Count(name => name == line.Value<String>("name")) == 1 &&
                                                     line.ContainsKey("assembly")).
                                      Select(line => line.Value<String>("name")),
                                Is.Empty,
                                "repositories of a name of their own, said with an assembly");
                });

            }
            finally
            {
                TestNodes.Remove(directory);
            }

        }

        #endregion

        #region TwoRepositoriesOfOneNameAreToldApartByTheirAssemblies()

        /// <summary>
        /// Where two repositories share a directory's name - the energy meter's
        /// tool and its library - the configuration names the assembly of each,
        /// as the banner does, and the others go by their names alone.
        /// </summary>
        [Test]
        public void TwoRepositoriesOfOneNameAreToldApartByTheirAssemblies()
        {

            var lines = BuiltFrom.ConfigurationLinesOf([
                            new LoadedAssembly("Hermod",                   "1.0", "Hermod",                "1111111111111111111111111111111111111111"),
                            new LoadedAssembly("ModbusTLSEnergyMeter",     "1.0", "ModbusTLSEnergyMeter",  "2222222222222222222222222222222222222222"),
                            new LoadedAssembly("ModbusTLSEnergyMeterCLI",  "1.0", "ModbusTLSEnergyMeter",  "3333333333333333333333333333333333333333")
                        ]).OfType<JObject>().Select(line => line.ToString(Formatting.None));

            Assert.That(lines, Is.EqualTo(new[] {
                """{"name":"Hermod","version":"1.0","commit":"1111111111111111111111111111111111111111"}""",
                """{"name":"ModbusTLSEnergyMeter","assembly":"ModbusTLSEnergyMeter","version":"1.0","commit":"2222222222222222222222222222222222222222"}""",
                """{"name":"ModbusTLSEnergyMeter","assembly":"ModbusTLSEnergyMeterCLI","version":"1.0","commit":"3333333333333333333333333333333333333333"}"""
            }));

        }

        #endregion

    }

}
