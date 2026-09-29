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

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// A node whose port somebody else took before it could bind it is made
    /// again on fresh ports and started again - with its first start still a
    /// first start - and is given up on only when that happens every time.
    /// </summary>
    /// <remarks>
    /// Somebody else is another node here, started on the port a node is about
    /// to be handed: the way another test run on the same machine takes it,
    /// and so on whatever address a node binds.
    /// </remarks>
    [TestFixture]
    public class StartedOnFreshPortsTests
    {

        #region Data

        private String                  directory  = default!;
        private readonly List<WWCPNode> squatters  = [];

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeTheDirectory()
        {
            directory = Path.Combine(Path.GetTempPath(), $"fresh-ports-{Guid.NewGuid().ToString("N")[..12]}");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task StopEverything()
        {

            foreach (var squatter in squatters)
                await squatter.DisposeAsync();

            squatters.Clear();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // A file a node let go of a moment too late; the temporary
                // directory is the system's to clear.
            }

        }

        #endregion


        #region ANodeWhosePortWasTakenIsStartedAgainOnAFreshOne()

        /// <summary>
        /// Made again on a fresh port, started - and its start a first start,
        /// with a password made up: the accounts the failed start made before
        /// it came to its port went with it.
        /// </summary>
        [Test]
        public async Task ANodeWhosePortWasTakenIsStartedAgainOnAFreshOne()
        {

            var taken = TestPorts.Free();

            await Squat(taken);

            var made = 0;

            await using var node = await TestPorts.StartedOnFreshPorts(() => NodeOn(made++ == 0 ? taken : TestPorts.Free(), "node"));

            Assert.Multiple(() => {
                Assert.That(made,                    Is.EqualTo(2),                "the node was not made again");
                Assert.That(node.HTTPPort,           Is.Not.EqualTo(IPPort.Parse(taken)));
                Assert.That(node.GeneratedPassword,  Is.Not.Null,
                            "the second start was no first start: the accounts of the one that failed were left behind");
            });

        }

        #endregion

        #region ANodeWhosePortsStayTakenIsGivenUpOn()

        /// <summary>
        /// Taken at every attempt, the port is taken for good, and said to be:
        /// the start ends in what the last one ended in.
        /// </summary>
        [Test]
        public async Task ANodeWhosePortsStayTakenIsGivenUpOn()
        {

            var taken = new List<UInt16>();

            for (var attempt = 0; attempt < TestPorts.StartAttempts; attempt++)
            {
                taken.Add(TestPorts.Free());
                await Squat(taken[^1]);
            }

            var made = 0;

            Assert.That(async () => await TestPorts.StartedOnFreshPorts(() => NodeOn(taken[made++], $"node{made}")),
                        Throws.TypeOf<PortUnavailableException>());

            Assert.That(made, Is.EqualTo(TestPorts.StartAttempts));

        }

        #endregion

        #region AccountsThatWereThereBeforeAFailedStartStay()

        /// <summary>
        /// Accounts a start found rather than made are not its to take away.
        /// </summary>
        [Test]
        public async Task AccountsThatWereThereBeforeAFailedStartStay()
        {

            await using (var before = NodeOn(TestPorts.Free(), "node"))
            {
                await before.Start();
            }

            var taken = TestPorts.Free();

            await Squat(taken);

            var made = 0;

            await using var node = await TestPorts.StartedOnFreshPorts(() => NodeOn(made++ == 0 ? taken : TestPorts.Free(), "node"));

            Assert.That(node.GeneratedPassword, Is.Null,
                        "the accounts that were there before were taken away with the start that failed");

        }

        #endregion


        #region (private) NodeOn(Port, Name)

        /// <summary>
        /// A node of no particular kind on the given port, keeping what it keeps
        /// in a directory of that name below this test's.
        /// </summary>
        private WWCPNode NodeOn(UInt16  Port,
                                String  Name)
        {

            var here           = Path.Combine(directory, Name);
            var configuration  = Path.Combine(here, WWCPConfigFile.DefaultFileName);

            Directory.CreateDirectory(here);
            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            return new WWCPNode(
                       HTTPPort:          IPPort.Parse(Port),
                       AccountsPath:      Path.Combine(here, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(here, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (private) Squat(Port)

        /// <summary>
        /// Another node on the port, started: the way another test run takes a
        /// port in the gap between its being handed out and its being bound.
        /// </summary>
        private async Task Squat(UInt16 Port)
        {

            var squatter = NodeOn(Port, $"squatter{squatters.Count}");

            await squatter.Start();

            squatters.Add(squatter);

        }

        #endregion

    }

}
