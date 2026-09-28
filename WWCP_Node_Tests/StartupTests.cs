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

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a node does with the configuration file it is handed and the
    /// accounts it finds, and what it refuses to do.
    /// </summary>
    /// <remarks>
    /// The configuration is read in the constructor, so those tests only build
    /// a node. The accounts are made by <c>Start()</c>, because creating one
    /// is asynchronous - so the tests about them start the node, and pay for a
    /// socket to do it.
    /// </remarks>
    public class StartupTests
    {

        #region Data

        private String directory = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
        {
            directory = TestNodes.TemporaryDirectory("startup");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
            => TestNodes.Remove(directory);

        #endregion


        #region AFirstStartMakesUpAnAccountAndKeepsOnlyItsHash()

        /// <summary>
        /// Nobody can sign in to a web interface with no accounts in it, and
        /// an unauthenticated setup page would be a door of its own. So the
        /// password is made up, handed back once, and kept only as a hash.
        /// </summary>
        [Test]
        public async Task AFirstStartMakesUpAnAccountAndKeepsOnlyItsHash()
        {

            await using var node = TestNodes.New(directory, TestNodes.Offline);

            await node.Start();

            Assert.Multiple(() => {

                Assert.That(node.GeneratedPassword,      Is.Not.Null.And.Not.Empty);
                Assert.That(node.ExtAPI.Users.Count(),   Is.EqualTo(1));
                Assert.That(node.ExtAPI.Users.First().Id.ToString(),
                                                         Is.EqualTo(WWCPNode.DefaultAdminUser));

                // The password is nowhere below the accounts directory, in any
                // of the files the HTTPExt API writes - only the hash of it.
                var written = String.Join(
                                  "\n",
                                  Directory.GetFiles(node.AccountsPath, "*", SearchOption.AllDirectories).
                                            Select(File.ReadAllText)
                              );

                Assert.That(written, Does.Not.Contain(node.GeneratedPassword!),
                            "The password this node made up was written to disk in the clear.");
                Assert.That(written, Does.Contain("$pbkdf2"));

            });

        }

        #endregion

        #region ASecondStartUsesTheAccountsItFindsAndMakesUpNothing()

        [Test]
        public async Task ASecondStartUsesTheAccountsItFindsAndMakesUpNothing()
        {

            String firstPassword;

            await using (var first = TestNodes.New(directory, TestNodes.Offline))
            {
                await first.Start();
                firstPassword = first.GeneratedPassword!;
            }

            await using var second = TestNodes.New(directory, TestNodes.Offline);

            await second.Start();

            Assert.Multiple(() => {
                Assert.That(second.GeneratedPassword,    Is.Null,
                            "A node that found accounts made up another password anyway.");
                Assert.That(second.ExtAPI.Users.Count(), Is.EqualTo(1),
                            "A second account was made beside the one the first start wrote.");
            });

            // That the first password still opens it is asked over the wire, of
            // every kind of node, by NodeConformanceTests.TheAccountSurvivesARestart;
            // here what is asked is only that nothing was made up a second time.
            Assert.That(firstPassword, Is.Not.Null.And.Not.Empty);

        }

        #endregion

        #region AnUnreadableConfigurationStopsTheNode()

        /// <summary>
        /// Somebody wrote down what their node is and got it wrong. Quietly
        /// running as something else would be worse than stopping.
        /// </summary>
        [Test]
        public void AnUnreadableConfigurationStopsTheNode()
        {

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), "{ dns: [ unquoted");

            // Configuration: null, so that the broken file written above is
            // left exactly as it is.
            var problem = Assert.Throws<InvalidOperationException>(
                              () => TestNodes.New(directory)
                          );

            Assert.That(problem!.Message, Does.Contain(WWCPConfigFile.DefaultFileName));

        }

        #endregion

        #region ANodeWithNoFilesRunsOnItsDefaults()

        [Test]
        public async Task ANodeWithNoFilesRunsOnItsDefaults()
        {

            await using var node = TestNodes.New(directory);

            Assert.Multiple(() => {
                Assert.That(node.DNSEnabled,  Is.True);
                Assert.That(node.NTSEnabled,  Is.True);
                Assert.That(node.Version,     Is.Not.Empty);
                Assert.That(node.CreatedAt,   Is.Not.EqualTo(default(DateTimeOffset)));
            });

        }

        #endregion

        #region TheClockIsSetBeforeAnythingAsksTheTime()

        /// <summary>
        /// The event log stamps its entries with the node's clock, and it is
        /// built inside the constructor - so a node handed a clock has to be
        /// using it from its very first line, or the log reads the system one
        /// and cannot be held against anything.
        /// </summary>
        [Test]
        public async Task TheClockIsSetBeforeAnythingAsksTheTime()
        {

            var clock = TestClock.At(2000, 1, 1);

            await using var node = TestNodes.New(directory, TestNodes.Offline, clock);

            Assert.Multiple(() => {

                Assert.That(node.CreatedAt,     Is.EqualTo(clock.Now));
                Assert.That(node.TimeProvider,  Is.SameAs(clock));

                // Everything the node said while it was being built.
                Assert.That(node.Log.Count, Is.GreaterThan(0),
                            "A node that said nothing while starting up cannot show this.");

                Assert.That(node.Log.Recent(100).Select(entry => entry.Timestamp),
                            Is.All.EqualTo(clock.Now),
                            "Something was logged against a clock other than the node's own.");

            });

        }

        #endregion

        #region ASwitchedOffTimeClientSchedulesNothing()

        /// <summary>
        /// The whole reason the fixtures write that section: switched off, no
        /// timer is put on the network at all.
        /// </summary>
        [Test]
        public async Task ASwitchedOffTimeClientSchedulesNothing()
        {

            await using var node = TestNodes.New(directory, TestNodes.Offline);

            await node.Start();

            Assert.Multiple(() => {

                Assert.That(node.NTSEnabled, Is.False);

                Assert.That(node.Log.Recent(200).Any(entry => entry.Message.Contains("not being checked")),
                            Is.True,
                            "A node with its time client switched off did not say that it is not checking its clock.");

                Assert.That(node.Log.Recent(200).Any(entry => entry.Message.Contains("will be checked against")),
                            Is.False,
                            "A node with its time client switched off scheduled a check anyway.");

            });

            await node.Stop();

        }

        #endregion

    }

}
