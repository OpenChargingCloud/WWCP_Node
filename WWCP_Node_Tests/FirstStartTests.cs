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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a start does with the accounts before anybody can sign in: the
    /// password a first start makes up, what a kind of node is shown of its
    /// accounts, and a clock nobody has checked yet.
    /// </summary>
    public class FirstStartTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region (class) WatchingNode

        /// <summary>
        /// A node that writes down what it saw of its accounts, and when.
        /// </summary>
        private sealed class WatchingNode(String  Directory,
                                          IPPort  Port)

            : WWCPNode(HTTPPort:          Port,
                       AccountsPath:      Path.Combine(Directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(Path.Combine(Directory, WWCPConfigFile.DefaultFileName)),
                       CertificatesPath:  Path.Combine(Directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false)

        {

            public List<(Boolean Listening, Boolean RootIsThere, String[] Groups)>  Seen  { get; } = [];

            protected override Task OnAccountsReady()
            {

                Seen.Add((HTTPServer.IsRunning,
                          ExtAPI.TryGetUser(User_Id.Parse(DefaultAdminUser), out _),
                          [.. ExtAPI.UserGroups.Select(group => group.Id.ToString()).Order(StringComparer.Ordinal)]));

                return Task.CompletedTask;

            }

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-first-start-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName), """{ "nts": { "enabled": false } }""");

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
            { }

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


        #region TheFirstPasswordIsMadeOfCharactersThatDoNotReadAsEachOther()

        /// <summary>
        /// The password a first start makes up is 24 characters long, none of
        /// them one that reads as another on a console - and never the same
        /// twice.
        /// </summary>
        /// <remarks>
        /// What it is drawn from is not something a test can see: a password
        /// from <c>Random.Shared</c> looks exactly like one from a
        /// cryptographic source. The source is said where it is drawn.
        /// </remarks>
        [Test]
        public async Task TheFirstPasswordIsMadeOfCharactersThatDoNotReadAsEachOther()
        {

            var passwords = new List<String>();

            for (var i = 0; i < 2; i++)
            {

                var here = Path.Combine(directory, $"node{i}");

                Directory.CreateDirectory(here);
                File.Copy(Path.Combine(directory, WWCPConfigFile.DefaultFileName), Path.Combine(here, WWCPConfigFile.DefaultFileName));

                await using var node = new WatchingNode(here, FreePort());

                await node.Start();

                passwords.Add(node.GeneratedPassword ?? "");

            }

            Assert.Multiple(() => {
                Assert.That(passwords,                       Has.All.Length.EqualTo(24));
                Assert.That(String.Concat(passwords),        Does.Not.Match("[Il0O]"),  "a character that reads as another");
                Assert.That(String.Concat(passwords),        Does.Match("^[A-Za-z1-9]+$"));
                Assert.That(passwords[0],                    Is.Not.EqualTo(passwords[1]));
            });

        }

        #endregion

        #region AKindOfNodeSeesItsAccountsBeforeThePortOpens()

        /// <summary>
        /// A kind of node is shown its accounts at every start, once they are
        /// read and the first account and the groups are made - and before the
        /// port is open.
        /// </summary>
        [Test]
        public async Task AKindOfNodeSeesItsAccountsBeforeThePortOpens()
        {

            var port = FreePort();

            await using (var node = new WatchingNode(directory, port))
            {

                await node.Start();

                Assert.Multiple(() => {
                    Assert.That(node.Seen,               Has.Count.EqualTo(1));
                    Assert.That(node.Seen[0].Listening,  Is.False,  "the port was open before the accounts were ready");
                    Assert.That(node.Seen[0].RootIsThere, Is.True,  "the first account was not made yet");
                    Assert.That(node.Seen[0].Groups,     Does.Contain(WWCPNode.AdminRole));
                });

            }

            // And again at the next start, when the accounts are read rather
            // than made.
            await using (var again = new WatchingNode(directory, FreePort()))
            {

                await again.Start();

                Assert.Multiple(() => {
                    Assert.That(again.Seen,               Has.Count.EqualTo(1));
                    Assert.That(again.Seen[0].RootIsThere, Is.True);
                    Assert.That(again.GeneratedPassword,  Is.Null,  "a second first account was made");
                });

            }

        }

        #endregion

        #region AClockNobodyCheckedIsNotSynchronised()

        /// <summary>
        /// A node that has not checked its clock does not call it synchronised.
        /// </summary>
        [Test]
        public async Task AClockNobodyCheckedIsNotSynchronised()
        {

            await using var node = new WatchingNode(directory, FreePort());

            Assert.That(node.ClockIsSynchronised,  Is.False);

        }

        #endregion

    }

}
