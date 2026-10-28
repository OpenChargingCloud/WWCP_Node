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

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using static cloud.charging.open.protocols.WWCP.Node.TestKit.OwnerOnlyChecks;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a node keeps of its accounts, its logs, its certificates and its
    /// SSH host key is for the account it runs under and nobody else - on
    /// Windows as well, where a folder at the root of a drive hands read
    /// access to every authenticated user down to everything below it.
    /// </summary>
    public class OwnerOnlyTests
    {

        #region Data

        private String directory = default!;

        private readonly List<WWCPNode> nodes = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-owner-only-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var node in nodes)
            {
                try
                {
                    await node.DisposeAsync();
                }
                catch (Exception)
                { }
            }

            nodes.Clear();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion

        #region ADirectoryIsItsOwnersAlone()

        [Test]
        public void ADirectoryIsItsOwnersAlone()
        {

            var path = Path.Combine(directory, "made");

            OwnerOnly.Directory(path, problem => Assert.Fail(problem));

            Assert.Multiple(() => {
                Assert.That(Directory.Exists(path), Is.True);
                Assert.That(OthersMayGetIn(path),   Is.Empty);
            });

        }

        #endregion

        #region WhatAnOlderVersionLeftOpenIsTakenBack()

        /// <summary>
        /// A directory that was there before, open to everybody, with a file
        /// in it that was written then: both are its owner's alone afterwards
        /// - the file on Windows by what it inherits from the directory.
        /// </summary>
        [Test]
        public void WhatAnOlderVersionLeftOpenIsTakenBack()
        {

            var path = Path.Combine(directory, "older");
            var file = Path.Combine(path, "secret.json");

            OpenToEverybody(path);
            File.WriteAllText(file, "{}");

            Assume.That(OthersMayGetIn(path), Is.Not.Empty);

            OwnerOnly.Directory(path, problem => Assert.Fail(problem));

            Assert.Multiple(() => {
                Assert.That(OthersMayGetIn(path), Is.Empty);
                if (OperatingSystem.IsWindows())
                    Assert.That(OthersMayGetIn(file), Is.Empty);
                Assert.That(File.ReadAllText(file), Is.EqualTo("{}"), "and still readable by its owner");
            });

        }

        #endregion

        #region AFileIsItsOwnersAlone()

        [Test]
        public void AFileIsItsOwnersAlone()
        {

            var path = Path.Combine(directory, "open");
            var file = Path.Combine(path, "key.pem");

            OpenToEverybody(path);
            File.WriteAllText(file, "key");

            OwnerOnly.File(file, problem => Assert.Fail(problem));

            Assert.Multiple(() => {
                Assert.That(OthersMayGetIn(file),   Is.Empty);
                Assert.That(File.ReadAllText(file), Is.EqualTo("key"));
            });

        }

        #endregion

        #region WhatCannotBeRestrictedIsSaidAndNotThrown()

        [Test]
        public void WhatCannotBeRestrictedIsSaidAndNotThrown()
        {

            var said = new List<String>();

            OwnerOnly.File(Path.Combine(directory, "not-there"), said.Add);

            Assert.That(said, Has.Count.EqualTo(1));
            Assert.That(said[0], Does.Contain("could not be made readable by its owner alone"));

        }

        #endregion

        #region ANodeKeepsWhatItKeepsToItself()

        /// <summary>
        /// The accounts, the log files and the signed log, the certificates and
        /// the SSH host key: each directory its owner's alone after a start -
        /// and the accounts as well where an older version left them open.
        /// </summary>
        [Test]
        public async Task ANodeKeepsWhatItKeepsToItself()
        {

            File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName),
                              """{ "nts": { "groups": { "legal": { "enabled": false } } } }""");

            var accounts = Path.Combine(directory, "accounts");

            OpenToEverybody(accounts);

            var node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                    AccountsPath:      accounts,
                                    ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                    CertificatesPath:  Path.Combine(directory, "certificates"),
                                    LogPath:           Path.Combine(directory, "logs"),
                                    LogToConsole:      false,
                                    BridgeDebugLog:    false,
                                    Log:               null,
                                    SSH:               new SSHSettings(Enabled: true, Port: IPPort.Parse(TestPorts.Free())));

            nodes.Add(node);

            await node.Start();

            var directories = new[] {
                                  accounts,
                                  Path.Combine(directory, "logs"),
                                  Path.Combine(directory, "logs", WWCPNode.DefaultMetrologicalLogDirectory),
                                  Path.Combine(directory, "certificates"),
                                  Path.GetDirectoryName(node.SSHHostKeyPath)!
                              };

            Assert.Multiple(() => {
                foreach (var path in directories)
                {
                    Assert.That(Directory.Exists(path),  Is.True,  path);
                    Assert.That(OthersMayGetIn(path),    Is.Empty, path);
                }
                Assert.That(node.Log.Recent(500).Where(entry => entry.Message.Contains("could not be made readable")), Is.Empty);
            });

        }

        #endregion

    }

}
