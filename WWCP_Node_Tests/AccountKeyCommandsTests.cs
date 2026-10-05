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
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// sshKeys and apiKeys at the node's console, which may manage the keys of
    /// every account: a key let in signs in, one taken out does not, a line
    /// that cannot be held to is refused with why, and an API key is shown
    /// whole once, when it is made, and by its beginning ever after.
    /// </summary>
    [TestFixture]
    public class AccountKeyCommandsTests
    {

        #region Data

        private String           directory  = default!;
        private WWCPNode         node       = default!;
        private NodeCLI          cli        = default!;
        private readonly List<String> said  = [];

        private static readonly User_Id Root = User_Id.Parse(WWCPNode.DefaultAdminUser);

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public async Task MakeTheNode()
        {

            directory = Path.Combine(Path.GetTempPath(), $"node-keys-{Guid.NewGuid().ToString("N")[..12]}");
            Directory.CreateDirectory(directory);

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            node = new WWCPNode(
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

            node.Log.OnLogged += entry => { lock (said) said.Add(entry.Message); };

            await node.Start();

            cli = new NodeCLI(node);

        }

        [TearDown]
        public async Task LetTheNodeGo()
        {

            cli.Dispose();

            await node.DisposeAsync();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            { }

        }

        #endregion


        #region TheConsoleLetsAKeyInListsItAndTakesItOut

        [Test]
        public async Task TheConsoleLetsAKeyInListsItAndTakesItOut()
        {

            var key          = SshHostKey.GenerateEd25519();
            var fingerprint  = SshFingerprint.Sha256(key.PublicKeyBlob);

            var added    = await cli.Execute($"sshKeys root add {KeyLine(key)}");

            Assert.Multiple(() => {
                Assert.That(added,  Is.EqualTo(new[] { $"'root' signs in with the key {fingerprint} now." }));
                Assert.That(node.ExtAPI.FindSSHKey(Root, key.PublicKeyBlob, DateTimeOffset.UtcNow), Is.Not.Null, "not let in");
                Assert.That(node.ExtAPI.GetSSHKeys(Root).Single().CreatedBy,                      Is.EqualTo("the console"));
                lock (said)
                    Assert.That(said, Has.Some.EqualTo($"Somebody at the command line let 'root' in over SSH with the key {fingerprint}."));
            });

            var listed   = await cli.Execute("sshKeys root");

            Assert.That(listed, Has.Length.EqualTo(1).And.Some.StartsWith(fingerprint).And.Some.Contains("by the console").And.Some.Contains("tester"));

            // By enough of its beginning, as somebody would type it.
            var removed  = await cli.Execute($"sshKeys root remove {fingerprint["SHA256:".Length..][..10]}");

            Assert.Multiple(() => {
                Assert.That(removed, Is.EqualTo(new[] { $"The key {fingerprint} lets 'root' in no more." }));
                Assert.That(node.ExtAPI.FindSSHKey(Root, key.PublicKeyBlob, DateTimeOffset.UtcNow), Is.Null, "still let in");
                lock (said)
                    Assert.That(said, Has.Some.EqualTo($"Somebody at the command line took the key {fingerprint} from 'root': it lets nobody in from now on."));
            });

        }

        #endregion

        #region AKeysOptionsComeThroughTheCommandLineWhole

        /// <summary>
        /// from="..." in front of a key is one word with its quotes on the
        /// command line, and the line is kept as it was typed.
        /// </summary>
        [Test]
        public async Task AKeysOptionsComeThroughTheCommandLineWhole()
        {

            var key   = SshHostKey.GenerateEd25519();
            var line  = $"from=\"192.0.2.0/24\",no-pty {KeyLine(key)}";

            await cli.Execute($"sshKeys root add {line}");

            var kept  = node.ExtAPI.GetSSHKeys(Root).Single();

            Assert.Multiple(() => {
                Assert.That(kept.Line,                                 Is.EqualTo(line));
                Assert.That(kept.Key.Restrictions.SourceAddresses,     Is.Not.Null.And.Not.Empty);
                Assert.That(kept.Key.Restrictions.AllowPty,            Is.False);
            });

        }

        #endregion

        #region WhatCannotBeLetInSaysWhy

        [Test]
        public async Task WhatCannotBeLetInSaysWhy()
        {

            var key = SshHostKey.GenerateEd25519();

            var unenforceable  = await cli.Execute($"sshKeys root add permitopen=\"10.0.0.1:80\" {KeyLine(key)}");
            var noAccount      = await cli.Execute($"sshKeys nobody add {KeyLine(key)}");
            var noName         = await cli.Execute($"sshKeys add {KeyLine(key)}");
            var noKey          = await cli.Execute("sshKeys root remove AAAA");
            var none           = await cli.Execute("sshKeys");

            Assert.Multiple(() => {
                Assert.That(unenforceable,  Has.Length.EqualTo(1));
                Assert.That(unenforceable,  Has.Some.StartsWith("The key was not let in:").And.Some.Contains("'permitopen' cannot be held to"));
                Assert.That(noAccount,      Is.EqualTo(new[] { "'nobody' is no account of this WWCP node." }));
                Assert.That(noName,         Has.Some.StartsWith("At the console, name the account"));
                Assert.That(noKey,          Is.EqualTo(new[] { "'root' has no key AAAA." }));
                Assert.That(none,           Is.EqualTo(new[] { "No account of this WWCP node has an SSH key." }));
            });

            Assert.That(node.ExtAPI.GetSSHKeys(Root), Is.Empty);

        }

        #endregion


        #region AnAPIKeyIsShownWholeOnceAndByItsBeginningAfter

        [Test]
        public async Task AnAPIKeyIsShownWholeOnceAndByItsBeginningAfter()
        {

            var made    = await cli.Execute("apiKeys root add readWrite for the dashboard");

            Assert.That(made, Has.Length.EqualTo(2), String.Join("\n", made));

            var secret  = made[1];

            Assert.Multiple(() => {
                Assert.That(made[0],  Is.EqualTo("'root' has a new API key, ReadWrite. It is shown here once, and never again:"));
                Assert.That(secret,   Has.Length.EqualTo(APIKeysCommand.KeyLength).And.Match("^[A-Za-z0-9]+$"));
                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(secret), out var apiKey), Is.True, "the key shown is not the key made");
                Assert.That(apiKey!.AccessRights,                Is.EqualTo(APIKeyRights.ReadWrite));
                Assert.That(apiKey.Description.FirstText(),      Is.EqualTo("for the dashboard"));
                Assert.That(apiKey.UserId,                       Is.EqualTo(Root));
            });

            var listed  = await cli.Execute("apiKeys root");

            Assert.Multiple(() => {
                Assert.That(listed,                     Has.Length.EqualTo(1));
                Assert.That(listed[0],                  Does.StartWith(secret[..APIKeysCommand.Shown] + "..."));
                Assert.That(listed[0],                  Does.Not.Contain(secret), "a list shows the whole key");
                Assert.That(listed[0],                  Does.Contain("for the dashboard"));
                lock (said)
                    Assert.That(said,                   Has.None.Contains(secret), "the whole key is in the log");
            });

            var removed = await cli.Execute($"apiKeys root remove {secret[..APIKeysCommand.Shown]}");

            Assert.Multiple(() => {
                Assert.That(removed[0],                                                  Does.Contain("signs 'root' in no more"));
                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(secret), out _),   Is.False, "still there");
            });

        }

        #endregion

        #region AnAPIKeyIsReadOnlyUnlessItIsSaidOtherwise

        [Test]
        public async Task AnAPIKeyIsReadOnlyUnlessItIsSaidOtherwise()
        {

            var made = await cli.Execute("apiKeys root add");

            Assert.Multiple(() => {
                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(made[1]), out var apiKey), Is.True);
                Assert.That(apiKey!.AccessRights, Is.EqualTo(APIKeyRights.ReadOnly));
            });

        }

        #endregion


        private static String KeyLine(ISshHostKey Key)
            => SshPublicKey.FromHostKey(Key, "tester").ToAuthorizedKeyLine();

    }

}
