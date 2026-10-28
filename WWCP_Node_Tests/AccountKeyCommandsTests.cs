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

using org.GraphDefined.Vanaheimr.CLI;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// sshKeys and apiKeys at the node's console, which may manage the keys of
    /// every account: a key let in signs in, one taken out does not, a line
    /// that cannot be held to is refused with why, and an API key is shown
    /// whole - one given taken as it is - and named in the log by its
    /// beginning only.
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

            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "groups": { "legal": { "enabled": false } } } }""");

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
            Assert.That(listed, Has.None.Contains("switched off"));

            // Switched off on the account's page, it is said to be off.
            Assert.That(await node.ExtAPI.DisableSSHKey(Root, fingerprint), Is.Not.Null);
            Assert.That(await cli.Execute("sshKeys root"), Has.Some.StartsWith(fingerprint).And.Some.Contains("switched off"));
            Assert.That(await node.ExtAPI.EnableSSHKey(Root, fingerprint), Is.Not.Null);

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


        #region AnAPIKeyIsShownWholeAndInTheLogByItsBeginning

        [Test]
        public async Task AnAPIKeyIsShownWholeAndInTheLogByItsBeginning()
        {

            var made    = await cli.Execute("apiKeys root add readWrite for the dashboard");

            Assert.That(made, Has.Length.EqualTo(2), String.Join("\n", made));

            var secret  = made[1];

            Assert.Multiple(() => {
                Assert.That(made[0],  Is.EqualTo("'root' has a new API key, ReadWrite:"));
                Assert.That(secret,   Has.Length.EqualTo(APIKeysCommand.KeyLength).And.Match("^[A-Za-z0-9]+$"));
                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(secret), out var apiKey), Is.True, "the key shown is not the key made");
                Assert.That(apiKey!.AccessRights,                Is.EqualTo(APIKeyRights.ReadWrite));
                Assert.That(apiKey.Description.FirstText(),      Is.EqualTo("for the dashboard"));
                Assert.That(apiKey.UserId,                       Is.EqualTo(Root));
            });

            var listed  = await cli.Execute("apiKeys root");

            Assert.Multiple(() => {
                Assert.That(listed,                     Has.Length.EqualTo(1));
                Assert.That(listed[0],                  Does.StartWith(secret + "  ReadWrite"), "a list does not show the whole key");
                Assert.That(listed[0],                  Does.Contain("for the dashboard"));
            });

            var removed = await cli.Execute($"apiKeys root remove {secret[..APIKeysCommand.ShownInTheLog]}");

            Assert.Multiple(() => {
                Assert.That(removed[0],                                                  Is.EqualTo($"The API key {secret} signs 'root' in no more."));
                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(secret), out _),   Is.False, "still there");
                lock (said)
                {
                    Assert.That(said,                   Has.None.Contains(secret), "the whole key is in the log");
                    Assert.That(said,                   Has.Some.Contains($"gave 'root' the API key {secret[..APIKeysCommand.ShownInTheLog]}..."), "the key given is not in the log");
                    Assert.That(said,                   Has.Some.Contains($"took the API key {secret[..APIKeysCommand.ShownInTheLog]}... from 'root'"), "the key taken back is not in the log");
                }
            });

        }

        #endregion

        #region AnAPIKeyGivenIsTakenAsItIs

        [Test]
        public async Task AnAPIKeyGivenIsTakenAsItIs()
        {

            var own   = "my-own.key_for~debugging-1";
            var made  = await cli.Execute($"apiKeys root add readWrite key {own} for the dashboard");

            Assert.That(made, Is.EqualTo(new[] { "'root' has a new API key, ReadWrite:", own }), String.Join("\n", made));

            Assert.Multiple(() => {
                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(own), out var apiKey), Is.True, "the key given is not the key made");
                Assert.That(apiKey!.AccessRights,                Is.EqualTo(APIKeyRights.ReadWrite));
                Assert.That(apiKey.Description.FirstText(),      Is.EqualTo("for the dashboard"));
                Assert.That(apiKey.UserId,                       Is.EqualTo(Root));
                lock (said)
                    Assert.That(said,                            Has.None.Contains(own), "the whole key is in the log");
            });

            var again = await cli.Execute($"apiKeys root add key {own}");

            Assert.That(again[0], Does.StartWith("No API key was made:").And.Contain("already exists"));

        }

        #endregion

        #region AnAPIKeyIsNeverWrittenIntoTheHistory

        /// <summary>
        /// A line that names a key - one given to be added, one to be taken
        /// back - comes back with Up in its session and is never written to the
        /// history file; the lines around it are, and so is one that has a key
        /// made, which only the answer shows.
        /// </summary>
        [Test]
        public async Task AnAPIKeyIsNeverWrittenIntoTheHistory()
        {

            var own     = "my-own.key_for~debugging-1";

            await cli.Execute($"apiKeys root add readWrite key {own} for the dashboard");
            var made    = await cli.Execute("apiKeys root add for a script");
            var secret  = made[1];
            await cli.Execute("apiKeys root");
            await cli.Execute($"apiKeys root remove {secret}");
            await cli.Execute($"apiKeys root remove {own}");

            var file    = NodeCLI.HistoryPathOf(node, CLICaller.Console);
            var kept    = File.ReadAllText(file);

            Assert.Multiple(() => {
                Assert.That(file,                                           Is.EqualTo(Path.Combine(directory, "accounts", NodeCLI.HistoryDirectory, NodeCLI.ConsoleHistoryFile)));
                Assert.That(new HistoryFile(file).Read(),                   Is.EqualTo(new[] { "apiKeys root add for a script", "apiKeys root" }));
                Assert.That(kept,                                           Does.Not.Contain(own).And.Not.Contain(secret));
                Assert.That(cli.CommandHistory,                             Has.Member($"apiKeys root add readWrite key {own} for the dashboard").
                                                                            And.Member($"apiKeys root remove {secret}"), "the session's own history");
            });

        }

        #endregion

        #region AnAPIKeyGivenIsRefusedWithOtherCharactersOrTooShort

        [Test]
        public async Task AnAPIKeyGivenIsRefusedWithOtherCharactersOrTooShort()
        {

            node.ExtAPI.TryGetUser(Root, out var root);

            var before    = node.ExtAPI.GetAPIKeysForUser(root!).Count();

            var other     = await cli.Execute("apiKeys root add key slash/in/it/long/enough/yes");
            var umlaut    = await cli.Execute("apiKeys root add key Schlüssel-mit-Umlaut-lang-genug");
            var tooShort  = await cli.Execute($"apiKeys root add key {new String('a', node.ExtAPI.MinAPIKeyLength - 1)}");
            var noKey     = await cli.Execute("apiKeys root add readOnly key");
            var justLong  = await cli.Execute($"apiKeys root add key {new String('a', node.ExtAPI.MinAPIKeyLength)}");

            Assert.Multiple(() => {
                Assert.That(other,     Is.EqualTo(new[] { "No API key was made: an API key is letters, digits and . _ ~ - only." }));
                Assert.That(umlaut,    Is.EqualTo(new[] { "No API key was made: an API key is letters, digits and . _ ~ - only." }));
                Assert.That(tooShort,  Is.EqualTo(new[] { $"No API key was made: an API key has at least {node.ExtAPI.MinAPIKeyLength} characters; this one has {node.ExtAPI.MinAPIKeyLength - 1}." }));
                Assert.That(noKey,     Has.Length.EqualTo(1).And.Some.StartsWith("Usage: apiKeys"));
                Assert.That(justLong,  Has.Length.EqualTo(2), String.Join("\n", justLong));
                Assert.That(node.ExtAPI.GetAPIKeysForUser(root!).Count(), Is.EqualTo(before + 1), "a key refused was made");
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


        #region AnAPIKeyBoundToAddressesIsMadeListedAndLoggedWithThem

        /// <summary>
        /// "from" before "key" and after it, each address once, the description
        /// saying "from" itself further on: the key is bound to the addresses,
        /// and the answer, the list and the log say so - a key bound to nothing
        /// says nothing of it.
        /// </summary>
        [Test]
        public async Task AnAPIKeyBoundToAddressesIsMadeListedAndLoggedWithThem()
        {

            var own    = "Bound0by0the0command0line0abc";
            var made   = await cli.Execute($"apiKeys root add from 192.0.2.7,2001:db8::7,192.0.2.7 key {own} data from the hub");
            var other  = "Bound0the0other0way0round0abc";
            var also   = await cli.Execute($"apiKeys root add readWrite key {other} from ::1");
            var free   = await cli.Execute("apiKeys root add");
            var listed = await cli.Execute("apiKeys root");

            Assert.Multiple(() => {

                Assert.That(made,  Is.EqualTo(new[] { "'root' has a new API key, ReadOnly, only from 192.0.2.7, 2001:db8::7:", own }), String.Join("\n", made));
                Assert.That(also,  Is.EqualTo(new[] { "'root' has a new API key, ReadWrite, only from ::1:", other }),                  String.Join("\n", also));
                Assert.That(free[0], Is.EqualTo("'root' has a new API key, ReadOnly:"));

                Assert.That(node.ExtAPI.TryGetAPIKey(APIKey_Id.Parse(own), out var apiKey), Is.True, "not made");
                Assert.That(apiKey!.ValidRemoteIPAddresses.Select(address => System.Net.IPAddress.Parse(address.ToString()!.Trim('[', ']')).ToString()), Is.EqualTo(new[] { "192.0.2.7", "2001:db8::7" }));
                Assert.That(apiKey.Description.FirstText(),  Is.EqualTo("data from the hub"));

                Assert.That(listed, Has.Some.StartsWith(own).And.Some.Contains(", only from 192.0.2.7, 2001:db8::7"));
                Assert.That(listed, Has.Some.StartsWith(other).And.Some.Contains(", only from ::1"));
                Assert.That(listed.Single(line => line.StartsWith(free[1])), Does.Not.Contain("only from"));

                lock (said)
                    Assert.That(said, Has.Some.Contains($"gave 'root' the API key {own[..APIKeysCommand.ShownInTheLog]}... (ReadOnly, only from 192.0.2.7, 2001:db8::7)."));

            });

        }

        #endregion

        #region WhatAnAPIKeyCannotBeBoundToSaysWhy

        /// <summary>
        /// A network, an address with a zone, what is no address - "192.7"
        /// among them, which would be 192.0.0.7 - and "from" with nothing after
        /// it each make no key, and say why as the page says it.
        /// </summary>
        [Test]
        public async Task WhatAnAPIKeyCannotBeBoundToSaysWhy()
        {

            node.ExtAPI.TryGetUser(Root, out var root);

            var before   = node.ExtAPI.GetAPIKeysForUser(root!).Count();

            var network  = await cli.Execute("apiKeys root add from 192.0.2.7,10.0.0.0/8");
            var zone     = await cli.Execute("apiKeys root add from fe80::1%eth0");
            var wrongs   = new[] { "192.7", "300.1.1.1", "1.2.3.4.5", "1.2.3.", "proxy.example", "2001:db8::7::1", "12345::1" };
            var refused  = new List<String[]>();

            foreach (var wrong in wrongs)
                refused.Add(await cli.Execute($"apiKeys root add from 192.0.2.7,{wrong}"));

            var nothing  = await cli.Execute("apiKeys root add from ,");
            var missing  = await cli.Execute("apiKeys root add from");

            Assert.Multiple(() => {
                Assert.That(network,   Is.EqualTo(new[] { "No API key was made: '10.0.0.0/8' is a network; an API key is bound to addresses, one by one." }));
                Assert.That(zone,      Is.EqualTo(new[] { "No API key was made: 'fe80::1%eth0' names a zone; an API key is bound to the address without it." }));
                for (var i = 0; i < wrongs.Length; i++)
                    Assert.That(refused[i], Is.EqualTo(new[] { $"No API key was made: '{wrongs[i]}' is no IP address." }), wrongs[i]);
                Assert.That(nothing,   Is.EqualTo(new[] { "No API key was made: 'from' names no address." }));
                Assert.That(missing,   Has.Length.EqualTo(1).And.Some.StartsWith("Usage: apiKeys"));
                Assert.That(node.ExtAPI.GetAPIKeysForUser(root!).Count(), Is.EqualTo(before), "a key refused was made");
            });

        }

        #endregion

        #region AnAPIKeyBoundHereOpensTheDoorOnlyFromThere

        /// <summary>
        /// Made over the command line, bound to 127.0.0.1 it opens the node's
        /// API to a client at 127.0.0.1, and bound to 192.0.2.7 it does not.
        /// </summary>
        [Test]
        public async Task AnAPIKeyBoundHereOpensTheDoorOnlyFromThere()
        {

            _ = new PageAPI(node);

            var here       = (await cli.Execute("apiKeys root add from 127.0.0.1"))[1];
            var elsewhere  = (await cli.Execute("apiKeys root add from 192.0.2.7"))[1];

            using var http = new HttpClient { BaseAddress = new Uri(node.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            async Task<System.Net.HttpStatusCode> With(String Key)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "api/v1/auth/me");
                request.Headers.Add("API-Key", Key);
                using var response = await http.SendAsync(request);
                return response.StatusCode;
            }

            var fromHere       = await With(here);
            var fromElsewhere  = await With(elsewhere);

            Assert.Multiple(() => {
                Assert.That(fromHere,       Is.EqualTo(System.Net.HttpStatusCode.OK),            "the key bound to 127.0.0.1 is refused from 127.0.0.1");
                Assert.That(fromElsewhere,  Is.EqualTo(System.Net.HttpStatusCode.Unauthorized),  "the key bound to 192.0.2.7 opens the door from 127.0.0.1");
            });

        }

        /// <summary>
        /// The JSON API every node has, as a kind of node brings it: /api/v1/auth/me.
        /// </summary>
        private sealed class PageAPI(WWCPNode TheNode)
            : NodeHTTPAPI(TheNode.HTTPServer, TheNode, TheNode.ExtAPI, TheNode.Log);

        #endregion


        private static String KeyLine(ISshHostKey Key)
            => SshPublicKey.FromHostKey(Key, "tester").ToAuthorizedKeyLine();

    }

}
