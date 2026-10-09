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
using System.Net.Http.Headers;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What an account's own page changes is in the node's log, as what the
    /// command line's sshKeys and apiKeys change is: who changed which of an
    /// account's details, gave or took or switched which key - tagged "web"
    /// and "security" - and nothing for what was refused. An API key is said
    /// by its beginning only, in these lines and in the line every request
    /// writes.
    /// </summary>
    public class AccountLogTests
    {

        #region Data

        private const    String          Kim        = "kimberly";
        private const    String          KimsWord   = "Correct-Horse-1";

        private          String          directory  = "";
        private          String          password   = "";
        private          WWCPNode?       node;
        private          List<LogEntry>  logged     = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-account-log-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            var configFile = Path.Combine(directory, WWCPConfigFile.DefaultFileName);
            File.WriteAllText(configFile, """{ "nts": { "enabled": false } }""");

            // This test's own: a node of the test before may still log while it goes.
            List<LogEntry> logged = this.logged = [];

            var log = new EventLog();
            log.OnLogged += entry => { lock (logged) logged.Add(entry); };

            node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                AccountsPath:      Path.Combine(directory, "accounts"),
                                ConfigFile:        new WWCPConfigFile(configFile),
                                CertificatesPath:  Path.Combine(directory, "certificates"),
                                Log:               log,
                                LogToConsole:      false,
                                BridgeDebugLog:    false);

            await node.Start();

            password = node.GeneratedPassword!;

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (helpers) Client / Send / Said / Lines

        private HttpClient Client(String Login = WWCPNode.DefaultAdminUser, String? Password = null)
        {

            var client = new HttpClient { BaseAddress = new Uri(node!.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(20) };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                             "Basic",
                                                             Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Login}:{Password ?? password}"))
                                                         );

            return client;

        }

        private static async Task<(HttpStatusCode Status, JToken? JSON)> Send(HttpClient  HTTP,
                                                                            String      Method,
                                                                            String      Path,
                                                                            JToken?     JSON = null)
        {

            using var request = new HttpRequestMessage(new HttpMethod(Method), Path);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (JSON is not null)
                request.Content = new StringContent(JSON.ToString(), Encoding.UTF8, "application/json");

            using var response = await HTTP.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();

            return (response.StatusCode, text.StartsWith('{') || text.StartsWith('[') ? JToken.Parse(text) : null);

        }

        /// <summary>
        /// Everything the log has said so far, taken under its lock.
        /// </summary>
        private LogEntry[] Said()
        {
            lock (logged)
                return [.. logged];
        }

        /// <summary>
        /// The lines tagged "web" that say what was changed of an account.
        /// </summary>
        private LogEntry[] Lines()
            => [.. Said().Where(entry => entry.Tags.Contains("web") && entry.Message.Contains("on the web interface"))];

        #endregion


        #region WhatTheAccountsPageChangesIsInTheLog()

        /// <summary>
        /// Saved details, an API key given, switched off and on and taken, an
        /// SSH key the same: each a line, with who did it, of which account,
        /// and what - as the page sends them.
        /// </summary>
        [Test]
        public async Task WhatTheAccountsPageChangesIsInTheLog()
        {

            using var http  = Client();

            var (_, read)   = await Send(http, "GET", "ext/users/root");
            var account     = (JObject) read!;
            account.Remove("youCanEdit");
            account["name"]   = new JObject(new JProperty("en", "Root of all"));
            account["email"]  = "root@example.test";

            Assert.That((await Send(http, "SET", "ext/users/root", account)).Status, Is.EqualTo(HttpStatusCode.OK));

            var key         = "Pagemade" + Guid.NewGuid().ToString("N");
            var keyPath     = $"ext/users/root/APIKeys/{key}";

            Assert.That((await Send(http, "ADD", "ext/users/root/APIKeys", new JObject(
                                                                            new JProperty("@id",           key),
                                                                            new JProperty("@context",      "https://opendata.social/contexts/UsersAPI/APIKey"),
                                                                            new JProperty("userId",        "root"),
                                                                            new JProperty("description",   new JObject(new JProperty("en", "monitoring"))),
                                                                            new JProperty("accessRights",  "readWrite"),
                                                                            new JProperty("created",       DateTime.UtcNow.ToString("o"))
                                                                        ))).Status, Is.EqualTo(HttpStatusCode.OK));

            Assert.That((await Send(http, "SET",    keyPath, new JObject(new JProperty("isDisabled", true)))). Status, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await Send(http, "SET",    keyPath, new JObject(new JProperty("isDisabled", false)))).Status, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await Send(http, "DELETE", keyPath)).Status, Is.EqualTo(HttpStatusCode.OK));

            var sshKey      = SshHostKey.GenerateEd25519();
            var fingerprint = SshFingerprint.Sha256(sshKey.PublicKeyBlob);
            var sshPath     = $"ext/users/root/SSHKeys/{UserSSHKey.FingerprintInURL(fingerprint)}";

            Assert.That((await Send(http, "ADD", "ext/users/root/SSHKeys", new JObject(
                                                                             new JProperty("line",   SshPublicKey.FromHostKey(sshKey, "tester").ToAuthorizedKeyLine()),
                                                                             new JProperty("label",  "laptop")
                                                                         ))).Status, Is.EqualTo(HttpStatusCode.OK));

            Assert.That((await Send(http, "SET",    sshPath, new JObject(new JProperty("isDisabled", true)))). Status, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await Send(http, "SET",    sshPath, new JObject(new JProperty("isDisabled", false)))).Status, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await Send(http, "DELETE", sshPath)).Status, Is.EqualTo(HttpStatusCode.OK));

            var beginning   = key[..WWCPNode.APIKeyShownInTheLog] + "...";
            var lines       = Lines();

            Assert.Multiple(() => {

                Assert.That(lines.Select(line => line.Message), Is.EqualTo(new[] {
                    "'root' changed their account on the web interface: name, e-mail address.",
                    $"'root' gave 'root' the API key {beginning} (readWrite) on the web interface.",
                    $"'root' switched off the API key {beginning} of 'root' on the web interface: it opens nothing until it is switched on again.",
                    $"'root' switched on the API key {beginning} of 'root' on the web interface: it opens the door again.",
                    $"'root' took the API key {beginning} from 'root' on the web interface: it opens nothing from now on.",
                    $"'root' let 'root' in over SSH with the key {fingerprint} on the web interface.",
                    $"'root' switched off the key {fingerprint} of 'root' on the web interface: it lets nobody in until it is switched on again.",
                    $"'root' switched on the key {fingerprint} of 'root' on the web interface: it lets 'root' in again.",
                    $"'root' took the key {fingerprint} from 'root' on the web interface: it lets nobody in from now on."
                }));

                Assert.That(lines.Select(line => line.Level),          Is.All.EqualTo(LogLevel.Notice));
                Assert.That(lines.Skip(1).Select(line => line.Tags),   Is.All.Contains("security"), "a key changed is not tagged security");
                Assert.That(lines[0].Tags,                             Is.EqualTo(new[] { "auth", "web" }));

                // Not in these lines, and not in the one every request writes.
                Assert.That(Said().Where(entry => entry.Message.Contains(key)).Select(entry => entry.Message), Is.Empty, "the whole API key is in the log");

            });

        }

        #endregion

        #region WhatIsRefusedOrChangesNothingIsSaidAsSuch()

        /// <summary>
        /// Another account's refused change, and a key that is not there, say
        /// nothing of a change; a save that changed nothing says so.
        /// </summary>
        [Test]
        public async Task WhatIsRefusedOrChangesNothingIsSaidAsSuch()
        {

            var organization = node!.ExtAPI.GetOrganization(Organization_Id.Parse(node.Kind.Organization));

            var kim = await node.ExtAPI.CreateUser(User_Id.Parse(Kim),
                                                   I18NString.Create(Kim),
                                                   SimpleEMailAddress.Parse($"{Kim}@example.test"),
                                                   KimsWord,
                                                   SkipDefaultNotifications:  true,
                                                   SkipNewUserEMail:          true,
                                                   SkipNewUserNotifications:  true,
                                                   AcceptedEULA:              DateTimeOffset.UtcNow.AddDays(-1),
                                                   IsAuthenticated:           true);

            Assert.That((await node.ExtAPI.AddUserToOrganization(kim!, User2OrganizationEdgeLabel.IsMember, organization!)).IsSuccess, Is.True);

            using var asKim  = Client(Kim, KimsWord);
            using var asRoot = Client();

            var refused  = await Send(asKim,  "SET",    "ext/users/root", new JObject(
                                                                            new JProperty("@id",       "root"),
                                                                            new JProperty("@context",  "https://opendata.social/contexts/UsersAPI/user"),
                                                                            new JProperty("name",      new JObject(new JProperty("en", "Kim was here"))),
                                                                            new JProperty("email",     "kim@example.test")
                                                                        ));
            var missing  = await Send(asRoot, "DELETE", "ext/users/root/APIKeys/nobodys-key-0123456789abcdef");

            Assert.That(refused.Status, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(missing.Status, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(Lines(),        Is.Empty, "a change that was not made is in the log");

            var (_, read) = await Send(asKim, "GET", $"ext/users/{Kim}");
            var account   = (JObject) read!;
            account.Remove("youCanEdit");

            Assert.That((await Send(asKim, "SET", $"ext/users/{Kim}", account)).Status, Is.EqualTo(HttpStatusCode.OK));

            Assert.That(Lines().Select(line => line.Message), Is.EqualTo(new[] { $"'{Kim}' saved their account on the web interface, changing nothing." }));

        }

        #endregion

        #region APasswordChangedIsSaidAndNothingOfItsWords()

        /// <summary>
        /// A password changed on the web interface - SET users/{UserId}/password,
        /// as the e-mobility provider's profile page sends it - is a line;
        /// one refused for a wrong current password is not; and neither
        /// password is anywhere in the log.
        /// </summary>
        [Test]
        public async Task APasswordChangedIsSaidAndNothingOfItsWords()
        {

            const String newPassword = "Battery-Staple-42-x";

            using var http   = Client();

            var wrong        = await Send(http, "SET", "ext/users/root/password", new JObject(
                                                                                    new JProperty("currentPassword",  "Not-the-password-1"),
                                                                                    new JProperty("newPassword",      newPassword)
                                                                                ));

            Assert.That(wrong.Status, Is.Not.EqualTo(HttpStatusCode.OK));
            Assert.That(Lines(),      Is.Empty, "a refused change of password is in the log");

            var changed      = await Send(http, "SET", "ext/users/root/password", new JObject(
                                                                                    new JProperty("currentPassword",  password),
                                                                                    new JProperty("newPassword",      newPassword)
                                                                                ));

            Assert.That(changed.Status, Is.EqualTo(HttpStatusCode.OK));

            Assert.Multiple(() => {
                Assert.That(Lines().Select(line => line.Message), Is.EqualTo(new[] { "'root' changed their password on the web interface." }));
                Assert.That(Lines().Single().Tags,                Is.EqualTo(new[] { "auth", "security", "web" }));
                Assert.That(Said().Where(entry => entry.Message.Contains(newPassword) || entry.Message.Contains(password)).Select(entry => entry.Message),
                                                                  Is.Empty, "a password is in the log");
            });

        }

        #endregion

        #region AKeyInAPathIsSaidByItsBeginning()

        [Test]
        public void AKeyInAPathIsSaidByItsBeginning()
        {

            Assert.Multiple(() => {
                Assert.That(WWCPNode.PathForTheLog("/ext/users/root/APIKeys/AbCdEfGh0123456789abcdef"),         Is.EqualTo("/ext/users/root/APIKeys/AbCdEfGh..."));
                Assert.That(WWCPNode.PathForTheLog("/LC/ext/users/root/apikeys/AbCdEfGh0123456789abcdef?x=1"),  Is.EqualTo("/LC/ext/users/root/apikeys/AbCdEfGh...?x=1"));
                Assert.That(WWCPNode.PathForTheLog("/ext/users/root/APIKeys"),                                  Is.EqualTo("/ext/users/root/APIKeys"));
                Assert.That(WWCPNode.PathForTheLog("/ext/users/root/SSHKeys/abc-def_ghi"),                      Is.EqualTo("/ext/users/root/SSHKeys/abc-def_ghi"));
            });

        }

        #endregion

    }

}
