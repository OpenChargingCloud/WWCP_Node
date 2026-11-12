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
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// The node's files over SFTP, as every kind of node has to serve them:
    /// switched on by the configuration file alone, its areas and nothing else
    /// of the machine, the log files read as the Logs page is read and written
    /// by nobody, the metrological log without its private key, and a session
    /// that ends when what let it in no longer does.
    /// </summary>
    /// <remarks>
    /// Over the network and with Hermod's own client, as sftp, WinSCP or
    /// FileZilla would come. A kind's own areas are its suite's to ask; these
    /// ask only that they do not get in the way of the node's.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region (private) SftpAs(Account)

        /// <summary>
        /// The given account, let in with a key of its own, signed in over SSH,
        /// with an SFTP session open.
        /// </summary>
        private async Task<(SshClient Client, SftpClient Sftp)> SftpAs(String Account)
        {

            var client = await SignedInOverSSHAs(Account);

            try
            {
                return (client, await client.OpenSftpClientAsync());
            }
            catch
            {
                await client.DisposeAsync();
                throw;
            }

        }

        /// <summary>
        /// The given account, let in with a key of its own, signed in over SSH.
        /// </summary>
        private async Task<SshClient> SignedInOverSSHAs(String Account)
        {

            var key   = SshHostKey.GenerateEd25519();

            var added = await Node.AuthorizeSSHKey(Account, SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine());

            Assert.That(added.IsAdded, Is.True, added.Reason);

            return await SshClient.ConnectAsync("127.0.0.1",
                                                Node.SSHPort!.Value.ToUInt16(),
                                                new SshClientOptions {
                                                    Username       = Account,
                                                    VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                                    Credentials    = [ key ]
                                                });

        }

        #endregion

        #region (private) NamesIn(Sftp, Path) / DayFile(Day) / Refusal(Operation)

        /// <summary>
        /// The names a folder lists, without "." and "..".
        /// </summary>
        private static async Task<IReadOnlyList<String>> NamesIn(SftpClient  Sftp,
                                                                 String      Path)

            => [.. (await Sftp.ListDirectoryAsync(Path)).
                       Select(entry => entry.Name).
                       Where (name  => name is not "." and not "..")];

        /// <summary>
        /// What the log file of the given day is called on this kind of node.
        /// </summary>
        private String DayFile(String Day)

            => $"{Node.Kind.LogFilePrefix}-{Day}.log";

        /// <summary>
        /// The status SFTP refused the given operation with - or null, where it
        /// was not refused.
        /// </summary>
        private static async Task<SftpStatusCode?> Refusal(Func<Task> Operation)
        {

            try
            {
                await Operation();
                return null;
            }
            catch (SftpException refused)
            {
                return refused.Code;
            }

        }

        /// <summary>
        /// Whether the given SFTP session has ended within the given time:
        /// whether a request sent on it fails because its channel was closed.
        /// </summary>
        private static async Task<Boolean> EndsWithin(SftpClient  Sftp,
                                                      TimeSpan    Time)
        {

            var until = DateTimeOffset.UtcNow + Time;

            while (DateTimeOffset.UtcNow < until)
            {

                try
                {
                    await Sftp.RealPathAsync("/").AsTask().WaitAsync(TimeSpan.FromSeconds(2));
                }
                catch (Exception problem) when (problem is SshChannelClosedException or IOException or ObjectDisposedException)
                {
                    return true;
                }
                catch (SftpException)
                {
                    // Refused, and so not yet closed.
                }
                catch (TimeoutException)
                { }

                await Task.Delay(100);

            }

            return false;

        }

        #endregion


        #region SftpIsServedOnceTheFileSaysSoAndEndsWhenItNoLongerDoes

        /// <summary>
        /// Off unless the file says "sftp": true - the SSH server serving the
        /// command line refuses it - and switched on from the SSH server page,
        /// served from the next session on, without the server starting anew:
        /// the connection that was refused is served now. Switched off again,
        /// the session open ends - at once, not when it is next asked again
        /// whether it may go on.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SSH)]
        public async Task SftpIsServedOnceTheFileSaysSoAndEndsWhenItNoLongerDoes()
        {

            Node.SSHSessionRecheckEvery = TimeSpan.FromHours(1);

            await using var client  = await SignedInOverSSHAs(AdminLogin);

            Assert.That(Node.SFTPEnabled, Is.False, "SFTP is on although the file does not say so");

            Assert.That(async () => await client.OpenSftpClientAsync(), Throws.InstanceOf<SshWireException>(), "SFTP was served without the file saying so");

            using var http          = await SignedIn();

            var (switchedOn, on)    = await Send(http, HttpMethod.Put, "api/v1/configuration/ssh", new JObject(new JProperty("sftp", true)));

            Assert.That(switchedOn,                       Is.EqualTo(HttpStatusCode.OK), on.ToString());
            Assert.That(on.Value<Boolean?>("sftp"),       Is.True);

            await using var sftp    = await client.OpenSftpClientAsync();

            Assert.That(await NamesIn(sftp, "/"), Is.Not.Null, "the session SFTP was switched on for answers nothing");

            var (switchedOff, off)  = await Send(http, HttpMethod.Put, "api/v1/configuration/ssh", new JObject(new JProperty("sftp", false)));

            Assert.That(switchedOff,                      Is.EqualTo(HttpStatusCode.OK), off.ToString());
            Assert.That(off.Value<Boolean?>("sftp"),      Is.False);

            await Assert.MultipleAsync(async () => {
                Assert.That(await NoSftpSessionWithin(TimeSpan.FromSeconds(3)), Is.True,  "the SFTP session went on after SFTP was switched off, until it would have been asked anything");
                Assert.That(await EndsWithin(sftp, TimeSpan.FromSeconds(5)),     Is.True,  "the SFTP session's channel stayed open after SFTP was switched off");
                Assert.That(async () => await client.OpenSftpClientAsync(),      Throws.InstanceOf<SshWireException>(), "SFTP was served after it was switched off");
                Assert.That(Node.SSHEnabled,                                     Is.True,  "switching SFTP off took the SSH server along");
            });

        }

        #endregion

        #region (private) NoSftpSessionWithin(Time)

        /// <summary>
        /// Whether the node has no SFTP session open within the given time -
        /// asked of the node, so that nothing sent to a session ends it.
        /// </summary>
        private async Task<Boolean> NoSftpSessionWithin(TimeSpan Time)
        {

            var until = DateTimeOffset.UtcNow + Time;

            while (Node.SSHSessions.Any(session => session.Kind == WWCPNode.SSHSession.SFTP))
            {

                if (DateTimeOffset.UtcNow >= until)
                    return false;

                await Task.Delay(50);

            }

            return true;

        }

        #endregion

        #region TheRootShowsTheAreasAndNothingElseOfTheMachine

        /// <summary>
        /// The root lists the node's areas - the log files among them - and no
        /// other name: not the accounts, the configuration file, the host key or
        /// the certificates that lie beside them on the disk, and no path leads
        /// out of the tree, however many ".." it has.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTPWithLogFiles)]
        public async Task TheRootShowsTheAreasAndNothingElseOfTheMachine()
        {

            var (client, sftp)  = await SftpAs(AdminLogin);

            await using var _   = client;
            await using var __  = sftp;

            var areas           = Node.SftpAreas.Select(area => area.Path.Split('/')[0]).Distinct().ToList();
            var root            = await NamesIn(sftp, "/");

            await Assert.MultipleAsync(async () => {

                Assert.That(root,                                         Does.Contain(WWCPNode.SftpLogsArea), "the root does not show the log files");
                Assert.That(root,                                         Is.SubsetOf(areas),                  "the root shows what is no area");
                Assert.That(await NamesIn(sftp, "/../../.."),             Is.EquivalentTo(root),               "'..' led out of the tree");
                Assert.That(await sftp.RealPathAsync("/logs/../../.."),   Is.EqualTo("/"));

                foreach (var outside in new[] { "/accounts", "/ssh", "/certificates", "/logs/../accounts", "/../" + Path.GetFileName(Directory) })
                    Assert.That(await Refusal(async () => await sftp.ListDirectoryAsync(outside)), Is.EqualTo(SftpStatusCode.NoSuchFile), outside);

            });

        }

        #endregion

        #region AnAccountReadsTheLogFilesExactlyWhereItMayReadTheLog

        /// <summary>
        /// An account that is not an administrator - one in a role that may
        /// read the name resolution and nothing else - reads the log files over
        /// SFTP exactly where it may read the Logs page: it lists a day's file
        /// and downloads it whole, and is shown no other name of the folder;
        /// or, where the kind's log is not for it, it is shown no /logs.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTPWithLogFiles)]
        public async Task AnAccountReadsTheLogFilesExactlyWhereItMayReadTheLog()
        {

            var account          = await AccountIn("supporter", "helpdesk", "Supporting-Only-1");

            var day              = DayFile("2026-01-02");
            var content          = $"2026-01-02T12:00:00.000Z [Info] The day {Guid.NewGuid():N} was logged.\n";

            File.WriteAllText(Path.Combine(Node.LogPath!, day),                                        content);
            File.WriteAllText(Path.Combine(Node.LogPath!, "notes.txt"),                                "not a log file");
            File.WriteAllText(Path.Combine(Node.LogPath!, $"{Node.Kind.LogFilePrefix}-backup-2026-01-02.log"), "not a day's file");

            var (client, sftp)   = await SftpAs("supporter");

            await using var _    = client;
            await using var __   = sftp;

            if (!Node.MayReadTheLog(account))
            {

                await Assert.MultipleAsync(async () => {
                    Assert.That(await NamesIn(sftp, "/"),                                                          Does.Not.Contain(WWCPNode.SftpLogsArea), "the root shows the log to an account it is not for");
                    Assert.That(await Refusal(async () => await sftp.DownloadAsync($"/logs/{day}")),               Is.EqualTo(SftpStatusCode.PermissionDenied));
                    Assert.That(await Refusal(async () => await sftp.ListDirectoryAsync("/logs")),                 Is.EqualTo(SftpStatusCode.PermissionDenied));
                });

                return;

            }

            var listed           = await NamesIn(sftp, "/logs");

            await Assert.MultipleAsync(async () => {

                Assert.That(await NamesIn(sftp, "/"),                                                              Does.Contain(WWCPNode.SftpLogsArea));
                Assert.That(listed,                                                                                Does.Contain(day));
                Assert.That(listed,                                                                                Does.Not.Contain("notes.txt").And.Not.Contain($"{Node.Kind.LogFilePrefix}-backup-2026-01-02.log"));
                Assert.That(listed.Where(name => name != "metrological"),                                          Has.All.Matches<String>(name => name!.StartsWith(Node.Kind.LogFilePrefix + "-", StringComparison.Ordinal) && name.EndsWith(".log", StringComparison.Ordinal)));
                Assert.That(Encoding.UTF8.GetString(await sftp.DownloadAsync($"/logs/{day}")),                     Is.EqualTo(content));
                Assert.That(await Refusal(async () => await sftp.DownloadAsync("/logs/notes.txt")),                Is.EqualTo(SftpStatusCode.NoSuchFile));

            });

        }

        #endregion

        #region NobodyWritesRemovesOrRenamesInTheLogs

        /// <summary>
        /// The logs are evidence: an administrator neither uploads a file into
        /// /logs, nor replaces, removes or renames a day's file there, nor makes
        /// a folder or sets a time - and nothing of an attempt is left behind.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTPWithLogFiles)]
        public async Task NobodyWritesRemovesOrRenamesInTheLogs()
        {

            var day              = DayFile("2026-01-03");
            var file             = Path.Combine(Node.LogPath!, day);
            var content          = "2026-01-03T08:00:00.000Z [Info] What was logged stays.\n";

            File.WriteAllText(file, content);

            var before           = System.IO.Directory.GetFiles(Node.LogPath!).Order().ToList();

            var (client, sftp)   = await SftpAs(AdminLogin);

            await using var _    = client;
            await using var __   = sftp;

            await Assert.MultipleAsync(async () => {

                Assert.That(await Refusal(async () => await sftp.UploadAsync($"/logs/{DayFile("2026-01-04")}", "made up"u8.ToArray())),    Is.EqualTo(SftpStatusCode.PermissionDenied), "a new file");
                Assert.That(await Refusal(async () => await sftp.UploadAsync($"/logs/{day}",                   "rewritten"u8.ToArray())),  Is.EqualTo(SftpStatusCode.PermissionDenied), "a day's file replaced");
                Assert.That(await Refusal(async () => await sftp.RemoveAsync($"/logs/{day}")),                                             Is.EqualTo(SftpStatusCode.PermissionDenied), "a day's file removed");
                Assert.That(await Refusal(async () => await sftp.RenameAsync($"/logs/{day}", $"/logs/{DayFile("2026-01-05")}")),           Is.EqualTo(SftpStatusCode.PermissionDenied), "a day's file renamed");
                Assert.That(await Refusal(async () => await sftp.MakeDirectoryAsync("/logs/kept")),                                        Is.EqualTo(SftpStatusCode.PermissionDenied), "a folder made");
                Assert.That(await Refusal(async () => await sftp.SetAttributesAsync($"/logs/{day}", new SftpFileAttributes { ModifyTime = DateTimeOffset.UnixEpoch })),
                                                                                                                                           Is.EqualTo(SftpStatusCode.PermissionDenied), "a time set");

                Assert.That(File.ReadAllText(file),                                                                                        Is.EqualTo(content), "the day's file changed");
                Assert.That(System.IO.Directory.GetFiles(Node.LogPath!).Order(),                                                           Is.EqualTo(before),  "something was left in the folder");

            });

        }

        #endregion

        #region TheSigningKeyIsNeitherListedNorOpened

        /// <summary>
        /// The metrological log's folder shows its day files and its public
        /// key, by which they are checked somewhere else - and not the private
        /// key beside them, which is neither listed nor opened nor looked at,
        /// by whatever path.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTPWithLogFiles)]
        public async Task TheSigningKeyIsNeitherListedNorOpened()
        {

            Assume.That(Node.MetrologicalLog, Is.Not.Null, $"This {Node.Kind.Name} keeps no metrological log.");

            var keys             = Node.MetrologicalLog!.Path;

            Assert.That(File.Exists(Path.Combine(keys, LogSigner.KeyFileName)), Is.True, "the private key is not where this test expects it, and the test would prove nothing");

            var (client, sftp)   = await SftpAs(AdminLogin);

            await using var _    = client;
            await using var __   = sftp;

            var listed           = await NamesIn(sftp, "/logs/metrological");

            await Assert.MultipleAsync(async () => {

                Assert.That(await NamesIn(sftp, "/logs"),  Does.Contain("metrological"));
                Assert.That(listed,                        Does.Contain(LogSigner.PublicKeyFileName));
                Assert.That(listed,                        Does.Not.Contain(LogSigner.KeyFileName));

                Assert.That(Encoding.ASCII.GetString(await sftp.DownloadAsync($"/logs/metrological/{LogSigner.PublicKeyFileName}")),
                            Is.EqualTo(File.ReadAllText(Path.Combine(keys, LogSigner.PublicKeyFileName))));

                foreach (var path in new[] { $"/logs/metrological/{LogSigner.KeyFileName}",
                                             $"/logs/../logs/metrological/./{LogSigner.KeyFileName}",
                                             $"logs/metrological/{LogSigner.KeyFileName}",
                                             $"/logs/metrological/x/../{LogSigner.KeyFileName}",
                                             $"/logs/metrological/..\\metrological\\{LogSigner.KeyFileName}" })
                {
                    Assert.That(await Refusal(async () => await sftp.DownloadAsync(path)),  Is.EqualTo(SftpStatusCode.NoSuchFile), $"opened: {path}");
                    Assert.That(await Refusal(async () => await sftp.StatAsync(path)),      Is.EqualTo(SftpStatusCode.NoSuchFile), $"looked at: {path}");
                }

            });

        }

        #endregion

        #region ADownloadEndsWhenItsAccountIsSwitchedOff

        /// <summary>
        /// An account switched off in the middle of a download: the next read
        /// is refused, and the session ends - without waiting for the session to
        /// be asked again, as every operation asks.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTPWithLogFiles)]
        public async Task ADownloadEndsWhenItsAccountIsSwitchedOff()
        {

            Node.SSHSessionRecheckEvery = TimeSpan.FromHours(1);

            var account          = await AccountIn("deputy", WWCPNode.AdminRole, "Deputy-For-Now-1");

            var day              = DayFile("2026-01-06");

            File.WriteAllBytes(Path.Combine(Node.LogPath!, day), new Byte[256 * 1024]);

            var (client, sftp)   = await SftpAs("deputy");

            await using var _    = client;
            await using var __   = sftp;

            await using var download = await sftp.OpenFileStreamAsync($"/logs/{day}", SftpOpenFlags.Read);

            var buffer           = new Byte[16 * 1024];

            Assert.That(await download.ReadAsync(buffer), Is.GreaterThan(0), "the download did not begin");

            await Node.ExtAPI.UpdateUser(account, user => user.IsDisabled = true, SkipUserUpdatedNotifications: true);

            await Assert.MultipleAsync(async () => {
                Assert.That(async () => { while (await download.ReadAsync(buffer) > 0) { } },  Throws.Exception,  "the download went on after its account was switched off");
                Assert.That(await EndsWithin(sftp, TimeSpan.FromSeconds(5)),                  Is.True,           "the session went on after its account was switched off");
            });

        }

        #endregion

        #region AnIdleSftpSessionEndsWhenItsAccountIsSwitchedOff

        /// <summary>
        /// An account switched off while its session asks nothing: the session
        /// ends when it is next asked again whether it may go on, as a session
        /// at the command line that types nothing does.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTP)]
        public async Task AnIdleSftpSessionEndsWhenItsAccountIsSwitchedOff()
        {

            Node.SSHSessionRecheckEvery = TimeSpan.FromMilliseconds(200);

            var account          = await AccountIn("deputy", WWCPNode.AdminRole, "Deputy-For-Now-1");

            var (client, sftp)   = await SftpAs("deputy");

            await using var _    = client;
            await using var __   = sftp;

            Assert.That(Node.SSHSessions.Select(session => (session.Kind, session.Account)), Does.Contain((WWCPNode.SSHSession.SFTP, "deputy")));

            await Node.ExtAPI.UpdateUser(account, user => user.IsDisabled = true, SkipUserUpdatedNotifications: true);

            await Assert.MultipleAsync(async () => {
                Assert.That(await NoSftpSessionWithin(TimeSpan.FromSeconds(3)),  Is.True,  "the idle session went on after its account was switched off");
                Assert.That(await EndsWithin(sftp, TimeSpan.FromSeconds(5)),     Is.True,  "the idle session's channel stayed open after its account was switched off");
            });

        }

        #endregion

        #region AnSftpSessionIsShownAmongTheSSHSessions

        /// <summary>
        /// The SSH server page shows who is connected over SFTP as it shows who
        /// is at the command line - with what they are at - until they leave.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SFTP)]
        public async Task AnSftpSessionIsShownAmongTheSSHSessions()
        {

            using var http       = await SignedIn();

            var (client, sftp)   = await SftpAs(AdminLogin);

            await using var _    = client;

            var shown            = (JArray) (await GetJSON(http, "api/v1/configuration/ssh"))["sessions"]!;

            Assert.That(shown.Select(session => (session.Value<String>("kind"), session.Value<String>("account"))),
                        Does.Contain(("sftp", AdminLogin)), shown.ToString());

            await sftp.DisposeAsync();

            for (var waited = 0; Node.SSHSessions.Any(session => session.Kind == WWCPNode.SSHSession.SFTP) && waited < 100; waited++)
                await Task.Delay(50);

            Assert.That(Node.SSHSessions.Where(session => session.Kind == WWCPNode.SSHSession.SFTP), Is.Empty, "the session is still shown after it ended");

        }

        #endregion

    }

}
