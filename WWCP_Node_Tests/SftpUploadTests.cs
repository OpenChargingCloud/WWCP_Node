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

using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Uploads over SFTP into an area that is written - which no area of the
    /// node itself is, so a test area of its own: an upload is put in place
    /// only when it is closed and its area's owner accepts it, and one that is
    /// refused, too large or unfinished leaves nothing behind; one under a
    /// temporary name is held until it is renamed into place; what a file
    /// replaces goes; and whoever may not write the area cannot.
    /// </summary>
    [TestFixture]
    public class SftpUploadTests
    {

        #region Data

        /// <summary>
        /// What the test area's files are called: a word and ".txt" or ".md".
        /// </summary>
        private static Boolean IsNote(String Name)

            => (Name.EndsWith(".txt", StringComparison.Ordinal) || Name.EndsWith(".md", StringComparison.Ordinal)) &&
               Name[..Name.LastIndexOf('.')].All(Char.IsAsciiLetterLower);

        private String                          directory  = "";
        private String                          notes      = "";
        private WWCPNode?                       node;
        private readonly List<SftpAreaChanged>  changes    = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-sftp-" + Guid.NewGuid().ToString("N")[..12]);
            notes     = Path.Combine(directory, "notes");

            Directory.CreateDirectory(directory);

            changes.Clear();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            node = null;

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion

        #region (private) Started(MaxFileSize) / SftpAs(Account) / AccountIn(Name, Role)

        /// <summary>
        /// A node with SFTP on, one area of notes written with "notes:edit" -
        /// which refuses a note that says "refuse", lets an ".md" note replace
        /// the ".txt" of its name, and holds two notes at most - and a role
        /// "support" from the file, which may read the name resolution and
        /// nothing else.
        /// </summary>
        private async Task<WWCPNode> Started(Int64? MaxFileSize = null)
        {

            node = await TestPorts.StartedOnFreshPorts(() => {

                File.WriteAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName),
                                  $$"""
                                  {
                                    "nts":   { "groups": { "legal": { "enabled": false } } },
                                    "ssh":   { "enabled": true, "port": {{TestPorts.Free()}}, "sftp": true },
                                    "roles": { "support": [ "dns:read" ] }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(directory, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                                        CertificatesPath:  Path.Combine(directory, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                var area = new SftpArea("notes",
                                        notes,
                                        IsNote,
                                        Read:   Permission.Read("notes"),
                                        Write:  Permission.Edit("notes")) {
                               AcceptName     = name => name.StartsWith("secret", StringComparison.Ordinal)
                                                            ? "A note is no place for a secret."
                                                            : null,
                               AcceptContent  = (name, file) => File.ReadAllText(file).Contains("refuse", StringComparison.Ordinal)
                                                                    ? $"'{name}' says it is to be refused."
                                                                    : null,
                               Replaces       = name => name.EndsWith(".md", StringComparison.Ordinal)
                                                            ? [ name[..^3] + ".txt" ]
                                                            : [],
                               MaxFileSize    = MaxFileSize,
                               MaxFiles       = 2
                           };

                area.Changed += changes.Add;

                made.AddSftpArea(area);

                return made;

            });

            return node;

        }

        /// <summary>
        /// The given account, let in with a key of its own, with an SFTP
        /// session open.
        /// </summary>
        private async Task<(SshClient Client, SftpClient Sftp)> SftpAs(String Account)
        {

            var key    = SshHostKey.GenerateEd25519();
            var added  = await node!.AuthorizeSSHKey(Account, SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine());

            Assert.That(added.IsAdded, Is.True, added.Reason);

            var client = await SshClient.ConnectAsync("127.0.0.1",
                                                      node.SSHPort!.Value.ToUInt16(),
                                                      new SshClientOptions {
                                                          Username       = Account,
                                                          VerifyHostKey  = blob => node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                                          Credentials    = [ key ]
                                                      });

            return (client, await client.OpenSftpClientAsync());

        }

        /// <summary>
        /// An account in the given role, in the node's organization.
        /// </summary>
        private async Task AccountIn(String  Name,
                                     String  Role)
        {

            Assert.That(node!.ExtAPI.TryGetOrganization(Organization_Id.Parse(node.Kind.Organization), out var organization) &&
                        organization is Organization, Is.True);

            await node.ExtAPI.CreateUser(User_Id.Parse(Name),
                                         I18NString.Create(Languages.en, Name),
                                         SimpleEMailAddress.Parse($"{Name}@localhost"),
                                         User2OrganizationEdgeLabel.IsMember,
                                         (Organization) organization!,
                                         Password:                  "Not-Used-Here-1",
                                         SkipDefaultNotifications:  true,
                                         SkipNewUserEMail:          true,
                                         SkipNewUserNotifications:  true,
                                         AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                         IsAuthenticated:           true);

            Assert.That(node.ExtAPI.TryGetUser(User_Id.Parse(Name), out var account) && account is User, Is.True);
            Assert.That(node.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group) && group is UserGroup, Is.True);

            await node.ExtAPI.AddUserToUserGroup((User) account!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

        }

        #endregion

        #region (private) Refusal(Operation) / OnDisk()

        /// <summary>
        /// The status and the sentence SFTP refused the given operation with -
        /// or null, where it was not refused.
        /// </summary>
        private static async Task<(SftpStatusCode Code, String Why)?> Refusal(Func<Task> Operation)
        {

            try
            {
                await Operation();
                return null;
            }
            catch (SftpException refused)
            {
                return (refused.Code, refused.Message);
            }

        }

        /// <summary>
        /// Every file in the area's directory, hidden ones included.
        /// </summary>
        private IReadOnlyList<String> OnDisk()

            => Directory.Exists(notes)
                   ? [.. Directory.GetFiles(notes).Select(file => Path.GetFileName(file)!).Order(StringComparer.Ordinal)]
                   : [];

        #endregion


        #region AnUploadIsInPlaceOnceItIsClosedAndNotBefore

        /// <summary>
        /// Written, an upload is under a hidden name that no listing shows; put
        /// in place when it is closed, with one rename; told to whoever listens
        /// once.
        /// </summary>
        [Test]
        public async Task AnUploadIsInPlaceOnceItIsClosedAndNotBefore()
        {

            await Started();

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            String[] whileWritten;
            IReadOnlyList<String> listedWhileWritten;

            await using (var upload = await sftp.OpenFileStreamAsync("/notes/hello.txt", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate))
            {

                await upload.WriteAsync("Hello, station."u8.ToArray());
                await upload.FlushAsync();

                whileWritten        = [.. OnDisk()];
                listedWhileWritten  = [.. (await sftp.ListDirectoryAsync("/notes")).Select(entry => entry.Name).Where(name => name is not "." and not "..")];

            }

            Assert.Multiple(() => {
                Assert.That(whileWritten,                                               Has.Length.EqualTo(1).And.All.StartsWith(SftpArea.UploadPrefix), "while it is written, the upload is not under its name");
                Assert.That(listedWhileWritten,                                         Is.Empty,  "an upload being written is listed");
                Assert.That(OnDisk(),                                                   Is.EqualTo(new[] { "hello.txt" }));
                Assert.That(File.ReadAllText(Path.Combine(notes, "hello.txt")),         Is.EqualTo("Hello, station."));
                Assert.That(changes.Select(change => (change.Name, change.Change)),     Is.EqualTo(new[] { ("hello.txt", SftpAreaChange.PutInPlace) }));
                Assert.That(changes.Single().Account.Id.ToString(),                     Is.EqualTo(WWCPNode.DefaultAdminUser));
            });

        }

        #endregion

        #region AnUploadItsOwnerRefusesLeavesWhatWasThere

        /// <summary>
        /// Refused when it is closed: told why, and the file of that name is
        /// what it was - nothing of the upload is left, nothing is told.
        /// </summary>
        [Test]
        public async Task AnUploadItsOwnerRefusesLeavesWhatWasThere()
        {

            await Started();

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "What was there.");

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            var refused        = await Refusal(async () => await sftp.UploadAsync("/notes/hello.txt", "Please refuse me."u8.ToArray()));

            Assert.Multiple(() => {
                Assert.That(refused?.Code,                                         Is.EqualTo(SftpStatusCode.Failure));
                Assert.That(refused?.Why,                                          Is.EqualTo("'hello.txt' says it is to be refused."));
                Assert.That(OnDisk(),                                              Is.EqualTo(new[] { "hello.txt" }), "something of the refused upload was left");
                Assert.That(File.ReadAllText(Path.Combine(notes, "hello.txt")),    Is.EqualTo("What was there."));
                Assert.That(changes,                                               Is.Empty);
            });

        }

        #endregion

        #region AnUploadTooLargeLeavesWhatWasThere

        /// <summary>
        /// Larger than the area takes: refused as soon as it would be, and the
        /// file of that name is what it was.
        /// </summary>
        [Test]
        public async Task AnUploadTooLargeLeavesWhatWasThere()
        {

            await Started(MaxFileSize: 1024);

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "What was there.");

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            var refused        = await Refusal(async () => await sftp.UploadAsync("/notes/hello.txt", Encoding.ASCII.GetBytes(new String('x', 4096))));

            Assert.Multiple(() => {
                Assert.That(refused?.Code,                                         Is.EqualTo(SftpStatusCode.Failure));
                Assert.That(refused?.Why,                                          Does.Contain("larger than 1 KiB"));
                Assert.That(OnDisk(),                                              Is.EqualTo(new[] { "hello.txt" }), "something of the upload was left");
                Assert.That(File.ReadAllText(Path.Combine(notes, "hello.txt")),    Is.EqualTo("What was there."));
            });

        }

        #endregion

        #region AnUploadUnderATemporaryNameIsHeldUntilItIsRenamedIntoPlace

        /// <summary>
        /// As WinSCP uploads a larger file: under "&lt;name&gt;.filepart", which is
        /// held when it is closed - on no disk under either name, in no listing,
        /// looked at by the session that wrote it - and put in place over the
        /// file there when it is renamed. Checked when it is closed, before a
        /// client takes the file it replaces away.
        /// </summary>
        [Test]
        public async Task AnUploadUnderATemporaryNameIsHeldUntilItIsRenamedIntoPlace()
        {

            await Started();

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "What was there.");

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            var refused        = await Refusal(async () => await sftp.UploadAsync("/notes/hello.txt.filepart", "Please refuse me."u8.ToArray()));

            await sftp.UploadAsync("/notes/hello.txt.filepart", "What is new."u8.ToArray());

            var heldSize       = (await sftp.StatAsync("/notes/hello.txt.filepart")).Size;
            var listed         = (await sftp.ListDirectoryAsync("/notes")).Select(entry => entry.Name).ToList();
            var whileHeld      = File.ReadAllText(Path.Combine(notes, "hello.txt"));
            var changedBefore  = changes.Count;

            await sftp.PosixRenameAsync("/notes/hello.txt.filepart", "/notes/hello.txt");

            Assert.Multiple(() => {
                Assert.That(refused?.Why,                                          Is.EqualTo("'hello.txt' says it is to be refused."), "a refused upload under a temporary name was held");
                Assert.That(heldSize,                                              Is.EqualTo("What is new."u8.Length));
                Assert.That(listed,                                                Does.Not.Contain("hello.txt.filepart"));
                Assert.That(whileHeld,                                             Is.EqualTo("What was there."), "the held upload took the place of the file before it was renamed");
                Assert.That(changedBefore,                                         Is.Zero);
                Assert.That(OnDisk(),                                              Is.EqualTo(new[] { "hello.txt" }), "something of the held upload was left");
                Assert.That(File.ReadAllText(Path.Combine(notes, "hello.txt")),    Is.EqualTo("What is new."));
                Assert.That(changes.Select(change => (change.Name, change.Change)).Last(), Is.EqualTo(("hello.txt", SftpAreaChange.PutInPlace)));
            });

        }

        #endregion

        #region AnUploadUnderATemporaryNameNeverRenamedGoesWithItsSession

        /// <summary>
        /// Held and never renamed: thrown away with the session, and nothing of
        /// it is left.
        /// </summary>
        [Test]
        public async Task AnUploadUnderATemporaryNameNeverRenamedGoesWithItsSession()
        {

            await Started();

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using (client)
            {
                await using (sftp)
                    await sftp.UploadAsync("/notes/hello.txt.filepart", "Never renamed."u8.ToArray());
            }

            for (var waited = 0; node!.SSHSessions.Count > 0 && waited < 100; waited++)
                await Task.Delay(50);

            Assert.Multiple(() => {
                Assert.That(node!.SSHSessions,  Is.Empty, "the session did not end");
                Assert.That(OnDisk(),           Is.Empty, "the held upload outlived its session");
                Assert.That(changes,            Is.Empty);
            });

        }

        #endregion

        #region ANameTheAreaDoesNotTakeIsRefusedBeforeAByteIsSent

        /// <summary>
        /// A name the area's owner refuses, one the area does not show, and one
        /// that would lie outside the area: refused when it is opened, with a
        /// sentence - and nothing is written.
        /// </summary>
        [Test]
        public async Task ANameTheAreaDoesNotTakeIsRefusedBeforeAByteIsSent()
        {

            await Started();

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            var secret         = await Refusal(async () => await sftp.UploadAsync("/notes/secret.txt",  "x"u8.ToArray()));
            var shown          = await Refusal(async () => await sftp.UploadAsync("/notes/Hello.exe",   "x"u8.ToArray()));
            var outside        = await Refusal(async () => await sftp.UploadAsync("/notes/../hello.txt", "x"u8.ToArray()));

            Assert.Multiple(() => {
                Assert.That(secret,   Is.EqualTo((SftpStatusCode.PermissionDenied, "A note is no place for a secret.")));
                Assert.That(shown,    Is.EqualTo((SftpStatusCode.PermissionDenied, "/notes takes no file called 'Hello.exe'.")));
                Assert.That(outside?.Code, Is.EqualTo(SftpStatusCode.PermissionDenied));
                Assert.That(OnDisk(), Is.Empty);
            });

        }

        #endregion

        #region AFileTakesThePlaceOfWhatItReplaces

        /// <summary>
        /// "hello.md" put in place takes the place of "hello.txt", which goes,
        /// and both are told - and the area's most files counts the file that
        /// goes as gone.
        /// </summary>
        [Test]
        public async Task AFileTakesThePlaceOfWhatItReplaces()
        {

            await Started();

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "Plain.");

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            await sftp.UploadAsync("/notes/hello.md", "# Marked down."u8.ToArray());

            Assert.Multiple(() => {
                Assert.That(OnDisk(),                                                Is.EqualTo(new[] { "hello.md" }));
                Assert.That(changes.Select(change => (change.Name, change.Change)),  Is.EquivalentTo(new[] { ("hello.md",  SftpAreaChange.PutInPlace),
                                                                                                            ("hello.txt", SftpAreaChange.Removed) }));
            });

        }

        #endregion

        #region AnAreaHoldsNoMoreFilesThanItSays

        /// <summary>
        /// The third note is refused when it is opened; a note of a name that is
        /// there replaces it and is not refused.
        /// </summary>
        [Test]
        public async Task AnAreaHoldsNoMoreFilesThanItSays()
        {

            await Started();

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "one.txt"), "1");
            File.WriteAllText(Path.Combine(notes, "two.txt"), "2");

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            var third          = await Refusal(async () => await sftp.UploadAsync("/notes/three.txt", "3"u8.ToArray()));
            var again          = await Refusal(async () => await sftp.UploadAsync("/notes/two.txt",   "2 again"u8.ToArray()));

            Assert.Multiple(() => {
                Assert.That(third?.Why,  Does.Contain("holds 2 file(s) at most"));
                Assert.That(again,       Is.Null);
                Assert.That(OnDisk(),    Is.EqualTo(new[] { "one.txt", "two.txt" }));
            });

        }

        #endregion

        #region WritingNeedsWhatTheAreaSays

        /// <summary>
        /// An account whose role may not edit the notes may neither upload nor
        /// remove one, and is told what it needs - and is not shown the area
        /// either, as it may not read it.
        /// </summary>
        [Test]
        public async Task WritingNeedsWhatTheAreaSays()
        {

            await Started();

            await AccountIn("supporter", "support");

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "What was there.");

            var (client, sftp) = await SftpAs("supporter");

            await using var _  = client;
            await using var __ = sftp;

            var upload         = await Refusal(async () => await sftp.UploadAsync("/notes/other.txt", "x"u8.ToArray()));
            var remove         = await Refusal(async () => await sftp.RemoveAsync("/notes/hello.txt"));
            var root           = (await sftp.ListDirectoryAsync("/")).Select(entry => entry.Name).ToList();

            Assert.Multiple(() => {
                Assert.That(upload,   Is.EqualTo((SftpStatusCode.PermissionDenied, "Writing /notes needs notes:edit.")));
                Assert.That(remove,   Is.EqualTo((SftpStatusCode.PermissionDenied, "Writing /notes needs notes:edit.")));
                Assert.That(root,     Does.Not.Contain("notes"));
                Assert.That(OnDisk(), Is.EqualTo(new[] { "hello.txt" }));
            });

        }

        #endregion

        #region OfAFileOnlyItsTimesAreSet

        /// <summary>
        /// What WinSCP sets after an upload - the modification time - is set;
        /// permissions are refused as a whole, and the time with them is not
        /// set.
        /// </summary>
        [Test]
        public async Task OfAFileOnlyItsTimesAreSet()
        {

            await Started();

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "Hello.");

            var (client, sftp) = await SftpAs(WWCPNode.DefaultAdminUser);

            await using var _  = client;
            await using var __ = sftp;

            var then           = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
            var later          = then.AddDays(1);

            await sftp.SetAttributesAsync("/notes/hello.txt", new SftpFileAttributes { ModifyTime = then, AccessTime = then });

            var permissions    = await Refusal(async () => await sftp.SetAttributesAsync("/notes/hello.txt", new SftpFileAttributes { Permissions = 0x1FF, ModifyTime = later }));

            Assert.Multiple(() => {
                Assert.That(File.GetLastWriteTimeUtc(Path.Combine(notes, "hello.txt")),  Is.EqualTo(then.UtcDateTime));
                Assert.That(permissions?.Code,                                            Is.EqualTo(SftpStatusCode.OpUnsupported));
            });

        }

        #endregion

        #region AnUploadThatNeverFinishedGoesAtTheNextStart

        /// <summary>
        /// What an upload left under its hidden name when the node stopped in
        /// the middle of it is taken away at the next start.
        /// </summary>
        [Test]
        public async Task AnUploadThatNeverFinishedGoesAtTheNextStart()
        {

            Directory.CreateDirectory(notes);
            File.WriteAllText(Path.Combine(notes, SftpArea.UploadPrefix + "left-by-a-crash"), "half");
            File.WriteAllText(Path.Combine(notes, "hello.txt"), "Hello.");

            await Started();

            Assert.That(OnDisk(), Is.EqualTo(new[] { "hello.txt" }));

        }

        #endregion

    }

}
