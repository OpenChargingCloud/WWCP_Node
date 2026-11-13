/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using System.Security.Cryptography;

using NUnit.Framework;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// File transfers a node makes on request, by the white paper "SFTP for
    /// Logfile Uploads and Firmware Downloads": the URL of a request chooses
    /// among the file servers the node holds and never introduces one; the host
    /// key comes from the node's configuration and never from the first
    /// handshake; the node signs in with a key per file server and login.
    /// </summary>
    [TestFixture]
    public class FileTransferTests
    {

        #region Data

        private const String  Login = WWCPNode.DefaultAdminUser;

        private String     directory  = "";
        private String     uploads    = "";
        private String     firmware   = "";
        private WWCPNode?  server;
        private WWCPNode?  node;

        private readonly List<(FileTransferJudgement Judgement, FileTransferDirections Direction)>  refused    = [];
        private readonly List<(SSHFileServer Server, String Shown)>                                 foreignKeys = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-filetransfer-" + Guid.NewGuid().ToString("N")[..12]);
            uploads   = Path.Combine(directory, "server", "upload");
            firmware  = Path.Combine(directory, "server", "firmware");
            Directory.CreateDirectory(uploads);
            Directory.CreateDirectory(firmware);
            Directory.CreateDirectory(Path.Combine(directory, "node"));
            refused.    Clear();
            foreignKeys.Clear();
        }

        [TearDown]
        public async Task TearDown()
        {

            if (node   is not null) await node.  DisposeAsync();
            if (server is not null) await server.DisposeAsync();

            node    = null;
            server  = null;

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion

        #region (private) TheServer() / TheNode() / FileServer(...) / Enrolled(...)

        /// <summary>
        /// A node whose SSH server serves two areas over SFTP: /upload and /firmware.
        /// </summary>
        private async Task<WWCPNode> TheServer()
        {

            var home = Path.Combine(directory, "server");

            server = await TestPorts.StartedOnFreshPorts(() => {

                File.WriteAllText(Path.Combine(home, WWCPConfigFile.DefaultFileName),
                                  $$"""
                                  {
                                    "nts":   { "groups": { "legal": { "enabled": false } } },
                                    "ssh":   { "enabled": true, "port": {{TestPorts.Free()}}, "sftp": true }
                                  }
                                  """);

                var made = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                        AccountsPath:      Path.Combine(home, "accounts"),
                                        ConfigFile:        new WWCPConfigFile(Path.Combine(home, WWCPConfigFile.DefaultFileName)),
                                        CertificatesPath:  Path.Combine(home, "certificates"),
                                        LogToConsole:      false,
                                        BridgeDebugLog:    false);

                made.AddSftpArea(new SftpArea("upload",   uploads,  name => true, Read: Permission.Read("upload"),   Write: Permission.Edit("upload")));
                made.AddSftpArea(new SftpArea("firmware", firmware, name => true, Read: Permission.Read("firmware"), Write: Permission.Edit("firmware")));

                return made;

            });

            return server;

        }

        /// <summary>
        /// The node that is asked to move files. It listens nowhere.
        /// </summary>
        private WWCPNode TheNode()
        {

            var home = Path.Combine(directory, "node");

            File.WriteAllText(Path.Combine(home, WWCPConfigFile.DefaultFileName),
                              """
                              {
                                "nts":   { "groups": { "legal": { "enabled": false } } },
                                "ssh":   { "enabled": false }
                              }
                              """);

            node = new WWCPNode(HTTPPort:          IPPort.Parse(TestPorts.Free()),
                                AccountsPath:      Path.Combine(home, "accounts"),
                                ConfigFile:        new WWCPConfigFile(Path.Combine(home, WWCPConfigFile.DefaultFileName)),
                                CertificatesPath:  Path.Combine(home, "certificates"),
                                LogToConsole:      false,
                                BridgeDebugLog:    false);

            node.OnFileTransferRefused       += (judgement, direction) => refused.    Add((judgement, direction));
            node.OnFileServerHostKeyRefused  += (fileServer, shown)    => foreignKeys.Add((fileServer, shown));

            return node;

        }

        private String Pin
            => server!.SSHHostKey!.Split(' ')[1];

        private UInt16 Port
            => server!.SSHPort!.Value.ToUInt16();

        private SSHFileServer FileServer(String?                  Pin            = null,
                                         UInt16?                  Port           = null,
                                         FileTransferDirections   Directions     = FileTransferDirections.Upload | FileTransferDirections.Download,
                                         String[]?                Users          = null,
                                         SSHConnection            Connection     = SSHConnection.Dedicated,
                                         String?                  User           = Login)

            => new ("files",
                    "127.0.0.1",
                    User,
                    new NTSServerSSH(Port ?? this.Port, HostKeyPins: [ Pin ?? this.Pin ]),
                    new SSHFileTransfers(Directions,
                                         Users,
                                         UploadPaths:    [ "/upload/" ],
                                         DownloadPaths:  [ "/firmware/" ],
                                         Connection:     Connection));

        /// <summary>
        /// The node holds the file server, the server holds the node's key for
        /// the login, and somebody confirmed that.
        /// </summary>
        private async Task Enrolled(Func<SSHFileServer>? FileServer = null, Boolean AtTheServer = true, Boolean Confirmed = true)
        {

            await TheServer();
            TheNode();

            Assert.That(await Hold(FileServer?.Invoke() ?? this.FileServer()), Is.Null);

            var line = node.FileTransferPublicKey("files", Login);
            Assert.That(line, Does.StartWith("ssh-ed25519 "));

            if (AtTheServer)
            {
                var added = await server!.AuthorizeSSHKey(Login, line!);
                Assert.That(added.IsAdded, Is.True, added.Reason);
            }

            if (Confirmed)
                Assert.That(node.ConfirmFileTransferKey("files", Login, line), Is.Null);

        }

        /// <summary>
        /// The SSH peers of the node from now on, each of them a file server:
        /// written into its configuration, as the page and OCPP write them.
        /// </summary>
        /// <returns>Why they are not taken, or null.</returns>
        private async Task<String?> Hold(params SSHFileServer[] FileServers)

            => (await node!.TryUpdateSSHPeers(peers => new JArray(FileServers.Select(fileServer => new SSHPeerConfiguration(fileServer.Id,
                                                                                                                                  DomainName.Parse(fileServer.Address),
                                                                                                                                  fileServer.User,
                                                                                                                                  fileServer.Trust,
                                                                                                                                  fileServer.FileTransfers).ToJSON())))).Error;

        /// <summary>
        /// The same from the JSON of the configuration file.
        /// </summary>
        private async Task<String?> HoldJSON(String Peers)
            => (await node!.TryUpdateSSHPeers(peers => JArray.Parse(Peers))).Error;

        private String URL(String Path, String? User = Login, UInt16? Port = null, String Host = "127.0.0.1")
            => $"sftp://{(User is null ? "" : User + "@")}{Host}:{Port ?? this.Port}{Path}";

        #endregion


        #region AURLIsReadAsThePaperReadsIt

        [Test]
        public void AURLIsReadAsThePaperReadsIt()
        {

            Assert.That(SftpLocation.TryParse("sftp://cs001@Logs.Example.ORG:2222/upload/cs001/", out var full, out _), Is.True);
            Assert.That(full!.Host,             Is.EqualTo("logs.example.org"));
            Assert.That(full.Port,              Is.EqualTo(2222));
            Assert.That(full.User,              Is.EqualTo("cs001"));
            Assert.That(full.Path,              Is.EqualTo("/upload/cs001/"));
            Assert.That(full.RemotePath,        Is.EqualTo("/upload/cs001/"));
            Assert.That(full.FileIn("a.log"),   Is.EqualTo("/upload/cs001/a.log"));
            Assert.That(full.WithoutUserInfo,   Is.EqualTo("sftp://logs.example.org:2222/upload/cs001/"));

            Assert.That(SftpLocation.TryParse("SFTP://logs.example.org/firmware/image%20v2.bin", out var plain, out _), Is.True);
            Assert.That(plain!.Port,            Is.EqualTo(22));
            Assert.That(plain.User,             Is.Null);
            Assert.That(plain.Path,             Is.EqualTo("/firmware/image v2.bin"));

            // Decoded once: what is still encoded after that is a part of the name.
            Assert.That(SftpLocation.TryParse("sftp://h.example/a%252Fb", out var once, out _), Is.True);
            Assert.That(once!.Path,             Is.EqualTo("/a%2Fb"));

            // Relative to the home directory of the login.
            Assert.That(SftpLocation.TryParse("sftp://cs001@h.example/~/upload", out var home, out _), Is.True);
            Assert.That(home!.IsHomeRelative,   Is.True);
            Assert.That(home.RemotePath,        Is.EqualTo("upload"));
            Assert.That(home.FileIn("a.log"),   Is.EqualTo("upload/a.log"));

            Assert.That(SftpLocation.TryParse("sftp://[2001:DB8::1]:2022/x", out var v6, out _), Is.True);
            Assert.That(v6!.Host,               Is.EqualTo("2001:db8::1"));
            Assert.That(v6.Port,                Is.EqualTo(2022));
            Assert.That(v6.WithoutUserInfo,     Is.EqualTo("sftp://[2001:db8::1]:2022/x"));

            // What the URL expects of the host key is kept, in SHA-256 only.
            Assert.That(SftpLocation.TryParse("sftp://cs001;fingerprint=SHA256:hOEj1ea61PSArpO3%2Fqj2Drlp024D2eiJ7DJQNNLl+hU@h.example/x", out var expecting, out _), Is.True);
            Assert.That(expecting!.User,        Is.EqualTo("cs001"));
            Assert.That(expecting.Fingerprint,  Is.EqualTo("SHA256:hOEj1ea61PSArpO3/qj2Drlp024D2eiJ7DJQNNLl+hU"));

            Assert.That(SftpLocation.TryParse("sftp://cs001;fingerprint=ssh-dss-c1-b1-30-29-d7-b8-de-6c-97-77-10-d7-46-41-63-87@h.example/x", out var md5, out _), Is.True);
            Assert.That(md5!.Fingerprint,       Is.Null, "any other notation says nothing");

        }

        #endregion

        #region AURLThatIsNoLocationIsNotRepaired

        [TestCase("",                                              "no URL")]
        [TestCase("https://logs.example.org/upload/",              "no sftp")]
        [TestCase("sftp://logs.example.org",                       "no path")]
        [TestCase("sftp://cs001:secret@logs.example.org/upload/",  "password")]
        [TestCase("sftp://logs.example.org/upload/?x=1",           "query")]
        [TestCase("sftp://logs.example.org/upload/#top",           "fragment")]
        [TestCase("sftp://logs.example.org/upload/../etc/",        "'..'")]
        [TestCase("sftp://logs.example.org/upload/%2e%2e/etc/",    "'..'")]
        [TestCase("sftp://logs.example.org/upload/a%00b",          "control")]
        [TestCase("sftp://logs.example.org/upload/a%0Ab",          "control")]
        [TestCase("sftp://logs.example.org/upload/a%zzb",          "percent-encoded")]
        [TestCase("sftp://logs.example.org/upload/a b",            "blank")]
        [TestCase("sftp://logs.example.org:0/upload/",             "port")]
        [TestCase("sftp://logs.example.org:65536/upload/",         "port")]
        [TestCase("sftp://logs.example.org:22x/upload/",           "port")]
        [TestCase("sftp://1.2.3/upload/",                          "neither")]
        [TestCase("sftp://logs..example.org/upload/",              "neither")]
        [TestCase("sftp:///upload/",                               "neither")]
        [TestCase("sftp://ro ot@logs.example.org/upload/",         "blank")]
        [TestCase("sftp://-rf@logs.example.org/upload/",           "login")]
        public void AURLThatIsNoLocationIsNotRepaired(String URL, String Says)
        {

            Assert.That(SftpLocation.TryParse(URL, out var location, out var error), Is.False, URL);
            Assert.That(location,  Is.Null);
            Assert.That(error,     Does.Contain(Says));
            Assert.That(error,     Does.Not.Contain("secret"), "an error never repeats a password");

        }

        #endregion

        #region HostsAreComparedAsText

        [Test]
        public void HostsAreComparedAsText()
        {

            Assert.That(SftpLocation.NormalizeHost("LOGS.Example.org."),   Is.EqualTo("logs.example.org"));
            Assert.That(SftpLocation.NormalizeHost("127.0.0.1"),           Is.EqualTo("127.0.0.1"));
            Assert.That(SftpLocation.NormalizeHost("[::1]"),               Is.EqualTo("::1"));
            Assert.That(SftpLocation.NormalizeHost("2001:0db8:0::0001"),   Is.EqualTo("2001:db8::1"));
            Assert.That(SftpLocation.NormalizeHost("1.2.3"),               Is.Null);
            Assert.That(SftpLocation.NormalizeHost("not a host"),          Is.Null);
            Assert.That(SftpLocation.NormalizeHost(""),                    Is.Null);

            // A name is no address and an address no name, whatever DNS would say.
            Assert.That(SftpLocation.NormalizeHost("localhost"),           Is.Not.EqualTo(SftpLocation.NormalizeHost("127.0.0.1")));

        }

        #endregion

        #region WhatAFileServerMayBeUsedForIsReadAndWritten

        [Test]
        public void WhatAFileServerMayBeUsedForIsReadAndWritten()
        {

            var json = JObject.Parse("""
                                     {
                                       "directions":     [ "upload", "download" ],
                                       "users":          [ "cs001", "cs001-fw" ],
                                       "uploadPaths":    [ "/upload/{id}" ],
                                       "downloadPaths":  [ "/firmware/", "~/images/" ],
                                       "connection":     "shared"
                                     }
                                     """);

            Assert.That(SSHFileTransfers.TryParse(json, "ssh.peers[0].fileTransfers", out var read, out var error), Is.True, error);

            Assert.That(read!.Allows(FileTransferDirections.Upload),     Is.True);
            Assert.That(read.Allows(FileTransferDirections.Download),    Is.True);
            Assert.That(read.IsShared,                                   Is.True);
            Assert.That(read.UploadPaths,                                Is.EqualTo(new[] { "/upload/{id}/" }), "a directory ends with its slash");

            Assert.That(read.AllowsLogin("cs001-fw", "cs001"),           Is.True);
            Assert.That(read.AllowsLogin("root",     "cs001"),           Is.False);

            // An upload names the directory, with or without its slash; the identity stands for {id}.
            Assert.That(read.AllowsPath(FileTransferDirections.Upload,   "/upload/cs001",       "cs001"), Is.True);
            Assert.That(read.AllowsPath(FileTransferDirections.Upload,   "/upload/cs001/logs/", "cs001"), Is.True);
            Assert.That(read.AllowsPath(FileTransferDirections.Upload,   "/upload/cs002/",      "cs001"), Is.False);
            Assert.That(read.AllowsPath(FileTransferDirections.Upload,   "/upload/cs0011/",     "cs001"), Is.False, "another station whose name only starts alike");
            Assert.That(read.AllowsPath(FileTransferDirections.Upload,   "/firmware/",          "cs001"), Is.False, "a directory of the other direction");

            // A download names a file in a directory, not the directory.
            Assert.That(read.AllowsPath(FileTransferDirections.Download, "/firmware/a.bin",     "cs001"), Is.True);
            Assert.That(read.AllowsPath(FileTransferDirections.Download, "~/images/a.bin",      "cs001"), Is.True);
            Assert.That(read.AllowsPath(FileTransferDirections.Download, "/firmware/",          "cs001"), Is.False);
            Assert.That(read.AllowsPath(FileTransferDirections.Download, "/firmware2/a.bin",    "cs001"), Is.False);
            Assert.That(read.AllowsPath(FileTransferDirections.Download, "/images/a.bin",       "cs001"), Is.False, "below the home directory is not below the root");

            Assert.That(SSHFileTransfers.TryParse(read.ToJSON(), "x", out var again, out _), Is.True);
            Assert.That(again!.ToJSON().ToString(), Is.EqualTo(read.ToJSON().ToString()));

            // Without logins, only the login of the peer; without directories, nowhere.
            var bare = new SSHFileTransfers(FileTransferDirections.Upload);
            Assert.That(bare.AllowsLogin("cs001", "cs001"),                                       Is.True);
            Assert.That(bare.AllowsLogin("other", "cs001"),                                       Is.False);
            Assert.That(bare.AllowsPath(FileTransferDirections.Upload, "/upload/", "cs001"),      Is.False);
            Assert.That(bare.Allows(FileTransferDirections.Download),                             Is.False);

            foreach (var wrong in new[] {
                         """{ "directions": [ "sideways" ] }""",
                         """{ "directions": [ "upload" ], "users": [ "-rf" ] }""",
                         """{ "directions": [ "upload" ], "uploadPaths": [ "upload/" ] }""",
                         """{ "directions": [ "upload" ], "uploadPaths": [ "/upload/../etc/" ] }""",
                         """{ "directions": [ "upload" ], "connection": "both" }"""
                     })
            {
                Assert.That(SSHFileTransfers.TryParse(JObject.Parse(wrong), "x", out _, out var why), Is.False, wrong);
                Assert.That(why, Is.Not.Empty);
            }

        }

        #endregion

        #region AFileServerNobodyCouldBelieveIsNone

        [Test]
        public async Task AFileServerNobodyCouldBelieveIsNone()
        {

            TheNode();

            const String pin = "SHA256:hOEj1ea61PSArpO3/qj2Drlp024D2eiJ7DJQNNLl+hU";

            String Peer(String Id, String Address, String Rest)
                => $$"""{ "id": "{{Id}}", "address": "{{Address}}", {{Rest}} }""";

            const String uploads = """ "fileTransfers": { "directions": [ "upload" ], "uploadPaths": [ "/upload/" ] } """;

            // Held to no host key and no CA: a peer nobody could believe is never stored.
            Assert.That(await HoldJSON($"[ {Peer("files", "logs.example.org", uploads)} ]"),
                        Does.Contain("held to no host key"));

            // What it may be used for is read as strictly as the rest of its entry.
            foreach (var (wrong, says) in new[] {
                         (""" "fileTransfers": { "directions": [ "sideways" ] } """,                                 "neither \"upload\" nor \"download\""),
                         (""" "fileTransfers": { "directions": [ "upload" ], "uploadPaths": [ "upload/" ] } """,     "is no directory"),
                         (""" "fileTransfers": { "directions": [ "upload" ], "uploadPaths": [ "/a/../b/" ] } """,    "'..'"),
                         (""" "fileTransfers": { "directions": [ "upload" ], "users": [ "-rf" ] } """,               "is no login"),
                         (""" "fileTransfers": { "directions": [ "upload" ], "connection": "both" } """,             "neither \"dedicated\" nor \"shared\""),
                         (""" "fileTransfers": "yes" """,                                                            "must be an object")
                     })
            {
                var error = await HoldJSON($$"""[ {{Peer("files", "logs.example.org", $"\"hostKeyPins\": [ \"{pin}\" ], {wrong}")}} ]""");
                Assert.That(error, Does.Contain(says).And.Contain("fileTransfers"), wrong);
            }

            Assert.That(node!.FileServers, Is.Empty, "nothing of what was refused is held");

            // A peer without "fileTransfers" is a peer, and no file server.
            Assert.That(await HoldJSON($$"""[ {{Peer("time", "time.example.org", $"\"hostKeyPins\": [ \"{pin}\" ]")}} ]"""), Is.Null);
            Assert.That(node.ConfiguredSSHPeers,  Has.Count.EqualTo(1));
            Assert.That(node.FileServers,         Is.Empty);
            Assert.That(node.JudgeFileTransfer("sftp://time.example.org/upload/", FileTransferDirections.Upload).Why, Does.Contain("is no file server"));

            // With it, it is one - and what it may be used for is written back as it was read.
            Assert.That(await HoldJSON($$"""[ {{Peer("files", "LOGS.example.org", $"\"port\": 2222, \"hostKeyPins\": [ \"{pin}\" ], {uploads}")}} ]"""), Is.Null);

            Assert.That(node.FileServers.Select(fileServer => (fileServer.Id, fileServer.Host, fileServer.Port)),
                        Is.EqualTo(new[] { ("files", "logs.example.org", (UInt16) 2222) }));

            Assert.That(node.ConfiguredSSHPeers[0].ToJSON()["fileTransfers"]!["uploadPaths"]!.Values<String>(), Is.EqualTo(new[] { "/upload/" }));

            // One peer per address: an SFTP server on a second port of that host is no second peer.
            Assert.That(await HoldJSON($$"""
                                         [ {{Peer("a", "logs.example.org", $"\"hostKeyPins\": [ \"{pin}\" ], {uploads}")}},
                                           {{Peer("b", "logs.example.org", $"\"port\": 2222, \"hostKeyPins\": [ \"{pin}\" ], {uploads}")}} ]
                                         """),
                        Does.Contain("one connection to a host"));

        }

        #endregion


        #region AFileIsUploadedUnderAnotherNameAndRenamed

        [Test]
        public async Task AFileIsUploadedUnderAnotherNameAndRenamed()
        {

            await Enrolled();

            var content  = RandomNumberGenerator.GetBytes(150_000);
            var progress = new List<Int64>();

            var result = await node!.UploadFileAsync(URL("/upload/"), new MemoryStream(content), "cs001_DiagnosticsLog_42.tar.gz", new Told(progress));

            Assert.That(result.Outcome,                           Is.EqualTo(FileTransferOutcome.Done), result.Why);
            Assert.That(result.Bytes,                             Is.EqualTo(content.Length));
            Assert.That(result.RemotePath,                        Is.EqualTo("/upload/cs001_DiagnosticsLog_42.tar.gz"));
            Assert.That(result.Judgement.Shared,                  Is.False);
            Assert.That(progress.Last(),                          Is.EqualTo(content.Length));

            Assert.That(Directory.GetFiles(uploads).Select(Path.GetFileName),
                        Is.EqualTo(new[] { "cs001_DiagnosticsLog_42.tar.gz" }), "the file is there under its name, and nothing else is");

            Assert.That(File.ReadAllBytes(Path.Combine(uploads, "cs001_DiagnosticsLog_42.tar.gz")), Is.EqualTo(content));
            Assert.That(refused, Is.Empty);

        }

        #endregion

        #region NothingIsWrittenOverAFileThatIsThere

        [Test]
        public async Task NothingIsWrittenOverAFileThatIsThere()
        {

            await Enrolled();

            var first = RandomNumberGenerator.GetBytes(1000);
            Assert.That((await node!.UploadFileAsync(URL("/upload/"), new MemoryStream(first), "a.log")).IsDone, Is.True);

            var again = await node.UploadFileAsync(URL("/upload/"), new MemoryStream(RandomNumberGenerator.GetBytes(2000)), "a.log");

            Assert.That(again.Outcome,          Is.EqualTo(FileTransferOutcome.FileExists));
            Assert.That(again.MayBeTriedAgain,  Is.False);
            Assert.That(File.ReadAllBytes(Path.Combine(uploads, "a.log")), Is.EqualTo(first), "the file that was there is untouched");

            // What an attempt before left behind is not written over either, and not removed.
            File.WriteAllBytes(Path.Combine(uploads, "b.log.part"), first);

            var overAPart = await node.UploadFileAsync(URL("/upload/"), new MemoryStream(RandomNumberGenerator.GetBytes(2000)), "b.log");

            Assert.That(overAPart.Outcome,      Is.EqualTo(FileTransferOutcome.FileExists));
            Assert.That(File.ReadAllBytes(Path.Combine(uploads, "b.log.part")), Is.EqualTo(first));
            Assert.That(File.Exists(Path.Combine(uploads, "b.log")),            Is.False);

            // And a name is a name: no path, and not the name of an unfinished upload.
            foreach (var name in new[] { "../a.log", "x/a.log", "a.log.part", "", "..", "a\nb" })
                Assert.That((await node.UploadFileAsync(URL("/upload/"), new MemoryStream(first), name)).Outcome, Is.EqualTo(FileTransferOutcome.Refused), name);

        }

        #endregion

        #region AFileIsDownloadedAndTakenUpWhereItStopped

        [Test]
        public async Task AFileIsDownloadedAndTakenUpWhereItStopped()
        {

            await Enrolled();

            var image = RandomNumberGenerator.GetBytes(120_000);
            File.WriteAllBytes(Path.Combine(firmware, "station-4.2.1.bin"), image);

            using var whole = new MemoryStream();
            var result = await node!.DownloadFileAsync(URL("/firmware/station-4.2.1.bin"), whole, MaxSize: image.Length);

            Assert.That(result.Outcome,     Is.EqualTo(FileTransferOutcome.Done), result.Why);
            Assert.That(result.Bytes,       Is.EqualTo(image.Length));
            Assert.That(whole.ToArray(),    Is.EqualTo(image));

            // What an interrupted attempt left, and the rest of it.
            using var resumed = new MemoryStream();
            resumed.Write(image, 0, 50_000);

            var rest = await node.DownloadFileAsync(URL("/firmware/station-4.2.1.bin"), resumed, Offset: 50_000);

            Assert.That(rest.Outcome,       Is.EqualTo(FileTransferOutcome.Done), rest.Why);
            Assert.That(rest.Bytes,         Is.EqualTo(image.Length - 50_000));
            Assert.That(resumed.ToArray(),  Is.EqualTo(image));

            // Larger than allowed: refused before a byte of it is read.
            using var none = new MemoryStream();
            var tooLarge = await node.DownloadFileAsync(URL("/firmware/station-4.2.1.bin"), none, MaxSize: image.Length - 1);

            Assert.That(tooLarge.Outcome,          Is.EqualTo(FileTransferOutcome.TooLarge));
            Assert.That(tooLarge.MayBeTriedAgain,  Is.False);
            Assert.That(none.Length,               Is.Zero);

            var missing = await node.DownloadFileAsync(URL("/firmware/no-such.bin"), none);

            Assert.That(missing.Outcome,           Is.EqualTo(FileTransferOutcome.NoSuchFile));
            Assert.That(missing.MayBeTriedAgain,   Is.False);

        }

        #endregion

        #region ARequestChoosesAmongFileServersAndNeverIntroducesOne

        [Test]
        public async Task ARequestChoosesAmongFileServersAndNeverIntroducesOne()
        {

            await Enrolled(() => FileServer(Directions: FileTransferDirections.Upload));

            FileTransferJudgement Upload(String Url)
                => node!.JudgeFileTransfer(Url, FileTransferDirections.Upload);

            Assert.That(Upload(URL("/upload/")).IsAllowed, Is.True);
            Assert.That(refused, Is.Empty);

            var cases = new (String What, FileTransferJudgement Judgement, String Says)[] {
                ("another host",                   Upload(URL("/upload/", Host: "127.0.0.2")),                                         "is no file server"),
                ("a name for the address",         Upload(URL("/upload/", Host: "localhost")),                                         "is no file server"),
                ("the right host on another port", Upload(URL("/upload/", Port: (UInt16) (Port + 1))),                                 "is no file server"),
                ("the other direction",            node!.JudgeFileTransfer(URL("/firmware/a.bin"), FileTransferDirections.Download),   "is not allowed downloads"),
                ("a login that is not listed",     Upload(URL("/upload/", User: "somebody")),                                          "is no login"),
                ("a path outside",                 Upload(URL("/firmware/")),                                                          "lies in no directory"),
                ("a path that only starts alike",  Upload(URL("/upload2/")),                                                           "lies in no directory"),
                ("another host key expected",      Upload($"sftp://{Login};fingerprint=SHA256:hOEj1ea61PSArpO3%2Fqj2Drlp024D2eiJ7DJQNNLl+hU@127.0.0.1:{Port}/upload/"), "expects the host key")
            };

            foreach (var (what, judgement, says) in cases)
            {
                Assert.That(judgement.IsAllowed,  Is.False, what);
                Assert.That(judgement.Refusal,    Is.EqualTo(FileTransferRefusal.FileServerNotPermitted), what + ": one code for all of them");
                Assert.That(judgement.Why,        Does.Contain(says), what);
            }

            Assert.That(refused, Has.Count.EqualTo(cases.Length), "each of them is reported: somebody asked for a place the node does not know");

            // The key the URL expects and the server is held to: no contradiction.
            Assert.That(Upload($"sftp://{Login};fingerprint={Uri.EscapeDataString(Pin)}@127.0.0.1:{Port}/upload/").IsAllowed, Is.True);

            // A malformed URL is a mistake, and is told so.
            var malformed = Upload($"sftp://{Login}:secret@127.0.0.1:{Port}/upload/");
            Assert.That(malformed.Refusal,  Is.EqualTo(FileTransferRefusal.InvalidURL));
            Assert.That(refused,            Has.Count.EqualTo(cases.Length), "and is no security event");

            // A transfer that is refused sends nothing.
            var notSent = await node.UploadFileAsync(URL("/upload/", Host: "127.0.0.2"), new MemoryStream([ 1, 2, 3 ]), "a.log");
            Assert.That(notSent.Outcome,    Is.EqualTo(FileTransferOutcome.Refused));
            Assert.That(Directory.GetFiles(uploads), Is.Empty);

        }

        #endregion

        #region AKeyIsNotUsedBeforeItIsConfirmed

        [Test]
        public async Task AKeyIsNotUsedBeforeItIsConfirmed()
        {

            await Enrolled(Confirmed: false);

            Assert.That(node!.IsFileTransferKeyConfirmed("files", Login), Is.False);

            var unconfirmed = node.JudgeFileTransfer(URL("/upload/"), FileTransferDirections.Upload);
            Assert.That(unconfirmed.Refusal,  Is.EqualTo(FileTransferRefusal.FileServerNotPermitted));
            Assert.That(unconfirmed.Why,      Does.Contain("not confirmed"));

            // Another key than the node's own confirms nothing.
            var foreign = SshPublicKey.FromHostKey(SshHostKey.GenerateEd25519()).ToAuthorizedKeyLine();
            Assert.That(node.ConfirmFileTransferKey("files", Login, foreign),     Does.Contain("is not the key"));
            Assert.That(node.ConfirmFileTransferKey("files", "somebody"),         Does.Contain("is no login"));
            Assert.That(node.ConfirmFileTransferKey("nowhere", Login),            Does.Contain("is no file server"));
            Assert.That(node.IsFileTransferKeyConfirmed("files", Login),          Is.False);

            Assert.That(node.ConfirmFileTransferKey("files", Login, node.FileTransferPublicKey("files", Login)), Is.Null);
            Assert.That(node.IsFileTransferKeyConfirmed("files", Login),          Is.True);
            Assert.That(node.JudgeFileTransfer(URL("/upload/"), FileTransferDirections.Upload).IsAllowed, Is.True);

        }

        #endregion

        #region AKeyPerFileServerAndLogin

        [Test]
        public async Task AKeyPerFileServerAndLogin()
        {

            await TheServer();
            TheNode();

            var both = FileServer(Users: [ "cs001", "cs001-fw" ]);
            Assert.That(await Hold(both, both with { Id = "other", Address = "127.0.0.2" }), Is.Null);

            var logs       = node.FileTransferPublicKey("files", "cs001");
            var images     = node.FileTransferPublicKey("files", "cs001-fw");
            var elsewhere  = node.FileTransferPublicKey("other", "cs001");

            Assert.That(new[] { logs, images, elsewhere }, Is.All.StartsWith("ssh-ed25519 "));
            Assert.That(new[] { logs, images, elsewhere }.Select(line => line!.Split(' ')[1]), Is.Unique, "one key per file server and login");
            Assert.That(logs,                                               Does.EndWith(" cs001@files"));
            Assert.That(node.FileTransferPublicKey("files", "cs001"),       Is.EqualTo(logs), "and it stays that key");
            Assert.That(node.FileTransferPublicKey("files", Login),         Is.Null, "no key for a login that is none");
            Assert.That(node.FileTransferPublicKey("nowhere", "cs001"),     Is.Null);

            Assert.That(node.ConfirmFileTransferKey("files", "cs001"),      Is.Null);
            Assert.That(File.Exists(node.FileTransferKeyPath("files", "cs001")), Is.True);
            Assert.That(File.Exists(node.FileTransferKeyPath("other", "cs001")), Is.True);

            // A login that is one no longer has its key deleted; added again, it gets a new one, unconfirmed.
            Assert.That(await Hold(FileServer(Users: [ "cs001-fw" ])), Is.Null);

            Assert.That(File.Exists(node.FileTransferKeyPath("files", "cs001")),     Is.False);
            Assert.That(File.Exists(node.FileTransferKeyPath("files", "cs001-fw")),  Is.True,  "the key of the login that stayed is untouched");
            Assert.That(File.Exists(node.FileTransferKeyPath("other", "cs001")),     Is.False, "and the keys of a file server that is none any more are gone");
            Assert.That(node.FileTransferPublicKey("files", "cs001-fw"),             Is.EqualTo(images));

            Assert.That(await Hold(both), Is.Null);

            Assert.That(node.FileTransferPublicKey("files", "cs001"),          Is.Not.EqualTo(logs));
            Assert.That(node.IsFileTransferKeyConfirmed("files", "cs001"),     Is.False);

        }

        #endregion

        #region AForeignHostKeyEndsTheTransferAndIsNotAskedAgain

        [Test]
        public async Task AForeignHostKeyEndsTheTransferAndIsNotAskedAgain()
        {

            // Held to another key than the one the server has.
            await Enrolled(() => FileServer(Pin: "SHA256:hOEj1ea61PSArpO3/qj2Drlp024D2eiJ7DJQNNLl+hU"));

            var result = await node!.UploadFileAsync(URL("/upload/"), new MemoryStream([ 1, 2, 3 ]), "a.log");

            Assert.That(result.Outcome,          Is.EqualTo(FileTransferOutcome.HostKeyRefused));
            Assert.That(result.MayBeTriedAgain,  Is.False, "a retry would only ask the same server again");
            Assert.That(result.HostKeyShown,     Is.EqualTo(Pin), "the key it showed is said");
            Assert.That(foreignKeys.Select(key => (key.Server.Id, key.Shown)), Is.EqualTo(new[] { ("files", Pin) }));
            Assert.That(Directory.GetFiles(uploads), Is.Empty);

            using var none = new MemoryStream();
            Assert.That((await node.DownloadFileAsync(URL("/firmware/a.bin"), none)).Outcome, Is.EqualTo(FileTransferOutcome.HostKeyRefused));

        }

        #endregion

        #region AServerThatDoesNotKnowTheKeyOrIsNotThere

        [Test]
        public async Task AServerThatDoesNotKnowTheKeyOrIsNotThere()
        {

            // Confirmed on the node, never entered at the server.
            await Enrolled(AtTheServer: false);

            var unknown = await node!.UploadFileAsync(URL("/upload/"), new MemoryStream([ 1, 2, 3 ]), "a.log");

            Assert.That(unknown.Outcome,          Is.EqualTo(FileTransferOutcome.LoginRefused), unknown.Why);
            Assert.That(unknown.MayBeTriedAgain,  Is.False);

            // Nobody listens on the port of the file server.
            var closed = TestPorts.Free();
            Assert.That(await Hold(FileServer(Port: closed)), Is.Null);
            Assert.That(node.ConfirmFileTransferKey("files", Login), Does.Contain("no key"), "another port is another server: the key shown to the one before is gone");
            Assert.That(node.FileTransferPublicKey("files", Login),  Is.Not.Null);
            Assert.That(node.ConfirmFileTransferKey("files", Login), Is.Null);

            var gone = await node.UploadFileAsync(URL("/upload/", Port: closed), new MemoryStream([ 1, 2, 3 ]), "a.log");

            Assert.That(gone.Outcome,             Is.EqualTo(FileTransferOutcome.Unreachable), gone.Why);
            Assert.That(gone.MayBeTriedAgain,     Is.True, "what is unreachable now may be reachable in a minute");

        }

        #endregion

        #region ATransferIsAChannelOfTheConnectionToThePeerWhereThePeerSaysSo

        [Test]
        public async Task ATransferIsAChannelOfTheConnectionToThePeerWhereThePeerSaysSo()
        {

            await TheServer();
            TheNode();

            // The connection the node keeps to that peer, signed in with a key of its own.
            var stationKey = SshHostKey.GenerateEd25519();
            var added      = await server!.AuthorizeSSHKey(Login, SshPublicKey.FromHostKey(stationKey).ToAuthorizedKeyLine());
            Assert.That(added.IsAdded, Is.True, added.Reason);

            var serversKey = Pin;

            await using var connection = new SshSharedConnection("127.0.0.1",
                                                                 Port,
                                                                 new SshClientOptions {
                                                                     Username       = Login,
                                                                     Credentials    = [ stationKey ],
                                                                     VerifyHostKey  = blob => SshFingerprint.Sha256(blob) == serversKey
                                                                 });

            var askedFor = new List<String>();
            String? notNow = null;

            Assert.That(await Hold(FileServer(Connection: SSHConnection.Shared)), Is.Null);

            // In the place of the connection the node would make to its peer by itself, one the
            // test can ask about.
            node!.AddSSHPeer(new SSHPeer(DomainName.Parse("127.0.0.1"),
                                         Port,
                                         connection,
                                         WhyNot: subsystem => { askedFor.Add(subsystem); return notNow; }));

            var content = RandomNumberGenerator.GetBytes(40_000);
            var result  = await node.UploadFileAsync(URL("/upload/"), new MemoryStream(content), "a.log");

            Assert.That(result.Outcome,                Is.EqualTo(FileTransferOutcome.Done), result.Why);
            Assert.That(result.Judgement.Shared,       Is.True);
            Assert.That(askedFor,                      Does.Contain("sftp"));
            Assert.That(File.ReadAllBytes(Path.Combine(uploads, "a.log")), Is.EqualTo(content));

            Assert.That(connection.Made,               Is.EqualTo(1));
            Assert.That(connection.Current,            Is.Not.Null, "the connection is the node's, and stays");
            Assert.That(File.Exists(node.FileTransferKeyPath("files", Login)), Is.False, "no key of its own was made for it");

            // A second transfer is one more channel of the same connection.
            Assert.That((await node.UploadFileAsync(URL("/upload/"), new MemoryStream(content), "b.log")).IsDone, Is.True);
            Assert.That(connection.Made,               Is.EqualTo(1));

            // A connection that may not carry it now - on probation, say - carries no file:
            // then it is a connection of its own, which needs a confirmed key, and there is none.
            notNow = "its host key is on probation";

            var onProbation = await node.UploadFileAsync(URL("/upload/"), new MemoryStream(content), "c.log");

            Assert.That(onProbation.Outcome,           Is.EqualTo(FileTransferOutcome.Refused));
            Assert.That(onProbation.Judgement.Shared,  Is.False);
            Assert.That(File.Exists(Path.Combine(uploads, "c.log")), Is.False);

        }

        #endregion


        private sealed class Told(List<Int64> Values) : IProgress<Int64>
        {
            public void Report(Int64 Value) { lock (Values) Values.Add(Value); }
        }

    }

}
