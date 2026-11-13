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

using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    #region FileTransferRefusal / FileTransferJudgement

    /// <summary>
    /// Why a request for a file transfer is not carried out, as the response to
    /// it says: little, on purpose. The two reason codes of section 5.1 of the
    /// white paper "SFTP for Logfile Uploads and Firmware Downloads".
    /// </summary>
    public enum FileTransferRefusal
    {

        /// <summary>
        /// It is carried out.
        /// </summary>
        None,

        /// <summary>
        /// The URL is no sftp:// URL as the paper reads it, or carries a
        /// password: InvalidURL.
        /// </summary>
        InvalidURL,

        /// <summary>
        /// The configuration knows no file server of that host and port, or
        /// does not allow this direction, login or path, or has no confirmed
        /// key for it: FileServerNotPermitted. One code for all of them, so
        /// that a response does not say which peers a node has.
        /// </summary>
        FileServerNotPermitted

    }


    /// <summary>
    /// What a request for a file transfer came to before anything was sent:
    /// which file server, which login and which way - or why not.
    /// </summary>
    /// <param name="Refusal">Whether, and by which reason code, it is refused.</param>
    /// <param name="Why">What exactly was missing: for the node's own log and the security event, not for the response.</param>
    /// <param name="Location">What the URL names, where it could be read.</param>
    /// <param name="Server">The file server it goes to.</param>
    /// <param name="Login">The login it is signed in under.</param>
    /// <param name="Shared">Whether it goes as one more channel of the node's connection to that peer.</param>
    public sealed record FileTransferJudgement(FileTransferRefusal  Refusal,
                                               String               Why,
                                               SftpLocation?        Location  = null,
                                               SSHFileServer?       Server    = null,
                                               String?              Login     = null,
                                               Boolean              Shared    = false)
    {

        /// <summary>
        /// Whether the transfer is carried out.
        /// </summary>
        public Boolean IsAllowed
            => Refusal == FileTransferRefusal.None;

    }

    #endregion

    #region FileTransferOutcome / FileTransferResult

    /// <summary>
    /// How a file transfer ended: section 5.4 of the white paper maps each to a
    /// status of OCPP, and says which is tried again.
    /// </summary>
    public enum FileTransferOutcome
    {

        /// <summary>The file is where it was to go.</summary>
        Done,

        /// <summary>The request was refused before anything was sent (<see cref="FileTransferJudgement"/>).</summary>
        Refused,

        /// <summary>The name was not resolved, the connection refused, timed out or lost. Tried again.</summary>
        Unreachable,

        /// <summary>The server showed a host key that neither a pin nor a CA vouches for. Never tried again.</summary>
        HostKeyRefused,

        /// <summary>The server does not signal strict KEX. Not tried again.</summary>
        AlgorithmsRefused,

        /// <summary>The server did not take the node's key for that login. Not tried again.</summary>
        LoginRefused,

        /// <summary>The server serves no sftp subsystem, or not to this login. Not tried again.</summary>
        NoSftp,

        /// <summary>SSH_FX_PERMISSION_DENIED. Not tried again.</summary>
        PermissionDenied,

        /// <summary>SSH_FX_NO_SUCH_FILE. Not tried again.</summary>
        NoSuchFile,

        /// <summary>The file to download is larger than allowed. Not tried again.</summary>
        TooLarge,

        /// <summary>The file to upload is there already: nothing is written over. Not tried again.</summary>
        FileExists,

        /// <summary>A quota, a full disk, another failure of the server. Tried again.</summary>
        Failed,

        /// <summary>The transfer was cancelled.</summary>
        Cancelled

    }


    /// <summary>
    /// How a file transfer ended.
    /// </summary>
    /// <param name="Outcome">How it ended.</param>
    /// <param name="Why">What happened, for the log.</param>
    /// <param name="Judgement">What the request came to before anything was sent.</param>
    /// <param name="Bytes">How many bytes were moved by this attempt.</param>
    /// <param name="RemotePath">The remote file, where one was named.</param>
    /// <param name="HostKeyShown">The SHA-256 fingerprint of a host key that was refused.</param>
    public sealed record FileTransferResult(FileTransferOutcome    Outcome,
                                            String                 Why,
                                            FileTransferJudgement  Judgement,
                                            Int64                  Bytes         = 0,
                                            String?                RemotePath    = null,
                                            String?                HostKeyShown  = null)
    {

        /// <summary>
        /// Whether the file is where it was to go.
        /// </summary>
        public Boolean IsDone
            => Outcome == FileTransferOutcome.Done;

        /// <summary>
        /// Whether another attempt may end differently: what is unreachable now
        /// may be reachable in a minute. A refused host key, a refused login and
        /// a missing permission would only be asked for again.
        /// </summary>
        public Boolean MayBeTriedAgain
            => Outcome is FileTransferOutcome.Unreachable or FileTransferOutcome.Failed;

    }

    #endregion


    /// <summary>
    /// File transfers of a node over SFTP, on somebody's request: a file of the
    /// node uploaded to a file server, a file of a file server downloaded -
    /// OCPP's GetLog, GetDiagnostics, UpdateFirmware and PublishFirmware with an
    /// "sftp://" URL, by the white paper "SFTP for Logfile Uploads and Firmware
    /// Downloads".
    /// </summary>
    /// <remarks>
    /// <para>
    /// A request chooses among the file servers the node holds, and never
    /// introduces one. Its URL names a host, a port, a login and a path; who
    /// that host is believed by, what it may be used for and the key the node
    /// signs in with come from the node's own configuration. There is no trust
    /// on first use, no mismatch that is recorded or accepted, and a server the
    /// configuration does not know is refused before a packet leaves the node.
    /// </para>
    /// <para>
    /// What the file is, is nothing this knows: a log, diagnostics and a
    /// firmware image are a stream and a name here. Collecting, packing,
    /// verifying and installing is the logic above.
    /// </para>
    /// <para>
    /// The node signs in with a key of its own per file server and login, made
    /// by itself and kept beside its SSH host key, and uses it only once
    /// somebody confirmed that the server holds its public half.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// Where the keys this node signs in with at its file servers are kept,
        /// beside its SSH host key: one directory per file server.
        /// </summary>
        public const String  FileTransferKeysDirectory     = "filetransfer";

        /// <summary>
        /// How long the SSH connection of a file transfer may take to be had.
        /// </summary>
        public TimeSpan      FileTransferConnectTimeout    { get; set; }  = TimeSpan.FromSeconds(30);

        /// <summary>
        /// How long a transfer may go without a byte moving before it counts as
        /// lost.
        /// </summary>
        public TimeSpan      FileTransferIdleTimeout       { get; set; }  = TimeSpan.FromSeconds(60);

        /// <summary>
        /// The file in the directory of a file server's keys that says which
        /// host and port they were made for.
        /// </summary>
        private const String  FileServerMarker  = ".server";

        private readonly Object   fileServersLock   = new ();
        private          String?  fileServersSeen;
        private          Int32    fileServersFollowed;

        #endregion

        #region Events

        /// <summary>
        /// A request named a file server, a login or a path the configuration
        /// does not allow: somebody with the right to send requests asked this
        /// node to move a file to or from a place it does not know. The security
        /// event FileTransferRefused.
        /// </summary>
        public event Action<FileTransferJudgement, FileTransferDirections>?  OnFileTransferRefused;

        /// <summary>
        /// A file server showed a host key that neither a pin nor a CA vouches
        /// for. The security event InvalidFileServerHostKey.
        /// </summary>
        public event Action<SSHFileServer, String>?                          OnFileServerHostKeyRefused;

        #endregion

        #region FileServers / FileTransferIdentity

        /// <summary>
        /// The SSH peers of this node that are file servers: those of its
        /// configuration whose entry says what they may be used for
        /// ("fileTransfers"). They are changed as the peers are, by
        /// <see cref="TryUpdateSSHPeers"/>, and by nothing else.
        /// </summary>
        public IReadOnlyList<SSHFileServer> FileServers
        {
            get
            {

                SSHFileServer[] servers = [.. ConfiguredSSHPeers.
                                                  Where (peer => peer.FileTransfers is not null).
                                                  Select(peer => new SSHFileServer(peer.Id, peer.Address.Trimmed, peer.User, peer.Trust, peer.FileTransfers!)).
                                                  Where (server => server.Problem is null)];

                // From the first time somebody asks - and before that no key was made - the keys
                // follow every change of the peers, when it is made and not when somebody asks next.
                if (Interlocked.Exchange(ref fileServersFollowed, 1) == 0)
                    OnSSHPeersChanged += () => _ = FileServers;

                KeepOnlyTheKeysOf(servers);

                return servers;

            }
        }

        /// <summary>
        /// What "{id}" stands for in the paths of a file server, and the login
        /// where neither a request nor the peer names one: the identity of this
        /// node, which is the login it has at its SSH peers.
        /// </summary>
        public String FileTransferIdentity
            => DefaultSSHPeerUser;

        #endregion

        #region (private) KeepOnlyTheKeysOf(Servers)

        /// <summary>
        /// Delete the keys of file servers and logins that are there no longer:
        /// added again, they get new ones. So do the keys of a peer whose
        /// address or port changed - under the same name it is another server,
        /// and its keys were never shown there.
        /// </summary>
        /// <remarks>
        /// Decided by what is on disk, not by what was seen before, so that a
        /// node that was restarted between two changes forgets no deletion.
        /// </remarks>
        private void KeepOnlyTheKeysOf(IReadOnlyList<SSHFileServer> Servers)
        {

            var seen = String.Join("|", Servers.Select(server => $"{server.Id}={server.Host}:{server.Port}:{String.Join(",", LoginsOf(server))}"));

            lock (fileServersLock)
            {

                if (seen == fileServersSeen)
                    return;

                fileServersSeen = seen;

                try
                {

                    var root = Path.GetDirectoryName(Path.GetDirectoryName(FileTransferKeyPath("x", "x"))!)!;

                    if (!Directory.Exists(root))
                        return;

                    foreach (var directory in Directory.GetDirectories(root))
                    {

                        var id      = Path.GetFileName(directory);
                        var server  = Servers.FirstOrDefault(candidate => String.Equals(candidate.Id, id, StringComparison.OrdinalIgnoreCase));
                        var marker  = Path.Combine(directory, FileServerMarker);
                        var madeFor = File.Exists(marker) ? File.ReadAllText(marker).Trim() : null;

                        if (server is null || madeFor != $"{server.Host}:{server.Port}")
                        {
                            DeleteFileTransferKeys(id, null);
                            continue;
                        }

                        var logins = LoginsOf(server);

                        foreach (var file in Directory.GetFiles(directory, "*_ed25519_key"))
                        {
                            var login = Path.GetFileName(file)[..^"_ed25519_key".Length];
                            if (!logins.Contains(login, StringComparer.Ordinal))
                                DeleteFileTransferKeys(id, login);
                        }

                    }

                }
                catch (Exception problem)
                {
                    Log.Warning($"The keys of file servers that are there no longer could not be looked for: {problem.Message}",
                                Kind.Tag, "ssh", "sftp", "filetransfer", "security");
                }

            }

        }

        #endregion

        #region (private) LoginOf(Server) / LoginsOf(Server) / FileServerOf(Id)

        /// <summary>
        /// The login of a file server where a request names none.
        /// </summary>
        private String LoginOf(SSHFileServer Server)
            => Server.User ?? DefaultSSHPeerUser;

        /// <summary>
        /// The logins this node may sign in under at a file server.
        /// </summary>
        private IReadOnlyList<String> LoginsOf(SSHFileServer Server)
            => Server.FileTransfers.Logins.Count > 0
                   ? Server.FileTransfers.Logins
                   : [ LoginOf(Server) ];

        /// <summary>
        /// The SSH peer the node keeps a connection to that is this file
        /// server: the same host, on the same port.
        /// </summary>
        private SSHPeer? PeerOf(SSHFileServer Server)
        {
            try
            {
                return SSHPeerTo(DomainName.Parse(Server.Host!)) is SSHPeer peer && peer.Port == Server.Port
                           ? peer
                           : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// The logins this node may sign in under at the given file server; none
        /// where that is no file server of this node.
        /// </summary>
        public IReadOnlyList<String> FileTransferLogins(String ServerId)
            => FileServerOf(ServerId) is SSHFileServer server
                   ? LoginsOf(server)
                   : [];

        private SSHFileServer? FileServerOf(String Id)
            => FileServers.FirstOrDefault(server => String.Equals(server.Id, Id, StringComparison.OrdinalIgnoreCase));

        #endregion


        #region Keys: FileTransferKeyPath / FileTransferPublicKey / ConfirmFileTransferKey / IsFileTransferKeyConfirmed

        /// <summary>
        /// Where the key for the given login at the given file server is kept.
        /// </summary>
        public String FileTransferKeyPath(String ServerId, String Login)
            => Beside(ConfigFile.Path,
                      Path.Combine(DefaultSSHDirectory, FileTransferKeysDirectory, ServerId.ToLowerInvariant(), Login + "_ed25519_key"));

        /// <summary>
        /// The public key this node signs in with under the given login at the
        /// given file server, as a line of an authorized_keys file - made now
        /// where there is none yet. Null where that is no login of that file
        /// server, or the key can be neither read nor made, which the log says
        /// why. FileTransferPublicKey[login] of SSHPeerController.
        /// </summary>
        public String? FileTransferPublicKey(String ServerId, String Login)
            => FileServerOf(ServerId) is SSHFileServer server                    &&
               LoginsOf(server).Contains(Login, StringComparer.Ordinal)          &&
               FileTransferKey(server, Login, Make: true) is ISshHostKey key
                   ? SshPublicKey.FromHostKey(key, $"{Login}@{server.Id}").ToAuthorizedKeyLine()
                   : null;

        /// <summary>
        /// Whether somebody confirmed that the given file server holds the
        /// public half of the key for the given login: before that, the key is
        /// not used, as the server would refuse the login anyway.
        /// </summary>
        public Boolean IsFileTransferKeyConfirmed(String ServerId, String Login)
        {

            if (FileServerOf(ServerId) is not SSHFileServer server ||
                FileTransferKey(server, Login, Make: false) is not ISshHostKey key)
            {
                return false;
            }

            try
            {
                var marker = FileTransferKeyPath(server.Id, Login) + ".confirmed";
                return File.Exists(marker) &&
                       File.ReadAllText(marker).Trim() == SshFingerprint.Sha256(key.PublicKeyBlob);
            }
            catch (Exception)
            {
                return false;
            }

        }

        /// <summary>
        /// Somebody says that the given file server holds the public half of
        /// the key for the given login: an SSHKeySigned of the CSMS, or an
        /// account on the node itself.
        /// </summary>
        /// <param name="PublicKey">The key that was enrolled, as a line of authorized_keys or a SHA-256 fingerprint; null where whoever confirms saw the key on the node itself.</param>
        /// <returns>Why it is not confirmed, or null.</returns>
        public String? ConfirmFileTransferKey(String ServerId, String Login, String? PublicKey = null)
        {

            if (FileServerOf(ServerId) is not SSHFileServer server)
                return $"'{ServerId}' is no file server of this {Kind.Name}";

            if (!LoginsOf(server).Contains(Login, StringComparer.Ordinal))
                return $"'{Login}' is no login of the file server '{server.Id}'";

            if (FileTransferKey(server, Login, Make: false) is not ISshHostKey key)
                return $"there is no key for '{Login}' at the file server '{server.Id}' yet";

            var fingerprint = SshFingerprint.Sha256(key.PublicKeyBlob);

            if (PublicKey is not null)
            {

                var enrolled = PublicKey.Trim();

                var said = enrolled.StartsWith("SHA256:", StringComparison.Ordinal)
                               ? enrolled.TrimEnd('=')
                               : SshPublicKey.TryParse(enrolled, out var parsed) && parsed is not null
                                     ? SshFingerprint.Sha256(parsed.Blob)
                                     : null;

                if (said != fingerprint)
                    return $"the key that was enrolled is not the key for '{Login}' at the file server '{server.Id}', which is {fingerprint}";

            }

            try
            {
                File.WriteAllText(FileTransferKeyPath(server.Id, Login) + ".confirmed", fingerprint + Environment.NewLine);
            }
            catch (Exception problem)
            {
                return $"the confirmation could not be kept: {problem.Message}";
            }

            Log.Notice($"The key {fingerprint} this {Kind.Name} signs in with as '{Login}' at the file server '{server.Id}' is confirmed as enrolled there.",
                       Kind.Tag, "ssh", "sftp", "filetransfer", "security");

            return null;

        }

        /// <summary>
        /// The key for the given login at the given file server: read from its
        /// file, or made and written there; null where neither can be done.
        /// </summary>
        private ISshHostKey? FileTransferKey(SSHFileServer Server, String Login, Boolean Make)
        {

            var path = FileTransferKeyPath(Server.Id, Login);

            lock (fileServersLock)
            {
                try
                {

                    if (File.Exists(path))
                        return SshKeyGenerator.LoadPrivateKey(File.ReadAllText(path)).Key;

                    if (!Make)
                        return null;

                    // A private key: whoever can read it can sign in as this node.
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    OwnerOnly.Directory(Path.GetDirectoryName(path)!, problem => Log.Warning(problem, Kind.Tag, "ssh", "sftp", "filetransfer", "security"));

                    // Which server the keys of this directory are for: another host or port
                    // under the same name is another server.
                    File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, FileServerMarker), $"{Server.Host}:{Server.Port}{Environment.NewLine}");

                    var key = SshHostKey.GenerateEd25519();
                    SshKeyGenerator.WriteKeyPairAsync(key, path, Comment: $"{Login}@{Server.Id}").GetAwaiter().GetResult();

                    Log.Notice($"A key was made for this {Kind.Name} to sign in with as '{Login}' at the file server '{Server.Id}': " +
                               $"{key.AlgorithmNames[0]} {SshFingerprint.Sha256(key.PublicKeyBlob)}, kept in '{path}'. It is used once it is confirmed as enrolled there.",
                               Kind.Tag, "ssh", "sftp", "filetransfer", "security");

                    return key;

                }
                catch (Exception problem)
                {
                    Log.Error($"The key this {Kind.Name} signs in with as '{Login}' at the file server '{Server.Id}' could not be had from '{path}': {problem.Message}",
                              Kind.Tag, "ssh", "sftp", "filetransfer", "security");
                    return null;
                }
            }

        }

        /// <summary>
        /// Delete the keys of a file server: of one login, or of all of them.
        /// </summary>
        private void DeleteFileTransferKeys(String ServerId, String? Login)
        {
            try
            {

                var directory = Path.GetDirectoryName(FileTransferKeyPath(ServerId, "x"))!;

                if (!Directory.Exists(directory))
                    return;

                if (Login is null)
                    Directory.Delete(directory, recursive: true);
                else
                    foreach (var file in Directory.GetFiles(directory, Login + "_ed25519_key*"))
                        File.Delete(file);

                Log.Notice(Login is null
                               ? $"'{ServerId}' is no file server of this {Kind.Name} any more: its keys are deleted."
                               : $"'{Login}' is no login at the file server '{ServerId}' any more: its key is deleted.",
                           Kind.Tag, "ssh", "sftp", "filetransfer", "security");

            }
            catch (Exception problem)
            {
                Log.Warning($"The keys of the file server '{ServerId}' could not be deleted: {problem.Message}",
                            Kind.Tag, "ssh", "sftp", "filetransfer", "security");
            }
        }

        #endregion


        #region JudgeFileTransfer(URL, Direction)

        /// <summary>
        /// What a request for a file transfer comes to, decided without the
        /// network, so that a refusal is an answer and not a failure some
        /// minutes later: section 5.1 of the white paper.
        /// </summary>
        /// <param name="URL">The location of the request.</param>
        /// <param name="Direction">Upload: the URL names the directory. Download: it names the file.</param>
        public FileTransferJudgement JudgeFileTransfer(String?                 URL,
                                                       FileTransferDirections  Direction)
        {

            var judgement = Judge(URL, Direction);

            if (!judgement.IsAllowed)
            {

                Log.Warning($"A request for {(Direction == FileTransferDirections.Upload ? "an upload to" : "a download from")} " +
                            $"{judgement.Location?.WithoutUserInfo ?? "a location that could not be read"} is refused: {judgement.Why}.",
                            Kind.Tag, "ssh", "sftp", "filetransfer", "security");

                // A malformed URL is a mistake; a server nobody configured is somebody trying.
                if (judgement.Refusal == FileTransferRefusal.FileServerNotPermitted)
                    try { OnFileTransferRefused?.Invoke(judgement, Direction); } catch (Exception) { }

            }

            return judgement;

        }

        private FileTransferJudgement Judge(String?                 URL,
                                            FileTransferDirections  Direction)
        {

            if (Direction is not (FileTransferDirections.Upload or FileTransferDirections.Download))
                return new (FileTransferRefusal.InvalidURL, "a transfer goes in one direction");

            // 1. The URL.
            if (!SftpLocation.TryParse(URL, out var location, out var error))
                return new (FileTransferRefusal.InvalidURL, error);

            FileTransferJudgement No(String Why, SSHFileServer? Server = null, String? Login = null)
                => new (FileTransferRefusal.FileServerNotPermitted, Why, location, Server, Login);

            // 2. A peer of that host and port. Compared as text: a name is never resolved to compare it.
            if (FileServers.FirstOrDefault(candidate => candidate.Host == location.Host && candidate.Port == location.Port) is not SSHFileServer server)
                return No($"{location.Host}:{location.Port} is no file server of this {Kind.Name}");

            // 3. This direction, this login, this path.
            if (!server.FileTransfers.Allows(Direction))
                return No($"the file server '{server.Id}' is not allowed {(Direction == FileTransferDirections.Upload ? "uploads" : "downloads")}", server);

            var login = location.User ?? LoginOf(server);

            if (!server.FileTransfers.AllowsLogin(login, LoginOf(server)))
                return No($"'{login}' is no login this {Kind.Name} has at the file server '{server.Id}'", server, login);

            if (!server.FileTransfers.AllowsPath(Direction, location.Path, FileTransferIdentity))
                return No($"'{location.Path}' lies in no directory the file server '{server.Id}' is allowed {(Direction == FileTransferDirections.Upload ? "uploads to" : "downloads from")}", server, login);

            // 4. Held to a host key before the request arrived; and what the URL expects must not contradict it.
            if (!server.Trust.IsPinned)
                return No($"the file server '{server.Id}' is held to no host key and no CA", server, login);

            if (location.Fingerprint is String expected && !server.Trust.Pins.Contains(expected, StringComparer.Ordinal))
                return No($"the URL expects the host key {expected}, which is none the file server '{server.Id}' is held to", server, login);

            // As one more channel of the connection the node keeps to that peer, where the peer says
            // so, the login is that connection's, and the connection may carry it now.
            if (server.FileTransfers.IsShared   &&
                login == LoginOf(server)        &&
                PeerOf(server) is SSHPeer peer  &&
                peer.WhyNot?.Invoke("sftp") is null)
            {
                return new (FileTransferRefusal.None, $"as a channel of the connection to '{server.Id}'", location, server, login, Shared: true);
            }

            // 5. A key for this login, confirmed as enrolled there.
            if (FileTransferKey(server, login, Make: true) is null)
                return No($"there is no key for '{login}' at the file server '{server.Id}'", server, login);

            if (!IsFileTransferKeyConfirmed(server.Id, login))
                return No($"the key for '{login}' at the file server '{server.Id}' is not confirmed as enrolled there yet", server, login);

            return new (FileTransferRefusal.None, $"on a connection of its own to '{server.Id}'", location, server, login);

        }

        #endregion

        #region UploadFileAsync(URL, Content, FileName, ...)

        /// <summary>
        /// Upload a file to the directory an "sftp://" URL names: one attempt.
        /// </summary>
        /// <remarks>
        /// Written under another name and renamed when the last byte is
        /// acknowledged, so that nobody on the server reads half a file; and
        /// never over a file that is there. An attempt that failed is not taken
        /// up again: the next one starts anew, as this node cannot read what
        /// arrived, and must not have to.
        /// </remarks>
        /// <param name="URL">The directory.</param>
        /// <param name="Content">The file, read from its current position to its end.</param>
        /// <param name="FileName">The name it gets there.</param>
        /// <param name="Progress">Told the number of bytes the server acknowledged so far.</param>
        public async Task<FileTransferResult> UploadFileAsync(String?            URL,
                                                              Stream             Content,
                                                              String             FileName,
                                                              IProgress<Int64>?  Progress           = null,
                                                              CancellationToken  CancellationToken  = default)
        {

            var judgement = JudgeFileTransfer(URL, FileTransferDirections.Upload);

            if (!judgement.IsAllowed)
                return new (FileTransferOutcome.Refused, judgement.Why, judgement);

            if (!SftpLocation.IsFileName(FileName))
                return new (FileTransferOutcome.Refused, $"'{FileName}' is no name of a file to upload", judgement);

            var remote = judgement.Location!.FileIn(FileName);
            var part   = remote + SftpLocation.PartSuffix;

            return await Transfer(judgement,
                                  remote,
                                  async (sftp, alive, cancellationToken) => {

                                      Int64 bytes;

                                      // The name is to be free, and to stay so: nothing is written over.
                                      if (await Exists(sftp, remote, cancellationToken).ConfigureAwait(false))
                                          throw new FileIsThereException(remote);

                                      // What an attempt before left behind, or somebody else's: not this one's
                                      // to write over, and not this one's to remove.
                                      if (await Exists(sftp, part, cancellationToken).ConfigureAwait(false))
                                          throw new FileIsThereException(part);

                                      try
                                      {
                                          bytes = await sftp.UploadAsync(part, Content, Exclusive: true, Progress: Alive(Progress, alive), CancellationToken: cancellationToken).ConfigureAwait(false);
                                      }
                                      catch (FileIsThereException)
                                      {
                                          throw;
                                      }
                                      catch (Exception)
                                      {
                                          try { await sftp.RemoveAsync(part, CancellationToken.None).ConfigureAwait(false); } catch (Exception) { }
                                          throw;
                                      }

                                      // The plain rename, which fails where the name was taken meanwhile;
                                      // posix-rename would write over it.
                                      try
                                      {
                                          await sftp.RenameAsync(part, remote, cancellationToken).ConfigureAwait(false);
                                      }
                                      catch
                                      {
                                          try { await sftp.RemoveAsync(part, CancellationToken.None).ConfigureAwait(false); } catch (Exception) { }
                                          throw;
                                      }

                                      return bytes;

                                  },
                                  CancellationToken).ConfigureAwait(false);

        }

        #endregion

        #region DownloadFileAsync(URL, Destination, Offset, MaxSize, ...)

        /// <summary>
        /// Download the file an "sftp://" URL names into a stream: one attempt,
        /// which may take up where the one before stopped.
        /// </summary>
        /// <remarks>
        /// The host key says who the server is, not what the file is: whether a
        /// firmware image is genuine and may be installed is decided after the
        /// download, by its signature, in the logic above.
        /// </remarks>
        /// <param name="URL">The file.</param>
        /// <param name="Destination">Where its bytes go, in order.</param>
        /// <param name="Offset">The first byte to read: what an attempt before brought already.</param>
        /// <param name="MaxSize">The most the whole file may have; a larger one is refused before a byte of it is read.</param>
        /// <param name="Progress">Told the position in the remote file reached so far.</param>
        public async Task<FileTransferResult> DownloadFileAsync(String?            URL,
                                                                Stream             Destination,
                                                                Int64              Offset             = 0,
                                                                Int64?             MaxSize            = null,
                                                                IProgress<Int64>?  Progress           = null,
                                                                CancellationToken  CancellationToken  = default)
        {

            var judgement = JudgeFileTransfer(URL, FileTransferDirections.Download);

            if (!judgement.IsAllowed)
                return new (FileTransferOutcome.Refused, judgement.Why, judgement);

            var remote = judgement.Location!.RemotePath;

            return await Transfer(judgement,
                                  remote,
                                  (sftp, alive, cancellationToken) =>
                                      sftp.DownloadAsync(remote, Destination, Offset, MaxSize, Alive(Progress, alive), cancellationToken).AsTask(),
                                  CancellationToken).ConfigureAwait(false);

        }

        #endregion

        #region (private) Transfer(Judgement, RemotePath, Move, CancellationToken)

        private sealed class FileIsThereException(String Path) : Exception($"'{Path}' is there already, and nothing is written over")
        { }

        /// <summary>
        /// A progress that also says the transfer is alive.
        /// </summary>
        private static IProgress<Int64> Alive(IProgress<Int64>? Progress, Action Alive)
            => new Told(Progress, Alive);

        private sealed class Told(IProgress<Int64>? Progress, Action Alive) : IProgress<Int64>
        {
            public void Report(Int64 Value)
            {
                Alive();
                Progress?.Report(Value);
            }
        }

        private static async Task<Boolean> Exists(SftpClient Sftp, String Path, CancellationToken CancellationToken)
        {
            try
            {
                await Sftp.LStatAsync(Path, CancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (SftpException)
            {
                // Not there - or not to be seen, which a write-only directory makes of everything.
                return false;
            }
        }

        /// <summary>
        /// Make the connection the judgement says, open sftp on it, move the
        /// file, and say how it ended: section 5.2 to 5.4 of the white paper.
        /// </summary>
        private async Task<FileTransferResult> Transfer(FileTransferJudgement                                       Judgement,
                                                        String                                                      RemotePath,
                                                        Func<SftpClient, Action, CancellationToken, Task<Int64>>    Move,
                                                        CancellationToken                                           CancellationToken)
        {

            var server  = Judgement.Server!;
            var login   = Judgement.Login!;
            var what    = $"{Judgement.Location!.WithoutUserInfo} as '{login}'";
            String? shown = null;

            FileTransferResult Ended(FileTransferOutcome Outcome, String Why, Int64 Bytes = 0)
            {

                var said = $"The file transfer with {what} ({Judgement.Why}) " +
                           (Outcome == FileTransferOutcome.Done
                                ? $"is done: {Bytes} bytes, '{RemotePath}'."
                                : $"ended as {Outcome}: {Why}");

                if (Outcome == FileTransferOutcome.Done)
                    Log.Info(said, Kind.Tag, "ssh", "sftp", "filetransfer");
                else
                    Log.Warning(said, Kind.Tag, "ssh", "sftp", "filetransfer");

                return new (Outcome, Why, Judgement, Bytes, RemotePath, Outcome == FileTransferOutcome.HostKeyRefused ? shown : null);

            }

            // Without a byte moving for too long, a transfer counts as lost.
            using var idle    = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            void StillAlive() { try { idle.CancelAfter(FileTransferIdleTimeout); } catch (ObjectDisposedException) { } }

            SshClient?   own   = null;
            SftpClient?  sftp  = null;

            try
            {

                SshClient client;

                if (Judgement.Shared)
                {
                    // One more channel of the node's connection to that peer: the host is the one
                    // that connection believed, and the login the one it signed in under.
                    client = await SharedSSHConnectionTo(DomainName.Parse(server.Host!), "sftp", CancellationToken).ConfigureAwait(false);
                }
                else
                {

                    var key = FileTransferKey(server, login, Make: false)
                                  ?? throw new InvalidOperationException($"There is no key for '{login}' at the file server '{server.Id}'.");

                    own = client = await SshClient.ConnectAsync(
                                             server.Host!,
                                             server.Port,
                                             new SshClientOptions {
                                                 Username          = login,
                                                 DNSClient         = dnsClient,
                                                 // This key and nothing else: no password, no other key of the node.
                                                 Credentials       = [ key ],
                                                 // A pin or a CA, or nothing: what a mismatch comes to elsewhere is not read here.
                                                 VerifyHostKey     = blob => server.Trust.Believes(blob, server.Host!, TimeProvider.GetUtcNow(), out shown, out _),
                                                 RequireStrictKex  = true,
                                                 ConnectTimeout    = FileTransferConnectTimeout
                                             },
                                             CancellationToken
                                         ).ConfigureAwait(false);

                }

                sftp = await client.OpenSftpClientAsync(CancellationToken).ConfigureAwait(false);

                StillAlive();
                var bytes = await Move(sftp, StillAlive, idle.Token).ConfigureAwait(false);

                return Ended(FileTransferOutcome.Done, "", bytes);

            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                return Ended(FileTransferOutcome.Cancelled, "it was cancelled.");
            }
            catch (OperationCanceledException)
            {
                return Ended(FileTransferOutcome.Unreachable, $"no byte moved for {FileTransferIdleTimeout.TotalSeconds:0} seconds.");
            }
            catch (SshHostKeyRejectedException)
            {

                shown ??= "a host key";

                Log.Metrological(LogLevel.Warning,
                                 $"The file server '{server.Id}' ({server.Host}:{server.Port}) showed the SSH host key {shown}, which neither a pin nor a CA of it vouches for: " +
                                 "nothing was sent to it, and it is not asked again for this request.",
                                 Kind.Tag, "ssh", "sftp", "filetransfer", "security");

                try { OnFileServerHostKeyRefused?.Invoke(server, shown); } catch (Exception) { }

                return Ended(FileTransferOutcome.HostKeyRefused, $"the server showed {shown}, which is none of the host keys it is held to.");

            }
            catch (SshStrictKexRequiredException problem)
            {
                return Ended(FileTransferOutcome.AlgorithmsRefused, problem.Message);
            }
            catch (SshAuthenticationException problem)
            {
                return Ended(FileTransferOutcome.LoginRefused, $"the server did not take the key for '{login}': {problem.Message}");
            }
            catch (SshSubsystemRefusedException)
            {
                return Ended(FileTransferOutcome.NoSftp, $"the server serves no sftp to '{login}'.");
            }
            catch (FileIsThereException problem)
            {
                return Ended(FileTransferOutcome.FileExists, problem.Message + ".");
            }
            catch (SftpFileTooLargeException problem)
            {
                return Ended(FileTransferOutcome.TooLarge, problem.Message);
            }
            catch (SftpException problem)
            {
                return Ended(problem.Code switch {
                                 SftpStatusCode.PermissionDenied  => FileTransferOutcome.PermissionDenied,
                                 SftpStatusCode.NoSuchFile        => FileTransferOutcome.NoSuchFile,
                                 _                                => FileTransferOutcome.Failed
                             },
                             $"{problem.Code}: {problem.Message}");
            }
            catch (InvalidOperationException problem)
            {
                // No key, or a shared connection that may not carry it now.
                return Ended(FileTransferOutcome.Refused, problem.Message);
            }
            catch (Exception problem) when (problem is SshWireException or SshChannelClosedException or SshConnectionLostException or
                                                       SocketException or IOException or TimeoutException or SshNameResolutionException)
            {
                return Ended(FileTransferOutcome.Unreachable, $"{problem.GetType().Name}: {problem.Message}");
            }
            finally
            {

                if (sftp is not null)
                    try { await sftp.DisposeAsync().ConfigureAwait(false); } catch (Exception) { }

                // A connection of its own ends with the transfer; a shared one is the node's, and stays.
                if (own is not null)
                    try { await own.DisposeAsync().ConfigureAwait(false); } catch (Exception) { }

            }

        }

        #endregion

    }

}
