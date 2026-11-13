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

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// The directions a file may be moved in between a node and a file server.
    /// What the file is - a log, diagnostics, a firmware image - is nothing the
    /// transport sees: FileTransfers of SSHPeerController.
    /// </summary>
    [Flags]
    public enum FileTransferDirections
    {

        /// <summary>
        /// The peer is no file server.
        /// </summary>
        None      = 0,

        /// <summary>
        /// Files of the node may be sent there.
        /// </summary>
        Upload    = 1,

        /// <summary>
        /// Files may be fetched from there.
        /// </summary>
        Download  = 2

    }


    /// <summary>
    /// What an SSH peer may be used for as a file server: in which directions,
    /// under which logins, on which paths, and whether a transfer has an SSH
    /// connection of its own (section 8.1 of the white paper "SFTP for Logfile
    /// Uploads and Firmware Downloads").
    /// </summary>
    /// <remarks>
    /// "fileTransfers" in the entry of a peer: { "directions", "users",
    /// "uploadPaths", "downloadPaths", "connection" }. A peer without it is no
    /// file server: a time server and a Local Controller are no places to send
    /// logs to until somebody says so.
    /// </remarks>
    /// <param name="Directions">The directions it may be used in.</param>
    /// <param name="Users">The logins a request may name; none: only the login of the peer.</param>
    /// <param name="UploadPaths">The directories an upload may go to, each with everything below it; none: nowhere.</param>
    /// <param name="DownloadPaths">The directories a download may come from, each with everything below it; none: nowhere.</param>
    /// <param name="Connection">Whether a request under the login of the node's connection to the peer goes as one more channel of it.</param>
    public sealed record SSHFileTransfers(FileTransferDirections   Directions,
                                          IReadOnlyList<String>?   Users          = null,
                                          IReadOnlyList<String>?   UploadPaths    = null,
                                          IReadOnlyList<String>?   DownloadPaths  = null,
                                          SSHConnection            Connection     = SSHConnection.Dedicated)
    {

        #region Data

        /// <summary>
        /// How many logins a file server may have.
        /// </summary>
        public const Int32   MaxUsers        = 8;

        /// <summary>
        /// How many directories a direction may have.
        /// </summary>
        public const Int32   MaxPaths        = 8;

        /// <summary>
        /// The longest directory.
        /// </summary>
        public const Int32   MaxPathLength   = 255;

        /// <summary>
        /// What stands for the identity of the node in a path, so that one value
        /// serves a fleet: "/upload/{id}/".
        /// </summary>
        public const String  IdentityMark    = "{id}";

        private static readonly Regex  userName  = new ("^[A-Za-z0-9._][A-Za-z0-9._@-]*$", RegexOptions.CultureInvariant);

        #endregion

        #region Properties

        /// <summary>
        /// The logins a request may name besides the login of the peer.
        /// </summary>
        public IReadOnlyList<String>  Logins
            => Users ?? [];

        /// <summary>
        /// Whether a request under the login of the node's connection to the
        /// peer goes as one more channel of that connection.
        /// </summary>
        public Boolean                IsShared
            => Connection == SSHConnection.Shared;

        #endregion


        #region Allows(Direction) / AllowsLogin(Login, LoginOfThePeer) / AllowsPath(Direction, Path, Identity)

        /// <summary>
        /// Whether the peer may be used in the given direction.
        /// </summary>
        public Boolean Allows(FileTransferDirections Direction)
            => Direction != FileTransferDirections.None && (Directions & Direction) == Direction;

        /// <summary>
        /// Whether a request may name the given login: one of the logins, or -
        /// where there are none - the login of the peer.
        /// </summary>
        public Boolean AllowsLogin(String Login, String LoginOfThePeer)
            => Logins.Count == 0
                   ? String.Equals(Login, LoginOfThePeer, StringComparison.Ordinal)
                   : Logins.Contains(Login, StringComparer.Ordinal);

        /// <summary>
        /// Whether a file may go to, or come from, the given path: it lies in
        /// one of the directories of that direction.
        /// </summary>
        /// <param name="Direction">Upload: the path is the directory. Download: the path is the file.</param>
        /// <param name="Path">The path as <see cref="SftpLocation.Path"/> has it: "/dir/file" or "~/dir/file".</param>
        /// <param name="Identity">What <see cref="IdentityMark"/> stands for.</param>
        public Boolean AllowsPath(FileTransferDirections  Direction,
                                  String                  Path,
                                  String                  Identity)
        {

            var directories = Direction == FileTransferDirections.Upload
                                  ? UploadPaths
                                  : DownloadPaths;

            // An upload names a directory, with or without the slash at its end.
            var path = Direction == FileTransferDirections.Upload && !Path.EndsWith('/')
                           ? Path + "/"
                           : Path;

            foreach (var directory in directories ?? [])
            {

                var prefix = directory.Replace(IdentityMark, Identity, StringComparison.Ordinal);

                // A download names a file in the directory, not the directory.
                if (path.StartsWith(prefix, StringComparison.Ordinal) &&
                    (Direction == FileTransferDirections.Upload || path.Length > prefix.Length))
                {
                    return true;
                }

            }

            return false;

        }

        #endregion

        #region (static) TryParse(JSON, Path, out FileTransfers, out Error)

        /// <summary>
        /// Read the "fileTransfers" object of a peer's entry.
        /// </summary>
        /// <param name="JSON">The value of "fileTransfers".</param>
        /// <param name="Path">Where it is in the file: "ssh.peers[0].fileTransfers".</param>
        public static Boolean TryParse(JToken                                     JSON,
                                       String                                     Path,
                                       [NotNullWhen(true)]  out SSHFileTransfers? FileTransfers,
                                       [NotNullWhen(false)] out String?           Error)
        {

            FileTransfers  = null;
            Error          = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object: {{ \"directions\", \"users\", \"uploadPaths\", \"downloadPaths\", \"connection\" }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadStrings(json, "directions",    Path, 2,        16,             out var directionTexts, out Error) ||
                !ConfigurationReader.TryReadStrings(json, "users",         Path, MaxUsers, 32,             out var users,          out Error) ||
                !ConfigurationReader.TryReadStrings(json, "uploadPaths",   Path, MaxPaths, MaxPathLength,  out var uploadPaths,    out Error) ||
                !ConfigurationReader.TryReadStrings(json, "downloadPaths", Path, MaxPaths, MaxPathLength,  out var downloadPaths,  out Error) ||
                !ConfigurationReader.TryReadString (json, "connection",    Path, 16,                       out var connectionText, out Error))
            {
                return false;
            }

            var directions = FileTransferDirections.None;

            foreach (var text in directionTexts ?? [])
            {
                switch (text.Trim().ToLowerInvariant())
                {
                    case "upload":    directions |= FileTransferDirections.Upload;    break;
                    case "download":  directions |= FileTransferDirections.Download;  break;
                    default:
                        Error = $"'{Path}.directions': '{text}' is neither \"upload\" nor \"download\".";
                        return false;
                }
            }

            foreach (var user in users ?? [])
            {
                if (!userName.IsMatch(user))
                {
                    Error = $"'{Path}.users': '{user}' is no login: letters, digits, '.', '_', '-' and '@', and at most 32 of them.";
                    return false;
                }
            }

            if (!TryDirectories(uploadPaths,   $"{Path}.uploadPaths",   out var upload,   out Error) ||
                !TryDirectories(downloadPaths, $"{Path}.downloadPaths", out var download, out Error))
            {
                return false;
            }

            var connection = SSHConnection.Dedicated;

            if (connectionText is not null && !SSHConnectionExtensions.TryParse(connectionText, out connection))
            {
                Error = $"'{Path}.connection': '{connectionText}' is neither \"dedicated\" nor \"shared\".";
                return false;
            }

            FileTransfers = new SSHFileTransfers(
                                directions,
                                users is { Count: > 0 } ? [.. users.Distinct(StringComparer.Ordinal)] : null,
                                upload.  Count > 0 ? upload   : null,
                                download.Count > 0 ? download : null,
                                connection
                            );

            return true;

        }

        /// <summary>
        /// Directories as they are compared: absolute or below the home
        /// directory, without "..", and with the slash at their end.
        /// </summary>
        private static Boolean TryDirectories(IReadOnlyList<String>?            Texts,
                                              String                            Path,
                                              out IReadOnlyList<String>         Directories,
                                              [NotNullWhen(false)] out String?  Error)
        {

            var parsed   = new List<String>();
            Directories  = parsed;
            Error        = null;

            foreach (var text in Texts ?? [])
            {

                var directory = text.Trim();

                if (!(directory.StartsWith('/') || directory.StartsWith("~/", StringComparison.Ordinal)))
                {
                    Error = $"'{Path}': '{text}' is no directory: it starts with '/', or with '~/' below the home directory of the login.";
                    return false;
                }

                if (directory.Split('/').Any(segment => segment == "..") ||
                    directory.Any(character => character < 0x20 || character == 0x7f))
                {
                    Error = $"'{Path}': '{text}' has a '..' or a control character in it.";
                    return false;
                }

                if (!directory.EndsWith('/'))
                    directory += "/";

                if (!parsed.Contains(directory))
                    parsed.Add(directory);

            }

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The "fileTransfers" object of the entry, with the usual left out.
        /// </summary>
        public JObject ToJSON()
        {

            var json        = new JObject();
            var directions  = new JArray();

            if (Allows(FileTransferDirections.Upload))    directions.Add("upload");
            if (Allows(FileTransferDirections.Download))  directions.Add("download");

            json.Add("directions", directions);

            if (Logins.Count > 0)                  json.Add("users",         new JArray(Logins));
            if (UploadPaths   is { Count: > 0 })   json.Add("uploadPaths",   new JArray(UploadPaths));
            if (DownloadPaths is { Count: > 0 })   json.Add("downloadPaths", new JArray(DownloadPaths));
            if (IsShared)                          json.Add("connection",    Connection.AsText());

            return json;

        }

        #endregion

    }


    /// <summary>
    /// An SSH peer that is a file server: who it is, what it is believed by,
    /// and what it may be used for.
    /// </summary>
    /// <remarks>
    /// The request chooses among file servers, it never introduces one: host,
    /// port, login and path of an "sftp://" URL are looked up here, and the
    /// host key comes from <paramref name="Trust"/> - never from the first
    /// handshake, and never from the request.
    /// </remarks>
    /// <param name="Id">The name of the peer, as whoever configured it called it.</param>
    /// <param name="Address">Its host name or address, as text.</param>
    /// <param name="User">The login of the peer, or null for the node's own.</param>
    /// <param name="Trust">Its SSH port, and the host keys and CAs it is held to. What a mismatch comes to is not read for a file transfer: it is refused.</param>
    /// <param name="FileTransfers">What it may be used for.</param>
    public sealed record SSHFileServer(String            Id,
                                       String            Address,
                                       String?           User,
                                       NTSServerSSH      Trust,
                                       SSHFileTransfers  FileTransfers)
    {

        private static readonly Regex  id  = new ("^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$", RegexOptions.CultureInvariant);

        /// <summary>
        /// The host in the form two hosts are compared in; null where the
        /// address is neither a DNS name nor an IP address.
        /// </summary>
        public String?  Host
            => SftpLocation.NormalizeHost(Address);

        /// <summary>
        /// Its SSH port.
        /// </summary>
        public UInt16   Port
            => Trust.PortOrDefault;

        /// <summary>
        /// Why this is no file server a node may hold, or null where it is one.
        /// </summary>
        public String? Problem
            => !id.IsMatch(Id)
                   ? $"'{Id}' is no name of a peer: letters, digits, '.', '_' and '-', at most 50 of them"
             : Host is null
                   ? $"the address '{Address}' of '{Id}' is neither a DNS name nor an IP address"
             : !Trust.IsPinned
                   ? $"'{Id}' is held to no host key and no CA: a file server nobody could believe is none"
             : null;

    }

}
