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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// What a back end that connects to this node over SSH - its CSMS, say - sees
    /// over SFTP: a tree of its own, which no other back end and no account
    /// sees, and the node's log files.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "/files" is the back end's: one directory on the disk for it alone,
    /// confined to it as a root jail, in which it uploads, downloads, makes
    /// folders, renames and removes as it likes - a firmware image it hands
    /// the node, say. What lies there stays there, the node restarting or the
    /// back end coming again, until one of them takes it away.
    /// </para>
    /// <para>
    /// "/logs" are the node's log files, one a day: read, and never written,
    /// renamed or removed - the logs are evidence. Nothing else of the log
    /// directory is shown.
    /// </para>
    /// <para>
    /// Nothing else of the machine is shown: "/" holds these two folders, and
    /// nothing can be put there.
    /// </para>
    /// </remarks>
    public sealed class BackEndSftpFileSystem : ISftpFileSystem,
                                                IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// What the folder of the back end's own files is called.
        /// </summary>
        public const String  FilesFolder  = "files";

        /// <summary>
        /// What the folder of the node's log files is called.
        /// </summary>
        public const String  LogsFolder   = "logs";

        private enum Mount
        {
            Root,
            InRoot,
            Files,
            Logs,
            NoLog
        }

        private sealed record Opened(Mount    Mount,
                                     String   Inner,
                                     String   Path,
                                     Boolean  Writing);

        private sealed class RootListing
        {
            public Boolean Read;
        }

        private readonly LocalSftpFileSystem                    files;
        private readonly LocalSftpFileSystem?                   logs;
        private readonly Func<String, Boolean>                  showsLog;
        private readonly Action<String>                         said;
        private readonly Action?                                ended;

        private readonly ConcurrentDictionary<String, Opened>   opened        = new ();
        private readonly ConcurrentDictionary<String, Object>   rootListings  = new ();

        private          Int64                                  lastHandle;
        private          Int32                                  disposed;

        #endregion

        #region Properties

        /// <summary>
        /// The directory on the disk of the back end's own files.
        /// </summary>
        public String  FilesDirectory    { get; }

        /// <summary>
        /// The directory on the disk of the node's log files, or null where it
        /// keeps none.
        /// </summary>
        public String? LogsDirectory     { get; }

        /// <summary>
        /// How many files were uploaded in this session.
        /// </summary>
        public Int32   FilesUp           { get; private set; }

        /// <summary>
        /// How many files were downloaded in this session.
        /// </summary>
        public Int32   FilesDown         { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The SFTP tree of a back end that connects to this node.
        /// </summary>
        /// <param name="FilesDirectory">The directory of the back end's own files; made where it is not there yet.</param>
        /// <param name="LogsDirectory">The directory of the node's log files, or null where it keeps none.</param>
        /// <param name="ShowsLog">Whether a name in the log directory is a log file that is shown.</param>
        /// <param name="Said">Told what was put up, downloaded, made or removed, as a sentence for the log.</param>
        /// <param name="Ended">Told once, when the session is over.</param>
        public BackEndSftpFileSystem(String                 FilesDirectory,
                                     String?                LogsDirectory,
                                     Func<String, Boolean>  ShowsLog,
                                     Action<String>?        Said    = null,
                                     Action?                Ended   = null)
        {

            this.FilesDirectory  = FilesDirectory;
            this.LogsDirectory   = LogsDirectory;
            this.files           = new LocalSftpFileSystem(FilesDirectory);
            this.logs            = LogsDirectory is not null
                                       ? new LocalSftpFileSystem(LogsDirectory, ReadOnly: true)
                                       : null;
            this.showsLog        = ShowsLog;
            this.said            = Said ?? (_ => { });
            this.ended           = Ended;

        }

        #endregion


        #region (private) Where(Path)

        /// <summary>
        /// Where the given path of the client lies: in "/", in the back end's
        /// files, or in the log files - and what it is called there. A path
        /// that is not absolute is taken from "/", and "." and ".." are read
        /// as they say, never above "/".
        /// </summary>
        private (Mount Mount, String Inner, String Path) Where(String Path)
        {

            var parts = new List<String>();

            foreach (var part in (Path ?? "").Replace('\\', '/').Split('/'))
            {

                if (part.Length == 0 || part == ".")
                    continue;

                if (part == "..")
                {
                    if (parts.Count > 0)
                        parts.RemoveAt(parts.Count - 1);
                    continue;
                }

                parts.Add(part);

            }

            var canonical = "/" + String.Join("/", parts);

            if (parts.Count == 0)
                return (Mount.Root, "/", canonical);

            var inner = "/" + String.Join("/", parts.Skip(1));

            switch (parts[0])
            {

                case FilesFolder:
                    return (Mount.Files, inner, canonical);

                case LogsFolder when logs is not null:

                    if (parts.Count == 1)
                        return (Mount.Logs, "/", canonical);

                    if (parts.Count == 2 && Shows(parts[1]))
                        return (Mount.Logs, inner, canonical);

                    // Nothing that is no log file of the node is there, and
                    // nothing is put there.
                    if (parts.Count == 2)
                        return (Mount.NoLog, inner, canonical);

                    throw new SftpException(SftpStatusCode.NoSuchFile, $"No such log file: {canonical}");

                // Right below "/": nothing there, and nothing to be put there.
                default:

                    if (parts.Count == 1)
                        return (Mount.InRoot, canonical, canonical);

                    throw new SftpException(SftpStatusCode.NoSuchFile, $"No such file or directory: {canonical}");

            }

        }

        private Boolean Shows(String Name)
        {
            try
            {
                return SftpArea.IsFileName(Name) && showsLog(Name);
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static SftpException ReadOnly(String Path)
            => new (SftpStatusCode.PermissionDenied, $"{Path}: the log files are read, never written, renamed or removed - they are evidence.");

        private static SftpException NotHere(String Path)
            => new (SftpStatusCode.PermissionDenied, $"{Path}: nothing is put here - only in /{FilesFolder}.");

        private String Handle(Opened Opened)
        {
            var handle = "b" + Interlocked.Increment(ref lastHandle).ToString();
            this.opened[handle] = Opened;
            return handle;
        }

        private Opened OpenedOf(String Handle)
            => opened.TryGetValue(Handle, out var found)
                   ? found
                   : throw new SftpException(SftpStatusCode.Failure, "No such handle.");

        private ISftpFileSystem FileSystemOf(Mount Mount)
            => Mount switch {
                   Mount.Files  => files,
                   Mount.Logs   => logs!,
                   _            => throw new SftpException(SftpStatusCode.Failure, "No such handle.")
               };

        #endregion


        #region OpenAsync / ReadAsync / WriteAsync / FlushAsync / CloseAsync

        public async ValueTask<String> OpenAsync(String Path, SftpOpenFlags Flags, CancellationToken CancellationToken = default)
        {

            var (mount, inner, path) = Where(Path);
            var writing              = (Flags & (SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create | SftpOpenFlags.Truncate)) != 0;

            switch (mount)
            {

                case Mount.Root:
                    throw NotHere(path);

                case Mount.InRoot:
                    throw writing
                              ? NotHere(path)
                              : new SftpException(SftpStatusCode.NoSuchFile, $"No such file: {path}");

                case Mount.Logs  when writing:
                case Mount.NoLog when writing:
                    throw ReadOnly(path);

                case Mount.NoLog:
                    throw new SftpException(SftpStatusCode.NoSuchFile, $"No such log file: {path}");

                case Mount.Logs when inner == "/":
                    throw new SftpException(SftpStatusCode.Failure, $"{path} is a folder.");

                case Mount.Files when inner == "/":
                    throw new SftpException(SftpStatusCode.Failure, $"{path} is a folder.");

            }

            var handle = await FileSystemOf(mount).OpenAsync(inner, Flags, CancellationToken).ConfigureAwait(false);

            return Handle(new Opened(mount, handle, path, writing));

        }

        public ValueTask<Byte[]> ReadAsync(String Handle, Int64 Offset, Int32 Length, CancellationToken CancellationToken = default)
        {
            var opened = OpenedOf(Handle);
            return FileSystemOf(opened.Mount).ReadAsync(opened.Inner, Offset, Length, CancellationToken);
        }

        public ValueTask WriteAsync(String Handle, Int64 Offset, ReadOnlyMemory<Byte> Data, CancellationToken CancellationToken = default)
        {

            var opened = OpenedOf(Handle);

            if (opened.Mount != Mount.Files)
                throw ReadOnly(opened.Path);

            return files.WriteAsync(opened.Inner, Offset, Data, CancellationToken);

        }

        public ValueTask FlushAsync(String Handle, CancellationToken CancellationToken = default)
        {
            var opened = OpenedOf(Handle);
            return FileSystemOf(opened.Mount).FlushAsync(opened.Inner, CancellationToken);
        }

        public async ValueTask CloseAsync(String Handle, CancellationToken CancellationToken = default)
        {

            if (rootListings.TryRemove(Handle, out _))
                return;

            if (!opened.TryRemove(Handle, out var closed))
                return;

            if (closed.Inner.Length > 0)
                await FileSystemOf(closed.Mount).CloseAsync(closed.Inner, CancellationToken).ConfigureAwait(false);

            if (closed.Mount == Mount.Root)
                return;

            if (closed.Writing)
            {
                FilesUp++;
                said($"put up {closed.Path}");
            }

            else if (!closed.Path.EndsWith('/'))
            {
                FilesDown++;
                said($"read {closed.Path}");
            }

        }

        #endregion

        #region OpenDirectoryAsync / ReadDirectoryAsync

        public async ValueTask<String> OpenDirectoryAsync(String Path, CancellationToken CancellationToken = default)
        {

            var (mount, inner, path) = Where(Path);

            if (mount == Mount.Root)
            {
                var handle = "r" + Interlocked.Increment(ref lastHandle).ToString();
                rootListings[handle] = new RootListing();
                return handle;
            }

            if (mount is Mount.InRoot or Mount.NoLog)
                throw new SftpException(SftpStatusCode.NoSuchFile, $"No such directory: {path}");

            if (mount == Mount.Logs && inner != "/")
                throw new SftpException(SftpStatusCode.Failure, $"{path} is a file.");

            var opened = await FileSystemOf(mount).OpenDirectoryAsync(inner, CancellationToken).ConfigureAwait(false);

            // A directory that is listed is no file that was read.
            return Handle(new Opened(mount, opened, path.TrimEnd('/') + "/", false));

        }

        public async ValueTask<IReadOnlyList<SftpDirectoryEntry>> ReadDirectoryAsync(String Handle, CancellationToken CancellationToken = default)
        {

            if (rootListings.TryGetValue(Handle, out var listing) && listing is RootListing root)
            {

                if (root.Read)
                    return [];

                root.Read = true;

                return logs is not null
                           ? [ new SftpDirectoryEntry(FilesFolder, SftpFileAttributes.Directory()),
                               new SftpDirectoryEntry(LogsFolder,  SftpFileAttributes.Directory(0x416D /* 040555 */)) ]
                           : [ new SftpDirectoryEntry(FilesFolder, SftpFileAttributes.Directory()) ];

            }

            var opened = OpenedOf(Handle);

            if (opened.Mount != Mount.Logs)
                return await FileSystemOf(opened.Mount).ReadDirectoryAsync(opened.Inner, CancellationToken).ConfigureAwait(false);

            // Of the log directory only its log files - read until a batch has
            // one, or there is nothing more.
            while (true)
            {

                var batch = await logs!.ReadDirectoryAsync(opened.Inner, CancellationToken).ConfigureAwait(false);

                if (batch.Count == 0)
                    return [];

                var shown = batch.Where(entry => !entry.Attributes.IsDirectory && Shows(entry.Name)).ToList();

                if (shown.Count > 0)
                    return shown;

            }

        }

        #endregion

        #region StatAsync / LStatAsync / RealPathAsync / ReadLinkAsync

        public ValueTask<SftpFileAttributes> StatAsync(String Path, CancellationToken CancellationToken = default)
        {

            var (mount, inner, path) = Where(Path);

            return mount switch {
                       Mount.Root    => ValueTask.FromResult(SftpFileAttributes.Directory(0x416D /* 040555 */)),
                       Mount.InRoot or
                       Mount.NoLog   => throw new SftpException(SftpStatusCode.NoSuchFile, $"No such file or directory: {path}"),
                       _             => FileSystemOf(mount).StatAsync(inner, CancellationToken)
                   };

        }

        public ValueTask<SftpFileAttributes> LStatAsync(String Path, CancellationToken CancellationToken = default)
        {

            var (mount, inner, path) = Where(Path);

            return mount switch {
                       Mount.Root    => ValueTask.FromResult(SftpFileAttributes.Directory(0x416D /* 040555 */)),
                       Mount.InRoot or
                       Mount.NoLog   => throw new SftpException(SftpStatusCode.NoSuchFile, $"No such file or directory: {path}"),
                       _             => FileSystemOf(mount).LStatAsync(inner, CancellationToken)
                   };

        }

        public async ValueTask<String> RealPathAsync(String Path, CancellationToken CancellationToken = default)
        {

            var (mount, inner, path) = Where(Path);

            if (mount != Mount.Files)
                return path;

            var real = await files.RealPathAsync(inner, CancellationToken).ConfigureAwait(false);

            return "/" + FilesFolder + (real == "/" ? "" : real);

        }

        public ValueTask<String> ReadLinkAsync(String Path, CancellationToken CancellationToken = default)
        {

            var (mount, inner, _) = Where(Path);

            return mount == Mount.Files
                       ? files.ReadLinkAsync(inner, CancellationToken)
                       : throw new SftpException(SftpStatusCode.OpUnsupported, "There are no symbolic links here.");

        }

        #endregion

        #region MakeDirectoryAsync / RemoveAsync / RemoveDirectoryAsync / RenameAsync / CreateSymbolicLinkAsync / SetAttributesAsync

        /// <summary>
        /// The path in the back end's own files the given one names, below
        /// its folder - or why nothing is changed there.
        /// </summary>
        private (String Inner, String Path) Changeable(String Path)
        {

            var (mount, inner, path) = Where(Path);

            return mount switch {
                       Mount.Files when inner != "/"  => (inner, path),
                       Mount.Logs or Mount.NoLog      => throw ReadOnly(path),
                       _                              => throw NotHere(path)
                   };

        }

        public async ValueTask MakeDirectoryAsync(String Path, CancellationToken CancellationToken = default)
        {
            var (inner, path) = Changeable(Path);
            await files.MakeDirectoryAsync(inner, CancellationToken).ConfigureAwait(false);
            said($"made the folder {path}");
        }

        public async ValueTask RemoveAsync(String Path, CancellationToken CancellationToken = default)
        {
            var (inner, path) = Changeable(Path);
            await files.RemoveAsync(inner, CancellationToken).ConfigureAwait(false);
            said($"removed {path}");
        }

        public async ValueTask RemoveDirectoryAsync(String Path, CancellationToken CancellationToken = default)
        {
            var (inner, path) = Changeable(Path);
            await files.RemoveDirectoryAsync(inner, CancellationToken).ConfigureAwait(false);
            said($"removed the folder {path}");
        }

        public async ValueTask RenameAsync(String OldPath, String NewPath, CancellationToken CancellationToken = default)
        {
            var (oldInner, oldPath) = Changeable(OldPath);
            var (newInner, newPath) = Changeable(NewPath);
            await files.RenameAsync(oldInner, newInner, CancellationToken).ConfigureAwait(false);
            said($"renamed {oldPath} to {newPath}");
        }

        public ValueTask CreateSymbolicLinkAsync(String LinkPath, String TargetPath, CancellationToken CancellationToken = default)
            => throw new SftpException(SftpStatusCode.OpUnsupported, "No symbolic links are made here.");

        public ValueTask SetAttributesAsync(String Path, SftpFileAttributes Attributes, CancellationToken CancellationToken = default)
        {

            // What a client sets after an upload - its times, its mode - is
            // taken in the back end's files, and nowhere else.
            var (mount, inner, path) = Where(Path);

            return mount switch {
                       Mount.Files  => files.SetAttributesAsync(inner, Attributes, CancellationToken),
                       Mount.Logs or
                       Mount.NoLog  => throw ReadOnly(path),
                       _            => throw NotHere(path)
                   };

        }

        #endregion


        #region DisposeAsync()

        /// <summary>
        /// Close what the client left open, and say that the session is over.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            if (Interlocked.Exchange(ref disposed, 1) == 1)
                return;

            foreach (var handle in opened.Keys.ToArray())
            {
                try
                {
                    if (opened.TryRemove(handle, out var left) && left.Inner.Length > 0)
                        await FileSystemOf(left.Mount).CloseAsync(left.Inner).ConfigureAwait(false);
                }
                catch (Exception)
                { }
            }

            rootListings.Clear();

            try
            {
                ended?.Invoke();
            }
            catch (Exception)
            { }

        }

        #endregion

    }

}
