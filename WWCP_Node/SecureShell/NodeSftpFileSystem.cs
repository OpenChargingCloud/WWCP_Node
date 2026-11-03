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

using System.Globalization;
using System.Security.Cryptography;

using Microsoft.Win32.SafeHandles;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// What one account sees of a node over SFTP, for one session: the areas
    /// it may read or write, and nothing else of the machine.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The root lists the areas the account may read or write, and only those.
    /// An area shows of its directory the names it admits; a name it does not
    /// admit is not there, whether a file of that name lies in the directory or
    /// not - so that the metrological log's private key is neither listed nor
    /// opened, by any path that leads to it.
    /// </para>
    /// <para>
    /// The role model is asked at every operation, and so is what let the
    /// session in: an account switched off, or out of the role that let it
    /// read an area, is refused from its next request on - and the node ends
    /// the session besides.
    /// </para>
    /// <para>
    /// An upload is written under a hidden name beside where it goes, checked
    /// by the area's owner when it is closed, and put in place with one rename;
    /// one that is refused, too large, or left unfinished when the session ends
    /// leaves nothing behind. Folders are neither made nor removed, links
    /// neither made nor followed, and of a file's attributes only its times
    /// are set.
    /// </para>
    /// </remarks>
    public sealed class NodeSftpFileSystem : ISftpFileSystem,
                                             IAsyncDisposable
    {

        #region (private) Open files and listings

        private abstract class Opened;

        private sealed class OpenedFile(SftpArea        Area,
                                        String          Name,
                                        SafeFileHandle  Handle,
                                        String?         Upload,
                                        Boolean         Append) : Opened
        {
            public SftpArea         Area        { get; } = Area;
            public String           Name        { get; } = Name;
            public SafeFileHandle   Handle      { get; } = Handle;
            public String?          Upload      { get; } = Upload;
            public Boolean          Append      { get; } = Append;
            public Int64            BytesRead   { get; set; }
            public String?          Failed      { get; set; }
            public DateTimeOffset?  ModifyTime  { get; set; }
            public DateTimeOffset?  AccessTime  { get; set; }
        }

        private sealed class OpenedListing(List<SftpDirectoryEntry> Entries) : Opened
        {
            public List<SftpDirectoryEntry>  Entries  { get; } = Entries;
            public Int32                     Next     { get; set; }
        }

        /// <summary>
        /// Where a path of the tree leads: a folder that holds areas, an area,
        /// a file of an area - whether it is there or not - or nowhere.
        /// </summary>
        private readonly record struct Place(String     Path,
                                             SftpArea?  Area,
                                             String?    Name,
                                             Boolean    IsFolder)
        {
            public String Shown => $"/{Path}";
        }

        #endregion

        #region Data

        private readonly IReadOnlyList<SftpArea>       areas;
        private readonly IUser                         account;
        private readonly String                        from;
        private readonly String                        nodeName;
        private readonly Func<Permission, Boolean>     isAllowed;
        private readonly Func<String?>                 signedOut;
        private readonly EventLog                      log;
        private readonly Action<NodeSftpFileSystem>?   ended;

        private readonly Lock                          gate     = new ();
        private readonly Dictionary<String, Opened>    opened   = [];
        private          Int64                         lastHandle;
        private          Boolean                       disposed;

        private          Int32                         filesUp;
        private          Int64                         bytesUp;
        private          Int32                         filesDown;
        private          Int64                         bytesDown;

        #endregion

        #region Properties

        /// <summary>
        /// The account the session is for.
        /// </summary>
        public IUser    Account      => account;

        /// <summary>
        /// How many files were put in place in this session.
        /// </summary>
        public Int32    FilesUp      => Volatile.Read(ref filesUp);

        /// <summary>
        /// How many bytes the files put in place held.
        /// </summary>
        public Int64    BytesUp      => Interlocked.Read(ref bytesUp);

        /// <summary>
        /// How many files were downloaded in this session.
        /// </summary>
        public Int32    FilesDown    => Volatile.Read(ref filesDown);

        /// <summary>
        /// How many bytes were downloaded.
        /// </summary>
        public Int64    BytesDown    => Interlocked.Read(ref bytesDown);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// What the given account sees over SFTP of the given areas.
        /// </summary>
        /// <param name="Areas">The node's areas.</param>
        /// <param name="Account">Who the session is for.</param>
        /// <param name="From">Where the session comes from, as the log says it.</param>
        /// <param name="NodeName">What the node is, as a sentence says it: "charging station".</param>
        /// <param name="IsAllowed">Whether the account may do what the given permission says, asked now.</param>
        /// <param name="SignedOut">Why the session may no longer go on, or null where it may - asked before every operation.</param>
        /// <param name="Log">The node's log.</param>
        /// <param name="Ended">Told once, when the session is over.</param>
        public NodeSftpFileSystem(IReadOnlyList<SftpArea>       Areas,
                                  IUser                         Account,
                                  String                        From,
                                  String                        NodeName,
                                  Func<Permission, Boolean>     IsAllowed,
                                  Func<String?>                 SignedOut,
                                  EventLog                      Log,
                                  Action<NodeSftpFileSystem>?   Ended  = null)
        {

            this.areas      = Areas;
            this.account    = Account;
            this.from       = From;
            this.nodeName   = NodeName;
            this.isAllowed  = IsAllowed;
            this.signedOut  = SignedOut;
            this.log        = Log;
            this.ended      = Ended;

        }

        #endregion


        #region ISftpFileSystem

        #region OpenAsync(Path, Flags, CancellationToken)

        public ValueTask<String> OpenAsync(String             Path,
                                           SftpOpenFlags      Flags,
                                           CancellationToken  CancellationToken = default)
        {

            StillIn();

            var writing  = (Flags & (SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create | SftpOpenFlags.Truncate)) != 0;

            if (writing && Locate(Path) is { IsFolder: false, Area: null } outside)
                throw Refused(SftpStatusCode.PermissionDenied, $"'{outside.Shown}' lies in no folder of this {nodeName}'s that takes files.");

            var place    = FileAt(Path);
            var area     = place.Area!;
            var name     = place.Name!;

            if (!writing)
            {

                MayRead(area);

                var file = ExistingFile(place);

                return ValueTask.FromResult(Register(new OpenedFile(area,
                                                                    name,
                                                                    Guard(() => File.OpenHandle(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, FileOptions.Asynchronous)),
                                                                    Upload:  null,
                                                                    Append:  false)));

            }

            MayWrite(area);

            var target   = AcceptedName(place);
            var exists   = File.Exists(target);

            if (exists && Flags.HasFlag(SftpOpenFlags.Create) && Flags.HasFlag(SftpOpenFlags.Exclusive))
                throw Refused(SftpStatusCode.Failure, $"'{place.Shown}' is there already.");

            if (!exists && !Flags.HasFlag(SftpOpenFlags.Create))
                throw NotThere(place);

            if (!exists && area.MaxFiles is Int32 most && FilesIn(area).Count() >= most)
                throw Refused(SftpStatusCode.Failure, $"/{area.Path} holds {most} file(s) at most: remove one first, or replace one of the same name.");

            var upload   = System.IO.Path.Combine(area.Directory, $"{SftpArea.UploadPrefix}{Guid.NewGuid():N}");

            return ValueTask.FromResult(Register(Guard(() => {

                System.IO.Directory.CreateDirectory(area.Directory);

                // Written into a copy where what is there is not to be cut off:
                // what the client does not write again stays what it was.
                if (exists && !Flags.HasFlag(SftpOpenFlags.Truncate))
                    File.Copy(target, upload);

                return new OpenedFile(area,
                                      name,
                                      File.OpenHandle(upload, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous),
                                      upload,
                                      Flags.HasFlag(SftpOpenFlags.Append));

            })));

        }

        #endregion

        #region ReadAsync(Handle, Offset, Length, CancellationToken)

        public async ValueTask<Byte[]> ReadAsync(String             Handle,
                                                 Int64              Offset,
                                                 Int32              Length,
                                                 CancellationToken  CancellationToken = default)
        {

            StillIn();

            var file    = FileOf(Handle);

            if (file.Upload is null)
                MayRead(file.Area);

            var buffer  = new Byte[Length];
            var read    = await RandomAccess.ReadAsync(file.Handle, buffer.AsMemory(0, Length), Offset, CancellationToken).ConfigureAwait(false);

            if (file.Upload is null)
                file.BytesRead += read;

            return read == Length ? buffer : buffer[..read];

        }

        #endregion

        #region WriteAsync(Handle, Offset, Data, CancellationToken)

        public async ValueTask WriteAsync(String                Handle,
                                          Int64                 Offset,
                                          ReadOnlyMemory<Byte>  Data,
                                          CancellationToken     CancellationToken = default)
        {

            StillIn();

            var file = FileOf(Handle);

            if (file.Upload is null)
                throw Refused(SftpStatusCode.PermissionDenied, $"'/{file.Area.Path}/{file.Name}' was opened for reading.");

            if (file.Failed is String failed)
                throw Refused(SftpStatusCode.Failure, failed);

            MayWrite(file.Area);

            var at = file.Append
                         ? RandomAccess.GetLength(file.Handle)
                         : Offset;

            if (file.Area.MaxFileSize is Int64 largest && at + Data.Length > largest)
            {
                file.Failed = $"'/{file.Area.Path}/{file.Name}' would be larger than {SizeOf(largest)}, which is the most /{file.Area.Path} takes.";
                throw Refused(SftpStatusCode.Failure, file.Failed);
            }

            await RandomAccess.WriteAsync(file.Handle, Data, at, CancellationToken).ConfigureAwait(false);

        }

        #endregion

        #region FlushAsync(Handle, CancellationToken)

        public ValueTask FlushAsync(String             Handle,
                                    CancellationToken  CancellationToken = default)
        {

            var file = FileOf(Handle);

            if (file.Upload is not null)
                RandomAccess.FlushToDisk(file.Handle);

            return ValueTask.CompletedTask;

        }

        #endregion

        #region CloseAsync(Handle, CancellationToken)

        public ValueTask CloseAsync(String             Handle,
                                    CancellationToken  CancellationToken = default)
        {

            Opened? closing;

            lock (gate)
                opened.Remove(Handle, out closing);

            if (closing is not OpenedFile file)
                return ValueTask.CompletedTask;

            if (file.Upload is null)
            {

                var length = Guard(() => RandomAccess.GetLength(file.Handle));

                file.Handle.Dispose();

                // A file opened and not read - a client looking before it
                // copies - is no download.
                if (file.BytesRead > 0 || length == 0)
                {

                    Interlocked.Increment(ref filesDown);
                    Interlocked.Add      (ref bytesDown, file.BytesRead);

                    log.Info($"'{account.Id}' downloaded /{file.Area.Path}/{file.Name} ({SizeOf(file.BytesRead)}) over SFTP from {from}.",
                             [ "ssh", "sftp", .. file.Area.Tags ]);

                }

                return ValueTask.CompletedTask;

            }

            try
            {
                PutInPlace(file);
            }
            finally
            {
                file.Handle.Dispose();
                Forget(file.Upload);
            }

            return ValueTask.CompletedTask;

        }

        #endregion

        #region OpenDirectoryAsync(Path, CancellationToken)

        public ValueTask<String> OpenDirectoryAsync(String             Path,
                                                    CancellationToken  CancellationToken = default)
        {

            StillIn();

            var place   = Locate(Path);

            if (!place.IsFolder)
                throw place is { Area: SftpArea of, Name: String name } && Sees(of) && of.ShowsName(name) && File.Exists(of.FileOf(name))
                          ? Refused(SftpStatusCode.Failure, $"'{place.Shown}' is a file, not a folder.")
                          : NotThere(place);

            var entries = new List<SftpDirectoryEntry> {
                              new (".",   FolderAttributes(place)),
                              new ("..",  SftpFileAttributes.Directory(0x4000 | 0x16D))
                          };

            if (place.Area is SftpArea area)
                MayRead(area);

            foreach (var folder in FoldersIn(place.Path))
                entries.Add(new SftpDirectoryEntry(folder, FolderAttributes(Locate($"{place.Path}/{folder}"))));

            if (place.Area is SftpArea shown)
                foreach (var name in FilesIn(shown).Order(StringComparer.Ordinal))
                    entries.Add(new SftpDirectoryEntry(name, FileAttributes(shown, shown.FileOf(name))));

            return ValueTask.FromResult(Register(new OpenedListing(entries)));

        }

        #endregion

        #region ReadDirectoryAsync(Handle, CancellationToken)

        public ValueTask<IReadOnlyList<SftpDirectoryEntry>> ReadDirectoryAsync(String             Handle,
                                                                               CancellationToken  CancellationToken = default)
        {

            StillIn();

            lock (gate)
            {

                if (!opened.TryGetValue(Handle, out var entry) || entry is not OpenedListing listing)
                    throw new SftpException(SftpStatusCode.Failure, "No such handle.");

                var batch = listing.Entries.Skip(listing.Next).Take(64).ToList();

                listing.Next += batch.Count;

                return ValueTask.FromResult<IReadOnlyList<SftpDirectoryEntry>>(batch);

            }

        }

        #endregion

        #region StatAsync(Path, CancellationToken)

        public ValueTask<SftpFileAttributes> StatAsync(String             Path,
                                                       CancellationToken  CancellationToken = default)
        {

            StillIn();

            var place = Locate(Path);

            if (place.IsFolder)
            {

                if (place.Area is SftpArea area && !Sees(area))
                    MayRead(area);

                return ValueTask.FromResult(FolderAttributes(place));

            }

            if (place.Area is not SftpArea of)
                throw NotThere(place);

            // Who may write a file may look at it after, as every client does.
            if (!Sees(of))
                MayRead(of);

            // A file being uploaded in this session is what it is so far: a
            // client may look at the handle it writes through.
            lock (gate)
                if (opened.Values.OfType<OpenedFile>().FirstOrDefault(file => file.Upload is not null && file.Area == of && file.Name == place.Name) is OpenedFile upload)
                    return ValueTask.FromResult(FileAttributes(of, upload.Upload!));

            return ValueTask.FromResult(FileAttributes(of, ExistingFile(place)));

        }

        #endregion

        #region RealPathAsync(Path, CancellationToken)

        public ValueTask<String> RealPathAsync(String             Path,
                                               CancellationToken  CancellationToken = default)
        {

            StillIn();

            return ValueTask.FromResult($"/{Normalized(Path)}");

        }

        #endregion

        #region MakeDirectoryAsync(Path, CancellationToken) / RemoveDirectoryAsync(Path, CancellationToken)

        public ValueTask MakeDirectoryAsync(String             Path,
                                            CancellationToken  CancellationToken = default)
        {
            StillIn();
            throw Refused(SftpStatusCode.PermissionDenied, $"The folders over SFTP are this {nodeName}'s: none is made or removed.");
        }

        public ValueTask RemoveDirectoryAsync(String             Path,
                                              CancellationToken  CancellationToken = default)
        {
            StillIn();
            throw Refused(SftpStatusCode.PermissionDenied, $"The folders over SFTP are this {nodeName}'s: none is made or removed.");
        }

        #endregion

        #region RemoveAsync(Path, CancellationToken)

        public ValueTask RemoveAsync(String             Path,
                                     CancellationToken  CancellationToken = default)
        {

            StillIn();

            var place = FileAt(Path);

            MayWrite(place.Area!);

            var file  = ExistingFile(place);

            Guard(() => { File.Delete(file); return true; });

            log.Notice($"'{account.Id}' removed {place.Shown} over SFTP from {from}.",
                       [ "ssh", "sftp", .. place.Area!.Tags ]);

            place.Area.RaiseChanged(new SftpAreaChanged(place.Area, place.Name!, SftpAreaChange.Removed, account, from), Problem);

            return ValueTask.CompletedTask;

        }

        #endregion

        #region RenameAsync(OldPath, NewPath, CancellationToken)

        public ValueTask RenameAsync(String             OldPath,
                                     String             NewPath,
                                     CancellationToken  CancellationToken = default)
        {

            StillIn();

            var before  = FileAt(OldPath);
            var after   = FileAt(NewPath);
            var area    = before.Area!;

            if (after.Area != area)
                throw Refused(SftpStatusCode.PermissionDenied, $"A file stays in its area over SFTP: '{before.Shown}' cannot become '{after.Shown}'.");

            MayWrite(area);

            var file    = ExistingFile(before);
            var target  = AcceptedName(after);

            if (File.Exists(target))
                throw Refused(SftpStatusCode.Failure, $"'{after.Shown}' is there already.");

            if (area.AcceptContent?.Invoke(after.Name!, file) is String refused)
                throw Refused(SftpStatusCode.Failure, refused);

            Guard(() => { File.Move(file, target); return true; });

            log.Notice($"'{account.Id}' renamed {before.Shown} to '{after.Name}' over SFTP from {from}.",
                       [ "ssh", "sftp", .. area.Tags ]);

            area.RaiseChanged(new SftpAreaChanged(area, before.Name!, SftpAreaChange.Removed, account, from), Problem);

            Replaced(area, after.Name!);

            area.RaiseChanged(new SftpAreaChanged(area, after.Name!, SftpAreaChange.PutInPlace, account, from), Problem);

            return ValueTask.CompletedTask;

        }

        #endregion

        #region SetAttributesAsync(Path, Attributes, CancellationToken)

        public ValueTask SetAttributesAsync(String              Path,
                                            SftpFileAttributes  Attributes,
                                            CancellationToken   CancellationToken = default)
        {

            StillIn();

            var place = FileAt(Path);

            MayWrite(place.Area!);

            if (Attributes.Size        is not null ||
                Attributes.Permissions is not null ||
                Attributes.UserId      is not null ||
                Attributes.GroupId     is not null)
            {
                throw Refused(SftpStatusCode.OpUnsupported, "Of a file only its times are set over SFTP: its size, permissions and owner are this " + nodeName + "'s.");
            }

            // A file being uploaded gets its times when it is put in place: an
            // upload is not there before, and a rename keeps them.
            lock (gate)
            {
                foreach (var upload in opened.Values.OfType<OpenedFile>().Where(file => file.Upload is not null && file.Area == place.Area && file.Name == place.Name))
                {
                    upload.ModifyTime = Attributes.ModifyTime ?? upload.ModifyTime;
                    upload.AccessTime = Attributes.AccessTime ?? upload.AccessTime;
                    return ValueTask.CompletedTask;
                }
            }

            var file = ExistingFile(place);

            Guard(() => {

                if (Attributes.ModifyTime is DateTimeOffset modified)
                    File.SetLastWriteTimeUtc (file, modified.UtcDateTime);

                if (Attributes.AccessTime is DateTimeOffset accessed)
                    File.SetLastAccessTimeUtc(file, accessed.UtcDateTime);

                return true;

            });

            return ValueTask.CompletedTask;

        }

        #endregion

        #endregion

        #region DisposeAsync()

        /// <summary>
        /// The session is over: what it left open is closed, an upload it did
        /// not finish is thrown away, and whoever made it is told.
        /// </summary>
        public ValueTask DisposeAsync()
        {

            List<Opened> left;

            lock (gate)
            {

                if (disposed)
                    return ValueTask.CompletedTask;

                disposed = true;
                left     = [.. opened.Values];

                opened.Clear();

            }

            foreach (var file in left.OfType<OpenedFile>())
            {

                file.Handle.Dispose();

                if (file.Upload is not null)
                {

                    Forget(file.Upload);

                    log.Info($"'{account.Id}' left SFTP in the middle of uploading /{file.Area.Path}/{file.Name}, which was not put in place.",
                             [ "ssh", "sftp", .. file.Area.Tags ]);

                }

            }

            ended?.Invoke(this);

            return ValueTask.CompletedTask;

        }

        #endregion


        #region (private) PutInPlace(Upload)

        /// <summary>
        /// An upload closed: checked again for who may write, checked by the
        /// area's owner, and put in place with one rename - or refused, with
        /// nothing changed.
        /// </summary>
        /// <remarks>
        /// Its handle is closed first: the owner reads the upload by its name,
        /// and Windows renames no file that is open.
        /// </remarks>
        private void PutInPlace(OpenedFile Upload)
        {

            var area     = Upload.Area;
            var shown    = $"/{area.Path}/{Upload.Name}";
            var staged   = Upload.Upload!;

            if (Upload.Failed is String failed)
                throw Refused(SftpStatusCode.Failure, $"'{shown}' was not put up: {failed}");

            StillIn();
            MayWrite(area);

            RandomAccess.FlushToDisk(Upload.Handle);

            var size     = RandomAccess.GetLength(Upload.Handle);

            Upload.Handle.Dispose();

            if (area.AcceptContent?.Invoke(Upload.Name, staged) is String refused)
            {

                log.Info($"'{account.Id}' could not put up {shown} over SFTP from {from}: {refused}",
                         [ "ssh", "sftp", .. area.Tags ]);

                throw Refused(SftpStatusCode.Failure, refused);

            }

            var sha256   = Guard(() => {

                               using var content = File.OpenRead(staged);

                               return Convert.ToHexStringLower(SHA256.HashData(content));

                           });

            Guard(() => {

                if (Upload.ModifyTime is DateTimeOffset modified)
                    File.SetLastWriteTimeUtc (staged, modified.UtcDateTime);

                if (Upload.AccessTime is DateTimeOffset accessed)
                    File.SetLastAccessTimeUtc(staged, accessed.UtcDateTime);

                File.Move(staged, area.FileOf(Upload.Name), overwrite: true);

                return true;

            });

            Interlocked.Increment(ref filesUp);
            Interlocked.Add      (ref bytesUp, size);

            log.Notice($"'{account.Id}' put up {shown} over SFTP from {from}: {SizeOf(size)}, SHA-256 {sha256}.",
                       [ "ssh", "sftp", .. area.Tags ]);

            Replaced(area, Upload.Name);

            area.RaiseChanged(new SftpAreaChanged(area, Upload.Name, SftpAreaChange.PutInPlace, account, from), Problem);

        }

        #endregion

        #region (private) Replaced(Area, Name)

        /// <summary>
        /// Remove what the file of the given name, now in place, takes the place of.
        /// </summary>
        private void Replaced(SftpArea  Area,
                              String    Name)
        {

            foreach (var other in Area.Replaces?.Invoke(Name) ?? [])
            {

                if (other == Name || !Area.ShowsName(other))
                    continue;

                var file = Area.FileOf(other);

                if (!File.Exists(file))
                    continue;

                try
                {
                    File.Delete(file);
                }
                catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
                {
                    Problem($"'/{Area.Path}/{other}' could not be removed, although '{Name}' takes its place: {problem.Message}");
                    continue;
                }

                log.Notice($"'/{Area.Path}/{other}' was removed: '{Name}', which '{account.Id}' put up over SFTP, takes its place.",
                           [ "ssh", "sftp", .. Area.Tags ]);

                Area.RaiseChanged(new SftpAreaChanged(Area, other, SftpAreaChange.Removed, account, from), Problem);

            }

        }

        #endregion

        #region (private) StillIn()

        /// <summary>
        /// Refuse everything once what let the session in no longer does - the
        /// node ends the session too, but a request may come first.
        /// </summary>
        private void StillIn()
        {

            if (Volatile.Read(ref disposed))
                throw new SftpException(SftpStatusCode.Failure, "This SFTP session is over.");

            if (signedOut() is String why)
                throw new SftpException(SftpStatusCode.PermissionDenied, $"Signed out: {why}.");

        }

        #endregion

        #region (private) MayRead(Area) / MayWrite(Area) / Sees(Area)

        private Boolean Reads(SftpArea Area)

            => Area.Read is not Permission needed || isAllowed(needed);

        private Boolean Writes(SftpArea Area)

            => Area.Write is Permission needed && isAllowed(needed);

        /// <summary>
        /// Whether the account may read or write the given area: whether it is
        /// shown to it at all.
        /// </summary>
        private Boolean Sees(SftpArea Area)

            => Reads(Area) || Writes(Area);

        /// <summary>
        /// Refuse, with what it needs, where the account may not read the area.
        /// </summary>
        private void MayRead(SftpArea Area)
        {
            if (!Reads(Area))
                throw Refused(SftpStatusCode.PermissionDenied, $"Reading /{Area.Path} needs {Area.Read}.");
        }

        /// <summary>
        /// Refuse, with what it needs, where the account may not write the area
        /// - or nobody may.
        /// </summary>
        private void MayWrite(SftpArea Area)
        {

            if (Area.Write is not Permission needed)
                throw Refused(SftpStatusCode.PermissionDenied,
                              $"/{Area.Path} is read-only for everybody: nothing is written, renamed or removed there.");

            if (!isAllowed(needed))
                throw Refused(SftpStatusCode.PermissionDenied, $"Writing /{Area.Path} needs {needed}.");

        }

        #endregion

        #region (private) Locate(Path) / FileAt(Path) / Normalized(Path)

        /// <summary>
        /// The path as the tree takes it: from its root, without "." and "..",
        /// which go no further up than the root.
        /// </summary>
        private static String Normalized(String Path)
        {

            var parts = new List<String>();

            foreach (var part in Path.Split('/'))
            {

                if (part is "" or ".")
                    continue;

                if (part == "..")
                {
                    if (parts.Count > 0)
                        parts.RemoveAt(parts.Count - 1);
                    continue;
                }

                parts.Add(part);

            }

            return String.Join('/', parts);

        }

        /// <summary>
        /// Where the given path leads, for this account: a folder only where it
        /// holds an area the account sees, an area only where it sees it.
        /// </summary>
        private Place Locate(String Path)
        {

            var path = Normalized(Path);

            if (path.Length == 0)
                return new Place("", null, null, IsFolder: true);

            if (areas.FirstOrDefault(area => area.Path == path) is SftpArea exactly)
                return new Place(path, exactly, null, IsFolder: true);

            if (areas.Any(area => area.Path.StartsWith(path + "/", StringComparison.Ordinal) && Sees(area)))
                return new Place(path, null, null, IsFolder: true);

            var cut  = path.LastIndexOf('/');
            var of   = cut < 0 ? "" : path[..cut];

            return areas.FirstOrDefault(area => area.Path == of) is SftpArea holding
                       ? new Place(path, holding, path[(cut + 1)..], IsFolder: false)
                       : new Place(path, null,    null,              IsFolder: false);

        }

        /// <summary>
        /// The file of an area the given path leads to - or the refusal of a
        /// path that leads to no file.
        /// </summary>
        private Place FileAt(String Path)
        {

            var place = Locate(Path);

            if (place.IsFolder)
                throw place.Path.Length == 0 || place.Area is null
                          ? Refused(SftpStatusCode.PermissionDenied, $"'{place.Shown}' is a folder of this {nodeName}'s: files go into its areas.")
                          : Refused(SftpStatusCode.Failure,          $"'{place.Shown}' is a folder.");

            if (place.Area is null)
                throw NotThere(place);

            return place;

        }

        #endregion

        #region (private) ExistingFile(Place) / AcceptedName(Place) / FilesIn(Area) / FoldersIn(Path)

        /// <summary>
        /// The file on the disk the given place shows, where it shows one and it
        /// is there.
        /// </summary>
        private static String ExistingFile(Place Place)
        {

            if (!Place.Area!.ShowsName(Place.Name!))
                throw NotThere(Place);

            var file = Place.Area.FileOf(Place.Name!);

            if (!File.Exists(file))
                throw NotThere(Place);

            return file;

        }

        /// <summary>
        /// The file on the disk a name to be written goes to, where it may be
        /// written: a name a file can have, which the area's owner accepts and
        /// the area shows.
        /// </summary>
        private String AcceptedName(Place Place)
        {

            var area = Place.Area!;
            var name = Place.Name!;

            if (!SftpArea.IsFileName(name))
                throw Refused(SftpStatusCode.PermissionDenied, $"'{name}' cannot be the name of a file of /{area.Path}.");

            if (area.AcceptName?.Invoke(name) is String refused)
                throw Refused(SftpStatusCode.PermissionDenied, refused);

            if (!area.ShowsName(name))
                throw Refused(SftpStatusCode.PermissionDenied, $"/{area.Path} takes no file called '{name}'.");

            return area.FileOf(name);

        }

        /// <summary>
        /// The names of the files the given area shows, which are there now.
        /// </summary>
        private static IEnumerable<String> FilesIn(SftpArea Area)
        {

            if (!System.IO.Directory.Exists(Area.Directory))
                return [];

            try
            {
                return [.. new DirectoryInfo(Area.Directory).EnumerateFiles().
                                                            Where (file => (file.Attributes & System.IO.FileAttributes.ReparsePoint) == 0).
                                                            Select(file => file.Name).
                                                            Where (Area.ShowsName)];
            }
            catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
            {
                return [];
            }

        }

        /// <summary>
        /// The folders in the given folder that hold an area the account sees:
        /// its next part of their paths.
        /// </summary>
        private IEnumerable<String> FoldersIn(String Path)

            => areas.Where (area => (Path.Length == 0 || area.Path.StartsWith(Path + "/", StringComparison.Ordinal)) &&
                                    area.Path != Path &&
                                    Sees(area)).
                     Select(area => area.Path[(Path.Length == 0 ? 0 : Path.Length + 1)..].Split('/')[0]).
                     Distinct().
                     Order(StringComparer.Ordinal);

        #endregion

        #region (private) FolderAttributes(Place) / FileAttributes(Area, File)

        /// <summary>
        /// A folder as a listing shows it: written into only where it is an
        /// area the account writes.
        /// </summary>
        private SftpFileAttributes FolderAttributes(Place Place)
        {

            var mode = Place.Area is SftpArea area && Writes(area)
                           ? 0x1EDu    // 0755
                           : 0x16Du;   // 0555

            var at   = Place.Area is SftpArea there && System.IO.Directory.Exists(there.Directory)
                           ? new DateTimeOffset(System.IO.Directory.GetLastWriteTimeUtc(there.Directory), TimeSpan.Zero)
                           : (DateTimeOffset?) null;

            return SftpFileAttributes.Directory(0x4000 | mode) with {
                       AccessTime = at,
                       ModifyTime = at
                   };

        }

        /// <summary>
        /// A file as a listing shows it: its size and times, and writable only
        /// where the account writes its area.
        /// </summary>
        private SftpFileAttributes FileAttributes(SftpArea  Area,
                                                  String    File)
        {

            var info = new FileInfo(File);

            return SftpFileAttributes.File(info.Exists ? info.Length : 0,
                                           0x8000 | (Writes(Area) ? 0x1A4u /* 0644 */ : 0x124u /* 0444 */)) with {
                       AccessTime = new DateTimeOffset(info.LastAccessTimeUtc, TimeSpan.Zero),
                       ModifyTime = new DateTimeOffset(info.LastWriteTimeUtc,  TimeSpan.Zero)
                   };

        }

        #endregion

        #region (private) Register(Opened) / FileOf(Handle) / Forget(Upload)

        private String Register(Opened Opened)
        {
            lock (gate)
            {

                if (disposed)
                {
                    if (Opened is OpenedFile file)
                    {
                        file.Handle.Dispose();
                        Forget(file.Upload);
                    }
                    throw new SftpException(SftpStatusCode.Failure, "This SFTP session is over.");
                }

                var handle = (++lastHandle).ToString(CultureInfo.InvariantCulture);

                opened[handle] = Opened;

                return handle;

            }
        }

        private OpenedFile FileOf(String Handle)
        {
            lock (gate)
                return opened.TryGetValue(Handle, out var entry) && entry is OpenedFile file
                           ? file
                           : throw new SftpException(SftpStatusCode.Failure, "No such handle.");
        }

        /// <summary>
        /// Take away an upload that was not put in place, if it is still there.
        /// </summary>
        private void Forget(String? Upload)
        {

            if (Upload is null)
                return;

            try
            {
                File.Delete(Upload);
            }
            catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
            {
                Problem($"An upload not put in place could not be taken away, and is taken away at the next start: '{Upload}': {problem.Message}");
            }

        }

        #endregion

        #region (private) Refused(...) / NotThere(Place) / Problem(Text) / Guard(Operation)

        private SftpException Refused(SftpStatusCode  Code,
                                      String          Why)
        {

            log.Debug($"Refused '{account.Id}' over SFTP from {from}: {Why}", "ssh", "sftp");

            return new SftpException(Code, Why);

        }

        private static SftpException NotThere(Place Place)

            => new (SftpStatusCode.NoSuchFile, $"There is no '{Place.Shown}'.");

        private void Problem(String Text)

            => log.Warning(Text, "ssh", "sftp");

        /// <summary>
        /// What the disk said, as an SFTP status: not there, not allowed by the
        /// machine, or a failure that says what failed.
        /// </summary>
        private static T Guard<T>(Func<T> Operation)
        {
            try
            {
                return Operation();
            }
            catch (FileNotFoundException)
            {
                throw new SftpException(SftpStatusCode.NoSuchFile, "No such file.");
            }
            catch (DirectoryNotFoundException)
            {
                throw new SftpException(SftpStatusCode.NoSuchFile, "No such file.");
            }
            catch (UnauthorizedAccessException)
            {
                throw new SftpException(SftpStatusCode.PermissionDenied, "The machine does not let this file be used.");
            }
            catch (IOException problem)
            {
                throw new SftpException(SftpStatusCode.Failure, problem.Message);
            }
        }

        #endregion

        #region (static) SizeOf(Bytes)

        /// <summary>
        /// How large something is, as somebody says it: "12 bytes", "310 KiB",
        /// "1.4 MiB".
        /// </summary>
        public static String SizeOf(Int64 Bytes)

            => Bytes < 1024              ? $"{Bytes} byte{(Bytes == 1 ? "" : "s")}"
             : Bytes < 1024 * 1024       ? $"{Math.Max(1, (Int64) Math.Round(Bytes / 1024.0))} KiB"
             : Bytes < 1024L * 1024 * 1024
                                         ? $"{(Bytes / (1024.0 * 1024)).ToString("0.#", CultureInfo.InvariantCulture)} MiB"
             :                             $"{(Bytes / (1024.0 * 1024 * 1024)).ToString("0.#", CultureInfo.InvariantCulture)} GiB";

        #endregion

    }

}
