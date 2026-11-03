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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// What became of a file in an area over SFTP.
    /// </summary>
    public enum SftpAreaChange
    {

        /// <summary>
        /// Put in place: uploaded, checked and renamed to its name - new, or
        /// in the place of the file of that name.
        /// </summary>
        PutInPlace,

        /// <summary>
        /// Removed, or renamed away.
        /// </summary>
        Removed

    }


    /// <summary>
    /// A file of an area put in place or removed over SFTP, and by whom.
    /// </summary>
    /// <param name="Area">The area.</param>
    /// <param name="Name">The file's name in it.</param>
    /// <param name="Change">What became of it.</param>
    /// <param name="Account">Who did it.</param>
    /// <param name="From">From where.</param>
    public sealed record SftpAreaChanged(SftpArea        Area,
                                         String          Name,
                                         SftpAreaChange  Change,
                                         IUser           Account,
                                         String          From);


    /// <summary>
    /// A folder of a node's SFTP tree: one directory on the disk, the names in
    /// it that are shown, and what reading and writing it needs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SFTP shows nothing of the machine but its areas. Each is declared by the
    /// node or by its kind before the node starts - see
    /// <see cref="WWCPNode.AddSftpArea(SftpArea)"/> - and shows of its directory
    /// only the names <see cref="Shows"/> admits: an allowlist, never "the
    /// whole directory", because what else lies there is not for everybody.
    /// The metrological log's directory holds its private signing key.
    /// </para>
    /// <para>
    /// An area is flat: files, and no folders of its own. An area may lie
    /// within another's path - "logs/metrological" within "logs" - and is then
    /// shown in it as a folder; a path whose first part no area has is a
    /// folder that holds only areas.
    /// </para>
    /// <para>
    /// What reading and writing need is asked of the node's role model at
    /// every operation, as the web interface asks it at every request. An
    /// upload is written under a hidden name, checked when it is closed, and
    /// only then put in place with one rename: a half upload, or one its
    /// owner refused, never takes the place of anything.
    /// </para>
    /// </remarks>
    public sealed class SftpArea
    {

        #region Data

        /// <summary>
        /// What the hidden name of an upload in progress begins with: never
        /// shown, never opened, and taken away at the next start where an
        /// upload never finished.
        /// </summary>
        public const String  UploadPrefix     = ".sftp-upload-";

        /// <summary>
        /// How long a name of a file may be.
        /// </summary>
        public const Int32   MaxNameLength    = 255;

        #endregion

        #region Properties

        /// <summary>
        /// Where the area is in the SFTP tree, without slashes around it:
        /// "logs", "logs/metrological".
        /// </summary>
        public String                              Path            { get; }

        /// <summary>
        /// The directory on the disk it shows.
        /// </summary>
        public String                              Directory       { get; }

        /// <summary>
        /// Whether a name in the directory is shown, and may be read - and,
        /// where the area is written, written.
        /// </summary>
        public Func<String, Boolean>               Shows           { get; }

        /// <summary>
        /// What listing the area and reading a file in it need beyond being
        /// signed in; null for nothing more.
        /// </summary>
        public Permission?                         Read            { get; }

        /// <summary>
        /// What uploading, replacing, renaming and removing a file need; null
        /// where nobody writes the area, administrators included.
        /// </summary>
        public Permission?                         Write           { get; }

        /// <summary>
        /// The owner's check of a name to be written, when it is opened and
        /// before a byte is sent: why it is refused, as a sentence, or null.
        /// </summary>
        public Func<String, String?>?              AcceptName      { get; init; }

        /// <summary>
        /// The owner's check of what was uploaded, under its name and in the
        /// file given, once it is closed and before it is put in place: why it
        /// is refused, as a sentence, or null. Asked again of a file renamed,
        /// under its new name.
        /// </summary>
        public Func<String, String, String?>?      AcceptContent   { get; init; }

        /// <summary>
        /// The names of other files a file put in place takes the place of,
        /// removed once it is in place: "ionity.png" for "ionity.svg", where
        /// there is one picture to a provider.
        /// </summary>
        public Func<String, IEnumerable<String>>?  Replaces        { get; init; }

        /// <summary>
        /// The largest file that may be written, in bytes; null for no limit.
        /// </summary>
        public Int64?                              MaxFileSize     { get; init; }

        /// <summary>
        /// How many files the area may hold; null for no limit.
        /// </summary>
        public Int32?                              MaxFiles        { get; init; }

        /// <summary>
        /// The tags the log gives what is done in the area, besides "sftp".
        /// </summary>
        public IReadOnlyList<String>               Tags            { get; init; } = [];

        /// <summary>
        /// Whether anybody may write the area.
        /// </summary>
        public Boolean                             IsWritable
            => Write is not null;

        #endregion

        #region Events

        /// <summary>
        /// Raised after a file was put in place or removed over SFTP.
        /// </summary>
        public event Action<SftpAreaChanged>?      Changed;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// An area of the SFTP tree.
        /// </summary>
        /// <param name="Path">Where it is in the tree: lower-case letters, digits, '-' and '_', parts separated by '/'.</param>
        /// <param name="Directory">The directory on the disk it shows; need not exist yet.</param>
        /// <param name="Shows">Whether a name in it is shown.</param>
        /// <param name="Read">What reading it needs beyond being signed in; null for nothing more.</param>
        /// <param name="Write">What writing it needs; null where nobody writes it.</param>
        public SftpArea(String                 Path,
                        String                 Directory,
                        Func<String, Boolean>  Shows,
                        Permission?            Read   = null,
                        Permission?            Write  = null)
        {

            if (!IsAreaPath(Path))
                throw new ArgumentException($"'{Path}' is no path of an SFTP area: lower-case letters, digits, '-' and '_', parts separated by '/'.", nameof(Path));

            if (String.IsNullOrWhiteSpace(Directory) || !System.IO.Path.IsPathFullyQualified(Directory))
                throw new ArgumentException($"The SFTP area '{Path}' needs a directory given in full, not '{Directory}'.", nameof(Directory));

            this.Path       = Path;
            this.Directory  = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(Directory));
            this.Shows      = Shows;
            this.Read       = Read;
            this.Write      = Write;

        }

        #endregion


        #region (static) IsAreaPath(Text)

        /// <summary>
        /// Whether the given text is the path of an area: parts of lower-case
        /// letters, digits, '-' and '_', separated by '/', none empty.
        /// </summary>
        public static Boolean IsAreaPath(String? Text)

            => Text is { Length: > 0 and <= 200 } &&
               Text.Split('/').All(part => part.Length > 0 &&
                                           part.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'));

        #endregion

        #region (static) IsFileName(Name)

        /// <summary>
        /// Whether the given name can be the name of a file of an area at all,
        /// whatever the area shows: one part, not "." or "..", without a
        /// separator of any platform, a drive's colon or a control character,
        /// and not the hidden name of an upload.
        /// </summary>
        public static Boolean IsFileName(String? Name)

            => Name is { Length: > 0 and <= MaxNameLength } &&
               Name is not "." and not ".." &&
               !Name.StartsWith(UploadPrefix, StringComparison.Ordinal) &&
               !Name.Any(c => c is '/' or '\\' or ':' || Char.IsControl(c)) &&
               Name.Trim() == Name &&
               !Name.EndsWith('.');

        #endregion

        #region (internal) ShowsName(Name)

        /// <summary>
        /// Whether the given name is a file of this area: a name a file can
        /// have, and one the area shows.
        /// </summary>
        internal Boolean ShowsName(String Name)
        {

            if (!IsFileName(Name))
                return false;

            try
            {
                return Shows(Name);
            }
            catch (Exception)
            {
                return false;
            }

        }

        #endregion

        #region (internal) FileOf(Name)

        /// <summary>
        /// Where the file of the given name lies on the disk - a name
        /// <see cref="ShowsName(String)"/> admitted, so that it lies in the
        /// area's directory and nowhere else.
        /// </summary>
        internal String FileOf(String Name)
        {

            var file = System.IO.Path.GetFullPath(System.IO.Path.Combine(Directory, Name));

            if (!String.Equals(System.IO.Path.GetDirectoryName(file), Directory, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidOperationException($"'{Name}' would lie outside the SFTP area '{Path}'.");

            return file;

        }

        #endregion

        #region (internal) RaiseChanged(Changed, OnProblem)

        /// <summary>
        /// Tell whoever listens that a file was put in place or removed - each
        /// of them, whatever another one did.
        /// </summary>
        internal void RaiseChanged(SftpAreaChanged  Changed,
                                   Action<String>   OnProblem)
        {

            foreach (var listener in this.Changed?.GetInvocationList().Cast<Action<SftpAreaChanged>>() ?? [])
            {
                try
                {
                    listener(Changed);
                }
                catch (Exception problem)
                {
                    OnProblem($"Whoever listens to the SFTP area '/{Path}' failed over '{Changed.Name}': {problem.Message}");
                }
            }

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"/{Path} ({Directory}){(IsWritable ? "" : ", read-only")}";

        #endregion

    }

}
