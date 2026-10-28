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

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Directories and files that nobody but the account a node runs under may
    /// read: the accounts, the logs, the certificates and their keys, the SSH
    /// host key, and whatever a node built on this one keeps of the same kind.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On Unix a directory is 0700 and a file 0600. On Windows both get a
    /// protected access control list - nothing inherited from the folder above -
    /// that grants the running account, SYSTEM and the administrators and
    /// nobody else, the same three a user's profile grants. That is the part
    /// that matters on Windows: a node kept below a folder at the root of a
    /// drive inherits read access for every authenticated user, and a key in
    /// it is then everybody's.
    /// </para>
    /// <para>
    /// What is in the directory is walked as well, at every start, so that a
    /// key or a password hash is not open to everybody the day somebody opens
    /// its directory, or the file itself, again. On Windows each entry with a
    /// list of its own - entries added by hand, or protected - is given the
    /// one its directory hands down and nothing else; on Unix, where a mode
    /// is each entry's own, directories become 0700 and files 0600. What is
    /// written into the directory later gets what Windows hands down, or on
    /// Unix whatever the umask gives it, below a directory nobody else may
    /// enter - until the next start takes it in. Symbolic links and other
    /// reparse points are left alone: what they point to is not the
    /// directory's.
    /// </para>
    /// <para>
    /// Best effort: a file system with no notion of either (a mounted share,
    /// say) is still one a node can run from. What could not be done is handed
    /// to <c>Complain</c>, for the log, and nothing is thrown.
    /// </para>
    /// </remarks>
    public static class OwnerOnly
    {

        #region Directory(Path, Complain = null)

        /// <summary>
        /// Make the given directory where it is not there yet, and keep
        /// everybody but its owner out of it and of everything in it.
        /// </summary>
        /// <param name="Path">The directory.</param>
        /// <param name="Complain">Told what could not be restricted, and why.</param>
        public static void Directory(String           Path,
                                     Action<String>?  Complain   = null)
        {

            System.IO.Directory.CreateDirectory(Path);

            Restrict(Path, IsDirectory: true, Complain);

        }

        #endregion

        #region File(Path, Complain = null)

        /// <summary>
        /// Keep everybody but its owner out of the given file.
        /// </summary>
        /// <param name="Path">The file, which must exist.</param>
        /// <param name="Complain">Told what could not be restricted, and why.</param>
        public static void File(String           Path,
                                Action<String>?  Complain   = null)

            => Restrict(Path, IsDirectory: false, Complain);

        #endregion


        #region (private static) Restrict(Path, IsDirectory, Complain)

        private static void Restrict(String           Path,
                                     Boolean          IsDirectory,
                                     Action<String>?  Complain)
        {
            try
            {

                if (OperatingSystem.IsWindows())
                    RestrictOnWindows(Path, IsDirectory);

                else
                    System.IO.File.SetUnixFileMode(Path, IsDirectory ? DirectoryMode : FileMode);

                if (IsDirectory)
                    RestrictWhatIsIn(Path, Complain);

            }
            catch (Exception problem)
            {
                Complain?.Invoke($"'{Path}' could not be made readable by its owner alone, and may be readable by other users of this machine: {problem.Message}");
            }
        }

        private const UnixFileMode DirectoryMode  = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        private const UnixFileMode FileMode       = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        #endregion

        #region (private static) RestrictWhatIsIn(Directory, Complain)

        /// <summary>
        /// Every entry below the given directory: on Windows the access list its
        /// directory hands down and nothing of its own, on Unix 0700 for a
        /// directory and 0600 for a file - each on its own, so that one that
        /// cannot be changed (another account's, say) does not leave the rest
        /// as they were. Said once, with how many there were.
        /// </summary>
        private static void RestrictWhatIsIn(String           Directory,
                                             Action<String>?  Complain)
        {

            var       failed  = 0;
            String?   first   = null;

            foreach (var entry in new DirectoryInfo(Directory).EnumerateFileSystemInfos("*", new EnumerationOptions {
                                                                                                  RecurseSubdirectories  = true,
                                                                                                  AttributesToSkip       = FileAttributes.ReparsePoint,
                                                                                                  IgnoreInaccessible     = true
                                                                                              }))
            {
                try
                {

                    if (OperatingSystem.IsWindows())
                        InheritOnWindows(entry);

                    else
                    {

                        var mode = entry is DirectoryInfo ? DirectoryMode : FileMode;

                        if (entry.UnixFileMode != mode)
                            entry.UnixFileMode = mode;

                    }

                }
                catch (Exception problem)
                {
                    failed++;
                    first ??= $"'{entry.FullName}': {problem.Message}";
                }
            }

            if (failed > 0)
                Complain?.Invoke($"{failed} entry(s) below '{Directory}' could not be made readable by their owner alone, and may be readable by other users of this machine - the first {first}");

        }

        #endregion

        #region (private static) InheritOnWindows(Entry)

        /// <summary>
        /// Give an entry what its directory hands down and nothing of its own -
        /// where it has anything of its own at all, so that a start does not
        /// write every file of a log again.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private static void InheritOnWindows(FileSystemInfo Entry)
        {

            FileSystemSecurity current = Entry is DirectoryInfo directory
                                             ? directory.GetAccessControl()
                                             : ((FileInfo) Entry).GetAccessControl();

            if (!current.AreAccessRulesProtected &&
                current.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier)).Count == 0)
            {
                return;
            }

            // No rule of its own, and open to what comes down from above.
            FileSystemSecurity inherited = Entry is DirectoryInfo
                                               ? new DirectorySecurity()
                                               : new FileSecurity();

            inherited.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);

            if (Entry is DirectoryInfo directoryInfo)
                directoryInfo.SetAccessControl((DirectorySecurity) inherited);

            else
                ((FileInfo) Entry).SetAccessControl((FileSecurity) inherited);

        }

        #endregion

        #region (private static) RestrictOnWindows(Path, IsDirectory)

        [SupportedOSPlatform("windows")]
        private static void RestrictOnWindows(String   Path,
                                              Boolean  IsDirectory)
        {

            using var identity = WindowsIdentity.GetCurrent();

            var owner        = identity.User
                                   ?? throw new InvalidOperationException("The account this runs under has no security identifier.");

            var inheritance  = IsDirectory
                                   ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
                                   : InheritanceFlags.None;

            FileSystemSecurity security = IsDirectory
                                              ? new DirectorySecurity()
                                              : new FileSecurity();

            // Protected: nothing comes down from the folder above any more.
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            foreach (var who in new[] {
                                    owner,
                                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid,           null),
                                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
                                }.Distinct())
            {
                security.AddAccessRule(new FileSystemAccessRule(who,
                                                                FileSystemRights.FullControl,
                                                                inheritance,
                                                                PropagationFlags.None,
                                                                AccessControlType.Allow));
            }

            if (IsDirectory)
                new DirectoryInfo(Path).SetAccessControl((DirectorySecurity) security);

            else
                new FileInfo(Path).SetAccessControl((FileSecurity) security);

        }

        #endregion

    }

}
