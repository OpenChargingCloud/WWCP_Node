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
    /// A directory's list is inherited by what is in it, so what was written
    /// there before - by an earlier version that did not do this - is taken in
    /// as soon as the directory is, at the next start.
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
                    System.IO.File.SetUnixFileMode(Path,
                                                   IsDirectory
                                                       ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                                       : UnixFileMode.UserRead | UnixFileMode.UserWrite);

            }
            catch (Exception problem)
            {
                Complain?.Invoke($"'{Path}' could not be made readable by its owner alone, and may be readable by other users of this machine: {problem.Message}");
            }
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
