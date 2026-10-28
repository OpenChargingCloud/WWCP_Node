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

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// Who may get into a directory or a file other than its owner - for the
    /// tests of <see cref="OwnerOnly"/> and of every node that keeps something
    /// with it.
    /// </summary>
    public static class OwnerOnlyChecks
    {

        #region OthersMayGetIn(Path)

        /// <summary>
        /// Who other than the owner, SYSTEM and the administrators may do
        /// anything with the given directory or file - or, on Unix, which bits
        /// of the group and the others are set. Empty where nobody may.
        /// </summary>
        public static IEnumerable<String> OthersMayGetIn(String Path)
        {

            if (OperatingSystem.IsWindows())
                return OthersMayGetInOnWindows(Path);

            var others = File.GetUnixFileMode(Path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                                                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);

            return others == UnixFileMode.None
                       ? []
                       : [ others.ToString() ];

        }

        // Of its own, for the platform analyser: a guard does not reach into the lambdas below.
        [SupportedOSPlatform("windows")]
        private static String[] OthersMayGetInOnWindows(String Path)
        {

            using var identity = WindowsIdentity.GetCurrent();

            var allowed  = new HashSet<SecurityIdentifier> {
                               identity.User!,
                               new (WellKnownSidType.LocalSystemSid,           null),
                               new (WellKnownSidType.BuiltinAdministratorsSid, null)
                           };

            FileSystemSecurity security = Directory.Exists(Path)
                                              ? new DirectoryInfo(Path).GetAccessControl()
                                              : new FileInfo(Path).GetAccessControl();

            return security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).
                            OfType<FileSystemAccessRule>().
                            Where (rule => rule.AccessControlType == AccessControlType.Allow &&
                                           !allowed.Contains((SecurityIdentifier) rule.IdentityReference)).
                            Select(rule => rule.IdentityReference.Value).
                            ToArray();

        }

        #endregion

        #region OpenToEverybody(Path)

        /// <summary>
        /// Make what an older version left, or somebody opened since: an
        /// existing file everybody may read, or else a directory everybody may
        /// read - made where it is not there - with whatever is in it that
        /// takes what the directory hands down (on Windows).
        /// </summary>
        public static void OpenToEverybody(String Path)
        {

            var isFile = File.Exists(Path);

            if (!isFile)
                Directory.CreateDirectory(Path);

            if (OperatingSystem.IsWindows())
                OpenToEverybodyOnWindows(Path, isFile);

            else
                File.SetUnixFileMode(Path, isFile ? (UnixFileMode) 0b110_100_100 : (UnixFileMode) 0b111_101_101);

        }

        [SupportedOSPlatform("windows")]
        private static void OpenToEverybodyOnWindows(String Path, Boolean IsFile)
        {

            var everybody = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            if (IsFile)
            {
                var info     = new FileInfo(Path);
                var security = info.GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(everybody, FileSystemRights.Read, AccessControlType.Allow));
                info.SetAccessControl(security);
            }

            else
            {
                var info     = new DirectoryInfo(Path);
                var security = info.GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(everybody,
                                                                FileSystemRights.ReadAndExecute,
                                                                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                                PropagationFlags.None,
                                                                AccessControlType.Allow));
                info.SetAccessControl(security);
            }

        }

        #endregion

    }

}
