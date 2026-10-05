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

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// What is read as SSH public keys: what somebody hands over - an
    /// authorized_keys line, an OpenSSH .pub, or what PuTTYgen saves - and the
    /// files the keys were kept in before they were kept with their account.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The keys an account signs in with are the account's, in the HTTPExt API:
    /// added and removed there, with who did it and when in the hash chain of
    /// its database file, and gone with the account. Hermod reads the
    /// authorized_keys line of each, so <c>from="10.0.0.0/8"</c> and
    /// <c>expiry-time="20271231"</c> in front of a key hold as OpenSSH holds
    /// them, and a line with an option that cannot be held to is refused.
    /// </para>
    /// <para>
    /// They were kept in a file per account, <c>accounts/ssh/&lt;account&gt;</c>,
    /// read at every sign-in. A node takes such a file over once, at its start,
    /// and renames it to <c>&lt;account&gt;.imported</c>: from then on it is
    /// not read, and a key written into a file by hand opens nothing.
    /// </para>
    /// </remarks>
    public static class AuthorizedKeysStore
    {

        #region Data

        /// <summary>
        /// Where the files of the keys were, below the accounts' directory.
        /// </summary>
        public const String DefaultDirectoryName  = "ssh";

        /// <summary>
        /// What a file taken over is renamed to end with.
        /// </summary>
        public const String ImportedSuffix        = ".imported";

        /// <summary>
        /// What an account's name may be made of to be a file's: no separator,
        /// no dot at the start, nothing a file system could read as something
        /// else.
        /// </summary>
        private static readonly Regex fileName = new ("^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,127}$", RegexOptions.Compiled);

        #endregion


        #region (static) IsAccountName(Account)

        /// <summary>
        /// Whether the given name can be an account's - and the name of a file
        /// of keys it had.
        /// </summary>
        public static Boolean IsAccountName(String Account)

            => fileName.IsMatch(Account);

        #endregion

        #region (static) TryRead(Text, out Keys, out Refused)

        /// <summary>
        /// The keys in what somebody hands over: lines as an <c>authorized_keys</c>
        /// file has them, or the block of RFC 4716 - what PuTTYgen's "Save public
        /// key" writes.
        /// </summary>
        /// <param name="Text">What was handed over.</param>
        /// <param name="Lines">Each key as the line it is written to a file as.</param>
        /// <param name="Refused">Why nothing could be read.</param>
        public static Boolean TryRead(String                                        Text,
                                      [NotNullWhen(true)]  out IReadOnlyList<String>?  Lines,
                                      [NotNullWhen(false)] out String?                 Refused)
        {

            Lines    = null;
            Refused  = null;

            if (Text.Contains("---- BEGIN SSH2 PUBLIC KEY ----", StringComparison.Ordinal))
            {
                try
                {
                    Lines = [ SshPublicKey.ParseRfc4716(Text).ToAuthorizedKeyLine() ];
                    return true;
                }
                catch (Exception problem)
                {
                    Refused = $"it is an RFC 4716 public key that could not be read: {problem.Message}";
                    return false;
                }
            }

            if (Text.Contains("PRIVATE KEY", StringComparison.Ordinal) || Text.StartsWith("PuTTY-User-Key-File", StringComparison.Ordinal))
            {
                Refused = "it is a private key. Only the public key goes here - the one in the .pub file, or what PuTTYgen shows for pasting into an authorized_keys file.";
                return false;
            }

            var lines = new List<String>();

            foreach (var raw in Text.Replace("\r\n", "\n").Split('\n'))
            {

                var line = raw.Trim();

                if (line.Length == 0 || line.StartsWith('#'))
                    continue;

                if (!AuthorizedKeysFile.TryParseLine(line, out _, out var why))
                {
                    Refused = $"'{(line.Length > 40 ? line[..40] + "..." : line)}' is no public key as an authorized_keys file has one: {why}";
                    return false;
                }

                lines.Add(line);

            }

            if (lines.Count == 0)
            {
                Refused = "there is no public key in it.";
                return false;
            }

            Lines = lines;
            return true;

        }

        #endregion

        #region (static) TryReadFile(File, out Text, out Refused)

        /// <summary>
        /// What a file of public keys holds, where it holds one; and otherwise
        /// what is wrong with it, in a sentence that names the file.
        /// </summary>
        /// <param name="File">The file: an OpenSSH .pub, an authorized_keys file, or what PuTTYgen saves.</param>
        /// <param name="Text">What it holds.</param>
        /// <param name="Refused">Why it holds no key that could be read.</param>
        public static Boolean TryReadFile(String                             File,
                                          [NotNullWhen(true)]  out String?   Text,
                                          [NotNullWhen(false)] out String?   Refused)
        {

            Text     = null;
            Refused  = null;

            if (!System.IO.File.Exists(File))
            {
                Refused = $"there is no file '{File}'.";
                return false;
            }

            try
            {
                Text = System.IO.File.ReadAllText(File);
            }
            catch (Exception problem)
            {
                Refused = $"'{File}' could not be read: {problem.Message}";
                return false;
            }

            if (!TryRead(Text, out _, out var why))
            {
                Text    = null;
                Refused = $"'{File}' holds no public key: {why}";
                return false;
            }

            return true;

        }

        #endregion

    }

}
