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
using System.Text;
using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// The keys each account may sign in over SSH with: one file per account,
    /// named after it, in the format of OpenSSH's <c>authorized_keys</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The format everybody already has a key in, and the one ssh-copy-id and
    /// PuTTYgen's "Public key for pasting into OpenSSH authorized_keys file"
    /// write - so a key can be put into an account's file by hand, and a key
    /// that is taken out of it is gone. Options in front of a key are honoured
    /// as OpenSSH honours them: <c>from="10.0.0.0/8"</c> confines it to where
    /// it may come from, <c>expiry-time="20271231"</c> to until when, and an
    /// option that cannot be enforced makes the whole line count for nothing
    /// rather than be ignored.
    /// </para>
    /// <para>
    /// A file is read at every sign-in, not at the start: a key put in works
    /// at once, and a key taken out stops working at once - which is what
    /// somebody who took out a key that leaked needs most.
    /// </para>
    /// <para>
    /// Beside the accounts, and not beside the configuration file: who may sign
    /// in with what is about the accounts, and goes where they go. An account
    /// that is deleted takes its keys' power with it whether or not its file is
    /// deleted too - a key opens nothing for an account that is not there.
    /// </para>
    /// </remarks>
    public sealed class AuthorizedKeysStore
    {

        #region Data

        /// <summary>
        /// Where the files are below the accounts' directory.
        /// </summary>
        public const String DefaultDirectoryName = "ssh";

        /// <summary>
        /// What an account's name may be made of to be a file's: no separator,
        /// no dot at the start, nothing a file system could read as something
        /// else.
        /// </summary>
        private static readonly Regex fileName = new ("^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,127}$", RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// The directory of the files.
        /// </summary>
        public String        Directory     { get; }

        /// <summary>
        /// The clock a key's validity is asked of.
        /// </summary>
        public TimeProvider  TimeProvider  { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The keys kept in the given directory.
        /// </summary>
        /// <param name="Directory">Where the files are.</param>
        /// <param name="TimeProvider">The clock; the system's by default.</param>
        public AuthorizedKeysStore(String         Directory,
                                   TimeProvider?  TimeProvider = null)
        {
            this.Directory     = Path.GetFullPath(Directory);
            this.TimeProvider  = TimeProvider ?? TimeProvider.System;
        }

        #endregion


        #region (static) IsAccountName(Account)

        /// <summary>
        /// Whether the given name can be an account's file - and so whether
        /// anybody can sign in under it with a key at all.
        /// </summary>
        public static Boolean IsAccountName(String Account)

            => fileName.IsMatch(Account);

        #endregion

        #region FileOf(Account)

        /// <summary>
        /// The file of the given account's keys, or null for a name that cannot
        /// be one.
        /// </summary>
        public String? FileOf(String Account)

            => IsAccountName(Account)
                   ? Path.Combine(Directory, Account)
                   : null;

        #endregion

        #region Of(Account)

        /// <summary>
        /// The keys of the given account, as its file says now; none where it
        /// has no file, or one that cannot be read.
        /// </summary>
        public IReadOnlyList<AuthorizedKey> Of(String Account)
        {

            var file = FileOf(Account);

            if (file is null || !File.Exists(file))
                return [];

            try
            {
                return AuthorizedKeysFile.Parse(File.ReadAllText(file));
            }
            catch (IOException)
            {
                return [];
            }
            catch (UnauthorizedAccessException)
            {
                return [];
            }

        }

        #endregion

        #region Find(Account, PublicKeyBlob)

        /// <summary>
        /// The entry of the given account's file that lets the given key in now,
        /// or null: a plain key - not a certificate authority - that is the
        /// same key and is within its validity.
        /// </summary>
        public AuthorizedKey? Find(String              Account,
                                   ReadOnlySpan<Byte>  PublicKeyBlob)
        {

            var now = TimeProvider.GetUtcNow();

            foreach (var key in Of(Account))
                if (!key.IsCertAuthority && key.Matches(PublicKeyBlob) && key.IsValidAt(now))
                    return key;

            return null;

        }

        #endregion

        #region AccountsWithKeys()

        /// <summary>
        /// The accounts that have at least one key in their file.
        /// </summary>
        public IReadOnlyList<String> AccountsWithKeys()
        {

            if (!System.IO.Directory.Exists(Directory))
                return [];

            return [.. System.IO.Directory.EnumerateFiles(Directory).
                           Select(Path.GetFileName).
                           OfType<String>().
                           Where(account => IsAccountName(account) && Of(account).Count > 0).
                           Order(StringComparer.Ordinal)];

        }

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

                if (!AuthorizedKeysFile.TryParseLine(line, out _))
                {
                    Refused = $"'{(line.Length > 40 ? line[..40] + "..." : line)}' is no public key as an authorized_keys file has one.";
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

        #region TryAuthorize(Account, Text, out Added, out Refused)

        /// <summary>
        /// Let the given account in with the keys in the given text, beside the
        /// keys it has. A key it has already is not written twice.
        /// </summary>
        /// <param name="Account">The account.</param>
        /// <param name="Text">The public keys, as <see cref="TryRead"/> reads them.</param>
        /// <param name="Added">The keys that were added, by fingerprint.</param>
        /// <param name="Refused">Why none could be.</param>
        public Boolean TryAuthorize(String                                        Account,
                                    String                                        Text,
                                    [NotNullWhen(true)]  out IReadOnlyList<String>?  Added,
                                    [NotNullWhen(false)] out String?                 Refused)
        {

            Added = null;

            var file = FileOf(Account);

            if (file is null)
            {
                Refused = $"'{Account}' cannot be the name of an account's file of keys.";
                return false;
            }

            if (!TryRead(Text, out var lines, out Refused))
                return false;

            var had    = Of(Account);
            var added  = new List<String>();
            var write  = new StringBuilder();

            foreach (var line in lines)
            {

                AuthorizedKeysFile.TryParseLine(line, out var key);

                if (had.Any(existing => existing.Matches(key!.PublicKey.Blob)) ||
                    added.Contains(key!.PublicKey.Sha256Fingerprint))
                    continue;

                write.Append(line).Append('\n');
                added.Add(key.PublicKey.Sha256Fingerprint);

            }

            try
            {

                System.IO.Directory.CreateDirectory(Directory);

                var isNew = !File.Exists(file);

                if (isNew)
                {
                    // Made for its owner alone before anything is in it: whoever
                    // can write this file can sign in as the account.
                    using (new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                    SshPrivateKeyFile.RestrictToOwner(file);
                }

                if (write.Length > 0)
                {

                    // A file written by hand may not end with its line.
                    var existing  = isNew ? "" : File.ReadAllText(file);
                    var separator = existing.Length > 0 && !existing.EndsWith('\n') ? "\n" : "";

                    File.AppendAllText(file, separator + write, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

                }

            }
            catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
            {
                Refused = $"'{file}' could not be written: {problem.Message}";
                return false;
            }

            Added = added;
            return true;

        }

        #endregion

    }

}
