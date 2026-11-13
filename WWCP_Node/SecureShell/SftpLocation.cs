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
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// The place an "sftp://" URL names: a host, a port, a login and a path, as
    /// chapter 3 of the white paper "SFTP for Logfile Uploads and Firmware
    /// Downloads" reads it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// sftp://[user[;fingerprint=...]@]host[:port]/path - read by hand, and
    /// not by <see cref="Uri"/>, which would resolve ".." segments, map names
    /// and decode more than once before anybody could refuse them.
    /// </para>
    /// <para>
    /// A URL that carries a password, a query, a fragment, a ".." segment or a
    /// control character is no location at all: none of them is something to
    /// repair.
    /// </para>
    /// </remarks>
    /// <param name="Host">The host as text, in the form two hosts are compared in (<see cref="NormalizeHost"/>).</param>
    /// <param name="Port">Its SSH port: the one of the URL, or 22.</param>
    /// <param name="User">The login the URL names, or null where it names none.</param>
    /// <param name="Path">The path: "/dir/file", or "~/dir/file" where it is relative to the home directory of the login.</param>
    /// <param name="Fingerprint">The host key fingerprint the URL expects, "SHA256:...", or null: never a source of trust, only something a pinned key can contradict.</param>
    public sealed record SftpLocation(String   Host,
                                      UInt16   Port,
                                      String?  User,
                                      String   Path,
                                      String?  Fingerprint)
    {

        #region Data

        /// <summary>
        /// The SSH port where a URL names none.
        /// </summary>
        public const UInt16  DefaultPort     = 22;

        /// <summary>
        /// The longest URL that is read at all.
        /// </summary>
        public const Int32   MaxLength       = 2000;

        /// <summary>
        /// The longest login.
        /// </summary>
        public const Int32   MaxUserLength   = 32;

        private static readonly Regex  userName  = new ("^[A-Za-z0-9._][A-Za-z0-9._@-]*$",                RegexOptions.CultureInvariant);
        private static readonly Regex  label     = new ("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$",        RegexOptions.CultureInvariant);
        private static readonly Regex  fileName  = new ("^[^/\\\\\\u0000-\\u001f\\u007f]{1,255}$",          RegexOptions.CultureInvariant);

        #endregion

        #region Properties

        /// <summary>
        /// Whether the path is relative to the home directory of the login.
        /// </summary>
        public Boolean  IsHomeRelative
            => Path.StartsWith("~/", StringComparison.Ordinal) || Path == "~";

        /// <summary>
        /// The path as the SFTP server is asked for it: absolute, or relative
        /// to where the login starts.
        /// </summary>
        public String   RemotePath
            => IsHomeRelative
                   ? Path.Length > 2 ? Path[2..] : "."
                   : Path;

        /// <summary>
        /// The location without its login and fingerprint: what a log and a
        /// security event may say.
        /// </summary>
        public String   WithoutUserInfo
            => $"sftp://{(Host.Contains(':') ? $"[{Host}]" : Host)}{(Port == DefaultPort ? "" : ":" + Port.ToString(CultureInfo.InvariantCulture))}{(IsHomeRelative ? "/" + Path : Path)}";

        #endregion


        #region (static) TryParse(Text, out Location, out Error)

        /// <summary>
        /// Read an "sftp://" URL.
        /// </summary>
        /// <param name="Text">The URL.</param>
        /// <param name="Location">What it names.</param>
        /// <param name="Error">Why it names nothing. It never repeats a password.</param>
        public static Boolean TryParse(String?                                 Text,
                                       [NotNullWhen(true)]  out SftpLocation?  Location,
                                       [NotNullWhen(false)] out String?        Error)
        {

            Location  = null;
            Error     = null;

            var text = Text?.Trim() ?? "";

            if (text.Length == 0)
            {
                Error = "there is no URL";
                return false;
            }

            if (text.Length > MaxLength)
            {
                Error = $"the URL has more than {MaxLength} characters";
                return false;
            }

            if (!text.StartsWith("sftp://", StringComparison.OrdinalIgnoreCase))
            {
                Error = "it is no sftp:// URL";
                return false;
            }

            var rest = text[7..];

            if (rest.Any(character => character < 0x21 || character == 0x7f))
            {
                Error = "the URL has a blank or a control character in it";
                return false;
            }

            // SFTP has neither, and a server would take them for a part of a name.
            if (rest.Contains('?') || rest.Contains('#'))
            {
                Error = "an sftp:// URL has no query and no fragment";
                return false;
            }

            var slash = rest.IndexOf('/');

            if (slash < 0)
            {
                Error = "the URL names no path";
                return false;
            }

            var authority  = rest[..slash];
            var rawPath    = rest[(slash + 1)..];

            #region The login, and what the URL expects of the host key

            String? user         = null;
            String? fingerprint  = null;

            var at = authority.LastIndexOf('@');

            if (at >= 0)
            {

                var userInfo = authority[..at];
                authority    = authority[(at + 1)..];

                var parts = userInfo.Split(';');

                // A password in a URL was written into every log on its way. It follows the
                // login; a ':' in a parameter is a part of that - "fingerprint=SHA256:...".
                if (parts[0].Contains(':'))
                {
                    Error = "the URL carries a password, which is never sent and never taken";
                    return false;
                }

                if (!TryDecode(parts[0], out var decodedUser))
                {
                    Error = "the login of the URL is not percent-encoded as a URL has it";
                    return false;
                }

                if (decodedUser.Length > 0)
                {

                    if (decodedUser.Length > MaxUserLength || !userName.IsMatch(decodedUser))
                    {
                        Error = $"the login of the URL is no login: letters, digits, '.', '_', '-' and '@', and at most {MaxUserLength} of them";
                        return false;
                    }

                    user = decodedUser;

                }

                foreach (var parameter in parts.Skip(1))
                {
                    if (parameter.StartsWith("fingerprint=", StringComparison.OrdinalIgnoreCase) &&
                        TryDecode(parameter[12..], out var said) &&
                        NTSServerSSH.TryParseFingerprint(said, out var sha256))
                    {
                        fingerprint = sha256;
                    }
                    // Any other notation, and any other parameter, says nothing here.
                }

            }

            #endregion

            #region The host and its port

            String  hostText;
            String? portText = null;

            if (authority.StartsWith('['))
            {

                var closing = authority.IndexOf(']');

                if (closing < 0)
                {
                    Error = "the IPv6 address of the URL is not closed by ']'";
                    return false;
                }

                hostText = authority[1..closing];
                var after = authority[(closing + 1)..];

                if (after.Length > 0)
                {
                    if (after[0] != ':')
                    {
                        Error = "the host of the URL is followed by something that is no port";
                        return false;
                    }
                    portText = after[1..];
                }

                if (!IPAddress.TryParse(hostText, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    Error = "what the URL has in brackets is no IPv6 address";
                    return false;
                }

            }
            else
            {
                var colon = authority.LastIndexOf(':');
                hostText  = colon >= 0 ? authority[..colon] : authority;
                portText  = colon >= 0 ? authority[(colon + 1)..] : null;
            }

            var port = DefaultPort;

            if (portText is not null)
            {
                if (portText.Length is 0 or > 5 ||
                    !portText.All(Char.IsAsciiDigit) ||
                    !UInt16.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) ||
                    port == 0)
                {
                    Error = "the port of the URL is no port";
                    return false;
                }
            }

            if (NormalizeHost(hostText) is not String host)
            {
                Error = "the host of the URL is neither a DNS name nor an IP address";
                return false;
            }

            #endregion

            #region The path

            // Decoded once: what is left encoded after that is a part of the name.
            if (!TryDecode(rawPath, out var path))
            {
                Error = "the path of the URL is not percent-encoded as a URL has it";
                return false;
            }

            if (path.Any(character => character < 0x20 || character == 0x7f))
            {
                Error = "the path of the URL has a control character in it";
                return false;
            }

            if (path.Split('/').Any(segment => segment == ".."))
            {
                Error = "the path of the URL has a '..' in it";
                return false;
            }

            // "~/..." is relative to the home directory of the login; every other path is absolute.
            if (!(path == "~" || path.StartsWith("~/", StringComparison.Ordinal)))
                path = "/" + path;

            #endregion

            Location = new SftpLocation(host, port, user, path, fingerprint);
            return true;

        }

        #endregion

        #region (static) NormalizeHost(Host)

        /// <summary>
        /// The form two hosts are compared in, as text: a DNS name in lower
        /// case and in its ASCII form, without the dot at its end; an IP address
        /// as it is canonically written. Null where the text is neither.
        /// </summary>
        /// <remarks>
        /// A name is never resolved in order to compare it: DNS would decide
        /// which peer a request means. So a name does not match a peer that is
        /// configured by its address, or the other way round.
        /// </remarks>
        public static String? NormalizeHost(String? Host)
        {

            var host = Host?.Trim() ?? "";

            if (host.StartsWith('[') && host.EndsWith(']'))
                host = host[1..^1];

            if (host.Length == 0)
                return null;

            // An address, when it is written as one: four numbers, or with a colon.
            if (host.Contains(':') || (Char.IsAsciiDigit(host[^1]) && host.All(character => Char.IsAsciiDigit(character) || character == '.')))
            {

                if (!IPAddress.TryParse(host, out var address))
                    return null;

                // "1.2.3" is an address to the parser, and a mistake to everybody else.
                if (address.AddressFamily == AddressFamily.InterNetwork && host.Count(character => character == '.') != 3)
                    return null;

                return address.ToString();

            }

            if (host.EndsWith('.'))
                host = host[..^1];

            String ascii;

            try
            {
                ascii = new IdnMapping().GetAscii(host).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                return null;
            }

            if (ascii.Length is 0 or > 253)
                return null;

            return ascii.Split('.').All(label.IsMatch)
                       ? ascii
                       : null;

        }

        #endregion

        #region (static) IsFileName(Name)

        /// <summary>
        /// Whether the given name is one a file is uploaded under: no path, no
        /// control character, and not the name an unfinished upload goes by.
        /// </summary>
        public static Boolean IsFileName(String? Name)

            => Name is not null             &&
               fileName.IsMatch(Name)       &&
               Name is not "." and not ".." &&
               !Name.EndsWith(PartSuffix, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// What the name of an upload ends with until its last byte arrived.
        /// </summary>
        public const String PartSuffix = ".part";

        #endregion

        #region FileIn(Name)

        /// <summary>
        /// The remote path of a file of the given name in the directory this
        /// location names.
        /// </summary>
        public String FileIn(String Name)
        {

            var directory = RemotePath;

            return directory.EndsWith('/')
                       ? directory + Name
                       : directory == "."
                             ? Name
                             : directory + "/" + Name;

        }

        #endregion

        #region (private static) TryDecode(Text, out Decoded)

        /// <summary>
        /// Percent-decode once, strictly: a '%' is followed by two hex digits,
        /// and what comes out is UTF-8.
        /// </summary>
        private static Boolean TryDecode(String Text, out String Decoded)
        {

            Decoded = "";

            var raw    = Encoding.UTF8.GetBytes(Text);
            var bytes  = new List<Byte>(raw.Length);

            for (var i = 0; i < raw.Length; i++)
            {

                if (raw[i] != (Byte) '%')
                {
                    bytes.Add(raw[i]);
                    continue;
                }

                if (i + 2 >= raw.Length ||
                    !Uri.IsHexDigit((Char) raw[i + 1]) ||
                    !Uri.IsHexDigit((Char) raw[i + 2]))
                {
                    return false;
                }

                bytes.Add(Convert.ToByte(new String([ (Char) raw[i + 1], (Char) raw[i + 2] ]), 16));
                i += 2;

            }

            try
            {
                Decoded = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes.ToArray());
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }

        }

        #endregion

    }

}
