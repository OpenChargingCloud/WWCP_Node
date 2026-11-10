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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The "ssh" section of the configuration file: whether the node's command
    /// line is served over SSH, on which port, whether a password opens it as
    /// well as a key - and whether the node's files are served over SFTP.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Who may sign in is not here, and neither is with which key. Those are
    /// the accounts' - an account's keys sit beside the accounts, one file per
    /// account - for the same reason the certificates are not in this file
    /// either: what is in a directory is described by that directory.
    /// </para>
    /// <para>
    /// A switch on the command line wins over this, as a command line is
    /// expected to: <c>--no-ssh</c> over <c>"enabled": true</c>, and
    /// <c>--ssh-port</c> over <c>"port"</c>.
    /// </para>
    /// </remarks>
    /// <param name="Enabled">Whether the SSH server runs; the program's default where absent.</param>
    /// <param name="Port">The port it listens on; 20000 above the web interface's where absent.</param>
    /// <param name="Passwords">Whether an account's password opens it as well as its keys; no where absent.</param>
    /// <param name="Sftp">Whether the node's files are served over SFTP on the SSH server; no where absent.</param>
    /// <param name="AccessRules">The SSH access rules, which can only restrict who signs in and what they use - see <see cref="SSHAccessRules"/>; none where absent.</param>
    /// <param name="MaxConnections">How many connections each kind that signs in may have open at once - "account" for the accounts, "station" for what a kind of node lets in besides; <see cref="DefaultMaxConnectionsOfAccounts"/> and <see cref="DefaultMaxConnectionsOfLogins"/> where absent.</param>
    /// <param name="StrictKex">Whether a client must signal strict KEX, the protection against Terrapin (CVE-2023-48795), or is turned away before it signs in; yes where absent.</param>
    public sealed record SSHConfiguration(Boolean?                             Enabled         = null,
                                          IPPort?                              Port            = null,
                                          Boolean?                             Passwords       = null,
                                          Boolean?                             Sftp            = null,
                                          SSHAccessRules?                      AccessRules     = null,
                                          IReadOnlyDictionary<String, Int32>?  MaxConnections  = null,
                                          Boolean?                             StrictKex       = null)
    {

        #region Data

        /// <summary>
        /// The name of this section in the configuration file.
        /// </summary>
        public const String SectionName = "ssh";

        /// <summary>
        /// How many connections the accounts may have open at once, where the section says nothing.
        /// </summary>
        public const Int32  DefaultMaxConnectionsOfAccounts  = 20;

        /// <summary>
        /// How many connections the logins of a kind of node - a local controller's charging stations -
        /// may have open at once, where the section says nothing.
        /// </summary>
        public const Int32  DefaultMaxConnectionsOfLogins    = 100;

        /// <summary>
        /// The most connections the section may give a kind.
        /// </summary>
        public const Int32  MaxMaxConnections                = 10000;

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The "ssh" section, or the one sentence that says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JObject                                    JSON,
                                       [NotNullWhen(true)]  out SSHConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?            Error)
        {

            Configuration = null;

            if (!ConfigurationReader.TryReadBoolean(JSON, "enabled",    SectionName, out var enabled,    out Error) ||
                !ConfigurationReader.TryReadPort   (JSON, "port",       SectionName, out var port,       out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "passwords",  SectionName, out var passwords,  out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "sftp",       SectionName, out var sftp,       out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "strictKex",  SectionName, out var strictKex,  out Error))
                return false;

            SSHAccessRules? accessRules = null;

            if (JSON.TryGetValue("accessRules", out var rules) && rules.Type != JTokenType.Null &&
                !SSHAccessRules.TryParse(rules, $"{SectionName}.accessRules", out accessRules, out Error))
                return false;

            if (!TryReadMaxConnections(JSON, out var maxConnections, out Error))
                return false;

            Configuration = new SSHConfiguration(enabled, port, passwords, sftp, accessRules, maxConnections, strictKex);

            return true;

        }

        #endregion

        #region (private static) TryReadMaxConnections(JSON, out MaxConnections, out Error)

        /// <summary>
        /// "maxConnections": how many connections each kind may have open at once, by its name - or the
        /// sentence that says what is wrong with it.
        /// </summary>
        private static Boolean TryReadMaxConnections(JObject                                       JSON,
                                                     out IReadOnlyDictionary<String, Int32>?       MaxConnections,
                                                     [NotNullWhen(false)] out String?              Error)
        {

            MaxConnections  = null;
            Error           = null;

            if (!JSON.TryGetValue("maxConnections", out var token) || token.Type == JTokenType.Null)
                return true;

            if (token is not JObject perKind)
            {
                Error = $"'{SectionName}.maxConnections' must be an object, with how many connections each kind may have open at once: " +
                        $"{{ \"{SSHPrincipal.Account}\": {DefaultMaxConnectionsOfAccounts}, \"station\": {DefaultMaxConnectionsOfLogins} }}.";
                return false;
            }

            var read = new Dictionary<String, Int32>(StringComparer.Ordinal);

            foreach (var kind in perKind.Properties())
            {

                if (kind.Name != SSHPrincipal.Account && !WWCPNode.IsPrincipalKind(kind.Name))
                {
                    Error = $"'{SectionName}.maxConnections' names '{kind.Name}', which is no kind that signs in: '{SSHPrincipal.Account}' for the accounts, " +
                            "or what a kind of node lets in besides - a lower-case letter, then lower-case letters, digits, '-' or '_', at most 32 characters.";
                    return false;
                }

                if (!ConfigurationReader.TryReadUInt32(perKind, kind.Name, $"{SectionName}.maxConnections", 1, MaxMaxConnections, out var max, out Error))
                    return false;

                if (max is UInt32 number)
                    read[kind.Name] = (Int32) number;

            }

            MaxConnections = read;

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Enabled   is not null)  json.Add("enabled",    Enabled.  Value);
            if (Port      is not null)  json.Add("port",       Port.     Value.ToUInt16());
            if (Passwords is not null)  json.Add("passwords",  Passwords.Value);
            if (Sftp      is not null)  json.Add("sftp",       Sftp.     Value);
            if (StrictKex is not null)  json.Add("strictKex",  StrictKex.Value);
            if (AccessRules is not null)  json.Add("accessRules",  AccessRules.ToJSON());

            if (MaxConnections is not null)
                json.Add("maxConnections", new JObject(MaxConnections.Select(kind => new JProperty(kind.Key, kind.Value))));

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Enabled == false
                   ? "no SSH"
                   : $"SSH{(Port is not null ? $" on port {Port}" : "")}{(Passwords == true ? " with passwords" : "")}{(Sftp == true ? " and SFTP" : "")}" +
                     (StrictKex == false ? ", strict KEX not required" : "") +
                     (AccessRules is { Rules.Count: > 0 } ? $", {AccessRules.Rules.Count} access rule(s)" : "") +
                     (MaxConnections is { Count: > 0 } ? $", at most {String.Join(", ", MaxConnections.Select(kind => $"{kind.Value} {kind.Key} connection(s)"))}" : "");

        #endregion

    }

}
