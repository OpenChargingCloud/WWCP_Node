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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The "ssh" section of the configuration file: whether the node's command
    /// line is served over SSH, on which port, and whether a password opens it
    /// as well as a key.
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
    public sealed record SSHConfiguration(Boolean?  Enabled    = null,
                                          IPPort?   Port       = null,
                                          Boolean?  Passwords  = null)
    {

        #region Data

        /// <summary>
        /// The name of this section in the configuration file.
        /// </summary>
        public const String SectionName = "ssh";

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
                !ConfigurationReader.TryReadBoolean(JSON, "passwords",  SectionName, out var passwords,  out Error))
                return false;

            Configuration = new SSHConfiguration(enabled, port, passwords);

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

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Enabled == false
                   ? "no SSH"
                   : $"SSH{(Port is not null ? $" on port {Port}" : "")}{(Passwords == true ? " with passwords" : "")}";

        #endregion

    }

}
