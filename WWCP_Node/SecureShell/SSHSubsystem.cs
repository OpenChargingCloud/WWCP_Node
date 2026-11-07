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

using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// A subsystem a kind of node serves on the node's SSH server, besides the command line and SFTP -
    /// OCPP or WWCP messages over "ocpp@open.charging.cloud" or "wwcp@open.charging.cloud".
    /// </summary>
    /// <remarks>
    /// <para>
    /// Who may use it: the logins a kind adds (see <see cref="ISSHSignIns"/>), where they say so for the
    /// login - and an account of the node only with <see cref="ForAccounts"/>, which no account holds
    /// unless a role gives it. A subsystem without it is served to no account at all.
    /// </para>
    /// <para>
    /// Asked of every session before it is served and every few seconds while it lasts, as the command
    /// line and SFTP are: the access rules ("subsystem:&lt;name&gt;"), what let the login in, and the
    /// account's permission. A session that may no longer go on is ended: its handler's token fires and
    /// its channel is closed.
    /// </para>
    /// </remarks>
    /// <param name="Name">The subsystem's name, as a client asks for it: "ocpp@open.charging.cloud".</param>
    /// <param name="Label">What the log, who and the SSH page call it: "OCPP".</param>
    /// <param name="Handler">Serves one session of it - Hermod closes the channel once it returns.</param>
    /// <param name="ForAccounts">What an account of the node needs to be served it; null for no account.</param>
    public sealed record SSHSubsystem(String               Name,
                                      String               Label,
                                      SshSubsystemHandler  Handler,
                                      Permission?          ForAccounts = null)
    {

        #region Data

        /// <summary>
        /// The longest name a subsystem may have.
        /// </summary>
        public const Int32 MaxNameLength = 64;

        #endregion

        #region (static) IsName(Name)

        /// <summary>
        /// Whether the given text may name a subsystem here: printable ASCII without spaces, at most
        /// <see cref="MaxNameLength"/> characters - and not "sftp", which stays the node's.
        /// </summary>
        public static Boolean IsName(String? Name)

            => Name is not null &&
               Name.Length is > 0 and <= MaxNameLength &&
               Name != "sftp" &&
               Name.All(c => c is > ' ' and < (Char) 0x7f);

        #endregion

    }

}
