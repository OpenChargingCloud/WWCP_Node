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

using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// NTS key establishment on the node's SSH server: the subsystem
    /// "ntske/1@open.charging.cloud" of the NTS-over-SSH white paper, next to
    /// OCPP and WWCP on the same port and under the same host key (its
    /// section 8.3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A charging station that runs OCPP over SSH gets its NTS keys and cookies
    /// over the connection it has anyway, as a further channel of it: with the
    /// key it signs in with for OCPP, against the host key it pins for OCPP -
    /// no certificate, no second key pair. The keys come from a secret the
    /// server sends in the SSH Key Binding record (option B), which takes
    /// nothing from the connection, so that a station may make its key exchange
    /// again on a connection that lasts for weeks.
    /// </para>
    /// <para>
    /// The node serves what an NTS server of Norn answers: that server holds the
    /// cookie master key and names the NTP server the cookies are for. Who may
    /// ask is decided here, as for every subsystem: the logins a kind adds, where
    /// they say so for the login, and an account only with the permission given.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What the log and the SSH page call the subsystem.
        /// </summary>
        public const String NTSKEOverSSHLabel = "NTS-KE";

        #endregion


        #region ServeNTSKEOverSSH(Server, ForAccounts = null)

        /// <summary>
        /// Serve the NTS key establishment of the given NTS server on the node's SSH
        /// server, as the subsystem <see cref="NTSKE_SSH.SubsystemName"/> - from now
        /// on, for the next session that asks for it.
        /// </summary>
        /// <param name="Server">The NTS server whose keys and cookies are handed out. It needs no SSH listener of its own.</param>
        /// <param name="ForAccounts">What an account of the node needs to be served it; null for no account, only the logins of a kind that name the subsystem.</param>
        /// <exception cref="ArgumentException">Where NTS-KE is served already.</exception>
        public void ServeNTSKEOverSSH(NTSServer    Server,
                                      Permission?  ForAccounts   = null)

            => AddSSHSubsystem(new SSHSubsystem(NTSKE_SSH.SubsystemName,
                                                NTSKEOverSSHLabel,
                                                Server.ServeSSHSubsystemAsync,
                                                ForAccounts));

        #endregion

        #region StopServingNTSKEOverSSH()

        /// <summary>
        /// Serve NTS-KE no more: refused to the next session that asks for it, and the
        /// sessions of it open now ended. Whether it was served.
        /// </summary>
        public Boolean StopServingNTSKEOverSSH()

            => RemoveSSHSubsystem(NTSKE_SSH.SubsystemName);

        #endregion

    }

}
