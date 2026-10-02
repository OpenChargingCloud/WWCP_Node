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

using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// What a node's program says about its SSH server, before the
    /// configuration file has had its say.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Whether a node serves its command line over SSH unless told otherwise
    /// is the program's to say and not the library's: a node made in a test,
    /// on whatever port the operating system had free, has no business opening
    /// a second one nobody asked for - and twenty thousand above a port of the
    /// dynamic range is no port at all. So a node runs no SSH server unless it
    /// is handed settings that say so, or its configuration file does; every
    /// program hands in <see cref="ByDefault"/>.
    /// </para>
    /// <para>
    /// Which wins: a switch, then the file, then the program's default.
    /// </para>
    /// </remarks>
    /// <param name="Enabled">What a switch said: false for --no-ssh, true where a port was given; null where no switch said anything.</param>
    /// <param name="Port">The port a switch gave (--ssh-port), or null.</param>
    /// <param name="OnByDefault">Whether the SSH server runs where neither a switch nor the file says.</param>
    /// <param name="Authorize">Accounts to let in with the public keys in the given files (--authorize-ssh-key), once the accounts are read and before a port opens.</param>
    public sealed record SSHSettings(Boolean?                                          Enabled      = null,
                                     IPPort?                                           Port         = null,
                                     Boolean                                           OnByDefault  = false,
                                     IReadOnlyList<(String Account, String File)>?     Authorize    = null)
    {

        #region Data

        /// <summary>
        /// How far above the web interface's port the SSH server listens where
        /// nobody says otherwise: the vehicle's web interface is on 2347 and its
        /// SSH server on 22347, the charging station's on 2348 and 22348. The
        /// web ports of the kinds lie close together, so one above each would
        /// be the next kind's web port.
        /// </summary>
        public const UInt16 DefaultPortOffset = 20000;

        /// <summary>
        /// What a program hands in: on, unless a switch or the file says otherwise.
        /// </summary>
        public static SSHSettings ByDefault { get; } = new (OnByDefault: true);

        #endregion


        #region (static) DefaultPortFor(WebInterfacePort)

        /// <summary>
        /// The SSH port beside the given port of the web interface:
        /// <see cref="DefaultPortOffset"/> above it, or null where that is past
        /// the last port there is.
        /// </summary>
        /// <param name="WebInterfacePort">The port of the web interface.</param>
        public static IPPort? DefaultPortFor(IPPort WebInterfacePort)
        {

            var port = WebInterfacePort.ToUInt16() + DefaultPortOffset;

            return port <= UInt16.MaxValue
                       ? IPPort.Parse((UInt16) port)
                       : null;

        }

        #endregion

    }

}
