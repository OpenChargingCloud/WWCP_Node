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

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// Whether what goes over SSH to a server has an SSH connection of its own,
    /// or is one more channel of the connection the node shares with that host:
    /// SSHConnection in the OCPP Device Model, "connection" in the file.
    /// </summary>
    public enum SSHConnection
    {

        /// <summary>
        /// A connection of its own: its own port, login, key and host key.
        /// </summary>
        Dedicated,

        /// <summary>
        /// One more channel of the node's connection to the SSH peer the
        /// server's host is: with the login, the key and the host key of that
        /// connection.
        /// </summary>
        Shared

    }


    /// <summary>
    /// What an <see cref="SSHConnection"/> is called in the configuration file.
    /// </summary>
    public static class SSHConnectionExtensions
    {

        /// <summary>
        /// The word the configuration file uses: "dedicated" or "shared".
        /// </summary>
        public static String AsText(this SSHConnection Connection)

            => Connection == SSHConnection.Shared
                   ? "shared"
                   : "dedicated";

        /// <summary>
        /// Read the word of the configuration file, whatever its case.
        /// </summary>
        public static Boolean TryParse(String? Text, out SSHConnection Connection)
        {

            switch (Text?.Trim().ToLowerInvariant())
            {

                case "dedicated":
                    Connection = SSHConnection.Dedicated;
                    return true;

                case "shared":
                    Connection = SSHConnection.Shared;
                    return true;

                default:
                    Connection = SSHConnection.Dedicated;
                    return false;

            }

        }

    }


    /// <summary>
    /// A host the node keeps one SSH connection to, which everything that goes
    /// to that host over SSH shares as channels of it: OCPP, the key exchange of
    /// a time server, name resolution. The connection is the node's, and nobody
    /// else's: whoever needs it first has it made, and whoever needs it after it
    /// ended has it made again.
    /// </summary>
    /// <remarks>
    /// Who is believed to be that host, and who the node signs in as, is said by
    /// whoever adds the peer, in how its connection is dialled.
    /// </remarks>
    /// <param name="Host">The host, as the entries that share its connection name it.</param>
    /// <param name="Port">Its SSH port.</param>
    /// <param name="Connection">The one connection to it.</param>
    /// <param name="WhyNot">Why the given subsystem may not go over the connection now, or null where it may: a peer whose host key nobody vouched for yet carries what confirms it, and nothing else.</param>
    /// <param name="PublicKey">The public key the node signs in with there, as a line of an authorized_keys file; null where there is none.</param>
    public sealed record SSHPeer(DomainName               Host,
                                 UInt16                   Port,
                                 SshSharedConnection      Connection,
                                 Func<String, String?>?   WhyNot     = null,
                                 Func<String?>?           PublicKey  = null);

}
