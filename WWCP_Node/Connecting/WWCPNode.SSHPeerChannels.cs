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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.SSH;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.KeyPins;
using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// A connection over ssh:// is one more channel of the SSH peer this node
    /// keeps to its host: made, shared and let go of here.
    /// </summary>
    public partial class WWCPNode
    {

        #region Data

        // The peer each SSH client of a connection is a channel of, for as
        // long as this node holds on to that client.
        protected readonly ConcurrentDictionary<WWCPSshClient, SSHPeer> sshPeerOf = new ();

        #endregion

        #region (private) SshPeerFor(Connection, Login, Trust)

        /// <summary>
        /// The SSH peer the host of the given connection becomes: with a
        /// connection of the station's own to it, made with the given login when
        /// the first one needs it. Null where that host is a peer already - of
        /// another connection of this station, with a login and a trust of its
        /// own - or its name is none a peer goes by: that connection is made
        /// for OCPP alone, as before.
        /// </summary>
        protected SSHPeer? SshPeerFor(ConnectionEntry   Connection,
                                    SSHClientOptions  Login,
                                    SshHostKeyTrust   Trust)
        {

            if (!DomainName.TryParse(Connection.URL.Host.ToString(), out var host, out _) || host is null)
                return null;

            if (SSHPeerTo(host) is not null)
                return null;

            var port  = Connection.URL.Port ?? IPPort.SSH;

            var peer  = new SSHPeer(
                            host,
                            port,
                            new SshSharedConnection(
                                Connection.URL.Host.ToString(),
                                port,
                                Login with { DNSClient = Login.DNSClient ?? DNSClient }
                            ),
                            WhyNot:     subsystem => subsystem == SshSubsystemOf(Connection)
                                                         ? null
                                                         : Trust.Pins.Count == 0
                                                               ? "its host is held to no pinned host key yet, and nothing but what this node connects to goes over it until a signed pin set says which it is."
                                                               : null,
                            PublicKey:  () => SshKey.PublicKeyLine
                        );

            // Another one became the peer of that host meanwhile.
            if (AddSSHPeer(peer) is SSHPeer before)
            {
                AddSSHPeer(before);
                return null;
            }

            return peer;

        }

        #endregion

        #region (private) DropSshConnectionOf(Client)

        /// <summary>
        /// Close the SSH connection the given client of OCPP is a channel of,
        /// for everything on it. The host stays a peer: whoever needs the
        /// connection next has it made anew, with a handshake of its own - which
        /// is what a host that is believed no longer, or by something else than
        /// before, has to go through again.
        /// </summary>
        protected async Task DropSshConnectionOf(WWCPSshClient Client)
        {

            if (!sshPeerOf.TryGetValue(Client, out var peer) || peer.Connection.Current is not SSHClient ssh)
                return;

            try
            {
                await ssh.DisposeAsync();
            }
            catch (Exception e)
            {
                Log.Debug($"The SSH connection to {peer.Host.Trimmed} did not close cleanly: {e.Message}", "ocpp", "connections", "ssh");
            }

        }

        #endregion

        #region (private) ReleaseSshPeerOf(Client) / ReleaseSshPeer(Peer)

        /// <summary>
        /// The station is done with the given SSH client of OCPP: the peer it
        /// was a channel of is no peer any more, and its connection is closed -
        /// for everything that shared it.
        /// </summary>
        protected async Task ReleaseSshPeerOf(WWCPSshClient Client)
        {

            if (sshPeerOf.TryRemove(Client, out var peer))
                await ReleaseSshPeer(peer);

        }

        /// <summary>
        /// Remove the given SSH peer and close its connection, unless an SSH
        /// client of OCPP the station still holds on to is a channel of it.
        /// </summary>
        protected async Task ReleaseSshPeer(SSHPeer Peer)
        {

            if (sshPeerOf.Values.Any(other => ReferenceEquals(other, Peer)))
                return;

            RemoveSSHPeer(Peer);

            try
            {
                await Peer.Connection.DisposeAsync();
            }
            catch (Exception e)
            {
                Log.Debug($"The SSH connection to {Peer.Host.Trimmed} did not close cleanly: {e.Message}", "ocpp", "connections", "ssh");
            }

        }

        #endregion

    }

}
