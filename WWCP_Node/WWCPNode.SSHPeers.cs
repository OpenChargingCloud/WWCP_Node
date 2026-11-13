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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The SSH peers of a node: the hosts it keeps one SSH connection to each,
    /// shared by everything that goes to that host over SSH.
    /// </summary>
    /// <remarks>
    /// The connection to a peer belongs to the node. OCPP is one of its users,
    /// as the key exchange of a time server is, and none of them comes first:
    /// a station that starts cold may have the time and its names over the
    /// connection before a single OCPP message went over it.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        private readonly ConcurrentDictionary<DomainName, SSHPeer> sshPeers = new ();

        #endregion

        #region SSHPeers

        /// <summary>
        /// The SSH peers of this node.
        /// </summary>
        public IEnumerable<SSHPeer> SSHPeers
            => sshPeers.Values;

        #endregion

        #region AddSSHPeer(Peer)

        /// <summary>
        /// Add an SSH peer, in the place of the one of the same host there may
        /// be. The peer before, and its connection, stay whose they were: this
        /// closes nothing.
        /// </summary>
        /// <returns>The peer of that host before, or null.</returns>
        public SSHPeer? AddSSHPeer(SSHPeer Peer)
        {

            SSHPeer? before = null;

            sshPeers.AddOrUpdate(Peer.Host,
                                 Peer,
                                 (host, old) => { before = old; return Peer; });

            return ReferenceEquals(before, Peer)
                       ? null
                       : before;

        }

        #endregion

        #region RemoveSSHPeer(Peer)

        /// <summary>
        /// Remove the given SSH peer, where it still is the peer of its host.
        /// Its connection stays whose it was: this closes nothing.
        /// </summary>
        public Boolean RemoveSSHPeer(SSHPeer Peer)

            => sshPeers.TryRemove(new KeyValuePair<DomainName, SSHPeer>(Peer.Host, Peer));

        #endregion

        #region SSHPeerTo(Host)

        /// <summary>
        /// The SSH peer the given host is, or null where it is none.
        /// </summary>
        public SSHPeer? SSHPeerTo(DomainName Host)

            => sshPeers.TryGetValue(Host, out var peer)
                   ? peer
                   : null;

        #endregion

        #region SharedSSHConnectionTo(Host, Subsystem, CancellationToken)

        /// <summary>
        /// The node's SSH connection to the given peer, for one more channel of
        /// the given subsystem on it: the one that lasts, or - where there is
        /// none - one made now, for this and for everything after it.
        /// </summary>
        /// <param name="Host">The host of the peer.</param>
        /// <param name="Subsystem">What the channel is for, e.g. "ntske/1@open.charging.cloud".</param>
        /// <exception cref="InvalidOperationException">The host is no SSH peer of this node, or the subsystem may not go over its connection now.</exception>
        public async ValueTask<SshClient> SharedSSHConnectionTo(DomainName         Host,
                                                                String             Subsystem,
                                                                CancellationToken  CancellationToken = default)
        {

            CancellationToken.ThrowIfCancellationRequested();

            if (SSHPeerTo(Host) is not SSHPeer peer)
                throw new InvalidOperationException($"{Host.Trimmed} is no SSH peer of this {Kind.Name}: there is no connection to share.");

            if (peer.WhyNot?.Invoke(Subsystem) is String whyNot)
                throw new InvalidOperationException($"The SSH connection to {Host.Trimmed} is not shared with {Subsystem} now: {whyNot}");

            return await peer.Connection.GetAsync(CancellationToken).ConfigureAwait(false);

        }

        #endregion

    }

}
