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

using org.GraphDefined.Vanaheimr.Hermod.WebSocket;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.SSH;
using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a protocol whose connections carry messages and nothing beside
    /// them says of those connections: the one networking node that makes them,
    /// the subprotocols a connection offers, and the SSH subsystem a connection
    /// over ssh:// goes over. Everything else is what <see cref="ConnectingProtocol"/>
    /// says - no signatures, no gate while a key pin is on probation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Over a WebSocket and over SSH alike, as OCPP is connected: the WebSocket
    /// by ConnectWebSocketClient of the networking node, ssh:// by a
    /// <see cref="WWCPSshClient"/> of it on the subsystem - the part of what OCPP's nodes do over SSH that is no
    /// matter of OCPP. Who is at the other end is routed by the name of the
    /// connection itself (see <see cref="WWCPNode.NextHopOf"/>), and nothing
    /// is reached through it.
    /// </para>
    /// <para>
    /// OCPI's is one: a CSMS connects to an EMSP with it, and an EMSP lets a CPO
    /// in by the networking node it names. What the messages say is the
    /// networking node's to know, not this.
    /// </para>
    /// </remarks>
    public class MessageConnecting : ConnectingProtocol
    {

        #region Data

        private readonly Func<AWWCPNetworkingNode>                   networkingNode;
        private readonly Func<ConnectionEntry, IEnumerable<String>>  subProtocols;
        private readonly String                                      sshSubsystem;

        #endregion

        #region Properties

        /// <summary>
        /// The networking node that makes the connections.
        /// </summary>
        public AWWCPNetworkingNode  NetworkingNode
            => networkingNode();

        #endregion

        #region Constructor(s)

        /// <summary>
        /// What a protocol of messages says of the connections of the given node.
        /// </summary>
        /// <param name="Node">The node whose connections these are.</param>
        /// <param name="NetworkingNode">The networking node that makes the connections - asked for whenever it is needed.</param>
        /// <param name="SubProtocols">The subprotocols a connection offers, best first: by its version and the way its messages are written.</param>
        /// <param name="SshSubsystem">The SSH subsystem a connection over ssh:// goes over.</param>
        public MessageConnecting(WWCPNode                                    Node,
                                 Func<AWWCPNetworkingNode>                   NetworkingNode,
                                 Func<ConnectionEntry, IEnumerable<String>>  SubProtocols,
                                 String                                      SshSubsystem)

            : base(Node)

        {

            this.networkingNode  = NetworkingNode;
            this.subProtocols    = SubProtocols;
            this.sshSubsystem    = SshSubsystem;

        }

        #endregion


        #region (override) ConnectingNodes / ConnectingNodeOrNoneOf(Connection)

        /// <summary>
        /// The one networking node that makes the connections.
        /// </summary>
        public override IEnumerable<AWWCPNetworkingNode> ConnectingNodes

            => [ this.NetworkingNode ];

        /// <summary>
        /// The one networking node, which makes every connection of the protocol.
        /// </summary>
        public override AWWCPNetworkingNode? ConnectingNodeOrNoneOf(ConnectionEntry Connection)

            => ReconnectingNode;

        #endregion

        #region (override) SubProtocolsOf(Connection) / SshSubsystem

        /// <summary>
        /// The subprotocols the given connection offers, best first, in the
        /// WebSocket handshake and over ssh:// alike.
        /// </summary>
        public override String[] SubProtocolsOf(ConnectionEntry Connection)

            => [.. subProtocols(Connection)];

        /// <summary>
        /// The SSH subsystem a connection over ssh:// goes over.
        /// </summary>
        public override String? SshSubsystem
            => sshSubsystem;

        #endregion

        #region (override) ConnectOverSSH(Connection, NetworkingNode, Login, SshConnection, CancellationToken)

        /// <summary>
        /// Open the given connection over the SSH subsystem of the protocol, by
        /// the given networking node, offering the subprotocols of the
        /// connection: routed under the name of the connection, as over a
        /// WebSocket.
        /// </summary>
        public override async Task<(IWWCPClient? Client, Boolean IsConnected, Exception? Error)>

            ConnectOverSSH(ConnectionEntry                                    Connection,
                           AWWCPNetworkingNode                                NetworkingNode,
                           SSHClientOptions                                   Login,
                           Func<CancellationToken, ValueTask<SSHClient>>?     SshConnection,
                           CancellationToken                                  CancellationToken)

        {

            var sshClient = new WWCPSshClient(
                                NetworkingNode,
                                WWCPSshClient.OptionsFrom(
                                    Connection.URL,
                                    Login,
                                    sshSubsystem,
                                    SubProtocolsOf(Connection),
                                    NetworkingNode.ReconnectPolicy,
                                    WWCPNode.SshPingEvery,
                                    WWCPNode.NameResolver,
                                    SshConnection
                                ),
                                ConnectAs: WWCPSshClient.ConnectAsFrom(Connection.URL)
                            );

            try
            {

                await NetworkingNode.ConnectSshClient(
                          sshClient,
                          WWCPNode.NextHopOf  (Connection),
                          WWCPNode.CSMSNamesOf(Connection),
                          CancellationToken
                      );

                return (sshClient, true, null);

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                return (sshClient, false, e);
            }

        }

        #endregion

        #region (private) ReconnectingNode

        /// <summary>
        /// The networking node, which connects again after a connection dropped,
        /// and until it answers at all - as what is said of a connection then
        /// promises: "it comes back by itself". A policy given to it before is kept.
        /// </summary>
        private AWWCPNetworkingNode ReconnectingNode
        {
            get
            {

                var node = this.NetworkingNode;

                node.ReconnectPolicy ??= new WebSocketClientReconnectPolicy();

                return node;

            }
        }

        #endregion

    }

}
