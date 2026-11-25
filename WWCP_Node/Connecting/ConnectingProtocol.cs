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
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.KeyPins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What the protocol a node speaks over its connections says of them: by
    /// which networking node they are connected, which subprotocols they offer,
    /// how their messages are written, which SSH subsystem they go over, and
    /// what is executed while a learned key pin is on probation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A node has one for each protocol its connections carry - see
    /// <see cref="WWCPNode.ConnectingOf(ConnectionEntry)"/> - and the connecting of
    /// <see cref="WWCPNode"/> asks the one of a connection whatever is a matter
    /// of the protocol rather than of the node. This one speaks no protocol: a
    /// node that has it connects to nothing, and says so. A node that speaks one
    /// gives itself the protocol's - OCPP's is OCPPConnecting of WWCP_OCPP_Node,
    /// and one whose connections carry messages and nothing beside them is a
    /// <see cref="MessageConnecting"/>, as OCPI's.
    /// </para>
    /// <para>
    /// What is the node's own - whether a connection that is up is told
    /// anything, the networking mode it is connected in, what it depends on -
    /// stays with the node, as virtual members of <see cref="WWCPNode"/>.
    /// </para>
    /// </remarks>
    /// <param name="Node">The node whose connections these are.</param>
    public class ConnectingProtocol(WWCPNode Node)
    {

        #region Properties

        /// <summary>
        /// The node whose connections these are.
        /// </summary>
        public WWCPNode  WWCPNode    { get; } = Node;

        #endregion


        #region ConnectingNodes / ConnectingNodeOrNoneOf(Connection)

        /// <summary>
        /// The networking nodes the node connects with - none.
        /// </summary>
        public virtual IEnumerable<AWWCPNetworkingNode> ConnectingNodes

            => [];

        /// <summary>
        /// The networking node that makes the given connection, or none where
        /// the node does not speak what it carries - none.
        /// </summary>
        public virtual AWWCPNetworkingNode? ConnectingNodeOrNoneOf(ConnectionEntry Connection)

            => null;

        #endregion

        #region SetSignatureFormatsOf(Connection, Client) / SignatureFormatsOf(Connection)

        /// <summary>
        /// Say which signatures the messages over the given client of the
        /// given connection get, before the first of them is signed: nothing.
        /// </summary>
        public virtual void SetSignatureFormatsOf(ConnectionEntry  Connection,
                                                  IWWCPClient      Client)
        { }

        /// <summary>
        /// Which signatures the networking node writes for the given
        /// connection now - or null, where its signature policy decides.
        /// </summary>
        public virtual SignatureFormats? SignatureFormatsOf(ConnectionEntry Connection)

            => null;

        #endregion

        #region ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken)

        /// <summary>
        /// Open the WebSocket of the given connection, by the networking node
        /// that makes it: under a name of its own, and the primary under the
        /// name of the node at the other end as well - see NextHopOf and CSMSNamesOf.
        /// </summary>
        /// <param name="Connection">The connection.</param>
        /// <param name="Basic">The password it signs in with, where it has one.</param>
        /// <param name="Validator">How the server is believed: by its key pins, by its CA, or not asked where there is no TLS.</param>
        /// <param name="Certificates">The client certificate it holds up, with its chain, where it has one.</param>
        /// <param name="TOTP">The one-time password it signs in with, where it has one.</param>
        /// <param name="TOTPLogin">The login the one-time password is sent under.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        public virtual Task<HTTPResponse> ConnectOverWebSocket(ConnectionEntry                                                 Connection,
                                                               IHTTPAuthentication?                                            Basic,
                                                               RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  Validator,
                                                               X509Certificate2[]?                                             Certificates,
                                                               TOTPConfig?                                                     TOTP,
                                                               String?                                                         TOTPLogin,
                                                               CancellationToken                                               CancellationToken)

            => WWCPNode.ConnectingNodeOf(Connection).ConnectWebSocketClient(
                   RemoteURL:                   Connection.URL,
                   NetworkingMode:              WWCPNode.NetworkingModeOf(Connection),
                   NextHopNetworkingNodeId:     WWCPNode.NextHopOf(Connection),
                   RoutingNetworkingNodeIds:    WWCPNode.CSMSNamesOf(Connection),
                   SecWebSocketProtocols:       WWCPNode.SubProtocolsOf(Connection),
                   HTTPAuthentication:          Basic,
                   RemoteCertificateValidator:  Validator,
                   ClientCertificates:          WWCPNode.CertificateShownAlone(Certificates),
                   ClientCertificateChain:      WWCPNode.CertificateWithItsChain(Certificates),
                   TOTPConfig:                  TOTP,
                   TOTPLogin:                   TOTPLogin,
                   DNSClient:                   WWCPNode.NameResolver,
                   CancellationToken:           CancellationToken
               );

        #endregion

        #region SubProtocolsOf(Connection) / IsCBORSubprotocol(Subprotocol)

        /// <summary>
        /// The subprotocols the given connection offers, best first: none.
        /// </summary>
        public virtual String[] SubProtocolsOf(ConnectionEntry Connection)

            => [];

        /// <summary>
        /// Whether the given subprotocol has every message as CBOR in a binary
        /// frame: one that ends in "cbor", as "ocpp2.1cbor" does.
        /// </summary>
        public virtual Boolean IsCBORSubprotocol(String? Subprotocol)

            => Subprotocol is not null &&
               Subprotocol.Length > 4  &&
               Subprotocol.EndsWith("cbor", StringComparison.Ordinal);

        #endregion

        #region CBORFrameOf(Text) / TryCBORAsJSON(Frame, out JSON, out Error)

        /// <summary>
        /// The request of a connection test as the frame of a connection that
        /// agreed on CBOR: none, as nothing is written as CBOR.
        /// </summary>
        public virtual Byte[] CBORFrameOf(String Text)

            => throw new NotSupportedException($"This {WWCPNode.NodeNoun} writes nothing as CBOR.");

        /// <summary>
        /// What the given CBOR frame stands for, as JSON: nothing is read as CBOR.
        /// </summary>
        public virtual Boolean TryCBORAsJSON(Byte[]                                Frame,
                                             [NotNullWhen(true)]  out JArray?  JSON,
                                             [NotNullWhen(false)] out String?  Error)
        {
            JSON   = null;
            Error  = $"This {WWCPNode.NodeNoun} reads nothing as CBOR.";
            return false;
        }

        #endregion

        #region SshSubsystem / ConnectOverSSH(Connection, NetworkingNode, Login, SshConnection, CancellationToken)

        /// <summary>
        /// The SSH subsystem the messages of a connection over ssh:// go over: none.
        /// </summary>
        public virtual String? SshSubsystem

            => null;

        /// <summary>
        /// Open the given connection over SSH, by the given networking node:
        /// nothing goes over SSH.
        /// </summary>
        /// <param name="Connection">The connection.</param>
        /// <param name="NetworkingNode">The networking node that makes it.</param>
        /// <param name="Login">How it signs in, and how the server is believed.</param>
        /// <param name="SshConnection">The SSH connection of the peer it is a channel of, where it shares one.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        public virtual Task<(IWWCPClient? Client, Boolean IsConnected, Exception? Error)>

            ConnectOverSSH(ConnectionEntry                                    Connection,
                           AWWCPNetworkingNode                                NetworkingNode,
                           SSHClientOptions                                   Login,
                           Func<CancellationToken, ValueTask<SSHClient>>?     SshConnection,
                           CancellationToken                                  CancellationToken)

            => Task.FromResult<(IWWCPClient?, Boolean, Exception?)>(
                   (null, false, new NotSupportedException($"This {WWCPNode.NodeNoun} connects to nothing over SSH."))
               );

        #endregion

        #region ProbationRules(Probation, Action, Payload)

        /// <summary>
        /// Why the given request is not executed while the key pin of its
        /// connection is on probation - or null, where it may be: nothing is.
        /// </summary>
        public virtual String? ProbationRules(Probation  Probation,
                                              String     Action,
                                              JObject?   Payload)

            => $"This {WWCPNode.NodeNoun} believes its server by a key pin it learned on its first connection, " +
                "which is on probation: until a signed pin set confirms it, nothing is executed.";

        #endregion

        #region SignsInAtSSHPeersWithItsKey / DefaultSSHPeerUser

        /// <summary>
        /// Whether the node signs in at its SSH peers with the key of its
        /// connections (<see cref="WWCPNode.SshKey"/>), as a peer it connected to
        /// over ssh:// shares it - and names the hosts of those connections as
        /// its peers to be. Not where it connects to nothing: it signs in with a key
        /// of its own.
        /// </summary>
        public virtual Boolean SignsInAtSSHPeersWithItsKey

            => false;

        /// <summary>
        /// The user the node signs in as at an SSH peer that says none - or
        /// null for the node's own default.
        /// </summary>
        public virtual User_Id? DefaultSSHPeerUser

            => null;

        #endregion

    }

}
