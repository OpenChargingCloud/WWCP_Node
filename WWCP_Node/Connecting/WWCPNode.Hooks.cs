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
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.KeyPins;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What the connecting asks beyond what is the same for every node: of the
    /// protocol a connection carries (<see cref="ConnectingOf(ConnectionEntry)"/>),
    /// and of the node itself - nothing, unless it says otherwise.
    /// </summary>
    /// <remarks>
    /// A node has one <see cref="ConnectingProtocol"/> for each protocol its
    /// connections carry - see <see cref="ConnectionUse"/>: OCPP's for what it
    /// connects to over OCPP, OCPI's for an EMSP a CSMS connects to. Whatever is
    /// asked of a connection is asked of the protocol of that connection, and of
    /// no other.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// The protocols the connections of this node carry, by what they are
        /// used for.
        /// </summary>
        private readonly ConcurrentDictionary<ConnectionUse, ConnectingProtocol> connectings = new ();

        #endregion

        #region Connecting / ConnectingOf(Use) / ConnectingOf(Connection) / SetConnectingOf(Use, Protocol)

        /// <summary>
        /// What OCPP says of the connections of this node that carry it. One
        /// that speaks none until a kind of node gives itself one - OCPP's,
        /// where it connects over OCPP.
        /// </summary>
        public ConnectingProtocol Connecting
        {
            get           => ConnectingOf(ConnectionUse.OCPP);
            protected set => SetConnectingOf(ConnectionUse.OCPP, value);
        }

        /// <summary>
        /// What the protocol of the given use says of the connections that
        /// carry it - one that speaks none, where this node was given none for it:
        /// a connection of it is connected to nothing, and says so.
        /// </summary>
        /// <param name="Use">What the connections are used for: OCPP, OCPI.</param>
        public ConnectingProtocol ConnectingOf(ConnectionUse Use)

            => connectings.GetOrAdd(Use, _ => new ConnectingProtocol(this));

        /// <summary>
        /// What the protocol the given connection carries says of it.
        /// </summary>
        /// <param name="Connection">A connection.</param>
        public ConnectingProtocol ConnectingOf(ConnectionEntry Connection)

            => ConnectingOf(Connection.Use);

        /// <summary>
        /// Give this node the protocol of the given use: from now on, what is
        /// asked of a connection that carries it is asked of that protocol.
        /// </summary>
        /// <param name="Use">What the connections are used for: OCPP, OCPI.</param>
        /// <param name="Protocol">What the protocol says of them.</param>
        protected void SetConnectingOf(ConnectionUse       Use,
                                       ConnectingProtocol  Protocol)

            => connectings[Use] = Protocol;

        #endregion


        #region (protected internal virtual) ConnectingNodes / ConnectingNodeOrNoneOf(Connection) / ConnectingNodeOf(Connection)

        /// <summary>
        /// The networking nodes this node connects with, as its protocols say:
        /// those of every one of them.
        /// </summary>
        protected internal virtual IEnumerable<AWWCPNetworkingNode> ConnectingNodes

            => connectings.Values.
                   SelectMany(protocol => protocol.ConnectingNodes).
                   Distinct  ();

        /// <summary>
        /// The networking node that makes the given connection, or none where
        /// this node does not speak what it carries.
        /// </summary>
        protected internal virtual AWWCPNetworkingNode? ConnectingNodeOrNoneOf(ConnectionEntry Connection)

            => ConnectingOf(Connection).ConnectingNodeOrNoneOf(Connection);

        /// <summary>
        /// The networking node that makes the given connection.
        /// </summary>
        protected internal AWWCPNetworkingNode ConnectingNodeOf(ConnectionEntry Connection)

            => ConnectingNodeOrNoneOf(Connection)
                   ?? throw new InvalidOperationException($"This {NodeNoun} does not speak {Connection.Protocol}.");

        #endregion

        #region (protected internal virtual) SetSignatureFormatsOf(Connection, Client) / SignatureFormatsOf(Connection)

        /// <summary>
        /// Say which signatures the messages over the given client of the
        /// given connection get, before the first of them is signed.
        /// </summary>
        protected internal virtual void SetSignatureFormatsOf(ConnectionEntry  Connection,
                                                              IWWCPClient      Client)

            => ConnectingOf(Connection).SetSignatureFormatsOf(Connection, Client);

        /// <summary>
        /// Which signatures the networking node of this node writes for the
        /// given connection now - or null, where its signature policy decides.
        /// </summary>
        public virtual SignatureFormats? SignatureFormatsOf(ConnectionEntry Connection)

            => ConnectingOf(Connection).SignatureFormatsOf(Connection);

        #endregion

        #region (protected internal virtual) ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken)

        /// <summary>
        /// Open the WebSocket of the given connection, as the protocol of this
        /// node opens one.
        /// </summary>
        /// <remarks>
        /// A node that has more to say of its lines - the networking mode, how
        /// often it pings, how long it waits, which versions of TLS it speaks -
        /// opens it itself.
        /// </remarks>
        /// <param name="Connection">The connection.</param>
        /// <param name="Basic">The password it signs in with, where it has one.</param>
        /// <param name="Validator">How the server is believed: by its key pins, by its CA, or not asked where there is no TLS.</param>
        /// <param name="Certificates">The client certificate it holds up, with its chain, where it has one.</param>
        /// <param name="TOTP">The one-time password it signs in with, where it has one.</param>
        /// <param name="TOTPLogin">The login the one-time password is sent under.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        protected internal virtual Task<HTTPResponse> ConnectOverWebSocket(ConnectionEntry                                                 Connection,
                                                                           IHTTPAuthentication?                                            Basic,
                                                                           RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  Validator,
                                                                           X509Certificate2[]?                                             Certificates,
                                                                           TOTPConfig?                                                     TOTP,
                                                                           String?                                                         TOTPLogin,
                                                                           CancellationToken                                               CancellationToken)

            => ConnectingOf(Connection).ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken);

        #endregion

        #region (protected internal virtual) SubProtocolsOf(Connection) / IsCBORSubprotocol(Connection, Subprotocol)

        /// <summary>
        /// The subprotocols the given connection offers, best first.
        /// </summary>
        protected internal virtual String[] SubProtocolsOf(ConnectionEntry Connection)

            => ConnectingOf(Connection).SubProtocolsOf(Connection);

        /// <summary>
        /// Whether the given subprotocol of the given connection has every
        /// message as CBOR in a binary frame.
        /// </summary>
        protected internal virtual Boolean IsCBORSubprotocol(ConnectionEntry  Connection,
                                                             String?          Subprotocol)

            => ConnectingOf(Connection).IsCBORSubprotocol(Subprotocol);

        #endregion

        #region (protected internal virtual) CBORFrameOf(Connection, Text) / TryCBORAsJSON(Connection, Frame, out JSON, out Error)

        /// <summary>
        /// The request of a connection test as the frame of a connection that
        /// agreed on CBOR.
        /// </summary>
        protected internal virtual Byte[] CBORFrameOf(ConnectionEntry  Connection,
                                                      String           Text)

            => ConnectingOf(Connection).CBORFrameOf(Text);

        /// <summary>
        /// What the given CBOR frame of the given connection stands for, as JSON.
        /// </summary>
        protected internal virtual Boolean TryCBORAsJSON(ConnectionEntry                   Connection,
                                                         Byte[]                            Frame,
                                                         [NotNullWhen(true)]  out JArray?  JSON,
                                                         [NotNullWhen(false)] out String?  Error)

            => ConnectingOf(Connection).TryCBORAsJSON(Frame, out JSON, out Error);

        #endregion

        #region (protected internal virtual) SshSubsystemOf(Connection) / ConnectOverSSH(Connection, NetworkingNode, Login, SshConnection, CancellationToken)

        /// <summary>
        /// The SSH subsystem the messages of the given connection over ssh://
        /// go over.
        /// </summary>
        protected internal virtual String? SshSubsystemOf(ConnectionEntry Connection)

            => ConnectingOf(Connection).SshSubsystem;

        /// <summary>
        /// Open the given connection over SSH, by the given networking node.
        /// </summary>
        /// <param name="Connection">The connection.</param>
        /// <param name="NetworkingNode">The networking node that makes it.</param>
        /// <param name="Login">How it signs in, and how the server is believed.</param>
        /// <param name="SshConnection">The SSH connection of the peer it is a channel of, where it shares one.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        protected internal virtual Task<(IWWCPClient? Client, Boolean IsConnected, Exception? Error)>

            ConnectOverSSH(ConnectionEntry                                    Connection,
                           AWWCPNetworkingNode                                NetworkingNode,
                           SSHClientOptions                                   Login,
                           Func<CancellationToken, ValueTask<SSHClient>>?     SshConnection,
                           CancellationToken                                  CancellationToken)

            => ConnectingOf(Connection).ConnectOverSSH(Connection, NetworkingNode, Login, SshConnection, CancellationToken);

        #endregion

        #region (protected internal virtual) ProbationRules(Probation, Action, Payload)

        /// <summary>
        /// Why the given request is not executed while the key pin of its
        /// connection is on probation - or null, where it may be. Asked of
        /// OCPP, whose messages the gate of a probation is in front of.
        /// </summary>
        protected internal virtual String? ProbationRules(Probation  Probation,
                                                          String     Action,
                                                          JObject?   Payload)

            => Connecting.ProbationRules(Probation, Action, Payload);

        #endregion

        #region (protected internal static) CertificateShownAlone(Certificates) / CertificateWithItsChain(Certificates)

        /// <summary>
        /// What a connection proves itself with, as a client that shows one
        /// certificate takes it: the certificate, where nothing travels with
        /// it - and null where something does, see
        /// <see cref="CertificateWithItsChain"/>.
        /// </summary>
        /// <remarks>
        /// One or the other, never both: a client given its certificates and
        /// a chain as well shows the certificates and sends no chain.
        /// </remarks>
        /// <param name="Certificates">The certificate with the key first, then what travels with it - as WhatItProvesItselfWith gives it.</param>
        protected internal static X509Certificate2[]? CertificateShownAlone(X509Certificate2[]? Certificates)
            => Certificates is { Length: > 1 }
                   ? null
                   : Certificates;

        /// <summary>
        /// What a connection proves itself with, as a client that sends a
        /// chain takes it: the certificate with the key first and the
        /// certificates of the CAs above it after it - or null, where nothing
        /// travels with the certificate.
        /// </summary>
        /// <param name="Certificates">The certificate with the key first, then what travels with it - as WhatItProvesItselfWith gives it.</param>
        protected internal static X509Certificate2[]? CertificateWithItsChain(X509Certificate2[]? Certificates)
            => Certificates is { Length: > 1 }
                   ? Certificates
                   : null;

        #endregion


        #region (protected internal virtual) NetworkingModeOf(Connection)

        /// <summary>
        /// The networking mode the given connection is connected in, or null
        /// for what the networking node does where nothing is said: the plain
        /// frame of its protocol.
        /// </summary>
        /// <remarks>
        /// A node that connects downwards says it by what is at the other end:
        /// a local controller and a gateway are spoken to in the overlay
        /// network, so that the charging stations behind them are reached
        /// through them; a charging station in the plain frame.
        /// </remarks>
        protected internal virtual NetworkingMode? NetworkingModeOf(ConnectionEntry Connection)

            => null;

        #endregion

        #region (protected internal virtual) WhatItIsConnectedOn(Connection)

        /// <summary>
        /// What the connecting of the given connection depends on beyond what
        /// is written of it, as a text that is another once it changed - or
        /// null, where it depends on nothing else.
        /// </summary>
        /// <remarks>
        /// Asked when a connection is made and again whenever the
        /// connections are gone through (ApplyConnectionChanges): a
        /// connection whose answer changed is let go of and connected again,
        /// as one that was written anew is. A node that connects downwards says
        /// here what the login of the node at the other end says of it -
        /// switched off, a local controller or not - and goes through its
        /// connections when a login changes.
        /// </remarks>
        protected internal virtual String? WhatItIsConnectedOn(ConnectionEntry Connection)

            => null;

        #endregion

        #region (protected internal virtual) WhyItIsNotConnected(Connection)

        /// <summary>
        /// Why the given connection is not connected, for something beyond
        /// what is written of it - or null, where nothing stands in its way.
        /// </summary>
        /// <remarks>
        /// Asked before anything of the connection is tried. A reason given
        /// leaves it not connected, with the reason beside it - a refusal of
        /// this node's own, not an end that could not be reached. A node that
        /// connects downwards says here what the login of the node at the other
        /// end says against it - switched off, or marked as another kind of
        /// node than the connection says; WhatItIsConnectedOn has it connected
        /// again once that changes.
        /// </remarks>
        protected internal virtual String? WhyItIsNotConnected(ConnectionEntry Connection)

            => null;

        #endregion

        #region ConnectionsCertificateUsage

        /// <summary>
        /// What the certificate of the server of a connection is judged
        /// for, and remembered under: the use a root of this node's
        /// certificate store is kept for where it vouches for one.
        /// </summary>
        public virtual String ConnectionsCertificateUsage

            => OCPPCertificateUsage;

        #endregion

        #region (protected internal virtual) ConnectionIsUp(Connection)

        /// <summary>
        /// The given connection is up, now or again. A charging station
        /// tells its CSMS that it started and sends what waited; a local
        /// controller has nothing of the kind to say.
        /// </summary>
        protected internal virtual void ConnectionIsUp(ConnectionEntry Connection)
        { }

        #endregion

        #region (protected internal virtual) EndRegistrations(Nodes)

        /// <summary>
        /// Nothing more is asked of a CSMS for the given nodes, nor waited
        /// for: they are let go of.
        /// </summary>
        protected internal virtual void EndRegistrations(params AWWCPNetworkingNode?[] Nodes)
        { }

        #endregion

        #region (protected internal virtual) FlushOfflineQueueOf(Version)

        /// <summary>
        /// Send what the node of the given version kept for its CSMS while it
        /// was out of reach.
        /// </summary>
        protected internal virtual Task FlushOfflineQueueOf(OCPPVersion Version)

            => Task.CompletedTask;

        #endregion

        #region (protected internal virtual) QueueSecurityEvent(Version, Type, TechInfo)

        /// <summary>
        /// Tell the CSMS of a security event, by the node of the given
        /// version, now or once it is in reach.
        /// </summary>
        protected internal virtual void QueueSecurityEvent(OCPPVersion  Version,
                                                           String       Type,
                                                           String       TechInfo)
        { }

        #endregion

        #region (private) ConnectionsThatShow(Handle, Kind)

        /// <summary>
        /// What of this node uses an identity of its certificate store: the
        /// connections that show it when they are made.
        /// </summary>
        /// <remarks>
        /// Deleted from under them, they would be connected with an identity
        /// that is not there, and refused at the next handshake rather than
        /// here. Switching it off is what takes an identity out of service;
        /// choosing another one for its connections is what lets it go.
        /// </remarks>
        private String? ConnectionsThatShow(String            Handle,
                                            CertificateKind?  Kind)
        {

            if (Connections is not null && (Kind is null || Kind == CertificateKind.TLSIdentity))
            {

                var showing = Connections.Connections.
                                  Where (connection => !connection.IsSSH && connection.Identities.Any(identity => identity.Id == Handle)).
                                  Select(connection => connection.Description).
                                  ToArray();

                if (showing.Length > 0)
                    return (showing.Length == 1
                                ? $"The connection '{showing[0]}' shows it"
                                : $"{showing.Length} connections show it ({String.Join(", ", showing.Select(name => $"'{name}'"))})") +
                           $" when this {NodeNoun} connects. Choose another identity on the Connections page first - or switch this one off, which keeps it.";

            }

            return null;

        }

        #endregion

    }

}
