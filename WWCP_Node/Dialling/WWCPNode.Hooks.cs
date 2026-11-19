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
    /// What the dialling asks beyond what is the same for every node: of the
    /// protocol its connections speak (<see cref="Dialling"/>), and of the
    /// node itself - nothing, unless it says otherwise.
    /// </summary>
    public partial class WWCPNode
    {

        #region Data

        private DiallingProtocol? dialling;

        #endregion

        #region Dialling

        /// <summary>
        /// What the protocol this node speaks over its connections says of
        /// them. One that speaks none until a kind of node gives itself one -
        /// OCPP's, where it dials over OCPP.
        /// </summary>
        public DiallingProtocol Dialling
        {
            get => dialling ??= new DiallingProtocol(this);
            protected set => dialling = value;
        }

        #endregion


        #region (protected internal virtual) DiallingNodes / DiallingNodeOrNoneOf(Version) / DiallingNodeOf(Version)

        /// <summary>
        /// The networking nodes this node dials with, as its protocol says.
        /// </summary>
        protected internal virtual IEnumerable<AWWCPNetworkingNode> DiallingNodes

            => Dialling.DiallingNodes;

        /// <summary>
        /// The networking node that dials a connection of the given version,
        /// or none where this node does not speak it.
        /// </summary>
        protected internal virtual AWWCPNetworkingNode? DiallingNodeOrNoneOf(OCPPVersion Version)

            => Dialling.DiallingNodeOrNoneOf(Version);

        /// <summary>
        /// The networking node that dials a connection of the given version.
        /// </summary>
        protected internal AWWCPNetworkingNode DiallingNodeOf(OCPPVersion Version)

            => DiallingNodeOrNoneOf(Version)
                   ?? throw new InvalidOperationException($"This {NodeNoun} does not speak {ConnectionEntry.AsText(Version)}.");

        #endregion

        #region (protected internal virtual) SetSignatureFormatsOf(Connection, Client) / SignatureFormatsOf(Connection)

        /// <summary>
        /// Say which signatures the messages over the given client of the
        /// given connection get, before the first of them is signed.
        /// </summary>
        protected internal virtual void SetSignatureFormatsOf(ConnectionEntry  Connection,
                                                              IWWCPClient      Client)

            => Dialling.SetSignatureFormatsOf(Connection, Client);

        /// <summary>
        /// Which signatures the networking node of this node writes for the
        /// given connection now - or null, where its signature policy decides.
        /// </summary>
        public virtual SignatureFormats? SignatureFormatsOf(ConnectionEntry Connection)

            => Dialling.SignatureFormatsOf(Connection);

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

            => Dialling.ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken);

        #endregion

        #region (protected internal virtual) SubProtocolsOf(Connection) / IsCBORSubprotocol(Subprotocol)

        /// <summary>
        /// The subprotocols the given connection offers, best first.
        /// </summary>
        protected internal virtual String[] SubProtocolsOf(ConnectionEntry Connection)

            => Dialling.SubProtocolsOf(Connection);

        /// <summary>
        /// Whether the given subprotocol has every message as CBOR in a binary frame.
        /// </summary>
        protected internal virtual Boolean IsCBORSubprotocol(String? Subprotocol)

            => Dialling.IsCBORSubprotocol(Subprotocol);

        #endregion

        #region (protected internal virtual) CBORFrameOf(Text) / TryCBORAsJSON(Frame, out JSON, out Error)

        /// <summary>
        /// The request of a connection test as the frame of a connection that
        /// agreed on CBOR.
        /// </summary>
        protected internal virtual Byte[] CBORFrameOf(String Text)

            => Dialling.CBORFrameOf(Text);

        /// <summary>
        /// What the given CBOR frame stands for, as JSON.
        /// </summary>
        protected internal virtual Boolean TryCBORAsJSON(Byte[]                                Frame,
                                                         [NotNullWhen(true)]  out JArray?  JSON,
                                                         [NotNullWhen(false)] out String?  Error)

            => Dialling.TryCBORAsJSON(Frame, out JSON, out Error);

        #endregion

        #region (protected internal virtual) SshSubsystem / ConnectOverSSH(Connection, NetworkingNode, Login, SshConnection, CancellationToken)

        /// <summary>
        /// The SSH subsystem the messages of a connection over ssh:// go over.
        /// </summary>
        protected internal virtual String? SshSubsystem

            => Dialling.SshSubsystem;

        /// <summary>
        /// Open the given connection over SSH, by the given networking node.
        /// </summary>
        /// <param name="Connection">The connection.</param>
        /// <param name="NetworkingNode">The networking node that dials it.</param>
        /// <param name="Login">How it signs in, and how the server is believed.</param>
        /// <param name="SshConnection">The SSH connection of the peer it is a channel of, where it shares one.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        protected internal virtual Task<(IWWCPClient? Client, Boolean IsConnected, Exception? Error)>

            ConnectOverSSH(ConnectionEntry                                    Connection,
                           AWWCPNetworkingNode                                NetworkingNode,
                           SshClientOptions                                   Login,
                           Func<CancellationToken, ValueTask<SshClient>>?     SshConnection,
                           CancellationToken                                  CancellationToken)

            => Dialling.ConnectOverSSH(Connection, NetworkingNode, Login, SshConnection, CancellationToken);

        #endregion

        #region (protected internal virtual) ProbationRules(Probation, Action, Payload)

        /// <summary>
        /// Why the given request is not executed while the key pin of its
        /// connection is on probation - or null, where it may be.
        /// </summary>
        protected internal virtual String? ProbationRules(Probation  Probation,
                                                          String     Action,
                                                          JObject?   Payload)

            => Dialling.ProbationRules(Probation, Action, Payload);

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
        /// The networking mode the given connection is dialled in, or null
        /// for what the networking node does where nothing is said: the plain
        /// frame of its protocol.
        /// </summary>
        /// <remarks>
        /// A node that dials downwards says it by what is at the other end:
        /// a local controller and a gateway are spoken to in the overlay
        /// network, so that the charging stations behind them are reached
        /// through them; a charging station in the plain frame.
        /// </remarks>
        protected internal virtual NetworkingMode? NetworkingModeOf(ConnectionEntry Connection)

            => null;

        #endregion

        #region (protected internal virtual) WhatItIsDialledOn(Connection)

        /// <summary>
        /// What the dialling of the given connection depends on beyond what
        /// is written of it, as a text that is another once it changed - or
        /// null, where it depends on nothing else.
        /// </summary>
        /// <remarks>
        /// Asked when a connection is dialled and again whenever the
        /// connections are gone through (ApplyConnectionChanges): a
        /// connection whose answer changed is let go of and dialled again,
        /// as one that was written anew is. A node that dials downwards says
        /// here what the login of the node at the other end says of it -
        /// switched off, a local controller or not - and goes through its
        /// connections when a login changes.
        /// </remarks>
        protected internal virtual String? WhatItIsDialledOn(ConnectionEntry Connection)

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
        /// dials downwards says here what the login of the node at the other
        /// end says against it - switched off, or marked as another kind of
        /// node than the connection says; WhatItIsDialledOn has it dialled
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
        /// connections that show it when they are dialled.
        /// </summary>
        /// <remarks>
        /// Deleted from under them, they would be dialled with an identity
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
                           $" when this {NodeNoun} dials. Choose another identity on the Connections page first - or switch this one off, which keeps it.";

            }

            return null;

        }

        #endregion

    }

}
