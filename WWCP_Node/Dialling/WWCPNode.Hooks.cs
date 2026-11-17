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

using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.NetworkingNode;

using cloud.charging.open.protocols.WWCP.Node.Connections;


using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a node that dials a CSMS does of its own where the dialling is
    /// the same for all: nothing, unless it says otherwise.
    /// </summary>
    public partial class WWCPNode
    {

        #region (protected virtual) DiallingNodes / DiallingNodeOrNoneOf(Version) / DiallingNodeOf(Version)

        /// <summary>
        /// The networking nodes this node dials with - none, unless a kind of
        /// node says which: an OCPP node its nodes for OCPP 1.6 and 2.1.
        /// </summary>
        protected virtual IEnumerable<AWWCPNetworkingNode> DiallingNodes

            => [];

        /// <summary>
        /// The networking node that dials a connection of the given version,
        /// or none where this node does not speak it.
        /// </summary>
        protected virtual AWWCPNetworkingNode? DiallingNodeOrNoneOf(OCPPVersion Version)

            => null;

        /// <summary>
        /// The networking node that dials a connection of the given version.
        /// </summary>
        protected AWWCPNetworkingNode DiallingNodeOf(OCPPVersion Version)

            => DiallingNodeOrNoneOf(Version)
                   ?? throw new InvalidOperationException($"This {NodeWording.Noun} does not speak {ConnectionEntry.AsText(Version)}.");

        #endregion

        #region (protected virtual) SetSignatureFormatsOf(Connection, Client)

        /// <summary>
        /// Say which signatures the messages over the given client of the
        /// given connection get, before the first of them is signed: nothing,
        /// unless a kind of node signs its messages.
        /// </summary>
        protected virtual void SetSignatureFormatsOf(ConnectionEntry  Connection,
                                                     IWWCPClient      Client)
        { }

        #endregion

        #region (protected virtual) ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken)

        /// <summary>
        /// Open the WebSocket of the given connection, by the networking node
        /// that dials it: under a name of its own, and the primary under the
        /// name of the node at the other end as well - see NextHopOf and CSMSNamesOf.
        /// </summary>
        /// <remarks>
        /// What every node that dials says is said here. A node that has more
        /// to say of its lines - the networking mode, how often it pings, how
        /// long it waits, which versions of TLS it speaks - opens it itself.
        /// </remarks>
        /// <param name="Connection">The connection.</param>
        /// <param name="Basic">The password it signs in with, where it has one.</param>
        /// <param name="Validator">How the server is believed: by its key pins, by its CA, or not asked where there is no TLS.</param>
        /// <param name="Certificates">The client certificate it holds up, with its chain, where it has one.</param>
        /// <param name="TOTP">The one-time password it signs in with, where it has one.</param>
        /// <param name="TOTPLogin">The login the one-time password is sent under.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        protected virtual Task<HTTPResponse> ConnectOverWebSocket(ConnectionEntry                                                 Connection,
                                                                  IHTTPAuthentication?                                            Basic,
                                                                  RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  Validator,
                                                                  X509Certificate2[]?                                             Certificates,
                                                                  TOTPConfig?                                                     TOTP,
                                                                  String?                                                         TOTPLogin,
                                                                  CancellationToken                                               CancellationToken)

            => DiallingNodeOf(Connection.OCPPVersion).ConnectWebSocketClient(
                   RemoteURL:                   Connection.URL,
                   NetworkingMode:              NetworkingModeOf(Connection),
                   NextHopNetworkingNodeId:     NextHopOf(Connection),
                   RoutingNetworkingNodeIds:    CSMSNamesOf(Connection),
                   SecWebSocketProtocols:       SubProtocolsOf(Connection),
                   HTTPAuthentication:          Basic,
                   RemoteCertificateValidator:  Validator,
                   ClientCertificates:          CertificateShownAlone(Certificates),
                   ClientCertificateChain:      CertificateWithItsChain(Certificates),
                   TOTPConfig:                  TOTP,
                   TOTPLogin:                   TOTPLogin,
                   DNSClient:                   DNSClient,
                   CancellationToken:           CancellationToken
               );

        #endregion

        #region (protected virtual) SubProtocolsOf(Connection) / IsCBORSubprotocol(Subprotocol)

        /// <summary>
        /// The subprotocols the given connection offers, best first: none,
        /// unless a kind of node says which it speaks.
        /// </summary>
        protected virtual String[] SubProtocolsOf(ConnectionEntry Connection)

            => [];

        /// <summary>
        /// Whether the given subprotocol has every message as CBOR in a binary
        /// frame: one that ends in "cbor", as "ocpp2.1cbor" does.
        /// </summary>
        protected virtual Boolean IsCBORSubprotocol(String? Subprotocol)

            => Subprotocol is not null &&
               Subprotocol.Length > 4  &&
               Subprotocol.EndsWith("cbor", StringComparison.Ordinal);

        #endregion

        #region (protected virtual) CBORFrameOf(Text) / TryCBORAsJSON(Frame, out JSON, out Error)

        /// <summary>
        /// The request of a connection test as the frame of a connection that
        /// agreed on CBOR. A kind of node that speaks CBOR says how.
        /// </summary>
        protected virtual Byte[] CBORFrameOf(String Text)

            => throw new NotSupportedException($"This {NodeWording.Noun} writes nothing as CBOR.");

        /// <summary>
        /// What the given CBOR frame stands for, as JSON - where a kind of node
        /// that speaks CBOR can say.
        /// </summary>
        protected virtual Boolean TryCBORAsJSON(Byte[]                                                     Frame,
                                                [System.Diagnostics.CodeAnalysis.NotNullWhen(true)]  out Newtonsoft.Json.Linq.JArray?  JSON,
                                                [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out String?                       Error)
        {
            JSON   = null;
            Error  = $"This {NodeWording.Noun} reads nothing as CBOR.";
            return false;
        }

        #endregion

        #region (protected virtual) SshSubsystem / ConnectOverSSH(Connection, Node, Login, SshConnection, CancellationToken)

        /// <summary>
        /// The SSH subsystem the messages of a connection over ssh:// go over -
        /// none, unless a kind of node says which.
        /// </summary>
        protected virtual String? SshSubsystem

            => null;

        /// <summary>
        /// Open the given connection over SSH, by the given networking node:
        /// nothing, unless a kind of node says how its messages go over it.
        /// </summary>
        /// <param name="Connection">The connection.</param>
        /// <param name="Node">The networking node that dials it.</param>
        /// <param name="Login">How it signs in, and how the server is believed.</param>
        /// <param name="SshConnection">The SSH connection of the peer it is a channel of, where it shares one.</param>
        /// <param name="CancellationToken">Ends the attempt.</param>
        protected virtual Task<(IWWCPClient? Client, Boolean IsConnected, Exception? Error)>

            ConnectOverSSH(ConnectionEntry                                          Connection,
                           AWWCPNetworkingNode                                      Node,
                           org.GraphDefined.Vanaheimr.Hermod.SSH.Client.SshClientOptions  Login,
                           Func<CancellationToken, ValueTask<org.GraphDefined.Vanaheimr.Hermod.SSH.Client.SshClient>>?  SshConnection,
                           CancellationToken                                        CancellationToken)

            => Task.FromResult<(IWWCPClient?, Boolean, Exception?)>(
                   (null, false, new NotSupportedException($"This {NodeWording.Noun} dials nothing over SSH."))
               );

        #endregion

        #region (protected virtual) ProbationRules(Probation, Action, Payload)

        /// <summary>
        /// Why the given request is not executed while the key pin of its
        /// connection is on probation - or null, where it may be. Nothing is,
        /// unless a kind of node says which request confirms the pin.
        /// </summary>
        protected virtual String? ProbationRules(cloud.charging.open.protocols.WWCP.Node.KeyPins.Probation          Probation,
                                                 String                     Action,
                                                 Newtonsoft.Json.Linq.JObject?  Payload)

            => $"This {NodeWording.Noun} believes its server by a key pin it learned on its first connection, " +
                "which is on probation: until a signed pin set confirms it, nothing is executed.";

        #endregion

        #region (protected static) CertificateShownAlone(Certificates) / CertificateWithItsChain(Certificates)

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
        protected static X509Certificate2[]? CertificateShownAlone(X509Certificate2[]? Certificates)
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
        protected static X509Certificate2[]? CertificateWithItsChain(X509Certificate2[]? Certificates)
            => Certificates is { Length: > 1 }
                   ? Certificates
                   : null;

        #endregion

        #region (protected virtual) NetworkingModeOf(Connection)

        /// <summary>
        /// The networking mode the given connection is dialled in, or null
        /// for what the OCPP node does where nothing is said: the plain
        /// frame of OCPP.
        /// </summary>
        /// <remarks>
        /// A node that dials downwards says it by what is at the other end:
        /// a local controller is spoken to in the overlay network, so that
        /// the stations behind it are reached through it; a charging station
        /// in the plain frame.
        /// </remarks>
        protected virtual NetworkingMode? NetworkingModeOf(ConnectionEntry Connection)

            => null;

        #endregion

        #region (protected virtual) WhatItIsDialledOn(Connection)

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
        protected virtual String? WhatItIsDialledOn(ConnectionEntry Connection)

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

        #region (protected virtual) ConnectionIsUp(Connection)

        /// <summary>
        /// The given connection is up, now or again. A charging station
        /// tells its CSMS that it started and sends what waited; a local
        /// controller has nothing of the kind to say.
        /// </summary>
        protected virtual void ConnectionIsUp(ConnectionEntry Connection)
        { }

        #endregion

        #region (protected virtual) EndRegistrations(Nodes) / EndRegistrationOf(Connection)

        /// <summary>
        /// Nothing more is asked of a CSMS for the given nodes, nor waited
        /// for: they are let go of.
        /// </summary>
        protected virtual void EndRegistrations(params AWWCPNetworkingNode?[] Nodes)
        { }

        #endregion

        #region (protected virtual) FlushOfflineQueueOf(Version)

        /// <summary>
        /// Send what the node of the given version of OCPP kept for its CSMS
        /// while it was out of reach.
        /// </summary>
        protected virtual Task FlushOfflineQueueOf(OCPPVersion Version)

            => Task.CompletedTask;

        #endregion

        #region (protected virtual) QueueSecurityEvent(Version, Type, TechInfo)

        /// <summary>
        /// Tell the CSMS of a security event, by the node of the given
        /// version of OCPP, now or once it is in reach.
        /// </summary>
        protected virtual void QueueSecurityEvent(OCPPVersion  Version,
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
                           $" when this {NodeWording.Noun} dials. Choose another identity on the Connections page first - or switch this one off, which keeps it.";

            }

            return null;

        }

        #endregion

            }

}
