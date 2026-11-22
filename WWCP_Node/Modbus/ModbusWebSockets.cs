/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.TCP;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Modbus
{

    /// <summary>
    /// A WebSocket client of the subprotocol "modbus": what a node reads an
    /// energy meter over, its binary messages read as one stream.
    /// </summary>
    public sealed class ModbusWebSocketClient : WebSocketClient
    {

        #region Properties

        /// <summary>
        /// The WebSocket as a stream of bytes, for a Modbus client.
        /// </summary>
        public WebSocketMessageStream  Stream    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A WebSocket client of Modbus to the given URL, signing in with what it
        /// is given.
        /// </summary>
        public ModbusWebSocketClient(URL                                                             URL,
                                     IHTTPAuthentication?                                            HTTPAuthentication,
                                     RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  RemoteCertificateValidator,
                                     IEnumerable<X509Certificate2>?                                  ClientCertificates,
                                     IEnumerable<X509Certificate2>?                                  ClientCertificateChain,
                                     TOTPConfig?                                                     TOTPConfig,
                                     String?                                                         TOTPLogin,
                                     IDNSClient?                                                     DNSClient)

            : base(URL,
                   HTTPAuthentication:          HTTPAuthentication,
                   SecWebSocketProtocols:       [ ModbusWireNames.Subprotocol ],
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   ClientCertificates:          ClientCertificates,
                   ClientCertificateChain:      ClientCertificateChain,
                   TOTPConfig:                  TOTPConfig,
                   TOTPLogin:                   TOTPLogin,
                   DNSClient:                   DNSClient)

        {

            Stream = new WebSocketMessageStream(
                         async (message, cancellationToken) => {
                             var sent = await SendBinaryMessage(message, CancellationToken: cancellationToken);
                             if (sent != SentStatus.Success)
                                 throw new IOException($"A Modbus frame could not be sent over the WebSocket: {sent}");
                         },
                         () => Close(Reason: "Done.")
                     );

            OnCloseMessageReceived += (timestamp, client, connection, frame, eventTrackingId, statusCode, reason, cancellationToken) => {
                Stream.End();
                return Task.CompletedTask;
            };

        }

        #endregion


        #region ProcessBinaryMessage(...)

        /// <summary>
        /// A binary message is the next bytes of the stream.
        /// </summary>
        public override async Task ProcessBinaryMessage(DateTimeOffset             Timestamp,
                                                        WebSocketClientConnection  Connection,
                                                        WebSocketFrame             BinaryFrame,
                                                        EventTracking_Id           EventTrackingId,
                                                        Byte[]                     BinaryMessage,
                                                        CancellationToken          CancellationToken)
        {

            await base.ProcessBinaryMessage(Timestamp, Connection, BinaryFrame, EventTrackingId, BinaryMessage, CancellationToken);

            await Stream.Deliver(BinaryMessage);

        }

        #endregion

    }


    /// <summary>
    /// A WebSocket server of the subprotocol "modbus": what an energy meter is
    /// read over, each connection's binary messages read as one stream.
    /// </summary>
    /// <remarks>
    /// Who may come in is decided by its door - see WebSocketSignIns - before
    /// the upgrade; a connection that came in is handed to
    /// <see cref="OnModbusConnection"/> with its stream, and the stream ends
    /// when the connection does.
    /// </remarks>
    public sealed class ModbusWebSocketServer : WebSocketServer
    {

        #region Data

        private readonly ConcurrentDictionary<WebSocketServerConnection, WebSocketMessageStream> streams = new ();

        #endregion

        #region Events

        /// <summary>
        /// A connection came in, and Modbus may be served over its stream.
        /// </summary>
        public event Action<WebSocketServerConnection, WebSocketMessageStream>?  OnModbusConnection;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A WebSocket server of Modbus on the given address and port.
        /// </summary>
        public ModbusWebSocketServer(IPAddress?                                                IPAddress,
                                     IPPort                                                    TCPPort,
                                     String                                                    HTTPServerName,
                                     I18NString                                                Description,
                                     ServerCertificateSelectorDelegate?                        ServerCertificateSelector,
                                     RemoteTLSClientCertificateValidationHandler<ITCPServer>?  ClientCertificateValidator,
                                     Boolean?                                                  ClientCertificateRequired,
                                     Boolean?                                                  CheckCertificateRevocation)

            : base(IPAddress,
                   TCPPort,
                   HTTPServerName,
                   Description,
                   RequireAuthentication:       false,
                   SecWebSocketProtocols:       [ ModbusWireNames.Subprotocol ],
                   ServerCertificateSelector:   ServerCertificateSelector,
                   ClientCertificateValidator:  ClientCertificateValidator,
                   ClientCertificateRequired:   ClientCertificateRequired,
                   CheckCertificateRevocation:  CheckCertificateRevocation)

        {

            OnNewWebSocketConnection += (timestamp, server, connection, sharedSubprotocols, selectedSubprotocol, eventTrackingId, cancellationToken) => {

                var stream = new WebSocketMessageStream(
                                 async (message, sendCancellationToken) => {
                                     var sent = await SendBinaryMessage(connection, message, CancellationToken: sendCancellationToken);
                                     if (sent != SentStatus.Success)
                                         throw new IOException($"A Modbus frame could not be sent over the WebSocket: {sent}");
                                 },
                                 () => connection.Close(WebSocketFrame.ClosingStatusCode.NormalClosure, "Done.")
                             );

                streams[connection] = stream;

                OnModbusConnection?.Invoke(connection, stream);

                return Task.CompletedTask;

            };

            OnCloseMessageReceived += (timestamp, server, connection, frame, eventTrackingId, statusCode, reason, cancellationToken) => {
                Ended(connection);
                return Task.CompletedTask;
            };

            OnTCPConnectionClosed += (timestamp, server, connection, eventTrackingId, reason, cancellationToken) => {
                Ended(connection);
                return Task.CompletedTask;
            };

        }

        #endregion


        #region ProcessBinaryMessage(...)

        /// <summary>
        /// A binary message is the next bytes of the stream of its connection.
        /// </summary>
        public override async Task ProcessBinaryMessage(DateTimeOffset             Timestamp,
                                                        AWebSocketEndpoint         Server,
                                                        WebSocketServerConnection  Connection,
                                                        EventTracking_Id           EventTrackingId,
                                                        WebSocketFrame             BinaryFrame,
                                                        Byte[]                     BinaryMessage,
                                                        CancellationToken          CancellationToken)
        {

            await base.ProcessBinaryMessage(Timestamp, Server, Connection, EventTrackingId, BinaryFrame, BinaryMessage, CancellationToken);

            if (streams.TryGetValue(Connection, out var stream))
                await stream.Deliver(BinaryMessage);

        }

        #endregion

        #region (private) Ended(Connection)

        private void Ended(WebSocketServerConnection Connection)
        {
            if (streams.TryRemove(Connection, out var stream))
                stream.End();
        }

        #endregion

    }

}
