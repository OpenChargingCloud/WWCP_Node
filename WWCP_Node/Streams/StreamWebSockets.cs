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

namespace cloud.charging.open.protocols.WWCP.Node.Streams
{

    /// <summary>
    /// A WebSocket client of a protocol of streams - Modbus, the REST API of
    /// OpenADR in a tunnel -: its binary messages read as one stream.
    /// </summary>
    public sealed class StreamWebSocketClient : WebSocketClient
    {

        #region Properties

        /// <summary>
        /// The subprotocol it offers, and nothing else.
        /// </summary>
        public String                  Subprotocol    { get; }

        /// <summary>
        /// The WebSocket as a stream of bytes.
        /// </summary>
        public WebSocketMessageStream  Stream         { get; }

        /// <summary>
        /// Whether the stream is one of lines, each a text message - the messages
        /// of a PKI - rather than of bytes in binary messages.
        /// </summary>
        public Boolean                 TextLines      { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A WebSocket client of the given subprotocol to the given URL, signing
        /// in with what it is given.
        /// </summary>
        public StreamWebSocketClient(URL                                                             URL,
                                     String                                                          Subprotocol,
                                     IHTTPAuthentication?                                            HTTPAuthentication,
                                     RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  RemoteCertificateValidator,
                                     IEnumerable<X509Certificate2>?                                  ClientCertificates,
                                     IEnumerable<X509Certificate2>?                                  ClientCertificateChain,
                                     TOTPConfig?                                                     TOTPConfig,
                                     String?                                                         TOTPLogin,
                                     IDNSClient?                                                     DNSClient,
                                     Boolean                                                         TextLines   = false)

            : base(URL,
                   HTTPAuthentication:          HTTPAuthentication,
                   SecWebSocketProtocols:       [ Subprotocol ],
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   ClientCertificates:          ClientCertificates,
                   ClientCertificateChain:      ClientCertificateChain,
                   TOTPConfig:                  TOTPConfig,
                   TOTPLogin:                   TOTPLogin,
                   DNSClient:                   DNSClient)

        {

            this.Subprotocol  = Subprotocol;
            this.TextLines    = TextLines;

            Stream            = new WebSocketMessageStream(
                                    async (message, cancellationToken) => {
                                        var sent = TextLines
                                                       ? await SendTextMessage  (TextLine.Of(message), CancellationToken: cancellationToken)
                                                       : await SendBinaryMessage(message,              CancellationToken: cancellationToken);
                                        if (sent != SentStatus.Success)
                                            throw new IOException($"Bytes of '{Subprotocol}' could not be sent over the WebSocket: {sent}");
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

            if (!TextLines)
                await Stream.Deliver(BinaryMessage);

        }

        #endregion

        #region ProcessTextMessage(...)

        /// <summary>
        /// A text message is the next line of a stream of lines.
        /// </summary>
        public override async Task ProcessTextMessage(DateTimeOffset             Timestamp,
                                                      WebSocketClientConnection  Connection,
                                                      WebSocketFrame             TextFrame,
                                                      EventTracking_Id           EventTrackingId,
                                                      String                     TextMessage,
                                                      CancellationToken          CancellationToken)
        {

            await base.ProcessTextMessage(Timestamp, Connection, TextFrame, EventTrackingId, TextMessage, CancellationToken);

            if (TextLines)
                await Stream.Deliver(TextLine.Bytes(TextMessage));

        }

        #endregion

    }


    /// <summary>
    /// A stream of lines over a WebSocket: each line one text message - what
    /// is written is one line, ended by a line feed, which the message does
    /// not carry - and each text message one line of what is read.
    /// </summary>
    internal static class TextLine
    {

        /// <summary>
        /// The text message of a line written to the stream.
        /// </summary>
        public static String Of(Byte[] Written)

            => System.Text.Encoding.UTF8.GetString(Written).TrimEnd('\n', '\r');

        /// <summary>
        /// The line a text message is, as it is read from the stream.
        /// </summary>
        public static Byte[] Bytes(String TextMessage)

            => System.Text.Encoding.UTF8.GetBytes(TextMessage.Replace("\r", "").Replace("\n", " ") + "\n");

    }


    /// <summary>
    /// A WebSocket server of a protocol of streams - Modbus, the REST API of
    /// OpenADR in a tunnel -: each connection's binary messages read as one
    /// stream. And, beside it, of a protocol of messages - the JSON messages
    /// of OpenADR -, whose text messages are handed on as they come.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Who may come in is decided by its door - see WebSocketSignIns - before
    /// the upgrade; a connection that came in is handed to
    /// <see cref="OnStreamConnection"/> with its stream, and the stream ends
    /// when the connection does.
    /// </para>
    /// <para>
    /// A connection whose subprotocol is one of
    /// <see cref="MessageSubprotocols"/> has no stream: it is handed to
    /// <see cref="OnMessageConnection"/>, its text messages to
    /// <see cref="OnTextMessageOf"/>, and its end to
    /// <see cref="OnMessageConnectionEnded"/>.
    /// </para>
    /// </remarks>
    public sealed class StreamWebSocketServer : WebSocketServer
    {

        #region Data

        private readonly ConcurrentDictionary<WebSocketServerConnection, WebSocketMessageStream> streams             = new ();
        private readonly ConcurrentDictionary<WebSocketServerConnection, Byte>                   messageConnections  = new ();

        #endregion

        #region Events

        /// <summary>
        /// A connection came in, and its protocol may be served over its stream.
        /// </summary>
        public event Action<WebSocketServerConnection, WebSocketMessageStream>?  OnStreamConnection;

        /// <summary>
        /// A connection of a protocol of messages came in.
        /// </summary>
        public event Action<WebSocketServerConnection>?                          OnMessageConnection;

        /// <summary>
        /// A connection of a protocol of messages ended.
        /// </summary>
        public event Action<WebSocketServerConnection>?                          OnMessageConnectionEnded;

        #endregion

        #region Properties

        /// <summary>
        /// Whether the stream of a connection is one of lines, each a text
        /// message - the messages of a PKI - rather than of bytes in binary messages.
        /// </summary>
        public Boolean TextLines { get; }

        /// <summary>
        /// The subprotocols of messages rather than of a stream.
        /// </summary>
        public IReadOnlyList<String> MessageSubprotocols { get; }

        /// <summary>
        /// Where a text message of a connection of a protocol of messages goes:
        /// handed on in the order it came, one after the other.
        /// </summary>
        public Func<WebSocketServerConnection, String, Task>? OnTextMessageOf { get; set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A WebSocket server of the given subprotocols on the given address and
        /// port: of streams - and of messages, where any are given.
        /// </summary>
        public StreamWebSocketServer(IPAddress?                                                IPAddress,
                                     IPPort                                                    TCPPort,
                                     IEnumerable<String>                                       Subprotocols,
                                     String                                                    HTTPServerName,
                                     I18NString                                                Description,
                                     ServerCertificateSelectorDelegate?                        ServerCertificateSelector,
                                     RemoteTLSClientCertificateValidationHandler<ITCPServer>?  ClientCertificateValidator,
                                     Boolean?                                                  ClientCertificateRequired,
                                     Boolean?                                                  CheckCertificateRevocation,
                                     Boolean                                                   TextLines             = false,
                                     IEnumerable<String>?                                      MessageSubprotocols   = null)

            : base(IPAddress,
                   TCPPort,
                   HTTPServerName,
                   Description,
                   RequireAuthentication:       false,
                   SecWebSocketProtocols:       [ .. Subprotocols, .. MessageSubprotocols ?? [] ],
                   ServerCertificateSelector:   ServerCertificateSelector,
                   ClientCertificateValidator:  ClientCertificateValidator,
                   ClientCertificateRequired:   ClientCertificateRequired,
                   CheckCertificateRevocation:  CheckCertificateRevocation)

        {

            this.TextLines            = TextLines;
            this.MessageSubprotocols  = [ .. MessageSubprotocols ?? [] ];

            OnNewWebSocketConnection += (timestamp, server, connection, sharedSubprotocols, selectedSubprotocol, eventTrackingId, cancellationToken) => {

                if (selectedSubprotocol is String chosen && this.MessageSubprotocols.Contains(chosen))
                {
                    messageConnections[connection] = 0;
                    OnMessageConnection?.Invoke(connection);
                    return Task.CompletedTask;
                }

                var stream = new WebSocketMessageStream(
                                 async (message, sendCancellationToken) => {
                                     var sent = TextLines
                                                    ? await SendTextMessage  (connection, TextLine.Of(message), CancellationToken: sendCancellationToken)
                                                    : await SendBinaryMessage(connection, message,              CancellationToken: sendCancellationToken);
                                     if (sent != SentStatus.Success)
                                         throw new IOException($"Bytes of '{selectedSubprotocol}' could not be sent over the WebSocket: {sent}");
                                 },
                                 () => connection.Close(WebSocketFrame.ClosingStatusCode.NormalClosure, "Done.")
                             );

                streams[connection] = stream;

                OnStreamConnection?.Invoke(connection, stream);

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

            if (!TextLines && streams.TryGetValue(Connection, out var stream))
                await stream.Deliver(BinaryMessage);

        }

        #endregion

        #region ProcessTextMessage(...)

        /// <summary>
        /// A text message is the next line of the stream of lines of its
        /// connection - or, of a connection of messages, the next message.
        /// </summary>
        public override async Task ProcessTextMessage(DateTimeOffset             Timestamp,
                                                      AWebSocketEndpoint         Server,
                                                      WebSocketServerConnection  Connection,
                                                      EventTracking_Id           EventTrackingId,
                                                      WebSocketFrame             TextFrame,
                                                      String                     TextMessage,
                                                      CancellationToken          CancellationToken)
        {

            if (messageConnections.ContainsKey(Connection))
            {

                await base.ProcessTextMessage(Timestamp, Server, Connection, EventTrackingId, TextFrame, TextMessage, CancellationToken);

                if (OnTextMessageOf is Func<WebSocketServerConnection, String, Task> handler)
                    await handler(Connection, TextMessage);

                return;

            }

            if (!TextLines)
            {
                await base.ProcessTextMessage(Timestamp, Server, Connection, EventTrackingId, TextFrame, TextMessage, CancellationToken);
                return;
            }

            if (streams.TryGetValue(Connection, out var stream))
                await stream.Deliver(TextLine.Bytes(TextMessage));

        }

        #endregion

        #region (private) Ended(Connection)

        private void Ended(WebSocketServerConnection Connection)
        {

            if (messageConnections.TryRemove(Connection, out _))
                OnMessageConnectionEnded?.Invoke(Connection);

            if (streams.TryRemove(Connection, out var stream))
                stream.End();

        }

        #endregion

    }

}
