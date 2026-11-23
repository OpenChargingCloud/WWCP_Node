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

using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Streams
{

    /// <summary>
    /// A WebSocket client of a protocol of messages - the JSON messages of
    /// OpenADR -: every text message that comes is handed on as it comes, and
    /// one is sent as it is.
    /// </summary>
    /// <remarks>
    /// The other end of a connection of messages of a
    /// <see cref="StreamWebSocketServer"/>. Nothing is read into the messages:
    /// what they say is the protocol's, above.
    /// </remarks>
    public sealed class MessageWebSocketClient : WebSocketClient
    {

        #region Data

        private readonly TaskCompletionSource ended = new (TaskCreationOptions.RunContinuationsAsynchronously);

        #endregion

        #region Properties

        /// <summary>
        /// The subprotocol it offers, and nothing else.
        /// </summary>
        public String                       Subprotocol    { get; }

        /// <summary>
        /// Where a text message that came goes: handed on in the order it came,
        /// one after the other.
        /// </summary>
        public Func<String, Task>?          OnText         { get; set; }

        /// <summary>
        /// Done once the connection ended: closed by either end, or gone.
        /// </summary>
        public Task                         Ended
            => ended.Task;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A WebSocket client of the given subprotocol to the given URL, signing
        /// in with what it is given.
        /// </summary>
        public MessageWebSocketClient(URL                                                             URL,
                                      String                                                          Subprotocol,
                                      IHTTPAuthentication?                                            HTTPAuthentication,
                                      RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  RemoteCertificateValidator,
                                      IEnumerable<X509Certificate2>?                                  ClientCertificates,
                                      IEnumerable<X509Certificate2>?                                  ClientCertificateChain,
                                      TOTPConfig?                                                     TOTPConfig,
                                      String?                                                         TOTPLogin,
                                      IDNSClient?                                                     DNSClient)

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

            this.Subprotocol = Subprotocol;

            OnCloseMessageReceived += (timestamp, client, connection, frame, eventTrackingId, statusCode, reason, cancellationToken) => {
                ended.TrySetResult();
                return Task.CompletedTask;
            };

            // A WebSocket that went away without a close frame ended as well:
            // asked of the client, as nothing else says so.
            _ = Task.Run(async () => {

                    while (!ended.Task.IsCompleted)
                    {

                        await Task.Delay(250);

                        if (wasConnected && !Connected)
                            ended.TrySetResult();

                        if (Connected)
                            wasConnected = true;

                    }

                });

        }

        private volatile Boolean wasConnected;

        #endregion


        #region SendText(Text, CancellationToken = default)

        /// <summary>
        /// Send one text message; whether it went.
        /// </summary>
        public async Task<Boolean> SendText(String             Text,
                                            CancellationToken  CancellationToken   = default)

            => await SendTextMessage(Text, CancellationToken: CancellationToken) == SentStatus.Success;

        #endregion

        #region End()

        /// <summary>
        /// Say that the connection ended, whatever the client thinks.
        /// </summary>
        public void End()
            => ended.TrySetResult();

        #endregion

        #region ProcessTextMessage(...)

        /// <summary>
        /// A text message is the next message.
        /// </summary>
        public override async Task ProcessTextMessage(DateTimeOffset             Timestamp,
                                                      WebSocketClientConnection  Connection,
                                                      WebSocketFrame             TextFrame,
                                                      EventTracking_Id           EventTrackingId,
                                                      String                     TextMessage,
                                                      CancellationToken          CancellationToken)
        {

            await base.ProcessTextMessage(Timestamp, Connection, TextFrame, EventTrackingId, TextMessage, CancellationToken);

            if (OnText is Func<String, Task> handler)
                await handler(TextMessage);

        }

        #endregion

    }

}
