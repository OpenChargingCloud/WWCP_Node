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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.Node.OpenADR;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The grid operators this node connects to as a VEN of OpenADR 3: over a
    /// WebSocket or over an SSH subsystem of the grid operator, in the binding
    /// the connection says - see <see cref="OpenADRWireNames"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A connection of the type <see cref="ConnectionType.GridOperator"/>, made
    /// by this node, signed in as every connection signs in: over ws:// and
    /// wss:// with a password, a one-time password or a client certificate,
    /// over ssh:// with its key, a password or a one-time password, believing
    /// the server as every connection believes it. Who signs in is the VEN the
    /// grid operator wrote down for the login: no bearer token is had, and none
    /// is shown.
    /// </para>
    /// <para>
    /// <b>The REST binding</b> is a tunnel: the REST API of OpenADR 3, as
    /// HTTP/1.1, in the stream of the connection - its binary messages over a
    /// WebSocket, the channel of the subsystem over SSH. One connection is one
    /// connection of HTTP: what asks the VTN gets the stream from
    /// <see cref="OpenGridOperatorStream"/>, or an HTTP client that does from
    /// <see cref="GridOperatorHTTPHandler"/>, and gives it back by disposing
    /// it. A stream given back is the end of the connection, which is made
    /// again at once.
    /// </para>
    /// <para>
    /// <b>The binding of messages</b> carries text messages - the JSON messages
    /// of OpenADR, which this node does not read: whoever speaks them is told
    /// of every message that comes by <see cref="OnGridOperatorMessage"/>, of a
    /// connection that came up or ended by <see cref="OnGridOperatorMessageLink"/>,
    /// and sends by <see cref="SendToGridOperator"/>. Over a WebSocket of the
    /// subprotocol <c>openadr3.1</c> one text message is one message; over SSH
    /// the subsystem <c>openadr@open.charging.cloud</c> carries them in the
    /// frames of Hermod's messages over SSH, as OCPP over SSH does.
    /// </para>
    /// <para>
    /// A connection that drops is connected again after a while, as long as it
    /// is written down, switched on, and this node has not hung up.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// How long a connection to a grid operator that dropped or could not be
        /// made waits before it is tried again.
        /// </summary>
        public static TimeSpan GridOperatorConnectAgainAfter { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>
        /// The base URL an HTTP client asks the VTN of a tunnel at: the host is
        /// never looked up nor connected to - the connection is the tunnel - and
        /// the path is where the grid operator has its VTN there.
        /// </summary>
        public static readonly Uri GridOperatorTunnelURL = new ($"http://vtn.openadr.tunnel{OpenADRWireNames.RestTunnelPath}");

        /// <summary>
        /// One connection to a grid operator that is up: its stream, what it goes
        /// over, and what to let go of when it ends.
        /// </summary>
        private sealed class GridOperatorLink(ConnectionEntry  Connection,
                                              Stream           Stream,
                                              String           Transport,
                                              Func<Task>       LetGo,
                                              Task             Ended)
        {

            private Int32 handedOut;

            public ConnectionEntry  Connection  { get; } = Connection;
            public Stream           Stream      { get; } = Stream;
            public String           Transport   { get; } = Transport;
            public Func<Task>       LetGo       { get; } = LetGo;
            public Task             Ended       { get; } = Ended;

            /// <summary>
            /// Take the stream, where nobody has it yet.
            /// </summary>
            public Boolean TryHandOut()
                => Interlocked.CompareExchange(ref handedOut, 1, 0) == 0;

        }

        /// <summary>
        /// One connection to a grid operator in the binding of messages that is
        /// up: how a message is sent over it, what it goes over, and what to let
        /// go of when it ends.
        /// </summary>
        private sealed class GridOperatorMessageLink(ConnectionEntry                                 Connection,
                                                     Func<String, CancellationToken, Task<Boolean>>  Send,
                                                     String                                          Transport,
                                                     Func<Task>                                      LetGo,
                                                     Task                                            Ended)
        {
            public ConnectionEntry                                 Connection  { get; } = Connection;
            public Func<String, CancellationToken, Task<Boolean>>  Send        { get; } = Send;
            public String                                          Transport   { get; } = Transport;
            public Func<Task>                                      LetGo       { get; } = LetGo;
            public Task                                            Ended       { get; } = Ended;
        }

        private readonly ConcurrentDictionary<String, GridOperatorLink>         gridOperatorLinks          = new ();
        private readonly ConcurrentDictionary<String, GridOperatorMessageLink>  gridOperatorMessageLinks   = new ();
        private volatile Boolean                                                 hungUpOnTheGridOperators;

        #endregion

        #region Events

        /// <summary>
        /// Where a text message of a connection to a grid operator in the binding
        /// of messages goes: the connection, and the message - handed on in the
        /// order they came, one after the other.
        /// </summary>
        public Func<String, String, Task>?     OnGridOperatorMessage { get; set; }

        /// <summary>
        /// A connection to a grid operator in the binding of messages came up
        /// (true), or ended (false).
        /// </summary>
        public event Action<String, Boolean>?  OnGridOperatorMessageLink;

        #endregion


        #region GridOperatorConnectionIsUp(ConnectionId) / GridOperatorTransportOf(ConnectionId)

        /// <summary>
        /// Whether the given connection to a grid operator is up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        public Boolean GridOperatorConnectionIsUp(String ConnectionId)

            => gridOperatorLinks.       ContainsKey(ConnectionId) ||
               gridOperatorMessageLinks.ContainsKey(ConnectionId);

        /// <summary>
        /// What the given connection to a grid operator goes over now -
        /// "WebSocket", "WebSocket TLS" or "SSH" - or null where it is not up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        public String? GridOperatorTransportOf(String ConnectionId)

            => gridOperatorLinks.TryGetValue(ConnectionId, out var link)
                   ? link.Transport
                   : gridOperatorMessageLinks.TryGetValue(ConnectionId, out var messageLink)
                         ? messageLink.Transport
                         : null;

        #endregion

        #region SendToGridOperator(ConnectionId, Text, CancellationToken = default)

        /// <summary>
        /// Send one text message over the given connection to a grid operator in
        /// the binding of messages; whether it went - not where the connection is
        /// not up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        /// <param name="Text">The message.</param>
        /// <param name="CancellationToken">A token to cancel it.</param>
        public async Task<Boolean> SendToGridOperator(String             ConnectionId,
                                                      String             Text,
                                                      CancellationToken  CancellationToken   = default)
        {

            if (!gridOperatorMessageLinks.TryGetValue(ConnectionId, out var link))
                return false;

            try
            {
                return await link.Send(Text, CancellationToken);
            }
            catch (Exception e) when (e is not OperationCanceledException || !CancellationToken.IsCancellationRequested)
            {
                Log.Debug($"A message to the grid operator '{link.Connection.Description.FirstText()}' could not be sent: {e.Message}", "openadr", "connections");
                return false;
            }

        }

        #endregion

        #region OpenGridOperatorStream(ConnectionId, CancellationToken = default)

        /// <summary>
        /// The stream of the given connection to a grid operator in the REST
        /// binding - one connection of HTTP/1.1 to its VTN, at
        /// <see cref="OpenADRWireNames.RestTunnelPath"/> -, once it is up and
        /// nobody has it: waited for until then, or until the token ends it.
        /// Disposing it gives it back, and ends the connection, which is made
        /// again at once.
        /// </summary>
        /// <param name="ConnectionId">The connection to the grid operator.</param>
        /// <param name="CancellationToken">Ends the wait.</param>
        /// <exception cref="InvalidOperationException">The connection is no connection to a grid operator in the REST binding.</exception>
        public async Task<Stream> OpenGridOperatorStream(String             ConnectionId,
                                                         CancellationToken  CancellationToken = default)
        {

            while (true)
            {

                if (gridOperatorLinks.TryGetValue(ConnectionId, out var link) && link.TryHandOut())
                    return new TunnelStream(link.Stream, () => GiveBack(ConnectionId, link));

                if (Connections?.Connections.FirstOrDefault(entry => entry.Id == ConnectionId) is not ConnectionEntry entry ||
                    entry.ConnectionType != ConnectionType.GridOperator ||
                    entry.OpenADRBinding != OpenADRBinding.REST)
                {
                    throw new InvalidOperationException($"The connection '{ConnectionId}' of this {NodeNoun} is no connection to a grid operator in the binding '{ConnectionEntry.AsText(OpenADRBinding.REST)}'.");
                }

                if (!entry.AutoConnect)
                    throw new InvalidOperationException($"The connection '{entry.Description.FirstText()}' of this {NodeNoun} to its grid operator is switched off.");

                await Task.Delay(50, CancellationToken);

            }

        }

        #endregion

        #region GridOperatorHTTPHandler(ConnectionId)

        /// <summary>
        /// An HTTP handler that asks the VTN of the given connection to a grid
        /// operator in the REST binding: whatever host it is asked of - see
        /// <see cref="GridOperatorTunnelURL"/> - it goes over the stream of the
        /// connection, one request after the other.
        /// </summary>
        /// <param name="ConnectionId">The connection to the grid operator.</param>
        public SocketsHttpHandler GridOperatorHTTPHandler(String ConnectionId)

            => new () {
                   ConnectCallback              = async (context, cancellationToken) => await OpenGridOperatorStream(ConnectionId, cancellationToken),
                   MaxConnectionsPerServer      = 1,
                   PooledConnectionIdleTimeout  = Timeout.InfiniteTimeSpan,
                   PooledConnectionLifetime     = Timeout.InfiniteTimeSpan,
                   UseProxy                     = false,
                   UseCookies                   = false,
                   AllowAutoRedirect            = false
               };

        #endregion


        #region (protected) ConnectToTheGridOperator(Connection, Where, CancellationToken)

        /// <summary>
        /// One connection to a grid operator: who it signs in as, over what, and
        /// whether it got through.
        /// </summary>
        protected async Task ConnectToTheGridOperator(ConnectionEntry    Connection,
                                                      String             Where,
                                                      CancellationToken  CancellationToken)
        {

            hungUpOnTheGridOperators = false;

            if (gridOperatorLinks.ContainsKey(Connection.Id) || gridOperatorMessageLinks.ContainsKey(Connection.Id))
                return;

            if (Connection.OpenADRBinding == OpenADRBinding.Messages)
            {
                await ConnectToTheGridOperatorWithMessages(Connection, Where, CancellationToken);
                return;
            }

            try
            {

                var link = Connection.IsSSH
                               ? await GridOperatorLinkOverSSH      (Connection, Where, CancellationToken)
                               : await GridOperatorLinkOverWebSocket(Connection, Where, CancellationToken);

                if (link is null)
                    return;

                if (!gridOperatorLinks.TryAdd(Connection.Id, link))
                {
                    await link.LetGo();
                    return;
                }

                Note(Connection, $"Connected to the grid operator over {link.Transport}, speaking the REST API of OpenADR in a tunnel; it is connected again if it drops.");

                _ = FollowGridOperatorLink(Connection.Id, link);

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                Fail(Connection, ConnectionStatus.Trying, $"{Where} could not be reached: {e.Message}; it is tried again by itself.");
                ConnectToTheGridOperatorAgain(Connection.Id, GridOperatorConnectAgainAfter);
            }

        }

        #endregion

        #region (private) GridOperatorLinkOverWebSocket(Connection, Where, CancellationToken)

        private async Task<GridOperatorLink?> GridOperatorLinkOverWebSocket(ConnectionEntry    Connection,
                                                                            String             Where,
                                                                            CancellationToken  CancellationToken)
        {

            if (!WhatItProvesItselfWith(Connection, out var basic, out var totp, out var totpLogin, out var certificates, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            var keyPins      = KeyPinTrustFor(Connection, out var notByKeyPin);

            if (notByKeyPin is not null)
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, notByKeyPin));
                return null;
            }

            var validator    = keyPins is not null
                                   ? keyPins.Validator
                                   : Connection.IsSecure
                                         ? JudgedAsAServer(Connection.Id, Connection.URL)
                                         : null;

            var subprotocol  = OpenADRWireNames.SubprotocolOf(Connection.OpenADRBinding);

            Log.Info($"Connecting to {Where} as a grid operator over OpenADR ({subprotocol}), signing in with {says}.", "openadr", "connections");

            var client       = new StreamWebSocketClient(
                                   Connection.URL,
                                   subprotocol,
                                   basic,
                                   validator,
                                   CertificateShownAlone  (certificates),
                                   CertificateWithItsChain(certificates),
                                   totp,
                                   totpLogin?.ToString(),
                                   DNSClient
                               );

            var (_, response) = await client.Connect(CancellationToken: CancellationToken);

            if (response.HTTPStatusCode != HTTPStatusCode.SwitchingProtocols)
            {

                var unreached = response.HTTPRequest is null;

                // Turned away for now - a 503 of a door whose connection is
                // switched off, a server not up yet -: tried again then.
                var again     = keyPins?.Refused == true ? null : TurnedAwayForNow(response, GridOperatorConnectAgainAfter);

                await DisposeQuietly(client);

                Fail(Connection,
                     unreached || again is not null ? ConnectionStatus.Trying : ConnectionStatus.Refused,
                     (keyPins?.Refused == true
                          ? $"{Where} was not believed: {keyPins.WhyRefused()}"
                          : unreached
                                ? $"{Where} could not be reached: the attempt ended before anything could be asked of it"
                                : again is not null
                                      ? $"{Where} turned it away for now: {response.HTTPStatusCode}"
                                      : $"{Where} did not become a WebSocket connection: {response.HTTPStatusCode}") +
                     (unreached
                          ? "; it is tried again by itself."
                          : again is TimeSpan then
                                ? $"; it is tried again in {(Int64) Math.Ceiling(then.TotalSeconds)} s."
                                : "; that answer is final, and it is not tried again."));

                if (unreached || again is not null)
                    ConnectToTheGridOperatorAgain(Connection.Id, again ?? GridOperatorConnectAgainAfter);

                return null;

            }

            if (response.SecWebSocketProtocol is String agreed && agreed != subprotocol)
            {
                await DisposeQuietly(client);
                Fail(Connection, ConnectionStatus.Refused, $"{Where} agreed on the subprotocol '{agreed}', and not on '{subprotocol}'; it is not tried again.");
                return null;
            }

            var stream  = client.Stream;

            // A WebSocket that went away without a close frame ends its stream
            // as well: asked of the client, as nothing else says so.
            var ended   = Task.Run(async () => {
                              while (!stream.HasEnded)
                              {
                                  await Task.Delay(250);
                                  if (!client.Connected)
                                      stream.End();
                              }
                          });

            return new GridOperatorLink(
                       Connection,
                       stream,
                       Connection.IsSecure ? "WebSocket TLS" : "WebSocket",
                       async () => {
                           stream.End();
                           await DisposeQuietly(client);
                       },
                       ended
                   );

        }

        #endregion

        #region (private) GridOperatorLinkOverSSH(Connection, Where, CancellationToken)

        private async Task<GridOperatorLink?> GridOperatorLinkOverSSH(ConnectionEntry    Connection,
                                                                      String             Where,
                                                                      CancellationToken  CancellationToken)
        {

            var key = await SshKey.MakeIfNeeded(CancellationToken);

            if (!SshLoginOf(Connection, key, out var login, out var trust, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            var subsystem = OpenADRWireNames.SshSubsystemOf(Connection.OpenADRBinding);

            Log.Info($"Connecting to {Where} as a grid operator over OpenADR over SSH ({subsystem}), signing in with {says}; {WhatItBelieves(trust)}.", "openadr", "connections", "ssh");

            sshTrusts[Connection.Id] = trust;

            SSHClient? sshClient = null;

            try
            {

                sshClient = await SSHClient.Connect(
                                      Connection.URL.Host.ToString(),
                                      Connection.URL.Port ?? IPPort.SSH,
                                      login with { DNSClient = login.DNSClient ?? DNSClient },
                                      CancellationToken
                                  );

                var channel  = await sshClient.OpenSubsystem(subsystem, CancellationToken);
                var client   = sshClient;

                return new GridOperatorLink(
                           Connection,
                           channel.AsStream(),
                           "SSH",
                           async () => {
                               try { await channel.CloseAsync(); } catch { }
                               await DisposeQuietly(client);
                           },
                           channel.Closed
                       );

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {

                if (sshClient is not null)
                    await DisposeQuietly(sshClient);

                var final = trust.Refused || IsFinal(e);

                Fail(Connection,
                     final ? ConnectionStatus.Refused : ConnectionStatus.Trying,
                     WhyNotOverSSH(Where, trust, e) +
                     (final
                          ? "; that answer is final, and it is not tried again."
                          : "; it is tried again by itself."));

                if (!final)
                    ConnectToTheGridOperatorAgain(Connection.Id, GridOperatorConnectAgainAfter);

                return null;

            }

        }

        #endregion

        #region (private) ConnectToTheGridOperatorWithMessages(Connection, Where, CancellationToken)

        /// <summary>
        /// One connection to a grid operator in the binding of messages.
        /// </summary>
        private async Task ConnectToTheGridOperatorWithMessages(ConnectionEntry    Connection,
                                                                String             Where,
                                                                CancellationToken  CancellationToken)
        {

            try
            {

                var link = Connection.IsSSH
                               ? await GridOperatorMessageLinkOverSSH      (Connection, Where, CancellationToken)
                               : await GridOperatorMessageLinkOverWebSocket(Connection, Where, CancellationToken);

                if (link is null)
                    return;

                if (!gridOperatorMessageLinks.TryAdd(Connection.Id, link))
                {
                    await link.LetGo();
                    return;
                }

                Note(Connection, $"Connected to the grid operator over {link.Transport}, speaking the JSON messages of OpenADR; it is connected again if it drops.");

                OnGridOperatorMessageLink?.Invoke(Connection.Id, true);

                _ = FollowGridOperatorMessageLink(Connection.Id, link);

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                Fail(Connection, ConnectionStatus.Trying, $"{Where} could not be reached: {e.Message}; it is tried again by itself.");
                ConnectToTheGridOperatorAgain(Connection.Id, GridOperatorConnectAgainAfter);
            }

        }

        #endregion

        #region (private) GridOperatorMessageLinkOverWebSocket(Connection, Where, CancellationToken)

        private async Task<GridOperatorMessageLink?> GridOperatorMessageLinkOverWebSocket(ConnectionEntry    Connection,
                                                                                          String             Where,
                                                                                          CancellationToken  CancellationToken)
        {

            if (!WhatItProvesItselfWith(Connection, out var basic, out var totp, out var totpLogin, out var certificates, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            var keyPins      = KeyPinTrustFor(Connection, out var notByKeyPin);

            if (notByKeyPin is not null)
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, notByKeyPin));
                return null;
            }

            var validator    = keyPins is not null
                                   ? keyPins.Validator
                                   : Connection.IsSecure
                                         ? JudgedAsAServer(Connection.Id, Connection.URL)
                                         : null;

            var subprotocol  = OpenADRWireNames.SubprotocolOf(Connection.OpenADRBinding);

            Log.Info($"Connecting to {Where} as a grid operator over OpenADR ({subprotocol}), signing in with {says}.", "openadr", "connections");

            var client       = new MessageWebSocketClient(
                                   Connection.URL,
                                   subprotocol,
                                   basic,
                                   validator,
                                   CertificateShownAlone  (certificates),
                                   CertificateWithItsChain(certificates),
                                   totp,
                                   totpLogin?.ToString(),
                                   DNSClient
                               ) {
                                   OnText = text => OnGridOperatorMessage?.Invoke(Connection.Id, text) ?? Task.CompletedTask
                               };

            var (_, response) = await client.Connect(CancellationToken: CancellationToken);

            if (response.HTTPStatusCode != HTTPStatusCode.SwitchingProtocols)
            {

                var unreached = response.HTTPRequest is null;

                // Turned away for now - a 503 of a door whose connection is
                // switched off, a server not up yet -: tried again then.
                var again     = keyPins?.Refused == true ? null : TurnedAwayForNow(response, GridOperatorConnectAgainAfter);

                client.End();
                await DisposeQuietly(client);

                Fail(Connection,
                     unreached || again is not null ? ConnectionStatus.Trying : ConnectionStatus.Refused,
                     (keyPins?.Refused == true
                          ? $"{Where} was not believed: {keyPins.WhyRefused()}"
                          : unreached
                                ? $"{Where} could not be reached: the attempt ended before anything could be asked of it"
                                : again is not null
                                      ? $"{Where} turned it away for now: {response.HTTPStatusCode}"
                                      : $"{Where} did not become a WebSocket connection: {response.HTTPStatusCode}") +
                     (unreached
                          ? "; it is tried again by itself."
                          : again is TimeSpan then
                                ? $"; it is tried again in {(Int64) Math.Ceiling(then.TotalSeconds)} s."
                                : "; that answer is final, and it is not tried again."));

                if (unreached || again is not null)
                    ConnectToTheGridOperatorAgain(Connection.Id, again ?? GridOperatorConnectAgainAfter);

                return null;

            }

            if (response.SecWebSocketProtocol is String agreed && agreed != subprotocol)
            {
                client.End();
                await DisposeQuietly(client);
                Fail(Connection, ConnectionStatus.Refused, $"{Where} agreed on the subprotocol '{agreed}', and not on '{subprotocol}'; it is not tried again.");
                return null;
            }

            return new GridOperatorMessageLink(
                       Connection,
                       client.SendText,
                       Connection.IsSecure ? "WebSocket TLS" : "WebSocket",
                       async () => {
                           client.End();
                           await DisposeQuietly(client);
                       },
                       client.Ended
                   );

        }

        #endregion

        #region (private) GridOperatorMessageLinkOverSSH(Connection, Where, CancellationToken)

        private async Task<GridOperatorMessageLink?> GridOperatorMessageLinkOverSSH(ConnectionEntry    Connection,
                                                                                    String             Where,
                                                                                    CancellationToken  CancellationToken)
        {

            var key = await SshKey.MakeIfNeeded(CancellationToken);

            if (!SshLoginOf(Connection, key, out var login, out var trust, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            var subsystem = OpenADRWireNames.SshSubsystemOf(Connection.OpenADRBinding);

            Log.Info($"Connecting to {Where} as a grid operator over OpenADR over SSH ({subsystem}), signing in with {says}; {WhatItBelieves(trust)}.", "openadr", "connections", "ssh");

            sshTrusts[Connection.Id] = trust;

            SSHClient?         sshClient      = null;
            SshMessageClient?  messageClient  = null;

            try
            {

                sshClient = await SSHClient.Connect(
                                      Connection.URL.Host.ToString(),
                                      Connection.URL.Port ?? IPPort.SSH,
                                      login with { DNSClient = login.DNSClient ?? DNSClient },
                                      CancellationToken
                                  );

                var ssh    = sshClient;
                var ended  = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

                // The SSH connection is this node's, made above with what the
                // connection proves itself with; the client of messages only
                // asks for the subsystem on it.
                messageClient = new SshMessageClient(new SshMessageClientOptions {
                                    Host          = Connection.URL.Host.ToString(),
                                    Connection    = _ => ValueTask.FromResult(ssh),
                                    Subsystem     = subsystem,
                                    Subprotocols  = [ OpenADRWireNames.SubprotocolOf(Connection.OpenADRBinding) ]
                                });

                messageClient.OnTextMessageReceived += (timestamp, sender, connection, text, cancellationToken)
                                                           => OnGridOperatorMessage?.Invoke(Connection.Id, text) ?? Task.CompletedTask;

                messageClient.OnConnectionClosed    += (timestamp, sender, connection, close, cancellationToken) => {
                                                           ended.TrySetResult();
                                                           return Task.CompletedTask;
                                                       };

                var messages = await messageClient.ConnectAsync(CancellationToken);
                var client   = messageClient;

                return new GridOperatorMessageLink(
                           Connection,
                           async (text, cancellationToken) => await messages.SendTextMessage(text, cancellationToken) == SentStatus.Success,
                           "SSH",
                           async () => {
                               ended.TrySetResult();
                               try { await client.Close(); } catch { }
                               await DisposeQuietly(ssh);
                           },
                           ended.Task
                       );

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {

                if (messageClient is not null)
                    try { await messageClient.DisposeAsync(); } catch { }

                if (sshClient is not null)
                    await DisposeQuietly(sshClient);

                var final = trust.Refused || IsFinal(e) || e is SshMessageRefusedException;

                Fail(Connection,
                     final ? ConnectionStatus.Refused : ConnectionStatus.Trying,
                     WhyNotOverSSH(Where, trust, e) +
                     (final
                          ? "; that answer is final, and it is not tried again."
                          : "; it is tried again by itself."));

                if (!final)
                    ConnectToTheGridOperatorAgain(Connection.Id, GridOperatorConnectAgainAfter);

                return null;

            }

        }

        #endregion

        #region (private) FollowGridOperatorMessageLink(ConnectionId, Link)

        /// <summary>
        /// Wait for the given link of messages to end, and connect it again then.
        /// </summary>
        private async Task FollowGridOperatorMessageLink(String                   ConnectionId,
                                                         GridOperatorMessageLink  Link)
        {

            try
            {
                await Link.Ended;
            }
            catch
            { }

            if (!gridOperatorMessageLinks.TryRemove(KeyValuePair.Create(ConnectionId, Link)))
                return;

            await Link.LetGo();

            OnGridOperatorMessageLink?.Invoke(ConnectionId, false);

            if (hungUpOnTheGridOperators)
                return;

            Fail(Link.Connection, ConnectionStatus.Lost, $"The connection to the grid operator '{Link.Connection.Description.FirstText()}' over {Link.Transport} dropped; it is connected again by itself.");

            ConnectToTheGridOperatorAgain(ConnectionId, GridOperatorConnectAgainAfter);

        }

        #endregion

        #region (private) FollowGridOperatorLink(ConnectionId, Link) / GiveBack(ConnectionId, Link) / ConnectToTheGridOperatorAgain(ConnectionId, After)

        /// <summary>
        /// Wait for the given link to end, and connect it again then.
        /// </summary>
        private async Task FollowGridOperatorLink(String            ConnectionId,
                                                  GridOperatorLink  Link)
        {

            try
            {
                await Link.Ended;
            }
            catch
            { }

            if (!gridOperatorLinks.TryRemove(KeyValuePair.Create(ConnectionId, Link)))
                return;

            await Link.LetGo();

            if (hungUpOnTheGridOperators)
                return;

            Fail(Link.Connection, ConnectionStatus.Lost, $"The connection to the grid operator '{Link.Connection.Description.FirstText()}' over {Link.Transport} dropped; it is connected again by itself.");

            ConnectToTheGridOperatorAgain(ConnectionId, GridOperatorConnectAgainAfter);

        }

        /// <summary>
        /// The stream of the given link given back - by an HTTP client that is
        /// done with its connection: the link ends, and is made again at once.
        /// </summary>
        private async Task GiveBack(String            ConnectionId,
                                    GridOperatorLink  Link)
        {

            if (!gridOperatorLinks.TryRemove(KeyValuePair.Create(ConnectionId, Link)))
                return;

            await Link.LetGo();

            if (hungUpOnTheGridOperators)
                return;

            Log.Debug($"The tunnel to the grid operator '{Link.Connection.Description.FirstText()}' was given back; it is made again.", "openadr", "connections");

            ConnectToTheGridOperatorAgain(ConnectionId, TimeSpan.Zero);

        }

        /// <summary>
        /// Connect to the grid operator of the given connection again after the
        /// given while - as it is written down then, if it is written down and
        /// switched on still.
        /// </summary>
        private void ConnectToTheGridOperatorAgain(String    ConnectionId,
                                                   TimeSpan  After)

            => _ = Task.Run(async () => {

                       if (After > TimeSpan.Zero)
                           await Task.Delay(After);

                       if (hungUpOnTheGridOperators || gridOperatorLinks.ContainsKey(ConnectionId) || gridOperatorMessageLinks.ContainsKey(ConnectionId))
                           return;

                       if (Connections?.Connections.FirstOrDefault(entry => entry.Id == ConnectionId) is ConnectionEntry now &&
                           now.AutoConnect &&
                           !now.Inbound &&
                           now.Use == ConnectionUse.OpenADR)
                       {
                           await ConnectToTheGridOperator(now, $"'{now.Description.FirstText()}' ({now.URL})", CancellationToken.None);
                       }

                   });

        #endregion

        #region (protected) HangUpOnTheGridOperators()

        /// <summary>
        /// Close every connection to a grid operator, and connect none of them again.
        /// </summary>
        protected async Task HangUpOnTheGridOperators()
        {

            hungUpOnTheGridOperators = true;

            foreach (var id in gridOperatorLinks.Keys.ToArray())
                if (gridOperatorLinks.TryRemove(id, out var link))
                    await link.LetGo();

            foreach (var id in gridOperatorMessageLinks.Keys.ToArray())
                if (gridOperatorMessageLinks.TryRemove(id, out var messageLink))
                {
                    await messageLink.LetGo();
                    OnGridOperatorMessageLink?.Invoke(id, false);
                }

        }

        #endregion

        #region (private sealed class) TunnelStream

        /// <summary>
        /// The stream of a connection to a grid operator as an HTTP client has
        /// it: disposing it gives it back rather than closing what it goes over -
        /// see <see cref="GiveBack"/> -, and a read of no bytes waits for the
        /// next byte, as one of a socket does.
        /// </summary>
        /// <remarks>
        /// An HTTP client asks a connection it keeps whether the other end
        /// closed it by reading no bytes, which a socket answers once something
        /// came or it closed - and which a stream of a pipe may answer at once,
        /// taking the connection for closed. Here it is answered as a socket
        /// does: one byte is read ahead and kept for the next read.
        /// </remarks>
        private sealed class TunnelStream(Stream      Inner,
                                          Func<Task>  GiveBack) : Stream
        {

            private Int32  aheadByte  = -1;
            private Int32  given;

            public override Boolean  CanRead   => true;
            public override Boolean  CanWrite  => true;
            public override Boolean  CanSeek   => false;
            public override Int64    Length    => throw new NotSupportedException();
            public override Int64    Position  { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override async ValueTask<Int32> ReadAsync(Memory<Byte> Buffer, CancellationToken CancellationToken = default)
            {

                if (aheadByte >= 0)
                {

                    if (Buffer.Length == 0)
                        return 0;

                    Buffer.Span[0] = (Byte) aheadByte;
                    aheadByte      = -1;

                    return 1;

                }

                if (Buffer.Length == 0)
                {

                    var one  = new Byte[1];
                    var read = await Inner.ReadAsync(one, CancellationToken);

                    if (read == 1)
                        aheadByte = one[0];

                    return 0;

                }

                return await Inner.ReadAsync(Buffer, CancellationToken);

            }

            public override Task<Int32> ReadAsync(Byte[] Buffer, Int32 Offset, Int32 Count, CancellationToken CancellationToken)
                => ReadAsync(Buffer.AsMemory(Offset, Count), CancellationToken).AsTask();

            public override Int32 Read(Byte[] Buffer, Int32 Offset, Int32 Count)
                => ReadAsync(Buffer.AsMemory(Offset, Count)).AsTask().GetAwaiter().GetResult();

            public override ValueTask WriteAsync(ReadOnlyMemory<Byte> Buffer, CancellationToken CancellationToken = default)
                => Inner.WriteAsync(Buffer, CancellationToken);

            public override Task WriteAsync(Byte[] Buffer, Int32 Offset, Int32 Count, CancellationToken CancellationToken)
                => Inner.WriteAsync(Buffer, Offset, Count, CancellationToken);

            public override void Write(Byte[] Buffer, Int32 Offset, Int32 Count)
                => Inner.Write(Buffer, Offset, Count);

            public override void  Flush() => Inner.Flush();
            public override Task  FlushAsync(CancellationToken CancellationToken) => Inner.FlushAsync(CancellationToken);
            public override Int64 Seek(Int64 Offset, SeekOrigin Origin) => throw new NotSupportedException();
            public override void  SetLength(Int64 Value) => throw new NotSupportedException();

            protected override void Dispose(Boolean Disposing)
            {
                if (Disposing && Interlocked.Exchange(ref given, 1) == 0)
                    _ = GiveBack();
                base.Dispose(Disposing);
            }

            public override ValueTask DisposeAsync()
            {
                if (Interlocked.Exchange(ref given, 1) == 0)
                    _ = GiveBack();
                return ValueTask.CompletedTask;
            }

        }

        #endregion

    }

}
