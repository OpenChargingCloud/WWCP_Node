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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.PKI;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The PKIs this node connects to as a registration authority: over a
    /// WebSocket or over an SSH subsystem of the PKI, speaking the messages of a
    /// PKI - see <see cref="PKIWireNames"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A connection of the type <see cref="ConnectionType.PKI"/>, made by this
    /// node, signed in as every connection signs in: over ws:// and wss:// with
    /// a password, a one-time password or a client certificate, over ssh:// with
    /// its key, a password or a one-time password, believing the server as every
    /// connection believes it.
    /// </para>
    /// <para>
    /// Over it this node asks: <see cref="SignCertificateAtThePKI"/> for the CSR
    /// of a charging station, <see cref="GetCACertificatesOfThePKI"/>,
    /// <see cref="GetCertificateStatusAtThePKI"/>, <see cref="GetCRLOfThePKI"/>,
    /// <see cref="RevokeCertificateAtThePKI"/> and <see cref="GetOCSPResponseOfThePKI"/> - or any action with
    /// <see cref="AskThePKI"/>. A connection that drops is connected again after
    /// a while, as long as it is written down, switched on, and this node has
    /// not hung up.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// How long a connection to a PKI that dropped or could not be made waits
        /// before it is tried again.
        /// </summary>
        public static TimeSpan PKIConnectAgainAfter { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>
        /// One connection to a PKI that is up: its messages, what it goes over,
        /// and what to let go of when it ends.
        /// </summary>
        private sealed record PKILink(ConnectionEntry    Connection,
                                      PKIMessageChannel  Channel,
                                      String             Transport,
                                      Func<Task>         LetGo);

        private readonly ConcurrentDictionary<String, PKILink>  pkiLinks          = new ();
        private volatile Boolean                                 hungUpOnThePKIs;

        #endregion


        #region PKIConnectionIsUp(ConnectionId) / PKITransportOf(ConnectionId)

        /// <summary>
        /// Whether the given connection to a PKI is up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        public Boolean PKIConnectionIsUp(String ConnectionId)

            => pkiLinks.ContainsKey(ConnectionId);

        /// <summary>
        /// What the given connection to a PKI goes over now - "WebSocket",
        /// "WebSocket TLS" or "SSH" - or null where it is not up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        public String? PKITransportOf(String ConnectionId)

            => pkiLinks.TryGetValue(ConnectionId, out var link)
                   ? link.Transport
                   : null;

        #endregion

        #region AskThePKI(ConnectionId, Action, Payload, Timeout = null, CancellationToken = default)

        /// <summary>
        /// Ask the PKI of the given connection: the payload of its response, or
        /// the error it answered with as a <see cref="PKIException"/>. Waited for
        /// until the connection is up, or until the timeout.
        /// </summary>
        /// <param name="ConnectionId">The connection to the PKI.</param>
        /// <param name="Action">What is asked - see <see cref="PKIActions"/>.</param>
        /// <param name="Payload">What is asked of it.</param>
        /// <param name="Timeout">How long the connection and the response are waited for; <see cref="PKIMessageChannel.DefaultTimeout"/> by default.</param>
        /// <param name="CancellationToken">Ends the wait.</param>
        /// <exception cref="InvalidOperationException">The connection is no connection to a PKI, or switched off.</exception>
        public async Task<JObject> AskThePKI(String             ConnectionId,
                                             String             Action,
                                             JObject            Payload,
                                             TimeSpan?          Timeout            = null,
                                             CancellationToken  CancellationToken  = default)
        {

            var timeout = Timeout ?? PKIMessageChannel.DefaultTimeout;

            using var waiting  = new CancellationTokenSource(timeout);
            using var both     = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, waiting.Token);

            while (true)
            {

                if (pkiLinks.TryGetValue(ConnectionId, out var link))
                    return await link.Channel.Request(Action, Payload, timeout, CancellationToken);

                if (Connections?.Connections.FirstOrDefault(entry => entry.Id == ConnectionId) is not ConnectionEntry entry ||
                    entry.ConnectionType != ConnectionType.PKI)
                {
                    throw new InvalidOperationException($"The connection '{ConnectionId}' of this {NodeNoun} is no connection to a PKI.");
                }

                if (!entry.AutoConnect)
                    throw new InvalidOperationException($"The connection '{entry.Description.FirstText()}' of this {NodeNoun} to its PKI is switched off.");

                try
                {
                    await Task.Delay(50, both.Token);
                }
                catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException($"The connection '{entry.Description.FirstText()}' of this {NodeNoun} to its PKI was not up within {timeout.TotalSeconds} s.");
                }

            }

        }

        #endregion

        #region SignCertificateAtThePKI / GetCACertificatesOfThePKI / GetCertificateStatusAtThePKI / GetCRLOfThePKI / RevokeCertificateAtThePKI / GetOCSPResponseOfThePKI

        /// <summary>
        /// Have the PKI of the given connection sign a CSR - of a charging
        /// station, say - as it signs one over EST at the label of the request.
        /// </summary>
        public async Task<SignCertificateResponse> SignCertificateAtThePKI(String                  ConnectionId,
                                                                           SignCertificateRequest  Request,
                                                                           TimeSpan?               Timeout            = null,
                                                                           CancellationToken       CancellationToken  = default)

            => SignCertificateResponse.Parse(await AskThePKI(ConnectionId, PKIActions.SignCertificate, Request.ToJSON(), Timeout, CancellationToken));

        /// <summary>
        /// The CA certificates of the PKI of the given connection that a
        /// certificate signed at the label of the request chains to.
        /// </summary>
        public async Task<GetCACertificatesResponse> GetCACertificatesOfThePKI(String                    ConnectionId,
                                                                               GetCACertificatesRequest  Request,
                                                                               TimeSpan?                 Timeout            = null,
                                                                               CancellationToken         CancellationToken  = default)

            => GetCACertificatesResponse.Parse(await AskThePKI(ConnectionId, PKIActions.GetCACertificates, Request.ToJSON(), Timeout, CancellationToken));

        /// <summary>
        /// Whether a certificate of the PKI of the given connection is valid,
        /// revoked or expired.
        /// </summary>
        public async Task<GetCertificateStatusResponse> GetCertificateStatusAtThePKI(String                       ConnectionId,
                                                                                     GetCertificateStatusRequest  Request,
                                                                                     TimeSpan?                    Timeout            = null,
                                                                                     CancellationToken            CancellationToken  = default)

            => GetCertificateStatusResponse.Parse(await AskThePKI(ConnectionId, PKIActions.GetCertificateStatus, Request.ToJSON(), Timeout, CancellationToken));

        /// <summary>
        /// The CRL of a CA of the PKI of the given connection.
        /// </summary>
        public async Task<GetCRLResponse> GetCRLOfThePKI(String             ConnectionId,
                                                         GetCRLRequest      Request,
                                                         TimeSpan?          Timeout            = null,
                                                         CancellationToken  CancellationToken  = default)

            => GetCRLResponse.Parse(await AskThePKI(ConnectionId, PKIActions.GetCRL, Request.ToJSON(), Timeout, CancellationToken));

        /// <summary>
        /// Revoke a certificate this node had the PKI of the given connection sign.
        /// </summary>
        public async Task<RevokeCertificateResponse> RevokeCertificateAtThePKI(String                    ConnectionId,
                                                                               RevokeCertificateRequest  Request,
                                                                               TimeSpan?                 Timeout            = null,
                                                                               CancellationToken         CancellationToken  = default)

            => RevokeCertificateResponse.Parse(await AskThePKI(ConnectionId, PKIActions.RevokeCertificate, Request.ToJSON(), Timeout, CancellationToken));

        /// <summary>
        /// The answer of the OCSP responder of the PKI of the given connection
        /// to an OCSP request - of a charging station, say.
        /// </summary>
        public async Task<GetOCSPResponseResponse> GetOCSPResponseOfThePKI(String                  ConnectionId,
                                                                           GetOCSPResponseRequest  Request,
                                                                           TimeSpan?               Timeout            = null,
                                                                           CancellationToken       CancellationToken  = default)

            => GetOCSPResponseResponse.Parse(await AskThePKI(ConnectionId, PKIActions.GetOCSPResponse, Request.ToJSON(), Timeout, CancellationToken));

        #endregion


        #region (protected) ConnectToThePKI(Connection, Where, CancellationToken)

        /// <summary>
        /// One connection to a PKI: who it signs in as, over what, and whether
        /// it got through.
        /// </summary>
        protected async Task ConnectToThePKI(ConnectionEntry    Connection,
                                             String             Where,
                                             CancellationToken  CancellationToken)
        {

            hungUpOnThePKIs = false;

            if (pkiLinks.ContainsKey(Connection.Id))
                return;

            try
            {

                var link = Connection.IsSSH
                               ? await PKILinkOverSSH      (Connection, Where, CancellationToken)
                               : await PKILinkOverWebSocket(Connection, Where, CancellationToken);

                if (link is null)
                    return;

                if (!pkiLinks.TryAdd(Connection.Id, link))
                {
                    await link.LetGo();
                    return;
                }

                Note(Connection, $"Connected to the PKI over {link.Transport}, speaking the messages of a PKI; it is connected again if it drops.");

                _ = FollowPKILink(Connection.Id, link);

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                Fail(Connection, ConnectionStatus.Trying, $"{Where} could not be reached: {e.Message}; it is tried again by itself.");
                ConnectToThePKIAgain(Connection.Id, PKIConnectAgainAfter);
            }

        }

        #endregion

        #region (private) PKILinkOverWebSocket(Connection, Where, CancellationToken)

        private async Task<PKILink?> PKILinkOverWebSocket(ConnectionEntry    Connection,
                                                          String             Where,
                                                          CancellationToken  CancellationToken)
        {

            if (!WhatItProvesItselfWith(Connection, out var basic, out var totp, out var totpLogin, out var certificates, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            var keyPins    = KeyPinTrustFor(Connection, out var notByKeyPin);

            if (notByKeyPin is not null)
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, notByKeyPin));
                return null;
            }

            var validator  = keyPins is not null
                                 ? keyPins.Validator
                                 : Connection.IsSecure
                                       ? JudgedAsAServer(Connection.Id, Connection.URL)
                                       : null;

            Log.Info($"Connecting to {Where} as a PKI ({PKIWireNames.Subprotocol}), signing in with {says}.", "pki", "connections");

            var client     = new StreamWebSocketClient(
                                 Connection.URL,
                                 PKIWireNames.Subprotocol,
                                 basic,
                                 validator,
                                 CertificateShownAlone  (certificates),
                                 CertificateWithItsChain(certificates),
                                 totp,
                                 totpLogin?.ToString(),
                                 DNSClient,
                                 TextLines: true
                             );

            var (_, response) = await client.Connect(CancellationToken: CancellationToken);

            if (response.HTTPStatusCode != HTTPStatusCode.SwitchingProtocols)
            {

                var unreached = response.HTTPRequest is null;

                // Turned away for now - a 503 of a door whose connection is
                // switched off, a server not up yet -: tried again then.
                var again     = keyPins?.Refused == true ? null : TurnedAwayForNow(response, PKIConnectAgainAfter);

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
                    ConnectToThePKIAgain(Connection.Id, again ?? PKIConnectAgainAfter);

                return null;

            }

            if (response.SecWebSocketProtocol is String agreed && agreed != PKIWireNames.Subprotocol)
            {
                await DisposeQuietly(client);
                Fail(Connection, ConnectionStatus.Refused, $"{Where} agreed on the subprotocol '{agreed}', and not on '{PKIWireNames.Subprotocol}'; it is not tried again.");
                return null;
            }

            var stream   = client.Stream;
            var channel  = new PKIMessageChannel(stream);

            // A WebSocket that went away without a close frame ends its stream
            // as well: asked of the client, as nothing else says so.
            _ = Task.Run(async () => {
                    while (!stream.HasEnded)
                    {
                        await Task.Delay(250);
                        if (!client.Connected)
                            stream.End();
                    }
                });

            return new PKILink(
                       Connection,
                       channel,
                       Connection.IsSecure ? "WebSocket TLS" : "WebSocket",
                       async () => {
                           stream.End();
                           await channel.DisposeAsync();
                           await DisposeQuietly(client);
                       }
                   );

        }

        #endregion

        #region (private) PKILinkOverSSH(Connection, Where, CancellationToken)

        private async Task<PKILink?> PKILinkOverSSH(ConnectionEntry    Connection,
                                                    String             Where,
                                                    CancellationToken  CancellationToken)
        {

            var key = await SshKey.MakeIfNeeded(CancellationToken);

            if (!SshLoginOf(Connection, key, out var login, out var trust, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            Log.Info($"Connecting to {Where} as a PKI over SSH ({PKIWireNames.SshSubsystem}), signing in with {says}; {WhatItBelieves(trust)}.", "pki", "connections", "ssh");

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

                var subsystem  = await sshClient.OpenSubsystem(PKIWireNames.SshSubsystem, CancellationToken);
                var client     = sshClient;
                var channel    = new PKIMessageChannel(subsystem.AsStream());

                // The subsystem closed by the PKI ends what is read of it.
                _ = subsystem.Closed.ContinueWith(_ => channel.DisposeAsync().AsTask(), TaskScheduler.Default);

                return new PKILink(
                           Connection,
                           channel,
                           "SSH",
                           async () => {
                               await channel.DisposeAsync();
                               try { await subsystem.CloseAsync(); } catch { }
                               await DisposeQuietly(client);
                           }
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
                    ConnectToThePKIAgain(Connection.Id, PKIConnectAgainAfter);

                return null;

            }

        }

        #endregion

        #region (private) FollowPKILink(ConnectionId, Link) / ConnectToThePKIAgain(ConnectionId, After)

        /// <summary>
        /// Wait for the given link to end, and connect it again then.
        /// </summary>
        private async Task FollowPKILink(String   ConnectionId,
                                         PKILink  Link)
        {

            try
            {
                await Link.Channel.Ended;
            }
            catch
            { }

            if (!pkiLinks.TryRemove(KeyValuePair.Create(ConnectionId, Link)))
                return;

            await Link.LetGo();

            if (hungUpOnThePKIs)
                return;

            Fail(Link.Connection, ConnectionStatus.Lost, $"The connection to the PKI '{Link.Connection.Description.FirstText()}' over {Link.Transport} dropped" +
                                                         (Link.Channel.WhyEnded is String why ? $" ({why})" : "") +
                                                         "; it is connected again by itself.");

            ConnectToThePKIAgain(ConnectionId, PKIConnectAgainAfter);

        }

        /// <summary>
        /// Connect to the PKI of the given connection again after the given
        /// while - as it is written down then, if it is written down and
        /// switched on still.
        /// </summary>
        private void ConnectToThePKIAgain(String    ConnectionId,
                                          TimeSpan  After)

            => _ = Task.Run(async () => {

                       if (After > TimeSpan.Zero)
                           await Task.Delay(After);

                       if (hungUpOnThePKIs || pkiLinks.ContainsKey(ConnectionId))
                           return;

                       if (Connections?.Connections.FirstOrDefault(entry => entry.Id == ConnectionId) is ConnectionEntry now &&
                           now.AutoConnect &&
                           !now.Inbound &&
                           now.Use == ConnectionUse.PKI)
                       {
                           await ConnectToThePKI(now, $"'{now.Description.FirstText()}' ({now.URL})", CancellationToken.None);
                       }

                   });

        #endregion

        #region (protected) HangUpOnThePKIs()

        /// <summary>
        /// Close every connection to a PKI, and connect none of them again.
        /// </summary>
        protected async Task HangUpOnThePKIs()
        {

            hungUpOnThePKIs = true;

            foreach (var id in pkiLinks.Keys.ToArray())
                if (pkiLinks.TryRemove(id, out var link))
                    await link.LetGo();

        }

        #endregion

    }

}
