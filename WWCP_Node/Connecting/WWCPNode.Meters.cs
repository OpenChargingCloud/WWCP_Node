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
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Modbus;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ModbusTCPClient = org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common.ModbusTCPClient;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The energy meters this node connects to: read and commanded over Modbus,
    /// over a WebSocket of the subprotocol "modbus" or over the SSH subsystem
    /// "modbus@open.charging.cloud" of the meter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A connection of the type <see cref="ConnectionType.EnergyMeter"/>, made
    /// by this node, signed in as every connection signs in: over ws:// and
    /// wss:// with a password, a one-time password or a client certificate,
    /// over ssh:// with its key, a password or a one-time password, believing
    /// the server as every connection believes it. Once it is up, the frames of
    /// Modbus/TCP go over it, and nothing else.
    /// </para>
    /// <para>
    /// What this node may do at the meter is the meter's to decide, by the
    /// SunSpec role it gives the login: a request it refuses comes back as a
    /// Modbus exception, which <see cref="ReadMeterRegisters"/> and
    /// <see cref="WriteMeterRegisters"/> throw as a <see cref="ModbusException"/>.
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
        /// How long a connection to a meter that dropped or could not be made
        /// waits before it is tried again.
        /// </summary>
        public static TimeSpan MeterConnectAgainAfter { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>
        /// How long a request to a meter may take.
        /// </summary>
        public static readonly TimeSpan MeterRequestTimeout = TimeSpan.FromSeconds(10);

        /// <summary>
        /// One connection to a meter that is up: its Modbus client, what it goes
        /// over, and what to let go of when it ends.
        /// </summary>
        private sealed class MeterLink(ConnectionEntry          Connection,
                                       ModbusTCPClient          Client,
                                       String                   Transport,
                                       Func<Task>               LetGo,
                                       Task                     Ended)
        {
            public ConnectionEntry  Connection  { get; } = Connection;
            public ModbusTCPClient  Client      { get; } = Client;
            public String           Transport   { get; } = Transport;
            public Func<Task>       LetGo       { get; } = LetGo;
            public Task             Ended       { get; } = Ended;
        }

        private readonly ConcurrentDictionary<String, MeterLink>  meterLinks          = new ();
        private volatile Boolean                                   hungUpOnTheMeters;

        #endregion


        #region MeterConnectionIsUp(ConnectionId) / MeterTransportOf(ConnectionId)

        /// <summary>
        /// Whether the given connection to a meter is up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        public Boolean MeterConnectionIsUp(String ConnectionId)

            => meterLinks.ContainsKey(ConnectionId);

        /// <summary>
        /// What the given connection to a meter goes over now - "WebSocket",
        /// "WebSocket TLS" or "SSH" - or null where it is not up.
        /// </summary>
        /// <param name="ConnectionId">The connection.</param>
        public String? MeterTransportOf(String ConnectionId)

            => meterLinks.TryGetValue(ConnectionId, out var link)
                   ? link.Transport
                   : null;

        #endregion

        #region ExchangeWithMeter(ConnectionId, Unit, RequestPDU, CancellationToken = default)

        /// <summary>
        /// Send the given Modbus request to the meter of the given connection,
        /// and answer with its response PDU - an exception PDU included.
        /// </summary>
        /// <param name="ConnectionId">The connection to the meter.</param>
        /// <param name="Unit">The unit address.</param>
        /// <param name="RequestPDU">The request PDU: its function code and data.</param>
        /// <param name="CancellationToken">Ends the request.</param>
        /// <exception cref="InvalidOperationException">The connection is not up.</exception>
        public async Task<Byte[]> ExchangeWithMeter(String             ConnectionId,
                                                    Byte               Unit,
                                                    Byte[]             RequestPDU,
                                                    CancellationToken  CancellationToken = default)
        {

            if (!meterLinks.TryGetValue(ConnectionId, out var link))
                throw new InvalidOperationException($"The connection '{ConnectionId}' of this {NodeNoun} is no connection to an energy meter that is up.");

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            timeout.CancelAfter(MeterRequestTimeout);

            return await link.Client.ExchangeAsync(Unit, RequestPDU, timeout.Token);

        }

        #endregion

        #region ReadMeterRegisters (ConnectionId, Address, Count, Unit = 1, CancellationToken = default)

        /// <summary>
        /// Read holding registers of the meter of the given connection.
        /// </summary>
        /// <param name="ConnectionId">The connection to the meter.</param>
        /// <param name="Address">The first register, as it goes on the wire: 40000 for "SunS".</param>
        /// <param name="Count">How many.</param>
        /// <param name="Unit">The unit address.</param>
        /// <param name="CancellationToken">Ends the request.</param>
        /// <exception cref="ModbusException">The meter answered with a Modbus exception: 01 where its role may not read.</exception>
        public async Task<UInt16[]> ReadMeterRegisters(String             ConnectionId,
                                                       UInt16             Address,
                                                       UInt16             Count,
                                                       Byte               Unit               = 1,
                                                       CancellationToken  CancellationToken  = default)
        {

            var response = await ExchangeWithMeter(ConnectionId, Unit, ModbusPDU.BuildReadHoldingRegisters(Address, Count), CancellationToken);

            if (ModbusPDU.TryGetException(response) is { } exception)
                throw new ModbusException(exception);

            return ModbusPDU.DecodeReadResponse(response);

        }

        #endregion

        #region WriteMeterRegisters(ConnectionId, Address, Values, Unit = 1, CancellationToken = default)

        /// <summary>
        /// Write holding registers of the meter of the given connection: one with
        /// function code 06, more with 16.
        /// </summary>
        /// <param name="ConnectionId">The connection to the meter.</param>
        /// <param name="Address">The first register, as it goes on the wire: 40094 for the meter mode.</param>
        /// <param name="Values">What to write.</param>
        /// <param name="Unit">The unit address.</param>
        /// <param name="CancellationToken">Ends the request.</param>
        /// <exception cref="ModbusException">The meter answered with a Modbus exception: 01 where its role may not write there.</exception>
        public async Task WriteMeterRegisters(String             ConnectionId,
                                              UInt16             Address,
                                              UInt16[]           Values,
                                              Byte               Unit               = 1,
                                              CancellationToken  CancellationToken  = default)
        {

            if (Values.Length == 0)
                throw new ArgumentException("Nothing to write.", nameof(Values));

            var response = await ExchangeWithMeter(
                                     ConnectionId,
                                     Unit,
                                     Values.Length == 1
                                         ? ModbusPDU.BuildWriteSingleRegister   (Address, Values[0])
                                         : ModbusPDU.BuildWriteMultipleRegisters(Address, Values),
                                     CancellationToken
                                 );

            if (ModbusPDU.TryGetException(response) is { } exception)
                throw new ModbusException(exception);

        }

        #endregion


        #region (protected) ConnectOverModbus(Connection, Where, CancellationToken)

        /// <summary>
        /// One connection to an energy meter: who it signs in as, over what, and
        /// whether it got through.
        /// </summary>
        protected async Task ConnectOverModbus(ConnectionEntry    Connection,
                                               String             Where,
                                               CancellationToken  CancellationToken)
        {

            hungUpOnTheMeters = false;

            if (meterLinks.ContainsKey(Connection.Id))
                return;

            try
            {

                var link = Connection.IsSSH
                               ? await MeterLinkOverSSH      (Connection, Where, CancellationToken)
                               : await MeterLinkOverWebSocket(Connection, Where, CancellationToken);

                if (link is null)
                    return;

                if (!meterLinks.TryAdd(Connection.Id, link))
                {
                    await link.LetGo();
                    return;
                }

                Note(Connection, $"Connected to the energy meter over {link.Transport}, speaking Modbus; it is connected again if it drops.");

                _ = FollowMeterLink(Connection.Id, link);

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                Fail(Connection, ConnectionStatus.Trying, $"{Where} could not be reached: {e.Message}; it is tried again by itself.");
                ConnectToTheMeterAgain(Connection.Id);
            }

        }

        #endregion

        #region (private) MeterLinkOverWebSocket(Connection, Where, CancellationToken)

        private async Task<MeterLink?> MeterLinkOverWebSocket(ConnectionEntry    Connection,
                                                              String             Where,
                                                              CancellationToken  CancellationToken)
        {

            if (!WhatItProvesItselfWith(Connection, out var basic, out var totp, out var totpLogin, out var certificates, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            var keyPins     = KeyPinTrustFor(Connection, out var notByKeyPin);

            if (notByKeyPin is not null)
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, notByKeyPin));
                return null;
            }

            var validator   = keyPins is not null
                                  ? keyPins.Validator
                                  : Connection.IsSecure
                                        ? JudgedAsAServer(Connection.Id, Connection.URL)
                                        : null;

            Log.Info($"Connecting to {Where} as an energy meter over Modbus, signing in with {says}.", "modbus", "connections");

            var client      = new StreamWebSocketClient(
                                  Connection.URL,
                                  ModbusWireNames.Subprotocol,
                                  basic,
                                  validator,
                                  CertificateShownAlone  (certificates),
                                  CertificateWithItsChain(certificates),
                                  totp,
                                  totpLogin?.ToString(),
                                  NameResolver
                              );

            var (_, response) = await client.Connect(CancellationToken: CancellationToken);

            if (response.HTTPStatusCode != HTTPStatusCode.SwitchingProtocols)
            {

                var unreached = response.HTTPRequest is null;

                // Turned away for now - a 503 of a door whose connection is
                // switched off, a server not up yet -: tried again then.
                var again     = keyPins?.Refused == true ? null : TurnedAwayForNow(response, MeterConnectAgainAfter);

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
                    ConnectToTheMeterAgain(Connection.Id, again);

                return null;

            }

            if (response.SecWebSocketProtocol is String agreed && agreed != ModbusWireNames.Subprotocol)
            {
                await DisposeQuietly(client);
                Fail(Connection, ConnectionStatus.Refused, $"{Where} agreed on the subprotocol '{agreed}', and not on '{ModbusWireNames.Subprotocol}'; it is not tried again.");
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

            return new MeterLink(
                       Connection,
                       ModbusTCPClient.Over(stream),
                       Connection.IsSecure ? "WebSocket TLS" : "WebSocket",
                       async () => {
                           stream.End();
                           await DisposeQuietly(client);
                       },
                       ended
                   );

        }

        #endregion

        #region (private) MeterLinkOverSSH(Connection, Where, CancellationToken)

        private async Task<MeterLink?> MeterLinkOverSSH(ConnectionEntry    Connection,
                                                        String             Where,
                                                        CancellationToken  CancellationToken)
        {

            var key = await SshKey.MakeIfNeeded(CancellationToken);

            if (!SshLoginOf(Connection, key, out var login, out var trust, out var says, out var wrong))
            {
                Fail(Connection, ConnectionStatus.NotConnected, NotConnectedSaid(Where, wrong));
                return null;
            }

            Log.Info($"Connecting to {Where} as an energy meter over Modbus over SSH, signing in with {says}; {WhatItBelieves(trust)}.", "modbus", "connections", "ssh");

            sshTrusts[Connection.Id] = trust;

            SSHClient? sshClient = null;

            try
            {

                sshClient = await SSHClient.Connect(
                                      Connection.URL.Host.ToString(),
                                      Connection.URL.Port ?? IPPort.SSH,
                                      login with { DNSClient = login.DNSClient ?? NameResolver },
                                      CancellationToken
                                  );

                var channel  = await sshClient.OpenSubsystem(ModbusWireNames.SshSubsystem, CancellationToken);
                var client   = sshClient;

                return new MeterLink(
                           Connection,
                           ModbusTCPClient.Over(channel.AsStream()),
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
                    ConnectToTheMeterAgain(Connection.Id);

                return null;

            }

        }

        #endregion

        #region (private) FollowMeterLink(ConnectionId, Link) / ConnectToTheMeterAgain(ConnectionId)

        /// <summary>
        /// Wait for the given link to end, and connect it again then.
        /// </summary>
        private async Task FollowMeterLink(String     ConnectionId,
                                           MeterLink  Link)
        {

            try
            {
                await Link.Ended;
            }
            catch
            { }

            if (!meterLinks.TryRemove(KeyValuePair.Create(ConnectionId, Link)))
                return;

            await Link.LetGo();
            await DisposeQuietly(Link.Client);

            if (hungUpOnTheMeters)
                return;

            Fail(Link.Connection, ConnectionStatus.Lost, $"The connection to the energy meter '{Link.Connection.Description.FirstText()}' over {Link.Transport} dropped; it is connected again by itself.");

            ConnectToTheMeterAgain(ConnectionId);

        }

        /// <summary>
        /// Connect to the meter of the given connection again after the given
        /// while, or <see cref="MeterConnectAgainAfter"/> - as it is written down
        /// then, if it is written down and switched on still.
        /// </summary>
        private void ConnectToTheMeterAgain(String     ConnectionId,
                                            TimeSpan?  After   = null)

            => _ = Task.Run(async () => {

                       await Task.Delay(After ?? MeterConnectAgainAfter);

                       if (hungUpOnTheMeters || meterLinks.ContainsKey(ConnectionId))
                           return;

                       if (Connections?.Connections.FirstOrDefault(entry => entry.Id == ConnectionId) is ConnectionEntry now &&
                           now.AutoConnect &&
                           now.Use == ConnectionUse.Modbus)
                       {
                           await ConnectOverModbus(now, $"'{now.Description.FirstText()}' ({now.URL})", CancellationToken.None);
                       }

                   });

        #endregion

        #region (protected) HangUpOnTheMeters()

        /// <summary>
        /// Close every connection to a meter, and connect none of them again.
        /// </summary>
        protected async Task HangUpOnTheMeters()
        {

            hungUpOnTheMeters = true;

            foreach (var id in meterLinks.Keys.ToArray())
            {
                if (meterLinks.TryRemove(id, out var link))
                {
                    await link.LetGo();
                    await DisposeQuietly(link.Client);
                }
            }

        }

        #endregion

        #region (private static) DisposeQuietly(Disposable)

        private static async Task DisposeQuietly(IAsyncDisposable Disposable)
        {
            try
            {
                await Disposable.DisposeAsync();
            }
            catch
            { }
        }

        #endregion

    }

}
