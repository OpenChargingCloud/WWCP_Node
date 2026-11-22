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

using cloud.charging.open.protocols.WWCP.SSH;
using cloud.charging.open.protocols.WWCP.NetworkingNode;

using cloud.charging.open.protocols.WWCP.Node.Connections;
using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The back ends this station is connected to, peer by peer: one endpoint of
    /// each at a time, the next one when that one cannot be reached, and what
    /// is written down taken as it changes (work packages P7 and P8 of EVQI
    /// Transport, sections 11.3.2 and 11.7.1).
    /// </summary>
    /// <remarks>
    /// A peer that connects by itself is connected to at the first of its endpoints
    /// that does; the others wait in reserve. Its attempts are counted, and
    /// after <see cref="NetworkProfileConnectionAttempts"/> of them that failed
    /// - or at once where the answer is final, a password refused, an address
    /// that leads nowhere - that endpoint is hung up and the next one connected to,
    /// round and round, with a pause after every round that reached none. A
    /// peer of one endpoint goes on trying it as before.
    ///
    /// A change of what is written down is taken at once: a peer that connects by
    /// itself now is connected to, one that does not any more, or an endpoint taken
    /// away, is hung up, and one changed in how it is connected to is connected to again.
    /// A description written anew or a host key learned changes nothing that
    /// is up.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What is connected to of each peer that connects by itself: one endpoint.
        /// </summary>
        protected sealed class LiveEndpoint
        {

            public required String           PeerId       { get; init; }

            /// <summary>
            /// The connection as it was when it was made: the store changes
            /// its entries where they are, and what is up is what was connected to.
            /// </summary>
            public required ConnectionEntry  Connection      { get; init; }

            public required Int64            Revision     { get; init; }
            public required Boolean          Primary      { get; init; }

            /// <summary>
            /// What the node said the connection was connected on when it was
            /// made, beyond what is written of it - see WhatItIsConnectedOn.
            /// </summary>
            public String?                   ConnectedOn    { get; init; }
            public required Int32            Index        { get; init; }

            /// <summary>
            /// The endpoint the round of tries started at that this one belongs
            /// to: back at it, a round is over.
            /// </summary>
            public required Int32            RoundStart   { get; set; }

            /// <summary>
            /// The attempts made at it since it was last up, the first one
            /// included.
            /// </summary>
            public Int32                     Attempts     { get; set; }

            public Object?                   Client       { get; set; }

            public Boolean                   LetGo        { get; set; }

            /// <summary>
            /// Connected because somebody asked for it - see ConnectOnDemand - and
            /// not because it connects by itself: it stays at this endpoint, and
            /// is hung up when asked to, or when it is changed or taken away.
            /// </summary>
            public Boolean                   OnDemand     { get; init; }

            public CancellationTokenSource   Pause        { get; } = new ();

        }

        protected readonly Dictionary<String, LiveEndpoint>  livePeers  = [];
        protected readonly SemaphoreSlim                      liveLock   = new (1, 1);

        /// <summary>
        /// Whether the peers were connected to since this station started or last
        /// hung up: a change written down before is left to that connecting,
        /// which takes it anyway.
        /// </summary>
        protected Boolean                                     peersConnected;

        /// <summary>
        /// How many attempts at an endpoint fail before the next endpoint of
        /// its peer is connected to: OCPPCommCtrlr.NetworkProfileConnectionAttempts,
        /// fixed at 3 until it is read and written for real (P14).
        /// </summary>
        public Int32 NetworkProfileConnectionAttempts { get; set; } = 3;

        /// <summary>
        /// How long a peer waits after a round of all its endpoints reached
        /// none, before the first of them is connected to again.
        /// </summary>
        public TimeSpan FailoverPause { get; set; } = TimeSpan.FromSeconds(30);

        #endregion


        #region (private) ConnectToPeers(CancellationToken)

        /// <summary>
        /// Connect to every peer that connects by itself, at its first endpoint that
        /// does - each on its own, in the order they were first connected to, and
        /// none of them affected by how another went.
        /// </summary>
        protected async Task ConnectToPeers(CancellationToken CancellationToken = default)
        {

            var connections  = Connections.Connections.ToDictionary(entry => entry.Id);
            var peers        = Connections.Peers.
                                   Where  (peer => peer.Role != PeerRole.Service).
                                   OrderBy(peer => FirstConnectedAt(peer, connections)).
                                   ToArray();

            lock (connectionStates)
                connectionStates.Clear();

            await liveLock.WaitAsync(CancellationToken);

            try
            {

                // What was connected on demand is connected again as well: connecting
                // everything anew - the OCPP nodes replaced - is not somebody
                // asking for it to be hung up.
                String[] onDemand;

                lock (livePeers)
                {
                    onDemand = [.. livePeers.Values.Where(live => live.OnDemand && !live.LetGo).Select(live => live.Connection.Id)];
                    foreach (var live in livePeers.Values)
                        live.Pause.Cancel();
                    livePeers.Clear();
                }

                peersConnected = true;

                if (peers.Length == 0 && onDemand.Length == 0)
                {
                    Log.Info(connections.Count == 0
                                 ? $"No connections are configured; this {NodeNoun} connects nowhere."
                                 : $"None of the {connections.Count} configured connection(s) is set to connect by itself.",
                             "ocpp", "connections");
                    return;
                }

                foreach (var peer in peers)
                    await ConnectToPeer(peer, StartOf(peer, connections), null, CancellationToken);

                foreach (var id in onDemand)
                    await ConnectOnDemandUnlocked(id, CancellationToken);

            }
            finally
            {
                liveLock.Release();
            }

        }

        #endregion

        #region (private) ConnectToPeer(Peer, Index, RoundStart, CancellationToken, Left = null)

        /// <summary>
        /// Connect to the given endpoint of a peer, and say of its others that they
        /// wait in reserve - but the one it goes on from, which was said of
        /// already. Called under the live lock.
        /// </summary>
        protected async Task ConnectToPeer(PeerEntry          Peer,
                                    Int32              Index,
                                    Int32?             RoundStart,
                                    CancellationToken  CancellationToken,
                                    String?            Left       = null,
                                    Boolean            OnDemand   = false)
        {

            var connections = Connections.Connections.ToDictionary(entry => entry.Id);

            if (Index < 0 || Index >= Peer.EndpointIds.Count ||
                !connections.TryGetValue(Peer.EndpointIds[Index], out var entry))
                return;

            var connectedAs = entry.Copy();

            var live = new LiveEndpoint {
                           PeerId      = Peer.Id,
                           Connection     = connectedAs,
                           Revision    = Connections.ConnectionRevisionOf(entry.Id),
                           Primary     = IsPrimary(connectedAs),
                           ConnectedOn   = WhatItIsConnectedOn(connectedAs),
                           Index       = Index,
                           RoundStart  = RoundStart ?? Index,
                           Attempts    = 1,
                           OnDemand    = OnDemand
                       };

            lock (livePeers)
                livePeers[Peer.Id] = live;

            // The endpoint left behind was said of already, and why.
            foreach (var other in Peer.EndpointIds.Where(id => id != entry.Id && id != Left))
                if (connections.TryGetValue(other, out var reserve) && reserve.AutoConnect)
                    Record(reserve, ConnectionStatus.Standby,
                           $"In reserve: '{entry.Description.FirstText()}' is connected to for '{Peer.Description.FirstText()}', and this endpoint " +
                           "when that one cannot be reached.");

            await ConnectTo(connectedAs, CancellationToken);

        }

        #endregion

        #region (private) RememberClient(Connection, Client)

        /// <summary>
        /// The client that was made for the given connection when it was
        /// made: what is hung up when its peer goes on to another endpoint,
        /// or when it changes.
        /// </summary>
        protected void RememberClient(ConnectionEntry Connection, Object? Client)
        {
            if (Client is not null && LiveOf(Connection) is LiveEndpoint live)
                live.Client = Client;
        }

        #endregion

        #region (private) EndpointStatus(Connection, Status) / EndpointRetries(Connection)

        /// <summary>
        /// What became of an attempt at the endpoint a peer is connected to at: one
        /// that got through starts the count anew, one that cannot be tried
        /// again goes on to the next endpoint, and so does one the client tries
        /// again where that would be one too many.
        /// </summary>
        protected void EndpointStatus(ConnectionEntry Connection, ConnectionStatus Status)
        {

            if (LiveOf(Connection) is not LiveEndpoint live)
                return;

            switch (Status)
            {

                // Up, or up until a moment ago: what was tried before does not
                // count, and a round of tries starts here.
                case ConnectionStatus.Connected:
                case ConnectionStatus.Lost:
                    live.Attempts    = 0;
                    live.RoundStart  = live.Index;
                    break;

                case ConnectionStatus.Refused:
                case ConnectionStatus.Failed:
                case ConnectionStatus.NotConnected:
                    FailOver(live, "it cannot be tried again");
                    break;

                case ConnectionStatus.Trying:
                    if (live.Attempts >= NetworkProfileConnectionAttempts)
                        FailOver(live, $"{live.Attempts} attempt(s) failed");
                    break;

            }

        }

        /// <summary>
        /// The client is about to try the endpoint a peer is connected to at again.
        /// </summary>
        protected void EndpointRetries(ConnectionEntry Connection)
        {

            if (LiveOf(Connection) is not LiveEndpoint live)
                return;

            live.Attempts++;

            if (live.Attempts > NetworkProfileConnectionAttempts)
                FailOver(live, $"{live.Attempts - 1} attempt(s) failed");

        }

        protected LiveEndpoint? LiveOf(ConnectionEntry Connection)
        {
            lock (livePeers)
                return livePeers.Values.FirstOrDefault(live => !live.LetGo && live.Connection.Id == Connection.Id);
        }

        #endregion

        #region (private) FailOver(Live, Why)

        /// <summary>
        /// Hang up the endpoint a peer is connected to at, and connect to its next one -
        /// after a pause, where that one began the round. A peer of one
        /// endpoint goes on as it is.
        /// </summary>
        protected void FailOver(LiveEndpoint Live, String Why)
        {

            // Asked for at this endpoint, and at no other: its client goes on
            // trying it, as it would on its own.
            if (Live.OnDemand)
                return;

            var peer = Connections.Peers.FirstOrDefault(peer => peer.Id == Live.PeerId);

            if (peer is null)
                return;

            var connections  = Connections.Connections.ToDictionary(entry => entry.Id);
            var next         = NextConnectable(peer, Live.Index, connections);

            if (next is null || next == Live.Index)
                return;

            lock (livePeers)
            {
                if (Live.LetGo)
                    return;
                Live.LetGo = true;
            }

            // Out of the client's event, which this is called from, and after
            // whatever the live lock is held for now.
            _ = Task.Run(async () => {

                await liveLock.WaitAsync();

                try
                {

                    lock (livePeers)
                        if (!livePeers.TryGetValue(Live.PeerId, out var current) || current != Live)
                            return;

                    var nextName = connections.TryGetValue(peer.EndpointIds[next.Value], out var nextEntry)
                                       ? nextEntry.Description.FirstText()
                                       : peer.EndpointIds[next.Value];

                    Log.Notice($"'{Live.Connection.Description.FirstText()}' of '{peer.Description.FirstText()}' could not be reached - {Why}; '{nextName}' is connected to instead.",
                               "ocpp", "connections");

                    await HangUpEndpoint(Live, $"Failing over: {Why}.");

                    Record(Live.Connection, ConnectionStatus.Standby,
                           $"In reserve: it could not be reached ({Why}), so '{nextName}' is connected to for '{peer.Description.FirstText()}', " +
                           "and this endpoint again when that one cannot be reached either.");

                    if (next == Live.RoundStart)
                    {

                        Log.Notice($"None of the endpoints of '{peer.Description.FirstText()}' could be reached; they are tried again in " +
                                   $"{FailoverPause.TotalSeconds:0} s.", "ocpp", "connections");

                        liveLock.Release();

                        try
                        {
                            await Task.Delay(FailoverPause, Live.Pause.Token);
                        }
                        catch (OperationCanceledException)
                        {
                            await liveLock.WaitAsync();
                            return;
                        }

                        await liveLock.WaitAsync();

                        lock (livePeers)
                            if (!livePeers.TryGetValue(Live.PeerId, out var still) || still != Live)
                                return;

                    }

                    var now = Connections.Peers.FirstOrDefault(one => one.Id == Live.PeerId);

                    if (now is not null && now.Role != PeerRole.Service)
                        await ConnectToPeer(now, next.Value, next == Live.RoundStart ? null : Live.RoundStart, default, Live.Connection.Id);

                }
                catch (Exception e)
                {
                    Log.Warning($"Going on to the next endpoint of '{peer.Description.FirstText()}' failed: {e.Message}", "ocpp", "connections");
                }
                finally
                {
                    liveLock.Release();
                }

            });

        }

        #endregion

        #region (private) ApplyConnectionChanges()

        /// <summary>
        /// Take what is written down now: connect to a peer that connects by itself and
        /// is not connected to, hang up what is connected to and should not be, and connect
        /// again to an endpoint that was changed in how it is connected to.
        /// </summary>
        /// <remarks>
        /// Told by the store after every change it wrote; nothing here before
        /// this station was started. One at a time, and the last change taken
        /// is the one written last, as each looks at the store afresh.
        /// </remarks>
        protected async Task ApplyConnectionChanges()
        {

            if (!started || !peersConnected)
                return;

            await liveLock.WaitAsync();

            try
            {

                var connections  = Connections.Connections.ToDictionary(entry => entry.Id);
                var peers        = Connections.Peers.ToDictionary(peer => peer.Id);

                LiveEndpoint[] lives;

                lock (livePeers)
                    lives = [.. livePeers.Values];

                var connectAgain          = new Dictionary<String, Int32>();
                var connectAgainOnDemand  = new List<String>();
                var hungUp             = new HashSet<String>();

                foreach (var live in lives)
                {

                    peers.      TryGetValue(live.PeerId,     out var peer);
                    connections.TryGetValue(live.Connection.Id, out var entry);

                    String? why = null;

                    // Connected on demand, it is not hung up for not connecting by
                    // itself: it never did.
                    if (peer is null || (peer.Role == PeerRole.Service && !live.OnDemand))
                        why = $"'{live.Connection.Description.FirstText()}' is no longer connected to by itself";

                    else if (entry is null || !peer.EndpointIds.Contains(entry.Id))
                        why = $"'{live.Connection.Description.FirstText()}' is no longer an endpoint of '{peer.Description.FirstText()}'";

                    else if (Connections.ConnectionRevisionOf(entry.Id) != live.Revision)
                        why = $"'{entry.Description.FirstText()}' was changed";

                    else if (IsPrimary(entry) != live.Primary)
                        why = $"which back end is in charge of OCPP {ConnectionEntry.AsText(entry.OCPPVersion)} changed";

                    else if (WhatItIsConnectedOn(entry) != live.ConnectedOn)
                        why = $"what '{entry.Description.FirstText()}' is connected on changed";

                    if (why is null)
                        continue;

                    // The same endpoint again, where it still connects by itself;
                    // where not, its peer is connected to where it starts.
                    if (peer is not null && peer.Role != PeerRole.Service && entry is not null && entry.AutoConnect &&
                        peer.EndpointIds.Contains(entry.Id))
                        connectAgain[peer.Id] = peer.EndpointIds.ToList().IndexOf(entry.Id);

                    // Connected on demand and changed, it is connected again on
                    // demand, as it is now; taken away, or no longer an
                    // endpoint of its peer, it is not.
                    else if (live.OnDemand && peer is not null && entry is not null && !entry.Inbound &&
                             peer.EndpointIds.Contains(entry.Id))
                        connectAgainOnDemand.Add(entry.Id);

                    hungUp.Add(live.Connection.Id);

                    lock (livePeers)
                    {
                        live.LetGo = true;
                        live.Pause.Cancel();
                        livePeers.Remove(live.PeerId);
                    }

                    Log.Notice($"{why}: it is hung up{(connectAgain.ContainsKey(live.PeerId) || connectAgainOnDemand.Contains(live.Connection.Id) ? " and connected again" : "")}.", "ocpp", "connections");

                    await HangUpEndpoint(live, $"{why}.");

                }

                // Lines of what is not connected to any more, nor waits in reserve,
                // and of what was hung up: what it is now is said below.
                HashSet<String> stillLive;

                lock (livePeers)
                    stillLive = [.. livePeers.Values.Select(live => live.Connection.Id)];

                lock (connectionStates)
                    foreach (var id in connectionStates.Keys.ToArray())
                        if (hungUp.Contains(id) ||
                            !connections.TryGetValue(id, out var entry) ||
                            (!entry.AutoConnect && !stillLive.Contains(id)) ||
                            Connections.PeerOf(id) is not PeerEntry owner ||
                            (owner.Role == PeerRole.Service && !stillLive.Contains(id)))
                            connectionStates.Remove(id);

                foreach (var id in connectAgainOnDemand)
                    await ConnectOnDemandUnlocked(id, default);

                foreach (var peer in peers.Values.
                                         Where  (peer => peer.Role != PeerRole.Service).
                                         OrderBy(peer => FirstConnectedAt(peer, connections)))
                {

                    Boolean isLive;

                    lock (livePeers)
                        isLive = livePeers.ContainsKey(peer.Id);

                    if (isLive)
                    {

                        // An endpoint added to a peer that is up waits in reserve.
                        LiveEndpoint live;

                        lock (livePeers)
                            live = livePeers[peer.Id];

                        foreach (var id in peer.EndpointIds.Where(id => id != live.Connection.Id))
                            lock (connectionStates)
                                if (!connectionStates.ContainsKey(id) && connections.TryGetValue(id, out var reserve) && reserve.AutoConnect)
                                    connectionStates[id] = new ConnectionState(ConnectionStatus.Standby,
                                                                      TimeProvider.GetUtcNow(),
                                                                      $"In reserve: '{live.Connection.Description.FirstText()}' is connected to for '{peer.Description.FirstText()}', " +
                                                                       "and this endpoint when that one cannot be reached.",
                                                                      reserve.Description,
                                                                      reserve.URL,
                                                                      reserve.OCPPVersion);

                        continue;

                    }

                    var index = connectAgain.TryGetValue(peer.Id, out var again) && again >= 0
                                    ? again
                                    : StartOf(peer, connections);

                    Log.Info($"'{peer.Description.FirstText()}' is connected to{(connectAgain.ContainsKey(peer.Id) ? " again" : "")}, as written down now.", "ocpp", "connections");

                    await ConnectToPeer(peer, index, null, default);

                }

            }
            catch (Exception e)
            {
                Log.Warning($"Taking the changed connections failed: {e.Message}", "ocpp", "connections");
            }
            finally
            {
                liveLock.Release();
            }

        }

        #endregion

        #region (private) HangUpEndpoint(Live, Reason) / EndRegistrationOf(Connection)

        /// <summary>
        /// Close the connection a peer is connected to at, so that it does not come
        /// back by itself, have the node forget its client, and end what it
        /// was registered as.
        /// </summary>
        protected async Task HangUpEndpoint(LiveEndpoint Live, String Reason)
        {

            try
            {

                switch (Live.Client ?? ClientOf(Live.Connection))
                {

                    case WWCPSshClient sshClient:
                        await LetGo(sshClient, Reason);
                        break;

                    case Object client:
                        await Disconnect(client, Reason);
                        break;

                }

            }
            catch (Exception e)
            {
                Log.Debug($"The connection to {Live.Connection.URL} did not close cleanly: {e.Message}", "ocpp", "connections");
            }

            EndRegistrationOf(Live.Connection);

        }

        /// <summary>
        /// Nothing more is asked of the back end over the given connection, nor
        /// waited for: no BootNotification, no heartbeat.
        /// </summary>
        protected virtual void EndRegistrationOf(ConnectionEntry Connection)
        { }

        #endregion

        #region (private static) StartOf(Peer, Connections) / FirstConnectedAt(Peer, Connections)

        /// <summary>
        /// The endpoint a peer is connected to at first: the first of them that connects
        /// by itself.
        /// </summary>
        protected static Int32 StartOf(PeerEntry Peer, IReadOnlyDictionary<String, ConnectionEntry> Connections)
        {

            for (var i = 0; i < Peer.EndpointIds.Count; i++)
                if (Connections.TryGetValue(Peer.EndpointIds[i], out var entry) && entry.AutoConnect)
                    return i;

            return 0;

        }

        /// <summary>
        /// The endpoint of a peer that is connected to after the given one: the
        /// next one that connects by itself, round and round; null where none
        /// does.
        /// </summary>
        protected static Int32? NextConnectable(PeerEntry Peer, Int32 After, IReadOnlyDictionary<String, ConnectionEntry> Connections)
        {

            for (var step = 1; step <= Peer.EndpointIds.Count; step++)
            {
                var index = (After + step) % Peer.EndpointIds.Count;
                if (Connections.TryGetValue(Peer.EndpointIds[index], out var entry) && entry.AutoConnect)
                    return index;
            }

            return null;

        }

        protected static DateTimeOffset FirstConnectedAt(PeerEntry Peer, IReadOnlyDictionary<String, ConnectionEntry> Connections)

            => Peer.EndpointIds.
                   Select(id => Connections.TryGetValue(id, out var entry) && entry.AutoConnect ? entry.CreatedAt : DateTimeOffset.MaxValue).
                   DefaultIfEmpty(DateTimeOffset.MaxValue).
                   Min();

        #endregion

        #region ConnectOnDemand  (ConnectionId, CancellationToken)

        /// <summary>
        /// Connect the given connection because somebody asks for it: one that is
        /// not connected by itself - a service, a back end kept ready for the day
        /// somebody needs it - or one whose peer is not connected to at all.
        /// </summary>
        /// <remarks>
        /// Connected as a connection that connects by itself is, and then kept up
        /// as one: its client tries it again when it drops. It stays at this
        /// endpoint - nothing fails over to another one of its peer - until
        /// <see cref="HangUpOnDemand"/> hangs it up, it is taken away, or it is
        /// no longer an endpoint of its peer. Changed, it is connected again as
        /// it is then; whether it connects by itself is not changed.
        ///
        /// Not where the peer is connected to at another endpoint already: a peer is
        /// connected to at one endpoint at a time. A connection that is connected
        /// already is not connected twice, and is no refusal.
        ///
        /// What becomes of the call - connected, refused, not reached - is
        /// said in <see cref="ConnectionStates"/>, as of every other one: this
        /// says whether it was connected.
        /// </remarks>
        /// <param name="ConnectionId">The connection, by its identification.</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        /// <returns>Null where it was connected, or is already; why not otherwise.</returns>
        public async Task<String?> ConnectOnDemand(String             ConnectionId,
                                                CancellationToken  CancellationToken   = default)
        {

            if (!started || !peersConnected)
                return $"This {NodeNoun} does not connect yet: it connects once it is started.";

            await liveLock.WaitAsync(CancellationToken);

            try
            {
                return await ConnectOnDemandUnlocked(ConnectionId, CancellationToken);
            }
            finally
            {
                liveLock.Release();
            }

        }

        /// <summary>
        /// Connect the given connection on demand. Called under the live lock.
        /// </summary>
        private async Task<String?> ConnectOnDemandUnlocked(String             ConnectionId,
                                                         CancellationToken  CancellationToken)
        {

            var entry = Connections.Connections.FirstOrDefault(connection => connection.Id == ConnectionId);

            if (entry is null)
                return "There is no connection here under that identification.";

            if (entry.Inbound)
                return $"'{entry.Description.FirstText()}' is one the other end makes: there is nothing to connect to, and it is waited for.";

            if (Connections.PeerOf(entry.Id) is not PeerEntry peer)
                return $"'{entry.Description.FirstText()}' is an endpoint of no peer, and what is connected to is a peer at one of its endpoints.";

            LiveEndpoint? live;

            lock (livePeers)
                livePeers.TryGetValue(peer.Id, out live);

            if (live is not null && !live.LetGo)
            {

                if (live.Connection.Id == entry.Id)
                    return null;

                return $"'{peer.Description.FirstText()}' is connected to at '{live.Connection.Description.FirstText()}' already, and a peer is connected to at one endpoint " +
                       (live.OnDemand
                            ? "at a time: hang that one up first."
                            : "at a time - that one by itself.");

            }

            Log.Info($"'{entry.Description.FirstText()}' of '{peer.Description.FirstText()}' is connected on demand.", "ocpp", "connections");

            await ConnectToPeer(peer, peer.EndpointIds.ToList().IndexOf(entry.Id), null, CancellationToken, OnDemand: true);

            return null;

        }

        #endregion

        #region HangUpOnDemand(ConnectionId)

        /// <summary>
        /// Hang up the given connection, which was connected on demand - see
        /// <see cref="ConnectOnDemand"/> - so that it does not come back by
        /// itself.
        /// </summary>
        /// <remarks>
        /// Not one that connects by itself: that is hung up by switching it off,
        /// which is written down, rather than by a word that the next start
        /// forgets.
        /// </remarks>
        /// <param name="ConnectionId">The connection, by its identification.</param>
        /// <returns>Null where it was hung up; why not otherwise.</returns>
        public async Task<String?> HangUpOnDemand(String ConnectionId)
        {

            await liveLock.WaitAsync();

            try
            {

                LiveEndpoint? live;

                lock (livePeers)
                    live = livePeers.Values.FirstOrDefault(one => !one.LetGo && one.Connection.Id == ConnectionId);

                var description = live?.Connection.Description ??
                                  Connections.Connections.FirstOrDefault(connection => connection.Id == ConnectionId)?.Description;

                if (live is null)
                    return description is null
                               ? "There is no connection here under that identification."
                               : $"'{description}' is not connected.";

                if (!live.OnDemand)
                    return $"'{description}' is connected by itself: it is hung up by switching that off.";

                lock (livePeers)
                {
                    live.LetGo = true;
                    live.Pause.Cancel();
                    livePeers.Remove(live.PeerId);
                }

                Log.Info($"'{description}' is hung up on demand.", "ocpp", "connections");

                await HangUpEndpoint(live, "Hung up on demand.");

                // Not connected any more, as it was not before it was asked for.
                lock (connectionStates)
                    connectionStates.Remove(ConnectionId);

                return null;

            }
            finally
            {
                liveLock.Release();
            }

        }

        #endregion

        #region IsConnectedOnDemand(ConnectionId)

        /// <summary>
        /// Whether the given connection is connected because somebody asked for
        /// it - see <see cref="ConnectOnDemand"/>.
        /// </summary>
        /// <param name="ConnectionId">The connection, by its identification.</param>
        public Boolean IsConnectedOnDemand(String ConnectionId)
        {
            lock (livePeers)
                return livePeers.Values.Any(live => live.OnDemand && !live.LetGo && live.Connection.Id == ConnectionId);
        }

        #endregion

        #region (private) LetGoOfPeers()

        /// <summary>
        /// Forget what is connected to of the peers, for a station that hangs up.
        /// </summary>
        protected void LetGoOfPeers()
        {
            lock (livePeers)
            {
                peersConnected = false;
                foreach (var live in livePeers.Values)
                {
                    live.LetGo = true;
                    live.Pause.Cancel();
                }
                livePeers.Clear();
            }
        }

        #endregion

    }

}
