/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP_Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using System.Text;
using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.protocols.WWCP.WebSockets;
using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The connections the other end makes: a CSMS or a local controller that
    /// dials this node, on an OCPP server of its own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OCPP as it always is, with who opens the WebSocket the other way round.
    /// What dials in is written down as a connection (<see
    /// cref="ConnectionEntry.Inbound"/>), and from the moment it is in it is
    /// one: routed under a name of its own, the primary under the name of the
    /// CSMS as well, told that this node started, sent what waits - by the
    /// same code that does all of that for a connection this node dialled.
    /// </para>
    /// <para>
    /// Nothing gets in that is not written down. Who signs in is decided at
    /// the door of the kind of node - its station port, where whoever comes
    /// signs in with a WebSocket login: a back end with the login of the name
    /// its connection comes under, which the connection names nothing beside.
    /// The kind marks what it let in that way with <see cref="LetInAsInbound"/>,
    /// and asks <see cref="InboundConnectionOf"/> whose a name is.
    /// </para>
    /// <para>
    /// A kind of node hands its servers over with <see cref="ServeInbound"/>.
    /// What is let in over them as a connection written down here is the line
    /// up of the kind, not one of the others it lets in: <see cref="IsInbound"/>.
    /// Whether its login lets it in at all, and why it can not sign in, is the
    /// kind's to say - see <see cref="InboundLoginLetsIn"/> and
    /// <see cref="WhyInboundCanNotSignIn"/>.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// The OCPP servers of this node, by the version they speak.
        /// </summary>
        private readonly ConcurrentDictionary<OCPPVersion, WWCPWebSocketServer>       inboundServers      = new ();

        /// <summary>
        /// The connection each inbound connection is in over now, by the id of
        /// its entry: what tells the close of that one from the close of one
        /// it replaced.
        /// </summary>
        private readonly ConcurrentDictionary<String, WebSocketServerConnection>      inboundConnections  = new ();

        /// <summary>
        /// The inbound connections reached under the name of the CSMS as well,
        /// by the id of their entry: what is taken away again when they go.
        /// </summary>
        private readonly ConcurrentDictionary<String, NetworkingNode_Id[]>            inboundCSMSNames    = new ();

        /// <summary>
        /// The servers whose events are followed already, by the version they
        /// are followed for: a server served again - stopped and started, as a
        /// kind does that keeps one server - is not followed twice.
        /// </summary>
        private readonly List<(OCPPVersion Version, WWCPWebSocketServer Server)>      inboundServersWired   = [];

        private          Int32                                                        followsInboundChanges;

        /// <summary>
        /// What a connection carries that was let in as an inbound connection:
        /// the id of its entry.
        /// </summary>
        public const     String                                                       InboundConnectionKey  = "inboundConnection";

        #endregion

        #region InboundServed(Version)

        /// <summary>
        /// Whether this node serves the given version of OCPP to whoever dials
        /// it.
        /// </summary>
        public Boolean InboundServed(OCPPVersion Version)
            => inboundServers.ContainsKey(Version);

        #endregion

        #region (protected) ServeInbound(Version, Server) / StopServingInbound(Version)

        /// <summary>
        /// Let in over the given server what is written down as an inbound
        /// connection of the given version of OCPP. The server is attached to
        /// the node of that version, and the kind decides at its own door who
        /// signs in - by the WebSocket login of the name it comes under - and
        /// marks what it let in as such a connection with
        /// <see cref="LetInAsInbound"/>: only that is a connection of this node.
        /// </summary>
        /// <param name="Version">The version of OCPP the server speaks.</param>
        /// <param name="Server">The server, attached to the node of that version.</param>
        protected void ServeInbound(OCPPVersion          Version,
                                    WWCPWebSocketServer  Server)
        {

            inboundServers[Version] = Server;

            lock (inboundServersWired)
            {

                if (inboundServersWired.Any(wired => wired.Version == Version && ReferenceEquals(wired.Server, Server)))
                {
                    FollowInboundConnections();
                    return;
                }

                inboundServersWired.Add((Version, Server));

            }

            // Routed under its own names before the 101 goes out, as the node
            // routes the name it came under: what is said to it right after it
            // connected finds it.
            Server.OnNetworkingNodeWebSocketConnectionAccepted += (timestamp, server, connection, networkingNodeId, networkingMode, sharedSubprotocols, eventTrackingId, cancellationToken) => {

                if (ReferenceEquals(inboundServers.GetValueOrDefault(Version), Server) &&
                    WasLetInAsInbound(Version, connection) &&
                    InboundOf(Version, networkingNodeId.ToString()) is ConnectionEntry entry)
                {
                    RouteInbound(entry, networkingNodeId, connection);
                }

                return Task.CompletedTask;

            };

            // In: said, and then what is said to every connection that is up.
            Server.OnNetworkingNodeNewWebSocketConnection += (timestamp, server, connection, networkingNodeId, networkingMode, sharedSubprotocols, eventTrackingId, cancellationToken) => {

                if (!ReferenceEquals(inboundServers.GetValueOrDefault(Version), Server))
                    return Task.CompletedTask;

                // One of the others the kind lets in: the kind's, not this node's.
                if (!WasLetInAsInbound(Version, connection))
                    return Task.CompletedTask;

                if (InboundOf(Version, networkingNodeId.ToString()) is not ConnectionEntry entry)
                {

                    // Let in by credentials that are no longer anybody's: taken
                    // away between its handshake and now.
                    Log.Warning($"'{networkingNodeId}' dialled in from {connection.RemoteSocket} and is no inbound connection of this {NodeNoun} any more: it is let go of.",
                                "ocpp", "connections", "inbound");

                    _ = connection.Close(WebSocketFrame.ClosingStatusCode.PolicyViolation, "Not a connection of this node");

                    return Task.CompletedTask;

                }

                Note(entry, $"'{networkingNodeId}' dialled in from {connection.RemoteSocket}" +
                            (connection.Subprotocol is String subprotocol ? $" ({subprotocol})" : "") +
                            ", and is let in again whenever it dials.");

                ConnectionIsUp(entry);

                return Task.CompletedTask;

            };

            Server.OnNetworkingNodeCloseMessageReceived += (timestamp, server, connection, networkingNodeId, eventTrackingId, statusCode, reason, cancellationToken) => {

                InboundIsDown(Version, networkingNodeId, connection,
                              $"{(UInt16) statusCode} {statusCode}{(String.IsNullOrWhiteSpace(reason) ? "" : $": {reason}")}");

                return Task.CompletedTask;

            };

            Server.OnNetworkingNodeTCPConnectionClosed += (timestamp, server, connection, networkingNodeId, eventTrackingId, reason, cancellationToken) => {

                InboundIsDown(Version, networkingNodeId, connection,
                              String.IsNullOrWhiteSpace(reason) ? "its connection ended" : reason);

                return Task.CompletedTask;

            };

            if (Interlocked.Exchange(ref followsInboundChanges, 1) == 0)
                Connections.OnConnectionsChanged += FollowInboundConnections;

            FollowInboundConnections();

        }

        /// <summary>
        /// Let nothing in any more for the given version of OCPP: whoever is
        /// in is let go of, and the server is the kind's to stop.
        /// </summary>
        /// <param name="Version">The version of OCPP.</param>
        /// <param name="Why">Why, as the other end is told.</param>
        protected void StopServingInbound(OCPPVersion  Version,
                                          String       Why)
        {

            if (!inboundServers.TryRemove(Version, out var server))
                return;

            foreach (var entry in Connections.Connections.Where(entry => entry.Inbound && entry.OCPPVersion == Version))
            {

                if (inboundConnections.TryRemove(entry.Id, out var connection))
                {
                    UnrouteInbound(entry, server, connection);
                    _ = connection.Close(WebSocketFrame.ClosingStatusCode.GoingAway, Why);
                }

                WaitFor(entry);

            }

        }

        #endregion

        #region (protected) InboundConnectionOf(Version, Name) / LetInAsInbound(Connection, Entry) / IsInbound(Connection)

        /// <summary>
        /// The connection the other end makes of the given version of OCPP that
        /// comes under the given name - switched on or not -, or null: then
        /// whoever comes under that name is no back end of this node.
        /// </summary>
        /// <remarks>
        /// The name decides whose it is, before anything it signs in with is
        /// looked at: what comes under the name of a connection written down
        /// here is let in as that or not at all, whatever else the kind would
        /// have taken it for.
        /// </remarks>
        /// <param name="Version">The version of OCPP of the server it came to.</param>
        /// <param name="Name">The name it came under: the last segment of the path it asked for.</param>
        protected ConnectionEntry? InboundConnectionOf(OCPPVersion  Version,
                                                       String       Name)

            => Connections.Connections.FirstOrDefault(entry => entry.Inbound &&
                                                               entry.OCPPVersion == Version &&
                                                               entry.InboundName == Name);

        /// <summary>
        /// Take what came in over the given WebSocket as the given connection
        /// the other end makes: the kind let it in at its door, by the
        /// WebSocket login of the name it came under.
        /// </summary>
        /// <param name="Connection">The WebSocket, before its 101 goes out.</param>
        /// <param name="Entry">The connection the other end makes it came under.</param>
        protected static void LetInAsInbound(WebSocketServerConnection  Connection,
                                             ConnectionEntry            Entry)

            => Connection.TryAddCustomData(InboundConnectionKey, Entry.Id);

        /// <summary>
        /// Whether the WebSocket login an inbound connection comes under lets
        /// anything in at all - there is one, and it is switched on. Yes,
        /// unless the kind says otherwise: a connection whose login says no is
        /// let go of where it is in.
        /// </summary>
        /// <param name="Connection">An inbound connection that is switched on.</param>
        protected virtual Boolean InboundLoginLetsIn(ConnectionEntry Connection)
            => true;

        /// <summary>
        /// Why the other end of an inbound connection can not sign in at the
        /// given server, as its WebSocket login and the server are now - or
        /// null. Nothing, unless the kind says something.
        /// </summary>
        /// <param name="Connection">An inbound connection that is switched on.</param>
        /// <param name="Server">The server of its version of OCPP.</param>
        protected virtual String? WhyInboundCanNotSignIn(ConnectionEntry      Connection,
                                                         WWCPWebSocketServer  Server)
            => null;

        /// <summary>
        /// Whether the given connection is one somebody dialled who is written
        /// down as a connection of this node - its CSMS, the controller above
        /// it - and so a line up of this node, although this node accepted it.
        /// </summary>
        /// <param name="Connection">A connection something came over.</param>
        protected Boolean IsInbound(IMessageConnection? Connection)

            => Connection is WebSocketServerConnection webSocketConnection &&
               inboundConnections.Values.Any(itsConnection => ReferenceEquals(itsConnection, webSocketConnection));

        /// <summary>
        /// Whether what is sent to the given name goes over a connection
        /// somebody dialled who is written down as a connection of this node:
        /// the name it came under, the one of its own every connection has,
        /// or the CSMS's where it is the primary.
        /// </summary>
        /// <param name="Name">A name something is sent to.</param>
        protected Boolean LeadsToInbound(NetworkingNode_Id Name)
        {

            foreach (var id in inboundConnections.Keys)
            {

                if (inboundCSMSNames.TryGetValue(id, out var csmsNames) && csmsNames.Contains(Name))
                    return true;

                if (Connections.Connections.FirstOrDefault(one => one.Id == id) is ConnectionEntry entry &&
                    (NextHopOf(entry) == Name || entry.InboundName == Name.ToString()))
                {
                    return true;
                }

            }

            return false;

        }

        /// <summary>
        /// Whether a connection of a server served for the given version was
        /// let in as an inbound connection: those the kind marked with
        /// <see cref="LetInAsInbound"/>.
        /// </summary>
        private static Boolean WasLetInAsInbound(OCPPVersion                Version,
                                                 WebSocketServerConnection  Connection)

            => Connection.TryGetCustomData(InboundConnectionKey) is String;

        #endregion

        #region (private) InboundOf(Version, Name)

        /// <summary>
        /// The inbound connection of the given version of OCPP that comes under
        /// the given name and is switched on, or null.
        /// </summary>
        private ConnectionEntry? InboundOf(OCPPVersion  Version,
                                           String       Name)

            => Connections.Connections.FirstOrDefault(entry => entry.Inbound &&
                                                               entry.AutoConnect &&
                                                               entry.OCPPVersion == Version &&
                                                               entry.InboundName == Name);

        #endregion

        #region (private) FollowInboundConnections()

        /// <summary>
        /// Who is in over an inbound connection and may no longer be - switched
        /// off, its WebSocket login gone or switched off, or no longer written
        /// down - is let go of, and what is not in is said to be waited for,
        /// or why nothing can come. Asked whenever the connections change, and
        /// by the kind whenever its WebSocket logins do.
        /// </summary>
        protected void FollowInboundConnections()
        {

            try
            {

                foreach (var (version, server) in inboundServers.ToArray())
                {

                    var letIn = new HashSet<String>(StringComparer.Ordinal);

                    foreach (var entry in Connections.Connections.Where(entry => entry.Inbound && entry.OCPPVersion == version).ToArray())
                    {

                        if (entry.InboundName is not null &&
                            entry.AutoConnect &&
                            InboundLoginLetsIn(entry))
                        {
                            letIn.Add(entry.Id);
                        }

                        // In, and no longer to be: switched off, or its
                        // WebSocket login gone or switched off.
                        if (!letIn.Contains(entry.Id))
                        {

                            if (inboundConnections.TryRemove(entry.Id, out var connection))
                            {

                                UnrouteInbound(entry, server, connection);

                                _ = connection.Close(WebSocketFrame.ClosingStatusCode.PolicyViolation, "No longer a connection of this node");

                                Log.Notice($"'{entry.Description.FirstText()}' is let go of: it is no longer let in.", "ocpp", "connections", "inbound");

                            }

                            if (!IsUp(entry))
                                WaitFor(entry);

                        }

                        else if (!IsUp(entry))
                            WaitFor(entry);

                    }

                }

                // What was in for a connection that is not written down any more.
                foreach (var id in inboundConnections.Keys.ToArray())
                {
                    if (Connections.Connections.FirstOrDefault(one => one.Id == id) is not { Inbound: true })
                    {

                        if (inboundConnections.TryRemove(id, out var connection))
                            _ = connection.Close(WebSocketFrame.ClosingStatusCode.PolicyViolation, "No longer a connection of this node");

                        var itsOwnName = NetworkingNode_Id.Parse($"connection-{id}");

                        inboundCSMSNames.TryRemove(id, out var names);

                        foreach (var (version, server) in inboundServers.ToArray())
                        {

                            if (DiallingNodeOrNoneOf(version) is not { } node)
                                continue;

                            foreach (var name in (names ?? []).Append(itsOwnName).Concat(connection?.NamesLearned() ?? []))
                            {
                                if (server.NoLongerReachAs(name) &&
                                    node.Routing.LookupNetworkingNode(name, out var reachability) &&
                                    ReferenceEquals(reachability.Server, server))
                                {
                                    node.Routing.RemoveStaticRouting(name);
                                }
                            }

                        }

                    }
                }

            }
            catch (Exception e)
            {
                Log.Warning($"Who may dial this {NodeNoun} could not be brought up to date: {e.Message}", "ocpp", "connections", "inbound");
            }

        }

        #endregion

        #region (private) IsUp(Connection) / WaitFor(Connection)

        private Boolean IsUp(ConnectionEntry Connection)
            => inboundConnections.ContainsKey(Connection.Id);

        /// <summary>
        /// Say of an inbound connection that nothing is in over it: waited
        /// for, or why nothing can come.
        /// </summary>
        protected void WaitFor(ConnectionEntry Connection)
        {

            if (IsUp(Connection))
                return;

            var server = inboundServers.GetValueOrDefault(Connection.OCPPVersion);

            var what = !Connection.AutoConnect
                           ? $"'{Connection.InboundName}' is not let in: this connection is switched off."
                           : server is null
                                 ? $"'{Connection.InboundName}' can not dial in: this {NodeNoun} serves no {ConnectionEntry.AsText(Connection.OCPPVersion)} to whoever dials it."
                                 : WhyInboundCanNotSignIn(Connection, server) is String why
                                       ? $"'{Connection.InboundName}' can not sign in: {why}"
                                       : $"Waiting for '{Connection.InboundName}' to dial in.";

            lock (dialled)
            {

                // Said once, and not again at every change of something else.
                if (dialled.TryGetValue(Connection.Id, out var state) &&
                    state.Status == ConnectionStatus.Waiting &&
                    state.Said   == what)
                {
                    return;
                }

            }

            Record(Connection, ConnectionStatus.Waiting, what);

            Log.Info($"'{Connection.Description.FirstText()}': {what}", "ocpp", "connections", "inbound");

        }

        #endregion

        #region (private) RouteInbound(Connection, Name, WebSocketConnection) / UnrouteInbound(Connection, Server, WebSocketConnection)

        /// <summary>
        /// Reach an inbound connection under the name every connection has in
        /// the routing of its node - one of its own - and the primary under
        /// the name of the CSMS as well: both names of what came in, beside
        /// the one it came under, which the node routes to the server itself.
        /// </summary>
        private void RouteInbound(ConnectionEntry            Connection,
                                  NetworkingNode_Id          Name,
                                  WebSocketServerConnection  WebSocketConnection)
        {

            var node = DiallingNodeOf(Connection.OCPPVersion);

            if (!inboundServers.TryGetValue(Connection.OCPPVersion, out var server))
                return;

            inboundConnections[Connection.Id] = WebSocketConnection;

            // Accepted, and the line up of this node all the same: what comes
            // over it in the plain frame of OCPP is for this node, as over a
            // connection it dialled, see LineUpExtensions.
            WebSocketConnection.IsTheLineUp();

            server.ReachAs(NextHopOf(Connection), Name);

            node.Routing.RemoveStaticRouting     (NextHopOf(Connection));
            node.Routing.AddOrUpdateStaticRouting(NextHopOf(Connection), server);

            var csmsNames = CSMSNamesOf(Connection);

            if (csmsNames.Length > 0)
            {

                foreach (var csmsName in csmsNames)
                {
                    server.ReachAs(csmsName, Name);
                    node.Routing.RemoveStaticRouting     (csmsName);
                    node.Routing.AddOrUpdateStaticRouting(csmsName, server);
                }

                inboundCSMSNames[Connection.Id] = csmsNames;

            }

        }

        /// <summary>
        /// Take away the names an inbound connection was reached under: its
        /// own, the CSMS's where it had it, those learned from what its far end
        /// asked (see LineUpExtensions.IsReachedAsWell), and the one it came
        /// under - where that still leads to the given server.
        /// </summary>
        private void UnrouteInbound(ConnectionEntry            Connection,
                                    WWCPWebSocketServer        Server,
                                    WebSocketServerConnection  WebSocketConnection)
        {

            var node = DiallingNodeOrNoneOf(Connection.OCPPVersion);

            if (node is null)
                return;

            Server.NoLongerReachAs(NextHopOf(Connection));

            node.Routing.RemoveStaticRouting(NextHopOf(Connection));

            // Learned from the identification its far end wrote into what it
            // asked: where it is still this connection's, and its route still
            // leads here.
            if (Connection.InboundName is String cameUnder &&
                NetworkingNode_Id.TryParse(cameUnder, out var cameAs))
            {
                foreach (var learned in WebSocketConnection.NamesLearned())
                {

                    if (Server.ReachedAs(learned) == cameAs)
                        Server.NoLongerReachAs(learned);

                    if (node.Routing.LookupNetworkingNode(learned, out var toIt) &&
                        ReferenceEquals(toIt.Server, Server))
                    {
                        node.Routing.RemoveStaticRouting(learned);
                    }

                }
            }

            if (inboundCSMSNames.TryRemove(Connection.Id, out var csmsNames))
            {
                foreach (var csmsName in csmsNames)
                {

                    Server.NoLongerReachAs(csmsName);

                    // Where it still leads here, and not to a connection that
                    // took the name since.
                    if (node.Routing.LookupNetworkingNode(csmsName, out var toTheCSMS) &&
                        ReferenceEquals(toTheCSMS.Server, Server))
                    {
                        node.Routing.RemoveStaticRouting(csmsName);
                    }

                }
            }

            if (Connection.InboundName is String itsName &&
                NetworkingNode_Id.TryParse(itsName, out var name) &&
                node.Routing.LookupNetworkingNode(name, out var reachability) &&
                ReferenceEquals(reachability.Server, Server))
            {
                node.Routing.RemoveStaticRouting(name);
            }

        }

        #endregion

        #region (private) InboundIsDown(Version, Name, WebSocketConnection, Why)

        /// <summary>
        /// A connection somebody dialled is gone: where it is the one its
        /// inbound connection was in over - and not one that a newer one of
        /// the same name replaced - its names go with it, and it is waited for
        /// again.
        /// </summary>
        private void InboundIsDown(OCPPVersion                Version,
                                   NetworkingNode_Id          Name,
                                   WebSocketServerConnection  WebSocketConnection,
                                   String                     Why)
        {

            var entry = Connections.Connections.FirstOrDefault(one => one.Inbound &&
                                                                      one.OCPPVersion == Version &&
                                                                      one.InboundName == Name.ToString());

            if (entry is null)
                return;

            if (!inboundConnections.TryRemove(KeyValuePair.Create(entry.Id, WebSocketConnection)))
                return;

            if (inboundServers.TryGetValue(Version, out var server))
                UnrouteInbound(entry, server, WebSocketConnection);

            var what = $"'{Name}' went away ({Why}); it is let in again when it dials.";

            Record(entry, ConnectionStatus.Waiting, what);

            Log.Warning($"'{entry.Description.FirstText()}': {what}", "ocpp", "connections", "inbound");

        }

        #endregion

    }

}
