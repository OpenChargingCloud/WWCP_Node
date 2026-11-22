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
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.SSH;
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
    /// connects to this node, on an OCPP server of its own - its station port, or
    /// the OCPP subsystem of its SSH server.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OCPP as it always is, with who opens the connection the other way round -
    /// and OCPI, which a CPO makes to an EMSP: each server speaks one version
    /// of one protocol, and what comes to it is let in as a connection of that
    /// one only (see <see cref="ProtocolVersion"/>).
    /// What connects is written down as a connection (<see
    /// cref="ConnectionEntry.Inbound"/>), and from the moment it is in it is
    /// one: routed under a name of its own, the primary under the name of the
    /// CSMS as well, told that this node started, sent what waits - by the
    /// same code that does all of that for a connection this node made.
    /// </para>
    /// <para>
    /// Nothing gets in that is not written down. Who signs in is decided at
    /// the door of the kind of node. At its station port whoever comes signs
    /// in with a WebSocket login: a back end with the login of the name its
    /// connection comes under, which the connection names nothing beside. The
    /// kind marks what it let in that way with <see cref="LetInAsInbound"/>,
    /// and asks <see cref="InboundConnectionOf"/> whose a name is. Over SSH the
    /// SSH server let it in by the same login - the one an ssh:// connection
    /// of this node names - and what came under it is taken as that
    /// connection here.
    /// </para>
    /// <para>
    /// A kind of node hands its servers over with <see cref="ServeInbound(ProtocolVersion, WWCPWebSocketServer)"/>
    /// and <see cref="ServeInbound(ProtocolVersion, WWCPSshServer)"/>. What is let in over them as a connection
    /// written down here is the line up of the kind, not one of the others it
    /// lets in: <see cref="IsInbound"/>. Whether its login lets it in at all,
    /// and why it can not sign in, is the kind's to say - see
    /// <see cref="InboundLoginLetsIn"/> and <see cref="WhyInboundCanNotSignIn"/>.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// The OCPP servers of this node at its station port, by the version they speak.
        /// </summary>
        private readonly ConcurrentDictionary<ProtocolVersion, WWCPWebSocketServer>       inboundServers         = new ();

        /// <summary>
        /// The OCPP servers of this node over SSH, by the version they speak.
        /// </summary>
        private readonly ConcurrentDictionary<ProtocolVersion, WWCPSshServer>         inboundSshServers      = new ();

        /// <summary>
        /// What an inbound connection is in over now: the server, and the
        /// connection - the one that tells its close from the close of one it
        /// replaced.
        /// </summary>
        private readonly record struct InboundIn(IWWCPServer         Server,
                                                 IMessageConnection  Connection);

        /// <summary>
        /// What each inbound connection is in over now, by the id of its entry.
        /// </summary>
        private readonly ConcurrentDictionary<String, InboundIn>                      inboundConnections     = new ();

        /// <summary>
        /// The inbound connections reached under the name of the CSMS as well,
        /// by the id of their entry: what is taken away again when they go.
        /// </summary>
        private readonly ConcurrentDictionary<String, NetworkingNode_Id[]>            inboundCSMSNames       = new ();

        /// <summary>
        /// The servers whose events are followed already, by the version they
        /// are followed for: a server served again - stopped and started, as a
        /// kind does that keeps one server - is not followed twice.
        /// </summary>
        private readonly List<(ProtocolVersion Version, IWWCPServer Server)>          inboundServersWired    = [];

        private          Int32                                                        followsInboundChanges;

        /// <summary>
        /// What a connection carries that was let in as an inbound connection:
        /// the id of its entry.
        /// </summary>
        public const     String                                                       InboundConnectionKey   = "inboundConnection";

        #endregion

        #region InboundServed(Version)

        /// <summary>
        /// Whether this node serves the given protocol and version to whoever connects
        /// it - at its station port, or over SSH.
        /// </summary>
        public Boolean InboundServed(ProtocolVersion Version)
            => inboundServers.ContainsKey(Version) || inboundSshServers.ContainsKey(Version);

        #endregion

        #region (protected) ServeInbound(Version, Server) / StopServingInbound(Version)

        /// <summary>
        /// Let in over the given server what is written down as an inbound
        /// connection of the given protocol and version over a WebSocket. The server
        /// is attached to the node of that version, and the kind decides at its
        /// own door who signs in - by the WebSocket login of the name it comes
        /// under - and marks what it let in as such a connection with
        /// <see cref="LetInAsInbound"/>: only that is a connection of this node.
        /// </summary>
        /// <param name="Version">The protocol and version the server speaks: OCPP 2.1, OCPI 2.2.1.</param>
        /// <param name="Server">The server, attached to the node of that version.</param>
        protected void ServeInbound(ProtocolVersion      Version,
                                    WWCPWebSocketServer  Server)
        {

            inboundServers[Version] = Server;

            if (!FirstServed(Version, Server))
            {
                FollowInboundConnections();
                return;
            }

            // Routed under its own names before the 101 goes out, as the node
            // routes the name it came under: what is said to it right after it
            // connected finds it.
            Server.OnNetworkingNodeWebSocketConnectionAccepted += (timestamp, server, connection, networkingNodeId, networkingMode, sharedSubprotocols, eventTrackingId, cancellationToken) => {

                if (ReferenceEquals(inboundServers.GetValueOrDefault(Version), Server) &&
                    WasLetInAsInbound(connection) &&
                    InboundOf(Version, networkingNodeId.ToString(), OverSSH: false) is ConnectionEntry entry)
                {
                    RouteInbound(entry, networkingNodeId, Server, connection);
                }

                return Task.CompletedTask;

            };

            // In: said, and then what is said to every connection that is up.
            Server.OnNetworkingNodeNewWebSocketConnection += (timestamp, server, connection, networkingNodeId, networkingMode, sharedSubprotocols, eventTrackingId, cancellationToken) => {

                if (!ReferenceEquals(inboundServers.GetValueOrDefault(Version), Server))
                    return Task.CompletedTask;

                // One of the others the kind lets in: the kind's, not this node's.
                if (!WasLetInAsInbound(connection))
                    return Task.CompletedTask;

                if (InboundOf(Version, networkingNodeId.ToString(), OverSSH: false) is not ConnectionEntry entry)
                {

                    // Let in by credentials that are no longer anybody's: taken
                    // away between its handshake and now.
                    Log.Warning($"'{networkingNodeId}' connected from {connection.RemoteSocket} and is no inbound connection of this {NodeNoun} any more: it is let go of.",
                                "ocpp", "connections", "inbound");

                    _ = connection.Close(WebSocketFrame.ClosingStatusCode.PolicyViolation, "Not a connection of this node");

                    return Task.CompletedTask;

                }

                Note(entry, $"'{networkingNodeId}' connected from {connection.RemoteSocket}" +
                            (connection.Subprotocol is String subprotocol ? $" ({subprotocol})" : "") +
                            ", and is let in again whenever it connects.");

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

            FollowInboundChanges();

        }

        /// <summary>
        /// Let in over the given SSH server what is written down as an inbound
        /// connection of the given protocol and version over SSH. Who signs in is the
        /// SSH server's to decide, by the login an ssh:// connection names; what
        /// comes in under that login is that connection, and nothing else is.
        /// </summary>
        /// <param name="Version">The protocol and version the server speaks: OCPP 2.1, OCPI 2.2.1.</param>
        /// <param name="Server">The server, attached to the node of that version.</param>
        protected void ServeInbound(ProtocolVersion  Version,
                                    WWCPSshServer  Server)
        {

            inboundSshServers[Version] = Server;

            if (!FirstServed(Version, Server))
            {
                FollowInboundConnections();
                return;
            }

            // Welcomed and registered, before its first message is read: routed
            // under its own names, said, and then what is said to every
            // connection that is up.
            Server.OnNetworkingNodeConnectionAccepted += (timestamp, transport, connection, networkingNodeId, networkingMode, eventTrackingId, cancellationToken) => {

                if (!ReferenceEquals(inboundSshServers.GetValueOrDefault(Version), Server) ||
                    networkingNodeId is not NetworkingNode_Id name)
                {
                    return Task.CompletedTask;
                }

                // The name decides whose it is: what comes under the name of a
                // connection the other end makes is let in as that or not at all.
                // A server of any protocol but OCPP lets in nothing else: what
                // is no connection of its own there is nobody's - a charging
                // station, say, that came to the subsystem of OCPI.
                if (InboundConnectionOf(Version, name.ToString()) is not ConnectionEntry written)
                    return Version.Use == ConnectionUse.OCPP
                               ? Task.CompletedTask
                               : LetGo(connection, $"'{name}' is no connection of {Version} of this {NodeNoun}");

                if (!written.IsSSH)
                    return LetGo(connection, $"'{name}' is a back end that connects to this {NodeNoun} over a WebSocket, and came over SSH");

                if (!written.AutoConnect)
                    return LetGo(connection, $"'{name}' is the name '{written.Description.FirstText()}' comes under, a connection that is switched off");

                if (!InboundLoginLetsIn(written))
                    return LetGo(connection, $"'{name}' is the name '{written.Description.FirstText()}' comes under, and its login does not let it in");

                LetInAsInbound(connection, written);

                RouteInbound(written, name, Server, connection);

                Note(written, $"'{name}' connected over SSH from {connection.RemoteSocket}" +
                              (connection.Subprotocol is String subprotocol ? $" ({subprotocol})" : "") +
                              ", and is let in again whenever it connects.");

                ConnectionIsUp(written);

                return Task.CompletedTask;

            };

            Server.OnNetworkingNodeConnectionClosed += (timestamp, transport, connection, networkingNodeId, close, cancellationToken) => {

                if (networkingNodeId is NetworkingNode_Id name)
                    InboundIsDown(Version, name, connection,
                                  close.Code is MessageCloseCode code
                                      ? $"{(UInt16) code} {code}{(String.IsNullOrWhiteSpace(close.Reason) ? "" : $": {close.Reason}")}"
                                      : String.IsNullOrWhiteSpace(close.Reason) ? "its connection ended" : close.Reason);

                return Task.CompletedTask;

            };

            FollowInboundChanges();

            Task LetGo(SshMessageConnection Connection, String Why)
            {

                Log.Warning($"{Why}: it is let go of.", "ocpp", "connections", "inbound");

                _ = Connection.Close(MessageCloseCode.PolicyViolation, "Not a connection of this node");

                return Task.CompletedTask;

            }

        }

        /// <summary>
        /// Let nothing in any more for the given protocol and version, over either
        /// transport: whoever is in is let go of, and the servers are the
        /// kind's to stop.
        /// </summary>
        /// <param name="Version">The protocol and version.</param>
        /// <param name="Why">Why, as the other end is told.</param>
        protected void StopServingInbound(ProtocolVersion  Version,
                                          String       Why)
        {

            var served = inboundServers.TryRemove(Version, out _);

            StopServing(Version, OverSSH: false, Why, served);

        }

        /// <summary>
        /// Let nothing in any more over SSH for the given protocol and version:
        /// whoever is in over SSH is let go of, and the server is the kind's to
        /// stop. What connects over a WebSocket is not touched.
        /// </summary>
        /// <param name="Version">The protocol and version.</param>
        /// <param name="Why">Why, as the other end is told.</param>
        protected void StopServingInboundOverSSH(ProtocolVersion  Version,
                                                 String       Why)
        {

            var served = inboundSshServers.TryRemove(Version, out _);

            StopServing(Version, OverSSH: true, Why, served);

        }

        private void StopServing(ProtocolVersion  Version,
                                 Boolean      OverSSH,
                                 String       Why,
                                 Boolean      Served)
        {

            if (!Served)
                return;

            foreach (var entry in Connections.Connections.Where(entry => entry.Inbound && entry.IsSSH == OverSSH && entry.Protocol == Version))
            {

                if (inboundConnections.TryRemove(entry.Id, out var inbound))
                {
                    UnrouteInbound(entry, inbound);
                    _ = inbound.Connection.Close(MessageCloseCode.GoingAway, Why);
                }

                WaitFor(entry);

            }

        }

        /// <summary>
        /// Whether the given server is served for the given version for the
        /// first time: its events are followed then, and not twice.
        /// </summary>
        private Boolean FirstServed(ProtocolVersion  Version,
                                    IWWCPServer  Server)
        {
            lock (inboundServersWired)
            {

                if (inboundServersWired.Any(wired => wired.Version == Version && ReferenceEquals(wired.Server, Server)))
                    return false;

                inboundServersWired.Add((Version, Server));

                return true;

            }
        }

        /// <summary>
        /// Follow the changes of the connections, once, and look at them now.
        /// </summary>
        private void FollowInboundChanges()
        {

            if (Interlocked.Exchange(ref followsInboundChanges, 1) == 0)
                Connections.OnConnectionsChanged += FollowInboundConnections;

            FollowInboundConnections();

        }

        #endregion

        #region (protected) InboundConnectionOf(Version, Name) / LetInAsInbound(Connection, Entry) / IsInbound(Connection)

        /// <summary>
        /// The connection the other end makes of the given protocol and version that
        /// comes under the given name - switched on or not, over a WebSocket or
        /// over SSH -, or null: then whoever comes under that name is no back
        /// end of this node.
        /// </summary>
        /// <remarks>
        /// The name decides whose it is, before anything it signs in with is
        /// looked at: what comes under the name of a connection written down
        /// here is let in as that or not at all, whatever else the kind would
        /// have taken it for - and over the transport it names only.
        /// </remarks>
        /// <param name="Version">The protocol and version of the server it came to.</param>
        /// <param name="Name">The name it came under: the last segment of the path it asked for, or its SSH login.</param>
        protected ConnectionEntry? InboundConnectionOf(ProtocolVersion  Version,
                                                       String       Name)

            => Connections.Connections.FirstOrDefault(entry => entry.Inbound &&
                                                               entry.Protocol    == Version &&
                                                               entry.InboundName == Name);

        /// <summary>
        /// Take what came in over the given connection as the given connection
        /// the other end makes: the kind let it in at its door, by the login of
        /// the name it came under.
        /// </summary>
        /// <param name="Connection">The connection, before its 101 goes out or its first message is read.</param>
        /// <param name="Entry">The connection the other end makes it came under.</param>
        protected static void LetInAsInbound(IMessageConnection  Connection,
                                             ConnectionEntry     Entry)

            => Connection.TryAddCustomData(InboundConnectionKey, Entry.Id);

        /// <summary>
        /// Whether the login an inbound connection comes under lets anything in
        /// at all - there is one, and it is switched on. Yes, unless the kind
        /// says otherwise: a connection whose login says no is let go of where
        /// it is in.
        /// </summary>
        /// <param name="Connection">An inbound connection that is switched on.</param>
        protected virtual Boolean InboundLoginLetsIn(ConnectionEntry Connection)
            => true;

        /// <summary>
        /// Why the other end of an inbound connection can not sign in at the
        /// given server, as its login and the server are now - or null.
        /// Nothing, unless the kind says something.
        /// </summary>
        /// <param name="Connection">An inbound connection that is switched on.</param>
        /// <param name="Server">The server of its protocol and version and its transport.</param>
        protected virtual String? WhyInboundCanNotSignIn(ConnectionEntry  Connection,
                                                         IWWCPServer      Server)
            => null;

        /// <summary>
        /// Whether the given connection is one somebody made who is written
        /// down as a connection of this node - its CSMS, the controller above
        /// it - and so a line up of this node, although this node accepted it.
        /// </summary>
        /// <param name="Connection">A connection something came over.</param>
        protected Boolean IsInbound(IMessageConnection? Connection)

            => Connection is not null &&
               inboundConnections.Values.Any(inbound => ReferenceEquals(inbound.Connection, Connection));

        /// <summary>
        /// Whether what is sent to the given name goes over a connection
        /// somebody made who is written down as a connection of this node:
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
        /// Whether a connection was let in as an inbound connection: those the
        /// kind marked with <see cref="LetInAsInbound"/>.
        /// </summary>
        private static Boolean WasLetInAsInbound(IMessageConnection Connection)

            => Connection.TryGetCustomData(InboundConnectionKey) is String;

        #endregion

        #region (private) InboundOf(Version, Name, OverSSH) / ServerOf(Connection)

        /// <summary>
        /// The inbound connection of the given protocol and version and transport
        /// that comes under the given name and is switched on, or null.
        /// </summary>
        private ConnectionEntry? InboundOf(ProtocolVersion  Version,
                                           String       Name,
                                           Boolean      OverSSH)

            => Connections.Connections.FirstOrDefault(entry => entry.Inbound &&
                                                               entry.AutoConnect &&
                                                               entry.IsSSH       == OverSSH &&
                                                               entry.Protocol    == Version &&
                                                               entry.InboundName == Name);

        /// <summary>
        /// The server an inbound connection is let in at: the station port, or
        /// the SSH server, of its protocol and version - or null where it is not
        /// served.
        /// </summary>
        private IWWCPServer? ServerOf(ConnectionEntry Connection)

            => Connection.IsSSH
                   ? inboundSshServers.GetValueOrDefault(Connection.Protocol)
                   : inboundServers.   GetValueOrDefault(Connection.Protocol);

        #endregion

        #region (private) FollowInboundConnections()

        /// <summary>
        /// Who is in over an inbound connection and may no longer be - switched
        /// off, its login gone or switched off, or no longer written down - is
        /// let go of, and what is not in is said to be waited for, or why
        /// nothing can come. Asked whenever the connections change, and by the
        /// kind whenever its WebSocket logins do.
        /// </summary>
        protected void FollowInboundConnections()
        {

            try
            {

                foreach (var entry in Connections.Connections.Where(entry => entry.Inbound).ToArray())
                {

                    var letIn = entry.InboundName is not null &&
                                entry.AutoConnect &&
                                InboundLoginLetsIn(entry);

                    // In, and no longer to be: switched off, or its login gone
                    // or switched off - or in over the other transport than the
                    // one it names now.
                    if (inboundConnections.TryGetValue(entry.Id, out var inbound) &&
                        (!letIn || !ReferenceEquals(inbound.Server, ServerOf(entry))))
                    {

                        if (inboundConnections.TryRemove(KeyValuePair.Create(entry.Id, inbound)))
                        {

                            UnrouteInbound(entry, inbound);

                            _ = inbound.Connection.Close(MessageCloseCode.PolicyViolation, "No longer a connection of this node");

                            Log.Notice($"'{entry.Description.FirstText()}' is let go of: it is no longer let in.", "ocpp", "connections", "inbound");

                        }

                    }

                    if (!IsUp(entry))
                        WaitFor(entry);

                }

                // What was in for a connection that is not written down any more.
                foreach (var id in inboundConnections.Keys.ToArray())
                {
                    if (Connections.Connections.FirstOrDefault(one => one.Id == id) is not { Inbound: true })
                    {

                        if (!inboundConnections.TryRemove(id, out var inbound))
                            continue;

                        _ = inbound.Connection.Close(MessageCloseCode.PolicyViolation, "No longer a connection of this node");

                        var itsOwnName = NetworkingNode_Id.Parse($"connection-{id}");

                        inboundCSMSNames.TryRemove(id, out var names);

                        foreach (var node in InboundConnectingNodes())
                        {
                            foreach (var name in (names ?? []).Append(itsOwnName).Concat(inbound.Connection.NamesLearned()))
                            {
                                if (inbound.Server.NoLongerReachAs(name) &&
                                    node.Routing.LookupNetworkingNode(name, out var reachability) &&
                                    ReferenceEquals(reachability.Server, inbound.Server))
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
                Log.Warning($"Who may connect to this {NodeNoun} could not be brought up to date: {e.Message}", "ocpp", "connections", "inbound");
            }

        }

        /// <summary>
        /// The networking nodes of the protocols served to whoever connects to this node.
        /// </summary>
        private IEnumerable<AWWCPNetworkingNode> InboundConnectingNodes()

            => inboundServers.Keys.
                   Concat    (inboundSshServers.Keys).
                   Select    (served => served.Use).
                   Distinct  ().
                   SelectMany(use => ConnectingOf(use).ConnectingNodes).
                   Distinct  ();

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

            var server = ServerOf(Connection);

            var what = !Connection.AutoConnect
                           ? $"'{Connection.InboundName}' is not let in: this connection is switched off."
                           : server is null
                                 ? $"'{Connection.InboundName}' can not connect: this {NodeNoun} serves no {Connection.Protocol} " +
                                   $"{(Connection.IsSSH ? "over SSH " : "")}to whoever connects to it."
                                 : WhyInboundCanNotSignIn(Connection, server) is String why
                                       ? $"'{Connection.InboundName}' can not sign in: {why}"
                                       : $"Waiting for '{Connection.InboundName}' to connect{(Connection.IsSSH ? " over SSH" : "")}.";

            lock (connectionStates)
            {

                // Said once, and not again at every change of something else.
                if (connectionStates.TryGetValue(Connection.Id, out var state) &&
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

        #region (private) RouteInbound(Connection, Name, Server, MessageConnection) / UnrouteInbound(Connection, Inbound)

        /// <summary>
        /// Reach an inbound connection under the name every connection has in
        /// the routing of its node - one of its own - and the primary under
        /// the name of the CSMS as well: both names of what came in, beside
        /// the one it came under, which the node routes to the server itself.
        /// </summary>
        private void RouteInbound(ConnectionEntry     Connection,
                                  NetworkingNode_Id   Name,
                                  IWWCPServer         Server,
                                  IMessageConnection  MessageConnection)
        {

            var node = ConnectingNodeOf(Connection);

            inboundConnections[Connection.Id] = new InboundIn(Server, MessageConnection);

            // Accepted, and the line up of this node all the same: what comes
            // over it in the plain frame of OCPP is for this node, as over a
            // connection it made, see LineUpExtensions.
            MessageConnection.IsTheLineUp();

            Server.ReachAs(NextHopOf(Connection), Name);

            node.Routing.RemoveStaticRouting     (NextHopOf(Connection));
            node.Routing.AddOrUpdateStaticRouting(NextHopOf(Connection), Server);

            var csmsNames = CSMSNamesOf(Connection);

            if (csmsNames.Length > 0)
            {

                foreach (var csmsName in csmsNames)
                {
                    Server.ReachAs(csmsName, Name);
                    node.Routing.RemoveStaticRouting     (csmsName);
                    node.Routing.AddOrUpdateStaticRouting(csmsName, Server);
                }

                inboundCSMSNames[Connection.Id] = csmsNames;

                // The primary in the frame of the overlay network by the name
                // its far end answers to - "CSMS" -, as a connection this node
                // made itself: the far end does not know the
                // connection's own name, and turned away what this node says
                // by itself, its BootNotification first. Only where the server
                // reaches it under that name as well: it finds the connection
                // a message goes over by the name written on the wire.
                if (csmsNames.Contains(FarEndNameOf(Connection)))
                    NamedOnTheWire(Connection);

            }

        }

        /// <summary>
        /// Take away the names an inbound connection was reached under: its
        /// own, the CSMS's where it had it, those learned from what its far end
        /// asked (see LineUpExtensions.IsReachedAsWell), and the one it came
        /// under - where that still leads to the server it is in at.
        /// </summary>
        private void UnrouteInbound(ConnectionEntry  Connection,
                                    InboundIn        Inbound)
        {

            var node = ConnectingNodeOrNoneOf(Connection);

            if (node is null)
                return;

            var server = Inbound.Server;

            server.NoLongerReachAs(NextHopOf(Connection));

            // Its own name on the wire again, see RouteInbound.
            node.Routing.SetNameOnTheWire(NextHopOf(Connection), NextHopOf(Connection));

            node.Routing.RemoveStaticRouting(NextHopOf(Connection));

            // Learned from the identification its far end wrote into what it
            // asked: where it is still this connection's, and its route still
            // leads here.
            if (Connection.InboundName is String cameUnder &&
                NetworkingNode_Id.TryParse(cameUnder, out var cameAs))
            {
                foreach (var learned in Inbound.Connection.NamesLearned())
                {

                    if (server.ReachedAs(learned) == cameAs)
                        server.NoLongerReachAs(learned);

                    if (node.Routing.LookupNetworkingNode(learned, out var toIt) &&
                        ReferenceEquals(toIt.Server, server))
                    {
                        node.Routing.RemoveStaticRouting(learned);
                    }

                }
            }

            if (inboundCSMSNames.TryRemove(Connection.Id, out var csmsNames))
            {
                foreach (var csmsName in csmsNames)
                {

                    server.NoLongerReachAs(csmsName);

                    // Where it still leads here, and not to a connection that
                    // took the name since.
                    if (node.Routing.LookupNetworkingNode(csmsName, out var toTheCSMS) &&
                        ReferenceEquals(toTheCSMS.Server, server))
                    {
                        node.Routing.RemoveStaticRouting(csmsName);
                    }

                }
            }

            if (Connection.InboundName is String itsName &&
                NetworkingNode_Id.TryParse(itsName, out var name) &&
                node.Routing.LookupNetworkingNode(name, out var reachability) &&
                ReferenceEquals(reachability.Server, server))
            {
                node.Routing.RemoveStaticRouting(name);
            }

        }

        #endregion

        #region (private) InboundIsDown(Version, Name, MessageConnection, Why)

        /// <summary>
        /// A connection somebody made is gone: where it is the one its
        /// inbound connection was in over - and not one that a newer one of
        /// the same name replaced - its names go with it, and it is waited for
        /// again.
        /// </summary>
        private void InboundIsDown(ProtocolVersion     Version,
                                   NetworkingNode_Id   Name,
                                   IMessageConnection  MessageConnection,
                                   String              Why)
        {

            var entry = Connections.Connections.FirstOrDefault(one => one.Inbound &&
                                                                      one.Protocol    == Version &&
                                                                      one.InboundName == Name.ToString());

            if (entry is null)
                return;

            if (!inboundConnections.TryGetValue(entry.Id, out var inbound) ||
                !ReferenceEquals(inbound.Connection, MessageConnection)    ||
                !inboundConnections.TryRemove(KeyValuePair.Create(entry.Id, inbound)))
            {
                return;
            }

            UnrouteInbound(entry, inbound);

            var what = $"'{Name}' went away ({Why}); it is let in again when it connects.";

            Record(entry, ConnectionStatus.Waiting, what);

            Log.Warning($"'{entry.Description.FirstText()}': {what}", "ocpp", "connections", "inbound");

        }

        #endregion

    }

}
