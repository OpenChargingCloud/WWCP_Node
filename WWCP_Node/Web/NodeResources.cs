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

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The resources every node has, by the names a role writes them under.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The JSON API every node has asks for them under these names - see
    /// <see cref="NodeHTTPAPI"/> - and so does every route a kind of node
    /// adds, so that a role written for a vehicle's DNS settings means the
    /// same on a charging station's.
    /// </para>
    /// <para>
    /// The clock, the log and the event stream are none of them: they are for
    /// anybody signed in, as they have always been, because a screen that
    /// shows the time has to be able to say what it is worth and a page that
    /// cannot hear the event stream cannot show anything happening.
    /// </para>
    /// </remarks>
    public static class NodeResources
    {

        /// <summary>
        /// What a node is made of, as the Configuration page shows it: its web
        /// server, its accounts, its log and its time.
        /// </summary>
        public const String  Configuration  = "configuration";

        /// <summary>
        /// How a node resolves names: reading the settings, changing them, and
        /// asking a name server something to find out whether it can.
        /// </summary>
        public const String  DNS            = "dns";

        /// <summary>
        /// Where a node reads the time: reading the settings, changing them,
        /// and asking a time server something to find out whether it can.
        /// </summary>
        public const String  NTS            = "nts";

        /// <summary>
        /// The certificate store: seeing what is in it, and putting
        /// certificates in, taking them out and switching them on and off.
        /// </summary>
        /// <remarks>
        /// Both halves of the store behind one resource, because both are
        /// decisions about trust: somebody who can add a root can make the node
        /// believe a server nobody else would. Running it is the one thing
        /// that is no such decision: making a key with its signing request,
        /// sending that off where a kind of node can, bringing the
        /// certificate that comes back for it, and taking a key back that
        /// still waits for one. A certificate that comes with its key, and
        /// every root, is put in at the permission to change the store.
        /// </remarks>
        public const String  Certificates   = "certificates";

        /// <summary>
        /// The SSH server the command line is served over: seeing whether it
        /// runs, where, with which host key, who is connected and with which
        /// keys every account may sign in - and switching it on and off, moving
        /// it to another port, and letting passwords open it.
        /// </summary>
        /// <remarks>
        /// A resource of its own and not the configuration's: whoever may move
        /// the server or let passwords open it decides how this node is reached
        /// from a shell, which is more than reading what it is made of.
        /// </remarks>
        public const String  SSH            = "ssh";

        /// <summary>
        /// The log and its event stream: reading them, on the Logs page, at
        /// the command line and as files over SFTP.
        /// </summary>
        /// <remarks>
        /// Asked for only where a kind of node says so - see
        /// NodeHTTPAPI.ToReadTheLog: a node whose accounts include people the
        /// log is not for, as a hub's viewer, who is not to read what goes
        /// between the peers (POI3-ISSUES.md S29).
        /// </remarks>
        public const String  Log            = "log";

        /// <summary>
        /// The node itself, told to do something no other resource is about:
        /// run, a message asked of it that it would send by itself, as a
        /// BootNotification or a Heartbeat.
        /// </summary>
        /// <remarks>
        /// The white paper "Signed OCPP Messages and Signer Roles", section
        /// 5.3 (Q12): these six are what every kind of node can be asked over
        /// OCPP, by a signer whose role is one of the node's - so that a role
        /// may sign what it may do on the web page and at the command line,
        /// and nothing else.
        /// </remarks>
        public const String  Node            = "node";

        /// <summary>
        /// Restarting the node once it is idle: run, a restart that waits
        /// until nothing is going on that it would end.
        /// </summary>
        /// <remarks>
        /// A resource of its own, and not the node's: an operator's telephone
        /// support restarts nodes all day, so many people hold this, and it
        /// is to be all they hold.
        /// </remarks>
        public const String  Reset           = "reset";

        /// <summary>
        /// Restarting the node at once: run, a restart that ends what is
        /// going on - the sessions of a charging station, and on a local
        /// controller the line of every station behind it.
        /// </summary>
        /// <remarks>
        /// Apart from <see cref="Reset"/>, because it is the one of the two
        /// that can do damage.
        /// </remarks>
        public const String  ResetImmediate  = "reset-immediate";

        /// <summary>
        /// What is going on, apart from how the node is configured: read, the
        /// state of a charging station's EVSEs, or whether a local
        /// controller's line to its CSMS stands and which stations it has
        /// seen; run, that state reported again.
        /// </summary>
        /// <remarks>
        /// A resource of its own, and not a way of reading the others:
        /// somebody who is to see that an EVSE is faulted is not thereby
        /// somebody who is to read where the node dials and whom it lets in.
        /// </remarks>
        public const String  State           = "state";

        /// <summary>
        /// The node's firmware: read, which one runs; edited, another one
        /// installed.
        /// </summary>
        public const String  Firmware        = "firmware";

        /// <summary>
        /// Who may sign what: the signer roles, the keys bound to them and the
        /// signature policy - read, and edited.
        /// </summary>
        /// <remarks>
        /// Whoever edits this decides what every other role may sign, which is
        /// why no role but the administrators' holds it unless the file says
        /// so. Reading it gives away nothing: the keys are public ones.
        /// </remarks>
        public const String  Signatures      = "signatures";

        /// <summary>
        /// All of them.
        /// </summary>
        public static readonly IReadOnlyList<String>  All = [ Configuration, DNS, NTS, Certificates, SSH, Log,
                                                              Node, Reset, ResetImmediate, State, Firmware, Signatures ];

    }

}
