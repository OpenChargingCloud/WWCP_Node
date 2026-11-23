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

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Connections
{

    /// <summary>
    /// What a node writes down as a connection, and what not: held against
    /// every connection that is written or changed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One rule for every kind of node: a connection may lead to any kind of
    /// node, over ws://, wss:// and ssh://, in OCPP 1.6 and 2.1, made by
    /// this node or by the other end. A connection that names the node at its
    /// other end is spoken to by that name - a node below, say, which this node
    /// connects to; one that names none leads to a back end, spoken to as that. A
    /// charging station this node connects to is reached by its name alone, and has
    /// to be named.
    /// </para>
    /// <para>
    /// What may be at the other end, and over what, can still be narrowed for
    /// a node - but no kind of node narrows it by itself.
    /// </para>
    /// <para>
    /// An EMSP and a CPO are no kinds of node of the network of OCPP, and not
    /// among <see cref="Every"/>: a node that speaks OCPI to them names them in
    /// its <see cref="Types"/> - a CSMS that connects to an EMSP, an EMSP that
    /// lets a CPO connect to it. A connection to them carries OCPI and names
    /// no node at its other end: nothing is routed beyond it.
    /// </para>
    /// <para>
    /// Held against what is written, not against what is read: a file of
    /// before is read as it is.
    /// </para>
    /// </remarks>
    public sealed class ConnectionRules
    {

        #region Data

        /// <summary>
        /// What a node that connects to its back end has at the other end of a
        /// connection.
        /// </summary>
        public static readonly IReadOnlyList<ConnectionType> BackEnds = [
            ConnectionType.CSMS,
            ConnectionType.CSMSBackup,
            ConnectionType.LocalController,
            ConnectionType.Gateway
        ];

        /// <summary>
        /// What a node that connects downwards has at the other end of a
        /// connection.
        /// </summary>
        public static readonly IReadOnlyList<ConnectionType> NodesBelow = [
            ConnectionType.ChargingStation,
            ConnectionType.LocalController,
            ConnectionType.Gateway
        ];

        #endregion

        #region Properties

        /// <summary>
        /// Every kind of node a connection may lead to - an energy meter and a
        /// grid operator among them, which a node connects to and which never
        /// connect to it.
        /// </summary>
        public static readonly IReadOnlyList<ConnectionType> Every = [
            ConnectionType.CSMS,
            ConnectionType.CSMSBackup,
            ConnectionType.LocalController,
            ConnectionType.Gateway,
            ConnectionType.ChargingStation,
            ConnectionType.EnergyMeter,
            ConnectionType.GridOperator,
            ConnectionType.PKI
        ];

        /// <summary>
        /// What may be at the other end of a connection: the first of them
        /// is what a connection that says nothing is.
        /// </summary>
        public IReadOnlyList<ConnectionType>  Types                  { get; init; } = Every;

        /// <summary>
        /// Whether a connection may be one the other end makes.
        /// </summary>
        public Boolean                        Inbound                { get; init; } = true;

        /// <summary>
        /// Whether a connection may be one this node makes: no, for a node that
        /// only lets the other end connect - an EMSP, which connects to nothing yet.
        /// </summary>
        public Boolean                        Outbound               { get; init; } = true;

        /// <summary>
        /// Whether a connection may go over ssh://.
        /// </summary>
        public Boolean                        SSH                    { get; init; } = true;

        /// <summary>
        /// Whether a connection may speak OCPP 1.6.
        /// </summary>
        public Boolean                        OCPP1_6                { get; init; } = true;

        /// <summary>
        /// Whether a connection may name the node at its other end, which it
        /// is spoken to by then.
        /// </summary>
        public Boolean                        NamesTheNodeItLeadsTo  { get; init; } = true;

        /// <summary>
        /// The kind of connection one that says nothing is.
        /// </summary>
        public ConnectionType                 DefaultType

            => Types.Count > 0
                   ? Types[0]
                   : ConnectionType.CSMS;

        #endregion

        #region Check(URL, Type, Version, Inbound, RemoteNodeId, out Error)

        /// <summary>
        /// What of a connection this kind of node does not write down.
        /// </summary>
        public Boolean Check(URL                               URL,
                             ConnectionType                    Type,
                             OCPPVersion                       Version,
                             Boolean                           Inbound,
                             String?                           RemoteNodeId,
                             [NotNullWhen(false)] out String?  Error,
                             String?                           NodeNoun   = null)
        {

            if (!Types.Contains(Type))
            {
                Error = $"'{Type}' is not what a connection of this {NodeNoun ?? NodeWording.Noun} leads to. It leads to: {String.Join(", ", Types)}.";
                return false;
            }

            if (URL.Scheme == URIScheme.ssh && !SSH)
            {
                Error = $"This {NodeNoun ?? NodeWording.Noun} connects over ws:// and wss://, and not over ssh://.";
                return false;
            }

            if (Version == OCPPVersion.OCPP1_6 && !OCPP1_6 && ConnectionEntry.UseOf(Type) == ConnectionUse.OCPP)
            {
                Error = $"This {NodeNoun ?? NodeWording.Noun} speaks {ConnectionEntry.AsText(OCPPVersion.OCPP2_1)} on its connections, and no OCPP 1.6.";
                return false;
            }

            if (Inbound && !this.Inbound)
            {
                Error = $"A connection of this {NodeNoun ?? NodeWording.Noun} is one it makes. What connects to this {NodeNoun ?? NodeWording.Noun} comes in over its own server, " +
                        "and is written down there.";
                return false;
            }

            if (!Inbound && !Outbound)
            {
                Error = $"A connection of this {NodeNoun ?? NodeWording.Noun} is one the other end makes: this {NodeNoun ?? NodeWording.Noun} connects to nothing itself.";
                return false;
            }

            // Nothing is routed beyond a connection of OCPI, of Modbus or of
            // OpenADR: an EMSP, a CPO, an energy meter, a grid operator is the
            // end of it.
            if (ConnectionEntry.UseOf(Type) != ConnectionUse.OCPP && RemoteNodeId is not null)
            {
                Error = $"A connection to what is at the other end, '{Type}', carries {ConnectionEntry.UseOf(Type)}, and names no node there: nothing is reached through it.";
                return false;
            }

            // A meter is connected to, and connects to nothing: what reads it is
            // what makes the connection.
            if (Type == ConnectionType.EnergyMeter && Inbound)
            {
                Error = $"An energy meter connects to nothing: a connection to one is one this {NodeNoun ?? NodeWording.Noun} makes.";
                return false;
            }

            if (Type == ConnectionType.MeterReader && !Inbound)
            {
                Error = $"What reads an energy meter connects to it: a connection of a {ConnectionType.MeterReader} is one the other end makes.";
                return false;
            }

            // A grid operator is connected to by its VENs, and connects to none
            // of them: a VEN is what makes the connection.
            if (Type == ConnectionType.GridOperator && Inbound)
            {
                Error = $"A grid operator connects to nothing: a connection to one is one this {NodeNoun ?? NodeWording.Noun} makes.";
                return false;
            }

            if (Type == ConnectionType.VEN && !Inbound)
            {
                Error = $"A VEN connects to its grid operator: a connection of a {ConnectionType.VEN} is one the other end makes.";
                return false;
            }

            // A PKI is connected to by its registration authorities, and connects
            // to none of them: the one that asks to sign makes the connection.
            if (Type == ConnectionType.PKI && Inbound)
            {
                Error = $"A PKI connects to nothing: a connection to one is one this {NodeNoun ?? NodeWording.Noun} makes.";
                return false;
            }

            if (Type == ConnectionType.RegistrationAuthority && !Inbound)
            {
                Error = $"A registration authority connects to its PKI: a connection of a {ConnectionType.RegistrationAuthority} is one the other end makes.";
                return false;
            }

            if (!NamesTheNodeItLeadsTo && RemoteNodeId is not null)
            {
                Error = $"What this {NodeNoun ?? NodeWording.Noun} connects to is its back end, and is spoken to as that: a connection names no node at its other end.";
                return false;
            }

            // A charging station is nobody's back end: it is reached by its name.
            if (Type == ConnectionType.ChargingStation && !Inbound && RemoteNodeId is null)
            {
                Error = "Say which charging station is at the other end - the name it is spoken to by, as a charging station that connects is known by the " +
                        "name its URL ends with. Nothing in the URL of this connection says it: that ends with the name this " +
                        $"{NodeNoun ?? NodeWording.Noun} comes under.";
                return false;
            }

            Error = null;
            return true;

        }

        #endregion

    }

}
