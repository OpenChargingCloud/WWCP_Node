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

namespace cloud.charging.open.protocols.WWCP.Node.Modbus
{

    /// <summary>
    /// What Modbus is called on the wire, where it goes over something that is
    /// no TCP connection of its own: a WebSocket and an SSH subsystem.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The frames are those of Modbus/TCP - the MBAP header and the PDU - and
    /// nothing else, in both directions: over SSH one after the other on the
    /// channel, as over a TCP connection; over a WebSocket one frame in one
    /// binary message, and no text message at all.
    /// </para>
    /// <para>
    /// Who is at the other end is said by how it signed in - its login - and
    /// what it may do by the SunSpec role the meter gives that login, as the
    /// role in a client certificate says it over Modbus/TLS.
    /// </para>
    /// </remarks>
    public static class ModbusWireNames
    {

        /// <summary>
        /// The WebSocket subprotocol of Modbus.
        /// </summary>
        public const String Subprotocol   = "modbus";

        /// <summary>
        /// The SSH subsystem of Modbus.
        /// </summary>
        public const String SshSubsystem  = "modbus@open.charging.cloud";

    }

}
