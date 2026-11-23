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

namespace cloud.charging.open.protocols.WWCP.Node.PKI
{

    /// <summary>
    /// What the messages of a PKI are called on the wire, where a registration
    /// authority - a CSMS, say - asks a PKI over a WebSocket or over an SSH
    /// subsystem, rather than over EST or its JSON API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// | WebSocket subprotocol | SSH subsystem | one message is |
    /// |---|---|---|
    /// | <c>pki</c> | <c>pki@open.charging.cloud</c> | one JSON array as OCPP-J frames it: a text message over a WebSocket, a line ended by a line feed over SSH |
    /// </para>
    /// <para>
    /// The frames are those of OCPP-J - <c>[2, "&lt;id&gt;", "&lt;Action&gt;", {...}]</c>
    /// for a request, <c>[3, "&lt;id&gt;", {...}]</c> for its response,
    /// <c>[4, "&lt;id&gt;", "&lt;Code&gt;", "&lt;Text&gt;", {...}]</c> for an error -,
    /// with the actions of <see cref="PKIActions"/>. Who asks is said by how it
    /// signed in - its login - and the connection the PKI wrote down for it.
    /// </para>
    /// </remarks>
    public static class PKIWireNames
    {

        /// <summary>
        /// The WebSocket subprotocol of the messages of a PKI.
        /// </summary>
        public const String  Subprotocol    = "pki";

        /// <summary>
        /// The SSH subsystem of the messages of a PKI.
        /// </summary>
        public const String  SshSubsystem   = "pki@open.charging.cloud";

        /// <summary>
        /// The longest one message may be, in bytes: a CSR, a chain or a CRL of
        /// many certificates fit, and a peer that never ends a line does not
        /// fill the memory of the other end.
        /// </summary>
        public const Int32   MaxMessageSize = 1024 * 1024;

    }

}
