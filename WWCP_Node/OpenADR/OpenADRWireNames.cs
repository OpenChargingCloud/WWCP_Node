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

using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.OpenADR
{

    /// <summary>
    /// What OpenADR 3 is called on the wire, where it goes between a VEN - a
    /// local controller - and the VTN of its grid operator over a WebSocket or
    /// over an SSH subsystem, rather than over HTTPS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two bindings, each with a WebSocket subprotocol and an SSH subsystem of
    /// its own (see <see cref="OpenADRBinding"/>):
    /// </para>
    /// <para>
    /// | binding | WebSocket subprotocol | SSH subsystem | what goes over it |
    /// |---|---|---|---|
    /// | messages | <c>openadr3.1</c> | <c>openadr@open.charging.cloud</c> | the JSON messages of OpenADR, a request, a response or an error in one text message, as OCPP-J has them |
    /// | rest | <c>openadr3.1-rest</c> | <c>openadr-rest@open.charging.cloud</c> | the REST API of OpenADR 3, unchanged, as HTTP/1.1 in the stream of the connection - over a WebSocket in binary messages, read as one stream |
    /// </para>
    /// <para>
    /// Who is at the other end is said by how it signed in - its login - and
    /// which VEN that is by the connection the grid operator wrote down for
    /// it: there is no bearer token on either binding. The VTN is at
    /// <see cref="RestTunnelPath"/> in the tunnel, wherever the grid operator
    /// has it over HTTPS.
    /// </para>
    /// </remarks>
    public static class OpenADRWireNames
    {

        /// <summary>
        /// The WebSocket subprotocol of the JSON messages of OpenADR.
        /// </summary>
        public const String Subprotocol           = "openadr3.1";

        /// <summary>
        /// The SSH subsystem of the JSON messages of OpenADR.
        /// </summary>
        public const String SshSubsystem          = "openadr@open.charging.cloud";

        /// <summary>
        /// The WebSocket subprotocol of the REST API of OpenADR in a tunnel.
        /// </summary>
        public const String RestSubprotocol       = "openadr3.1-rest";

        /// <summary>
        /// The SSH subsystem of the REST API of OpenADR in a tunnel.
        /// </summary>
        public const String RestSshSubsystem      = "openadr-rest@open.charging.cloud";

        /// <summary>
        /// Where the VTN is in the tunnel of its REST API: "/openadr3/" - the
        /// programs, events and reports are below it.
        /// </summary>
        public const String RestTunnelPath        = "/openadr3/";


        #region SubprotocolOf(Binding) / SshSubsystemOf(Binding)

        /// <summary>
        /// The WebSocket subprotocol of the given binding.
        /// </summary>
        public static String SubprotocolOf(OpenADRBinding Binding)

            => Binding == OpenADRBinding.REST
                   ? RestSubprotocol
                   : Subprotocol;

        /// <summary>
        /// The SSH subsystem of the given binding.
        /// </summary>
        public static String SshSubsystemOf(OpenADRBinding Binding)

            => Binding == OpenADRBinding.REST
                   ? RestSshSubsystem
                   : SshSubsystem;

        #endregion

    }

}
