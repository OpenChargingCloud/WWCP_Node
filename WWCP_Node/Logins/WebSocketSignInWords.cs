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

namespace cloud.charging.open.protocols.WWCP.Node.Logins
{

    /// <summary>
    /// What the sign-in checks of a WebSocket port call the port, the ones
    /// who come to it and the ways they authenticate, in what they say -
    /// see <see cref="WebSocketSignIns"/>.
    /// </summary>
    /// <remarks>
    /// The kind's words, and not the checks': a node of OCPP calls its port
    /// "the station port" and the ways a client authenticates its security
    /// profiles, and what the log and a refusal have always said there is
    /// said there still. A node that serves no OCPP says what is written
    /// here when nothing says otherwise.
    /// </remarks>
    public sealed class WebSocketSignInWords
    {

        #region Properties

        /// <summary>
        /// The port, in the middle of a sentence: "the station port".
        /// </summary>
        public String                                      Port              { get; init; } = "the WebSocket port";

        /// <summary>
        /// Who comes to it, at the start of a sentence: "A charging station or
        /// a back end".
        /// </summary>
        public String                                      Who               { get; init; } = "A client";

        /// <summary>
        /// Whose a key pin is, where it is a login's: "the charging station" in
        /// "which is the charging station 'cs001''s".
        /// </summary>
        public String                                      PinnedLogin       { get; init; } = "the WebSocket login";

        /// <summary>
        /// The realm of the challenges of a refusal: "OCPP".
        /// </summary>
        public String                                      Realm             { get; init; } = "WWCP";

        /// <summary>
        /// What the log says a sign-in at the port is about - "auth" or "tls"
        /// is added: "ocpp", "station".
        /// </summary>
        public String[]                                    Tags              { get; init; } = [ "websocket" ];

        /// <summary>
        /// What the log says a sign-in of a connection the other end makes is
        /// about - "auth" is added: "ocpp", "csms".
        /// </summary>
        public String[]                                    InboundTags       { get; init; } = [ "websocket", "inbound" ];

        /// <summary>
        /// A way a client may authenticate, in words: "security profile 2".
        /// </summary>
        public Func<WebSocketClientAuthentication, String>  Authentication    { get; init; } = Describe;

        #endregion


        #region (static) Describe(Authentication)

        /// <summary>
        /// A way a client may authenticate, in words, when nothing says
        /// otherwise: "HTTP authentication over TLS".
        /// </summary>
        public static String Describe(WebSocketClientAuthentication Authentication)

            => Authentication switch {
                   WebSocketClientAuthentication.HTTPAuthWithoutTLS    => "HTTP authentication without TLS",
                   WebSocketClientAuthentication.HTTPAuthOverTLS       => "HTTP authentication over TLS",
                   _                                                   => "a TLS client certificate"
               };

        #endregion

    }

}
