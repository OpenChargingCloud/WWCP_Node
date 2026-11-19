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
    /// How a client of a WebSocket server may say who it is: by HTTP
    /// authentication over a connection without TLS, by HTTP authentication
    /// over TLS, or by the certificate it shows in its TLS handshake.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What a WebSocket server lets in, whatever its subprotocols speak: the
    /// one port of a node is the same door for OCPP 1.6, OCPP 2.1 and what may
    /// come later, and how a client authenticates at it is no question of the
    /// subprotocol it asks for.
    /// </para>
    /// <para>
    /// OCPP calls the three its security profiles 1, 2 and 3 - see
    /// OCPP.Node.Serving.ClientAuthenticationProfiles.
    /// </para>
    /// </remarks>
    public enum WebSocketClientAuthentication
    {

        /// <summary>
        /// HTTP authentication - a password, a one-time password or a token -
        /// over a connection without TLS, where the credential crosses the
        /// network in the clear. OCPP's security profile 1.
        /// </summary>
        HTTPAuthWithoutTLS,

        /// <summary>
        /// HTTP authentication over TLS. OCPP's security profile 2.
        /// </summary>
        HTTPAuthOverTLS,

        /// <summary>
        /// The client certificate shown in the TLS handshake, or the key of it
        /// pinned. OCPP's security profile 3.
        /// </summary>
        TLSClientCertificate

    }


    /// <summary>
    /// How the ways a client may authenticate are written, and what OCPP calls
    /// them.
    /// </summary>
    public static class WebSocketClientAuthentications
    {

        #region Data

        /// <summary>
        /// Every way, in the order OCPP numbers them.
        /// </summary>
        public static readonly WebSocketClientAuthentication[] All = [
                                                                         WebSocketClientAuthentication.HTTPAuthWithoutTLS,
                                                                         WebSocketClientAuthentication.HTTPAuthOverTLS,
                                                                         WebSocketClientAuthentication.TLSClientCertificate
                                                                     ];

        /// <summary>
        /// How each is written in a configuration file and over the HTTP API.
        /// </summary>
        public static readonly String[] Names = [ "httpAuthWithoutTLS", "httpAuthOverTLS", "tlsClientCertificate" ];

        #endregion


        #region ToText   (this Authentication)

        /// <summary>
        /// How the given way is written.
        /// </summary>
        public static String ToText(this WebSocketClientAuthentication Authentication)

            => Names[(Int32) Authentication];

        #endregion

        #region TryParse (Text, out Authentication)

        /// <summary>
        /// The way the given text names - or false, where it names none.
        /// </summary>
        public static Boolean TryParse(String?                            Text,
                                       out WebSocketClientAuthentication  Authentication)
        {

            var index = Array.IndexOf(Names, Text);

            Authentication = index >= 0
                                 ? (WebSocketClientAuthentication) index
                                 : default;

            return index >= 0;

        }

        #endregion

        #region IsOverTLS(this Authentication)

        /// <summary>
        /// Whether the given way needs a server that speaks TLS.
        /// </summary>
        public static Boolean IsOverTLS(this WebSocketClientAuthentication Authentication)

            => Authentication != WebSocketClientAuthentication.HTTPAuthWithoutTLS;

        #endregion

    }

}
