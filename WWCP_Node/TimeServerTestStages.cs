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

using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The stages a test of one time server goes through, as the white paper
    /// "Secure Time Synchronization", section 3.2.7, names them: what every
    /// step of <see cref="WWCPNode.TestTimeServerAsync(NTSGroup, String, CancellationToken)"/>
    /// is about, and the one a test that ends without a time ended at.
    /// </summary>
    /// <remarks>
    /// Words and not an enumeration, because they are the words of OCPP's
    /// TimeServerTestStageEnumType, and every way out of a node - the page,
    /// the command line, OCPP - writes them as they are.
    /// </remarks>
    public static class TimeServerTestStages
    {

        /// <summary>
        /// The settings of the client: what is asked, where, on which ports.
        /// </summary>
        public const String Configuration         = "Configuration";

        /// <summary>
        /// The name of the server and the addresses it resolves to.
        /// </summary>
        public const String NameResolution        = "NameResolution";

        /// <summary>
        /// The TCP connection to the NTS-KE server, or the SSH connection.
        /// </summary>
        public const String Connection            = "Connection";

        /// <summary>
        /// The TLS handshake, the certificate chain, the roots and the pins, or
        /// the SSH host key.
        /// </summary>
        public const String ServerAuthentication  = "ServerAuthentication";

        /// <summary>
        /// The NTS-KE records: AEAD algorithm, cookies, and the NTP server and
        /// port they name.
        /// </summary>
        public const String KeyExchange           = "KeyExchange";

        /// <summary>
        /// The NTS-protected NTP request and its answer.
        /// </summary>
        public const String TimeRequest           = "TimeRequest";


        #region Of(KeyExchangeError)

        /// <summary>
        /// The stage a key exchange that failed for the given reason failed at.
        /// </summary>
        /// <remarks>
        /// A timeout is the key exchange's: a connection that could not be made
        /// in time is a TCPConnect, and what times out after it is the exchange.
        /// </remarks>
        /// <param name="KeyExchangeError">Why the key exchange failed.</param>
        public static String Of(NTSKEErrorCategory KeyExchangeError)

            => KeyExchangeError switch {
                   NTSKEErrorCategory.DNS             => NameResolution,
                   NTSKEErrorCategory.TCPConnect      => Connection,
                   NTSKEErrorCategory.TLSHandshake    => ServerAuthentication,
                   NTSKEErrorCategory.TLSCertificate  => ServerAuthentication,
                   _                                  => KeyExchange
               };

        #endregion

        #region Of(TimeRequestError)

        /// <summary>
        /// The stage a time request that failed for the given reason failed at.
        /// </summary>
        /// <remarks>
        /// A time request that had to make a key exchange again, and could not,
        /// failed at the key exchange; one that could not resolve the name of
        /// the NTP server it was named, at name resolution.
        /// </remarks>
        /// <param name="TimeRequestError">Why the time request failed.</param>
        public static String Of(NTSQueryErrorCategory TimeRequestError)

            => TimeRequestError switch {
                   NTSQueryErrorCategory.NTSKE  => KeyExchange,
                   NTSQueryErrorCategory.DNS    => NameResolution,
                   _                            => TimeRequest
               };

        #endregion

    }

}
