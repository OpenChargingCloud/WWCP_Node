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

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Why a test query asked nothing at all: the reason codes of QueryDNS in
    /// the white paper "Advanced Diagnostics for OCPP".
    /// </summary>
    /// <remarks>
    /// Where a node says why nothing was asked, it says it in one of these, so
    /// that OCPP's Rejected, the command line and the web interface name the
    /// same reasons. A question that was put and came back with nothing - a
    /// timeout, NXDomain, a certificate that was refused - is none of them:
    /// that is an answer, and QueryDNS reports it as Accepted.
    ///
    /// Each at most 20 characters, the length of a reasonCode of OCPP 2.x.
    /// </remarks>
    public static class DNSQueryRefusals
    {

        /// <summary>
        /// Name resolution is switched off.
        /// </summary>
        public const String Disabled            = "Disabled";

        /// <summary>
        /// The name server asked for is none of the configured ones.
        /// </summary>
        public const String UnknownServer       = "UnknownServer";

        /// <summary>
        /// The name server asked for is configured by its domain name, and
        /// cannot be asked on its own without first resolving it.
        /// </summary>
        public const String ServerByName        = "ServerByName";

        /// <summary>
        /// The name is neither a domain name nor an IP address.
        /// </summary>
        public const String InvalidName         = "InvalidName";

        /// <summary>
        /// A record type is neither a mnemonic nor a number.
        /// </summary>
        public const String InvalidRecordType   = "InvalidRecordType";

        /// <summary>
        /// More record types were asked for than one query may ask for.
        /// </summary>
        public const String TooManyRecordTypes  = "TooManyRecordTypes";

    }

}
