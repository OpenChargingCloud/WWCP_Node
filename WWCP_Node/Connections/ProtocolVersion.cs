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

namespace cloud.charging.open.protocols.WWCP.Node.Connections
{

    /// <summary>
    /// Which protocol a connection carries, and in which version: OCPP 2.1,
    /// OCPI 2.2.1 - see <see cref="ConnectionEntry.Protocol"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What a server of a node lets in is said by it: a server speaks one
    /// version of one protocol - the node of OCPP 2.1 has one, the node of
    /// OCPP 1.6 another, OCPI one per version - and a connection the other end
    /// makes is let in at the server of its own, and at no other (see
    /// WWCPNode.Accepting.cs).
    /// </para>
    /// <para>
    /// Every version of OCPP is one, as it is written: "OCPP2.1". A version of
    /// OCPI is written as OCPI labels it, behind the protocol's name: "OCPI 2.2.1".
    /// </para>
    /// </remarks>
    /// <param name="Use">The protocol.</param>
    /// <param name="Version">Its version, as the protocol writes it: "2.1" of OCPP, "2.2.1" of OCPI.</param>
    public readonly record struct ProtocolVersion(ConnectionUse  Use,
                                                  String         Version)
    {

        #region (static) OCPI(Version)

        /// <summary>
        /// The given version of OCPI: "2.1.1", "2.2.1" or "2.3.0".
        /// </summary>
        /// <param name="Version">The version, as OCPI labels it.</param>
        public static ProtocolVersion OCPI(String Version)

            => new (ConnectionUse.OCPI, Version);

        #endregion

        #region (static) Modbus

        /// <summary>
        /// Modbus, which has no version: the frames of Modbus/TCP.
        /// </summary>
        public static ProtocolVersion Modbus { get; } = new (ConnectionUse.Modbus, "");

        #endregion

        #region (implicit) ProtocolVersion(OCPPVersion)

        /// <summary>
        /// The given version of OCPP.
        /// </summary>
        /// <param name="Version">The version of OCPP.</param>
        public static implicit operator ProtocolVersion(OCPPVersion Version)

            => new (ConnectionUse.OCPP,
                    Version == OCPPVersion.OCPP1_6
                        ? "1.6"
                        : "2.1");

        #endregion

        #region (override) ToString()

        /// <summary>
        /// The protocol and its version, as the log and the page say it:
        /// "OCPP2.1", as a version of OCPP is always written - see
        /// <see cref="ConnectionEntry.AsText(OCPPVersion)"/> -, and "OCPI 2.2.1".
        /// </summary>
        public override String ToString()

            => Use switch {
                   ConnectionUse.OCPI    => $"OCPI {Version}",
                   ConnectionUse.Modbus  => "Modbus",
                   _                     => $"OCPP{Version}"
               };

        #endregion

    }

}
