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

using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a port was to be for: the web interface, or something else a kind
    /// of node listens for beside it.
    /// </summary>
    /// <remarks>
    /// Carried rather than written into the sentence, because what to do about
    /// a port that cannot be had depends on which one it was, and the switches
    /// that say so belong to whoever started the node rather than to the node.
    /// A record rather than an enum, because the node knows only the one it
    /// listens for itself; a charging station's display is the station's to
    /// name, and compared by value it is the same wherever it is named.
    /// </remarks>
    /// <param name="Name">What it is called at the start of a sentence: "The web interface".</param>
    public sealed record NodePort(String Name)
    {

        /// <summary>
        /// The web interface, its JSON API and its event stream: the port of
        /// the node itself.
        /// </summary>
        public static readonly NodePort WebInterface = new ("The web interface");

        public override String ToString()
            => Name;

    }


    /// <summary>
    /// A port the node has to have, and cannot get.
    /// </summary>
    /// <remarks>
    /// Until this existed, the whole of what somebody starting a second copy
    /// of the node got was thirteen frames of stack trace under the
    /// operating system's own words for it - on a German Windows, "Normaler-
    /// weise darf jede Socketadresse (Protokoll, Netzwerkadresse oder
    /// Anschluss) nur jeweils einmal verwendet werden", under eleven lines of
    /// English log. The port was named nowhere in it, and where a kind of node
    /// listens on two, neither was which of them had wanted it.
    ///
    /// The reason is carried as the socket error's name rather than as the
    /// operating system's message: the name is the same everywhere, and a
    /// node standing in Germany should not answer in German to somebody
    /// reading the rest of its output in English.
    /// </remarks>
    public sealed class PortUnavailableException : Exception
    {

        #region Properties

        /// <summary>The port that could not be had.</summary>
        public IPPort       Port     { get; }

        /// <summary>What it was to listen for.</summary>
        public NodePort     Whose    { get; }

        /// <summary>Why not, as the socket layer names it.</summary>
        public SocketError  Because  { get; }

        #endregion

        #region Constructor

        /// <summary>
        /// A port that could not be had.
        /// </summary>
        /// <param name="Port">The port.</param>
        /// <param name="Problem">What the socket layer said.</param>
        /// <param name="Whose">What it was to listen for; the web interface unless a kind of node says otherwise.</param>
        public PortUnavailableException(IPPort           Port,
                                        SocketException  Problem,
                                        NodePort?        Whose   = null)

            : base($"{(Whose ?? NodePort.WebInterface).Name} could not be given port {Port}: {Why(Problem.SocketErrorCode)}",
                   Problem)

        {

            this.Port     = Port;
            this.Whose    = Whose ?? NodePort.WebInterface;
            this.Because  = Problem.SocketErrorCode;

        }

        #endregion


        #region (static) Why(Problem)

        /// <summary>
        /// What happened, in a clause rather than in a number.
        /// </summary>
        private static String Why(SocketError Problem)

            => Problem switch {

                   SocketError.AddressAlreadyInUse
                       => "something else is already listening on it",

                   // Windows keeps whole ranges to itself for Hyper-V and for
                   // WSL, and a port inside one of them is refused rather than
                   // taken - which looks nothing like a port in use and is the
                   // harder of the two to work out from a stack trace.
                   SocketError.AccessDenied
                       => "the operating system would not let this node have it",

                   SocketError.AddressNotAvailable
                       => "the address it was to listen on is not one this machine has",

                   _   => $"the socket layer answered {Problem}"

               };

        #endregion

    }

}
