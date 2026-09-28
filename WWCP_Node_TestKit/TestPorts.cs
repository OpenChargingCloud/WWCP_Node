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

using System.Net;
using System.Net.Sockets;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// Ports for a test: one to listen on, and one where a name server would
    /// be that never answers.
    /// </summary>
    public static class TestPorts
    {

        #region Free()

        /// <summary>
        /// A TCP port nobody was listening on a moment ago.
        /// </summary>
        /// <remarks>
        /// Asked of the operating system rather than counted up from a
        /// constant, so that tests do not fight with a node somebody has
        /// running on its usual port, nor with each other when the runner is
        /// told to parallelise. There is a gap between letting the port go and
        /// binding it again, which nothing here can close; what this buys is
        /// that the gap is milliseconds wide instead of the whole test run.
        /// </remarks>
        public static UInt16 Free()
        {

            var listener = new TcpListener(IPAddress.Loopback, 0);

            listener.Start();

            try
            {
                return (UInt16) ((IPEndPoint) listener.LocalEndpoint).Port;
            }
            finally
            {
                listener.Stop();
            }

        }

        #endregion

    }


    /// <summary>
    /// A name server that never answers: a UDP port on the loopback address
    /// that is held for as long as this is, and read by nobody.
    /// </summary>
    /// <remarks>
    /// Held rather than merely found free, so that the question a test puts to
    /// it is lost for certain - a port that was only free a moment ago may be
    /// somebody's by the time the question arrives, and answer it. A question
    /// asked here times out, which is what a name server that is down looks
    /// like from the node.
    /// </remarks>
    public sealed class SilentNameServer : IDisposable
    {

        private readonly UdpClient socket;

        /// <summary>
        /// The port questions go unanswered on.
        /// </summary>
        public UInt16 Port { get; }

        /// <summary>
        /// Hold a UDP port on the loopback address that nobody reads.
        /// </summary>
        public SilentNameServer()
        {
            socket  = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            Port    = (UInt16) ((IPEndPoint) socket.Client.LocalEndPoint!).Port;
        }

        /// <summary>
        /// Let the port go.
        /// </summary>
        public void Dispose()
            => socket.Dispose();

    }

}
