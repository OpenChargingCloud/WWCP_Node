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

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// Ports for a test: one to listen on, and one where a name server would
    /// be that never answers.
    /// </summary>
    /// <remarks>
    /// Every port handed out here, and every one a <see cref="ClosedPort"/>
    /// holds, is remembered for the rest of the test run, and none is handed
    /// out twice. The operating system does hand one out twice: asked for any
    /// free port, Linux picks one at random from some fourteen thousand, and a
    /// test run that asks a thousand times is given the same one again and
    /// again - now and then two that are needed at once. A charging station's
    /// setup was stopped by it, told that its display and its web interface
    /// would both listen on 127.0.0.1:36729.
    /// </remarks>
    public static class TestPorts
    {

        #region Data

        /// <summary>
        /// How often the operating system is asked for a port before this
        /// gives up on it.
        /// </summary>
        public const Int32 MaxAttempts = 100;

        /// <summary>
        /// How often <see cref="StartedOnFreshPorts"/> makes and starts a node
        /// before a port taken under it is said to be taken for good.
        /// </summary>
        public const Int32 StartAttempts = 3;

        /// <summary>
        /// Every port this test run has been handed, one way or another.
        /// </summary>
        private static readonly HashSet<UInt16>  claimed  = [];

        private static readonly Lock             padlock  = new();

        #endregion


        #region Free()

        /// <summary>
        /// A TCP port nobody was listening on a moment ago, and that nobody
        /// else in this test run has been handed.
        /// </summary>
        /// <remarks>
        /// Asked of the operating system rather than counted up from a
        /// constant, so that tests do not fight with a node somebody has
        /// running on its usual port, nor with each other when the runner is
        /// told to parallelise. There is a gap between letting the port go and
        /// binding it again, which nothing here can close; what this buys is
        /// that the gap is milliseconds wide instead of the whole test run.
        /// A port that nothing here can hold for the whole test is one a
        /// <see cref="ClosedPort"/> gives.
        /// </remarks>
        /// <exception cref="InvalidOperationException">The operating system offered nothing but ports this test run already has.</exception>
        public static UInt16 Free()
        {

            var listener = Take(Offer:   () => {
                                             var probe = new TcpListener(IPAddress.Loopback, 0);
                                             probe.Start();
                                             return probe;
                                         },
                                PortOf:  probe => (UInt16) ((IPEndPoint) probe.LocalEndpoint).Port,
                                LetGo:   probe => probe.Stop());

            var port = (UInt16) ((IPEndPoint) listener.LocalEndpoint).Port;

            listener.Stop();

            return port;

        }

        #endregion

        #region TryClaim(Port)

        /// <summary>
        /// Claim a port for the rest of this test run: false, where it was
        /// handed out or claimed already.
        /// </summary>
        /// <remarks>
        /// For a helper that binds a port of its own and holds it, so that
        /// <see cref="Free"/> does not hand the same number to somebody else
        /// once the helper has let go of it - and so that the helper learns
        /// when the operating system gave it a port that <see cref="Free"/>
        /// has just handed out, to somebody who has not bound it yet.
        /// </remarks>
        public static Boolean TryClaim(UInt16 Port)
        {
            lock (padlock)
                return claimed.Add(Port);
        }

        #endregion

        #region StartedOnFreshPorts(Make)

        /// <summary>
        /// A node that Make makes, started - and where a port it was handed was
        /// taken before it could bind it, made again, on fresh ports, and
        /// started again: up to <see cref="StartAttempts"/> times.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The gap between <see cref="Free"/> letting a port go and a node
        /// binding it is one nothing here can close, and a test run of another
        /// assembly or another checkout on the same machine falls into it now
        /// and then. A test that ends in "something else is already listening
        /// on it" has said nothing about the node it was to test - and on one
        /// afternoon, four test runs on one machine lost a test that way.
        /// </para>
        /// <para>
        /// Make is asked again at every attempt, and hands the node fresh ports,
        /// as <see cref="Free"/> does. A start makes its accounts before it
        /// comes to its port: those a failed start made - it made up a password,
        /// so they were not there before - go with it, so that the next start
        /// is a first start as the failed one was, and a test that asks for the
        /// password made up at the first start still has one. Accounts that
        /// were there before stay, and nothing outside the temporary directory
        /// is ever taken away.
        /// </para>
        /// </remarks>
        /// <param name="Make">A new node, on ports nobody has been handed yet.</param>
        /// <exception cref="PortUnavailableException">A port was taken <see cref="StartAttempts"/> times in a row.</exception>
        public static async Task<TNode> StartedOnFreshPorts<TNode>(Func<TNode> Make)

            where TNode : WWCPNode

        {

            for (var attempt = 1; ; attempt++)
            {

                var node = Make();

                try
                {
                    await node.Start();
                    return node;
                }
                catch (PortUnavailableException taken) when (attempt < StartAttempts)
                {

                    TestContext.Progress.WriteLine($"{taken.Message} - started again on fresh ports, attempt {attempt + 1} of {StartAttempts}.");

                    var itsOwnAccounts = node.GeneratedPassword is not null;

                    await node.DisposeAsync();

                    if (itsOwnAccounts)
                        ForgetAccounts(node.AccountsPath);

                }

            }

        }

        #endregion

        #region (private) ForgetAccounts(AccountsPath)

        /// <summary>
        /// Take away the accounts a failed start made - where they are below
        /// the temporary directory, which is where every test keeps them.
        /// </summary>
        private static void ForgetAccounts(String AccountsPath)
        {

            var accounts   = Path.GetFullPath(AccountsPath);
            var temporary  = Path.GetFullPath(Path.GetTempPath());

            if (accounts.StartsWith(temporary, StringComparison.OrdinalIgnoreCase) &&
                accounts.Length > temporary.Length &&
                System.IO.Directory.Exists(accounts))
            {
                System.IO.Directory.Delete(accounts, recursive: true);
            }

        }

        #endregion


        #region (internal) Take(Offer)

        /// <summary>
        /// The first port an offer makes that this test run has not been
        /// handed yet.
        /// </summary>
        internal static UInt16 Take(Func<UInt16> Offer)

            => Take(Offer,
                    PortOf:  port => port,
                    LetGo:   null);

        #endregion

        #region (internal) Take(Offer, PortOf, LetGo)

        /// <summary>
        /// The first thing an offer makes whose port this test run has not been
        /// handed yet - a listener, a socket, a number - claimed as it is taken.
        /// </summary>
        /// <remarks>
        /// What is turned down is held until something is taken, and only then
        /// let go of: let go of at once, it would be the very port the operating
        /// system offers next.
        /// </remarks>
        /// <param name="Offer">Something with a port, a new one at each call.</param>
        /// <param name="PortOf">Its port.</param>
        /// <param name="LetGo">What to do with one that is turned down, once something has been taken.</param>
        /// <exception cref="InvalidOperationException">The offer made nothing but ports this test run already has, <see cref="MaxAttempts"/> times.</exception>
        internal static T Take<T>(Func<T>          Offer,
                                  Func<T, UInt16>  PortOf,
                                  Action<T>?       LetGo)
        {

            var turnedDown = new List<T>();

            try
            {

                for (var attempt = 0; attempt < MaxAttempts; attempt++)
                {

                    var offered = Offer();

                    if (TryClaim(PortOf(offered)))
                        return offered;

                    turnedDown.Add(offered);

                }

            }
            finally
            {
                if (LetGo is not null)
                    foreach (var offered in turnedDown)
                        LetGo(offered);
            }

            throw new InvalidOperationException($"{MaxAttempts} ports were offered, and this test run had been handed every one of them already.");

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
