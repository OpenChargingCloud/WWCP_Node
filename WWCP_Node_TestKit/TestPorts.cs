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
    ///
    /// Windows hands them out one after another, upwards, to every process
    /// alike, and comes round again to the ports a test run has been handed -
    /// by then a stretch of them, hundreds in a row. Where the operating
    /// system offers one of those, a port is looked for elsewhere: at random
    /// among the dynamic ports, from <see cref="LowestDynamicPort"/> up. Asked
    /// again, Windows offered the next one up, until a hundred had been
    /// offered: a charging station's test run at four cores was told so in
    /// the set-up of a test or two, in three runs of six.
    /// </remarks>
    public static class TestPorts
    {

        #region Data

        /// <summary>
        /// How many ports are tried - the one the operating system offers, and
        /// then others - before this gives up.
        /// </summary>
        public const Int32 MaxAttempts = 100;

        /// <summary>
        /// The lowest of the dynamic ports - IANA's, from here to 65535 - among
        /// which a port is looked for where the operating system offered one
        /// this test run has been handed already. Windows hands these out to
        /// anybody who asks for any free port, and Linux, by default, those up
        /// to 60999.
        /// </summary>
        public const UInt16 LowestDynamicPort = 49152;

        /// <summary>
        /// How often <see cref="StartedOnFreshPorts"/> makes and starts a node
        /// before a port taken under it is said to be taken for good.
        /// </summary>
        public const Int32 StartAttempts = 3;

        /// <summary>
        /// How often a socket is asked for where the operating system had no
        /// buffer space left for one - WSAENOBUFS, 10055 - before that stands.
        /// </summary>
        public const Int32 RoomAttempts = 5;

        /// <summary>
        /// Every port this test run has been handed, one way or another.
        /// </summary>
        private static readonly HashSet<UInt16>  claimed  = [];

        private static readonly Lock             padlock  = new();

        #endregion


        #region Free()

        /// <summary>
        /// A TCP port nobody held a moment ago, on any address, and that nobody
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
        ///
        /// The port is tried as a <see cref="ClosedPort"/> holds its own: bound
        /// on [::], for both families, and exclusively, so that a port somebody
        /// holds on any address is passed over. A port looked for elsewhere is
        /// bound by its number, and Windows binds a listener on 127.0.0.1 next
        /// to somebody else's on 0.0.0.0 - which the port's probe used to be.
        /// </remarks>
        /// <exception cref="InvalidOperationException">No port was found that this test run had not been handed and that nobody else held.</exception>
        public static UInt16 Free()

            => Free(Holding:    port => ClosedPort.Bind(port, Exclusively: true),
                    Pause:      TimeSpan.FromMilliseconds(200),
                    Elsewhere:  null);

        /// <summary>
        /// A port from a socket Holding holds - asked again, after a pause,
        /// where the operating system had no buffer space left for a socket.
        /// </summary>
        /// <param name="Holding">A socket bound to the given port; at port 0, to one of the operating system's choice.</param>
        /// <param name="Pause">How long to wait before asking again the first time; the second waits twice as long, and so on.</param>
        /// <param name="Elsewhere">Where to look once the operating system offered a port handed out already; at random among the dynamic ports, where none is given.</param>
        internal static UInt16 Free(Func<UInt16, Socket>  Holding,
                                    TimeSpan              Pause,
                                    Func<UInt16>?         Elsewhere)
        {

            using var holder = Take(Bound:      port   => OnceThereIsRoom(() => Holding(port), Pause),
                                    PortOf:     socket => (UInt16) ((IPEndPoint) socket.LocalEndPoint!).Port,
                                    LetGo:      socket => socket.Dispose(),
                                    Elsewhere:  Elsewhere);

            return (UInt16) ((IPEndPoint) holder.LocalEndPoint!).Port;

        }

        #endregion

        #region (internal) OnceThereIsRoom(Make, Pause, Wait = null)

        /// <summary>
        /// What Make makes, made again after a pause where the operating system
        /// had no buffer space left for a socket - WSAENOBUFS (10055): up to
        /// <see cref="RoomAttempts"/> times, and then what it said stands.
        /// </summary>
        /// <remarks>
        /// Seen while the whole suites of several test runs ran on one machine
        /// at once: WWCP_Node's lost a test in its set-up, at Free's
        /// TcpListener.Start, and passed on the next run (found by the charging
        /// station). The room comes back as closed connections leave
        /// TIME_WAIT, so each pause is longer than the one before. Any other
        /// refusal stands at once.
        /// </remarks>
        /// <param name="Make">A socket, or what holds one.</param>
        /// <param name="Pause">How long to wait before asking again the first time; the second waits twice as long, and so on.</param>
        /// <param name="Wait">What waits; Thread.Sleep where none is given.</param>
        internal static T OnceThereIsRoom<T>(Func<T>             Make,
                                             TimeSpan            Pause,
                                             Action<TimeSpan>?   Wait = null)
        {

            for (var attempt = 1; ; attempt++)
            {

                try
                {
                    return Make();
                }
                catch (SocketException full) when (full.SocketErrorCode == SocketError.NoBufferSpaceAvailable && attempt < RoomAttempts)
                {
                    TestContext.Progress.WriteLine($"No buffer space for a socket: {full.Message} - asked again in {(Pause * attempt).TotalMilliseconds:0} ms, " +
                                                   $"attempt {attempt + 1} of {RoomAttempts}.");
                    (Wait ?? Thread.Sleep)(Pause * attempt);
                }

            }

        }

        #endregion

        #region TryClaim(Port)

        /// <summary>
        /// Claim a port for the rest of this test run: false, where it was
        /// handed out or claimed already.
        /// </summary>
        /// <remarks>
        /// For a helper that binds a port of its own and holds it, so that
        /// <see cref="Free()"/> does not hand the same number to somebody else
        /// once the helper has let go of it - and so that the helper learns
        /// when the operating system gave it a port that <see cref="Free()"/>
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
        /// The gap between <see cref="Free()"/> letting a port go and a node
        /// binding it is one nothing here can close, and a test run of another
        /// assembly or another checkout on the same machine falls into it now
        /// and then. A test that ends in "something else is already listening
        /// on it" has said nothing about the node it was to test - and on one
        /// afternoon, four test runs on one machine lost a test that way.
        /// </para>
        /// <para>
        /// Make is asked again at every attempt, and hands the node fresh ports,
        /// as <see cref="Free()"/> does. A start makes its accounts before it
        /// comes to its port: those a failed start made - it made up a password,
        /// so they were not there before - go with it, so that the next start
        /// is a first start as the failed one was, and a test that asks for the
        /// password made up at the first start still has one. Accounts that
        /// were there before stay, and nothing outside the temporary directory
        /// is ever taken away.
        /// </para>
        /// <para>
        /// A node whose start is given up on, or fails for another reason than
        /// a taken port, is let go of before the start ends in what it failed
        /// with: nobody else ever gets to see it.
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
                catch
                {
                    // Given up on, or failed for another reason: nobody else
                    // ever gets to see this node, to let it go.
                    await node.DisposeAsync();
                    throw;
                }

            }

        }

        #endregion

        #region StartedOnAFreshPort(Make, Start)

        /// <summary>
        /// A server that is no node - a stub of a peer a test needs answered -
        /// made on a port <see cref="Free()"/> hands out and started, and where
        /// that port was taken before it could be bound, made again on a fresh
        /// one: up to <see cref="StartAttempts"/> times, as
        /// <see cref="StartedOnFreshPorts"/> does for a node.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A port counts as taken where starting ends in a SocketException
        /// that says so: AddressAlreadyInUse, or AccessDenied, which is what
        /// Windows says of a port another socket holds for itself - a
        /// <see cref="ClosedPort"/>'s. The hub's stub OCPI peers had a loop of
        /// their own for this, and the hub proposed that every kind have one.
        /// </para>
        /// <para>
        /// A server given up on, or whose start failed for another reason, is
        /// let go of before the start ends in what it failed with.
        /// </para>
        /// </remarks>
        /// <typeparam name="TServer">What is made and started.</typeparam>
        /// <param name="Make">A new server on the given port, not started yet.</param>
        /// <param name="Start">What starts it.</param>
        /// <exception cref="SocketException">The port was taken <see cref="StartAttempts"/> times in a row.</exception>
        public static async Task<TServer> StartedOnAFreshPort<TServer>(Func<UInt16, TServer>  Make,
                                                                       Func<TServer, Task>    Start)

            where TServer : IAsyncDisposable

        {

            for (var attempt = 1; ; attempt++)
            {

                var server = Make(Free());

                try
                {
                    await Start(server);
                    return server;
                }
                catch (SocketException taken) when (IsTaken(taken) && attempt < StartAttempts)
                {
                    TestContext.Progress.WriteLine($"{taken.Message} - made again on a fresh port, attempt {attempt + 1} of {StartAttempts}.");
                    await server.DisposeAsync();
                }
                catch
                {
                    await server.DisposeAsync();
                    throw;
                }

            }

        }

        #endregion

        #region (private static) IsTaken(Refusal)

        /// <summary>
        /// Whether a socket was refused its port because somebody else has it.
        /// </summary>
        private static Boolean IsTaken(SocketException Refusal)

            => Refusal.SocketErrorCode is SocketError.AddressAlreadyInUse
                                       or SocketError.AccessDenied;

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


        #region (internal) Take(Bound, Elsewhere)

        /// <summary>
        /// The first port Bound makes of a port asked for - 0 at first, for the
        /// operating system's choice - that this test run has not been handed
        /// yet.
        /// </summary>
        internal static UInt16 Take(Func<UInt16, UInt16>  Bound,
                                    Func<UInt16>?         Elsewhere)

            => Take(Bound,
                    PortOf:     port => port,
                    LetGo:      null,
                    Elsewhere:  Elsewhere);

        #endregion

        #region (internal) Take(Bound, PortOf, LetGo, Elsewhere)

        /// <summary>
        /// The first thing bound to a port that this test run has not been
        /// handed yet - a socket, a number - claimed as it is taken: one on a
        /// port of the operating system's choice, and where it offered one
        /// handed out already, one on a port looked for elsewhere.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The operating system is asked once. Asked again, it would offer one
        /// handed out already again: Windows offers the next port up, and once
        /// it has come round to the ports a test run has been handed, a stretch
        /// of them follows. Elsewhere is a port this test run has not been
        /// handed; one that somebody else holds, or that may not be bound at
        /// all - Windows keeps ranges of the dynamic ports for itself - is
        /// passed over.
        /// </para>
        /// <para>
        /// What is turned down is held until something is taken, and only then
        /// let go of: let go of at once, it would be the very port the operating
        /// system offers to whoever asks next.
        /// </para>
        /// </remarks>
        /// <param name="Bound">Something bound to the given port, a new one at each call; at port 0, to one of the operating system's choice.</param>
        /// <param name="PortOf">Its port.</param>
        /// <param name="LetGo">What to do with one that is turned down, once something has been taken.</param>
        /// <param name="Elsewhere">The port to try next; at random among the dynamic ports this test run has not been handed, where none is given.</param>
        /// <exception cref="InvalidOperationException">No port was found that this test run had not been handed and that nobody else held, in <see cref="MaxAttempts"/> attempts.</exception>
        internal static T Take<T>(Func<UInt16, T>  Bound,
                                  Func<T, UInt16>  PortOf,
                                  Action<T>?       LetGo,
                                  Func<UInt16>?    Elsewhere)
        {

            var turnedDown = new List<T>();

            try
            {

                for (var attempt = 0; attempt < MaxAttempts; attempt++)
                {

                    T offered;

                    if (attempt == 0)
                        offered = Bound(0);

                    else
                    {
                        try
                        {
                            offered = Bound((Elsewhere ?? AnUnclaimedDynamicPort)());
                        }
                        catch (SocketException taken) when (IsTaken(taken))
                        {
                            continue;
                        }
                    }

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

            throw new InvalidOperationException($"{MaxAttempts} ports were tried, and every one of them had been handed out in this test run already or was held by somebody else.");

        }

        #endregion

        #region (internal) Unclaimed(Pick)

        /// <summary>
        /// A port Pick picks that this test run has not been handed - or, where
        /// <see cref="MaxAttempts"/> picks found none, the last one picked,
        /// which is turned down then as it is taken.
        /// </summary>
        /// <param name="Pick">A port, at each call.</param>
        internal static UInt16 Unclaimed(Func<UInt16> Pick)
        {
            lock (padlock)
            {

                var port = Pick();

                for (var picked = 1; picked < MaxAttempts && claimed.Contains(port); picked++)
                    port = Pick();

                return port;

            }
        }

        #endregion

        #region (internal) ADynamicPort()

        /// <summary>
        /// One of the dynamic ports, from <see cref="LowestDynamicPort"/> to
        /// 65535, at random.
        /// </summary>
        internal static UInt16 ADynamicPort()

            => (UInt16) Random.Shared.Next(LowestDynamicPort, UInt16.MaxValue + 1);

        #endregion

        #region (private static) AnUnclaimedDynamicPort()

        /// <summary>
        /// One of the dynamic ports, at random, that this test run has not been
        /// handed.
        /// </summary>
        private static UInt16 AnUnclaimedDynamicPort()

            => Unclaimed(ADynamicPort);

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
