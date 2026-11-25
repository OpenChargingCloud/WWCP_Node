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

using System.Globalization;
using System.Net.Sockets;
using System.Net.NetworkInformation;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// Send ICMP echo requests to a host, and say what came back: whether the
    /// node reaches it at all, before anything of OCPP, TLS or SSH is asked of
    /// it.
    /// </summary>
    /// <remarks>
    /// "ping csms.example.org", "ping 192.168.1.20", "ping 2001:db8::1",
    /// "ping fe80::1%eth0", "ping lc1.local -c 2". A name is resolved the
    /// way the node resolves a host it connects to - see
    /// <see cref="WWCPNode.ResolveHostAsync"/> -, so that "ping lc1.local"
    /// answers where Multicast DNS is switched on and says that it is not
    /// where it is not, instead of asking the operating system, which might
    /// know the name when the node does not.
    ///
    /// The echo requests are the operating system's (.NET's Ping): on Linux
    /// without the right to open a raw socket that is an ICMP datagram socket
    /// or the ping program, so nothing here needs more rights than the node
    /// has.
    ///
    /// Who may run the DNS test may ping: both find out whether this node
    /// reaches a host it is configured to reach, and neither changes
    /// anything.
    /// </remarks>
    /// <param name="CLI">The command line of the node that pings.</param>
    public class PingCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                            ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as: "PingCommand" without its last seven
        /// characters.
        /// </summary>
        public static readonly String    CommandName      = nameof(PingCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// How many echo requests are sent where nothing is said.
        /// </summary>
        public const           UInt32    DefaultCount     = 4;

        /// <summary>
        /// The most echo requests one command sends: a console waits for all
        /// of them before it shows anything.
        /// </summary>
        public const           UInt32    MaxCount         = 100;

        /// <summary>
        /// How long one echo request waits for its reply.
        /// </summary>
        public static readonly TimeSpan  ReplyTimeout     = TimeSpan.FromSeconds(2);

        /// <summary>
        /// The time between two echo requests where nothing is said.
        /// </summary>
        public static readonly TimeSpan  DefaultInterval  = TimeSpan.FromSeconds(1);

        /// <summary>
        /// The bytes each echo request carries: .NET's, which the ping program
        /// of Linux sends as well.
        /// </summary>
        public const           Int32     PayloadSize      = 32;

        private static readonly String[] Options          = [ "-c", "-i", "-4", "-6" ];

        /// <summary>
        /// What is said where the operating system gave an echo request up the
        /// moment it was asked to send it.
        /// </summary>
        public static readonly String    GaveUpAtOnce     = "the operating system gave up at once, without waiting for a reply - " +
                                                            "as it does where this node may not send ICMP (on Linux: " +
                                                            "net.ipv4.ping_group_range for its group, or cap_net_raw for the ping program).";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
            {

                if (CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                    return [ SuggestionResponse.CommandHelp(Help()) ];

                if (CommandName.StartsWith(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                    return [ SuggestionResponse.CommandCompleted(CommandName) ];

                return [];

            }

            // The host is somebody's to type; after it, the options.
            if (!CommandName.Equals(Arguments[0], StringComparison.CurrentCultureIgnoreCase) ||
                Arguments.Length < 3 ||
                !Arguments[^1].StartsWith('-'))
            {
                return [];
            }

            var before = String.Join(" ", Arguments[..^1]);

            return Options.Where (option => option.StartsWith(Arguments[^1], StringComparison.Ordinal)).
                           Select(option => option == Arguments[^1]
                                                ? SuggestionResponse.ParameterCompleted($"{before} {option}")
                                                : SuggestionResponse.ParameterPrefix   ($"{before} {option}"));

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (Arguments.Length < 2)
                return [ $"Usage: {Help()}" ];

            if (!cli.MayDo(Permission.Run(NodeResources.DNS), CommandName, out var refused))
                return [ refused ];

            if (!TryReadArguments(Arguments, out var host, out var count, out var interval, out var family, out var error))
                return [ error ];

            cli.Node.Log.Info(
                $"{cli.Caller.Asker} asked this {cli.Node.Kind.Name} to ping '{host}'.",
                cli.Caller.Tags("network", "ping")
            );

            #region Where to

            var resolved = await cli.Node.ResolveHostAsync(host, CancellationToken);

            if (!resolved.Found)
                return [ $"ping {host}: {resolved.Error ?? "no address"}" ];

            var usable   = resolved.Addresses.
                                    Where(address => family is null || address.AddressFamily == family).
                                    // A link-local address of IPv6 found by a name
                                    // came without its interface, and cannot be
                                    // sent to.
                                    Where(address => !(address.IsIPv6LinkLocal && address.ScopeId == 0)).
                                    ToArray();

            if (usable.Length == 0)
                return [ $"ping {host}: {resolved.Via} gave {String.Join(", ", resolved.Addresses)}, and none of them " +
                         (family is not null
                              ? $"is an address of {(family == AddressFamily.InterNetwork ? "IPv4" : "IPv6")}."
                              : "can be reached without naming its interface - ping it as <address>%<interface>.") ];

            var target   = usable[0];
            var others   = resolved.Addresses.Where(address => !address.Equals(target)).ToArray();

            #endregion

            var lines    = new List<String> {
                               (resolved.Via == "address"
                                    ? $"PING {Show(target)}"
                                    : $"PING {host} ({Show(target)}, by {resolved.Via})") +
                               $": {count} echo request{(count == 1 ? "" : "s")} of {PayloadSize} bytes"
                           };

            if (others.Length > 0)
                lines.Add($"  {host} is also {String.Join(", ", others.Select(Show))}");

            var times    = new List<Double>();

            using var ping = new Ping();

            for (var sequence = 1U; sequence <= count; sequence++)
            {

                if (sequence > 1)
                    await Task.Delay(interval, cli.Node.TimeProvider, CancellationToken);

                try
                {

                    // No payload and no options of its own: on Linux without the
                    // right to a raw or an ICMP datagram socket, .NET hands the
                    // request to the ping program, which takes neither.
                    var sent  = cli.Node.TimeProvider.GetTimestamp();
                    var reply = await ping.SendPingAsync(target, ReplyTimeout, null, null, CancellationToken);

                    // "Timed out" long before the time was up: nothing was
                    // waited for. On Linux that is the ping program giving up
                    // at once, which .NET reports so - where this node may
                    // open neither a raw nor an ICMP datagram socket, and the
                    // program has no right to one either. Said once, with
                    // where the right comes from, and not tried again.
                    if (reply.Status == IPStatus.TimedOut &&
                        cli.Node.TimeProvider.GetElapsedTime(sent) < ReplyTimeout / 2)
                    {
                        lines.Add($"  seq={sequence}: not sent: {GaveUpAtOnce}");
                        count = sequence;
                        break;
                    }

                    if (reply.Status == IPStatus.Success)
                    {
                        times.Add(reply.RoundtripTime);
                        lines.Add($"  reply from {Show(reply.Address ?? target)}: seq={sequence} time={reply.RoundtripTime} ms" +
                                  (reply.Options?.Ttl is Int32 ttl and > 0 ? $" ttl={ttl}" : ""));
                    }
                    else
                        lines.Add($"  seq={sequence}: {Said(reply.Status)}");

                }
                catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
                {
                    lines.Add($"  stopped after {sequence - 1}");
                    count = sequence - 1;
                    break;
                }
                catch (Exception e) when (e is PingException or InvalidOperationException or PlatformNotSupportedException or SocketException)
                {
                    // The operating system would not send it at all - no right
                    // to, no ping program, no route: said once, and not tried
                    // again a hundred times.
                    lines.Add($"  seq={sequence}: not sent: {(e.InnerException ?? e).Message}");
                    count = sequence;
                    break;
                }

            }

            var received = times.Count;
            var lost     = count == 0 ? 0 : (count - received) * 100.0 / count;

            lines.Add($"--- {host}: {count} sent, {received} received, " +
                      $"{lost.ToString("0.#", CultureInfo.InvariantCulture)} % lost" +
                      (received > 0
                           ? $"; round trip min/avg/max {times.Min().ToString("0.#", CultureInfo.InvariantCulture)}/" +
                                                      $"{times.Average().ToString("0.#", CultureInfo.InvariantCulture)}/" +
                                                      $"{times.Max().ToString("0.#", CultureInfo.InvariantCulture)} ms"
                           : ""));

            return [.. lines];

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <host> [-c <count>] [-i <seconds>] [-4|-6] - send ICMP echo requests to a host name, an IPv4 " +
               $"address or an IPv6 address (fe80::1%eth0 with its interface), {DefaultCount} where no count is said, one a " +
                "second; a name is resolved the way this node resolves the hosts it connects to, a name under .local by " +
                "Multicast DNS where that is switched on";

        #endregion


        #region (static) TryReadArguments(Arguments, out Host, out Count, out Interval, out Family, out Error)

        /// <summary>
        /// The host and the options, in any order after the command.
        /// </summary>
        public static Boolean TryReadArguments(String[]            Arguments,
                                               out String          Host,
                                               out UInt32          Count,
                                               out TimeSpan        Interval,
                                               out AddressFamily?  Family,
                                               out String          Error)
        {

            Host      = "";
            Count     = DefaultCount;
            Interval  = DefaultInterval;
            Family    = null;
            Error     = "";

            String? host = null;

            for (var i = 1; i < Arguments.Length; i++)
            {

                var argument = Arguments[i].Trim();

                switch (argument)
                {

                    case "-4":
                    case "-6":
                        var wanted = argument == "-4" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                        if (Family is not null && Family != wanted)
                        {
                            Error = "Say -4 or -6, not both.";
                            return false;
                        }
                        Family = wanted;
                        break;

                    case "-c":
                        if (i + 1 >= Arguments.Length ||
                            !UInt32.TryParse(Arguments[++i], NumberStyles.None, CultureInfo.InvariantCulture, out var count) ||
                            count < 1 || count > MaxCount)
                        {
                            Error = $"-c takes a count from 1 to {MaxCount}.";
                            return false;
                        }
                        Count = count;
                        break;

                    case "-i":
                        if (i + 1 >= Arguments.Length ||
                            !Double.TryParse(Arguments[++i], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var seconds) ||
                            seconds < 0.2 || seconds > 60)
                        {
                            Error = "-i takes the seconds between two echo requests, from 0.2 to 60.";
                            return false;
                        }
                        Interval = TimeSpan.FromSeconds(seconds);
                        break;

                    default:
                        if (argument.StartsWith('-') && argument.Length > 1 && !Char.IsDigit(argument[1]))
                        {
                            Error = $"'{argument}' is no option of {CommandName}; there are -c, -i, -4 and -6.";
                            return false;
                        }
                        if (host is not null)
                        {
                            Error = $"Ping one host at a time, not '{host}' and '{argument}'.";
                            return false;
                        }
                        host = argument;
                        break;

                }

            }

            if (host is null)
            {
                Error = "Name the host to ping.";
                return false;
            }

            Host = host;

            // An address says its family itself.
            if (Family is not null &&
                WWCPNode.TryParseHostAddress(host, out var address, out _) &&
                address.AddressFamily != Family)
            {
                Error = $"'{host}' is an address of {(address.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6")}, " +
                        $"and {(Family == AddressFamily.InterNetwork ? "-4" : "-6")} was said.";
                return false;
            }

            return true;

        }

        #endregion

        #region (private static) Show(Address) / Said(Status)

        /// <summary>
        /// An address as it is typed: an IPv6 address with its interface by
        /// index after a "%", where it has one.
        /// </summary>
        private static String Show(System.Net.IPAddress Address)
            => Address.ToString();

        /// <summary>
        /// What a reply that was not one says, in words.
        /// </summary>
        private static String Said(IPStatus Status)

            => Status switch {
                   IPStatus.TimedOut                    => "no reply within " + ReplyTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture) + " s",
                   IPStatus.DestinationHostUnreachable  => "the host is unreachable",
                   IPStatus.DestinationNetworkUnreachable => "the network is unreachable",
                   IPStatus.DestinationUnreachable      => "unreachable",
                   IPStatus.TimeExceeded or
                   IPStatus.TtlExpired                  => "the time to live ran out on the way",
                   IPStatus.PacketTooBig                => "the packet was too big",
                   _                                    => Status.ToString()
               };

        #endregion

    }

}
