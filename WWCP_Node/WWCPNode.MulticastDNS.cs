/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The addresses a host name or an address stands for, and how they were
    /// found - or why there are none.
    /// </summary>
    /// <param name="Name">What was asked about, as typed.</param>
    /// <param name="Addresses">The addresses, in the order the answer gave them: those of IPv6 first, then those of IPv4.</param>
    /// <param name="Via">How they were found: "address" where the name was one, "DNS", or "Multicast DNS".</param>
    /// <param name="Error">Why there are none; null where there are.</param>
    public sealed record HostAddresses(String                                Name,
                                       IReadOnlyList<System.Net.IPAddress>   Addresses,
                                       String                                Via,
                                       String?                               Error = null)
    {

        /// <summary>
        /// Whether the name stands for at least one address.
        /// </summary>
        public Boolean Found
            => Error is null && Addresses.Count > 0;

    }


    /// <summary>
    /// Names under ".local" asked for by Multicast DNS (RFC 6762) - off unless
    /// the "dns" section says "multicast": { "enabled": true }, on the network
    /// interfaces it names (mDNS-Concept.md, B.1 and B.2).
    /// </summary>
    /// <remarks>
    /// The client and its sockets are made at the first name that needs them,
    /// and not at the start: a node that never asks for a ".local" name never
    /// binds port 5353, which the operating system's own responder may hold
    /// as well. A change of the settings lets go of them; the next name makes
    /// them anew with what is in effect then.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        private readonly SemaphoreSlim         multicastDNSLock  = new (1, 1);
        private          MulticastDNSClient?    multicastDNSClient;
        private          IMulticastDNSTransport? multicastDNSTransport;

        #endregion

        #region Properties

        /// <summary>
        /// Whether names under ".local" are asked for by Multicast DNS. Off
        /// unless the "dns" section says otherwise.
        /// </summary>
        public Boolean                MulticastDNSEnabled       { get; private set; }

        /// <summary>
        /// The network interfaces Multicast DNS asks on, by name; none is every
        /// interface that is up and can multicast, the loopback interface left
        /// out.
        /// </summary>
        public IReadOnlyList<String>  MulticastDNSInterfaces    { get; private set; } = [];

        /// <summary>
        /// Whether the IPv4 group 224.0.0.251 is asked.
        /// </summary>
        public Boolean                MulticastDNSIPv4          { get; private set; } = true;

        /// <summary>
        /// Whether the IPv6 group ff02::fb is asked.
        /// </summary>
        public Boolean                MulticastDNSIPv6          { get; private set; } = true;

        /// <summary>
        /// What makes the transport of Multicast DNS from the options in
        /// effect: UDP on port 5353, unless a test has the node ask on a
        /// network of its own.
        /// </summary>
        public Func<UDPMulticastDNSTransportOptions, IMulticastDNSTransport>  MulticastDNSTransportFactory  { get; set; }

            = options => new UDPMulticastDNSTransport(options);

        #endregion


        #region (private) ApplyMulticastDNSConfiguration(Configuration)

        /// <summary>
        /// Put the object "multicast" of a "dns" section into effect; what it
        /// does not say is left as it is.
        /// </summary>
        /// <returns>What changed, in the words of the log line.</returns>
        private IReadOnlyList<String> ApplyMulticastDNSConfiguration(MulticastDNSConfiguration? Configuration)
        {

            var changed = new List<String>();

            if (Configuration is null)
                return changed;

            if (Configuration.Enabled.HasValue && MulticastDNSEnabled != Configuration.Enabled.Value)
            {
                MulticastDNSEnabled = Configuration.Enabled.Value;
                changed.Add($"multicast DNS {(MulticastDNSEnabled ? "switched on" : "switched off")}");
            }

            if (Configuration.Interfaces is not null && !MulticastDNSInterfaces.SequenceEqual(Configuration.Interfaces))
            {
                MulticastDNSInterfaces = Configuration.Interfaces;
                changed.Add($"multicast DNS interfaces = {(MulticastDNSInterfaces.Count > 0 ? String.Join(", ", MulticastDNSInterfaces) : "all")}");
            }

            // Taken together: one of the two must stay, which the section
            // checked for itself and a second section, saying only the other
            // one, could still undo.
            var ipv4 = Configuration.IPv4 ?? MulticastDNSIPv4;
            var ipv6 = Configuration.IPv6 ?? MulticastDNSIPv6;

            if (!ipv4 && !ipv6)
                Log.Warning("DNS configuration: multicast DNS must keep IPv4 or IPv6, so neither was taken away.", "dns", "config", "mdns");

            else
            {

                if (ipv4 != MulticastDNSIPv4)
                {
                    MulticastDNSIPv4 = ipv4;
                    changed.Add($"multicast DNS over IPv4 = {ipv4}");
                }

                if (ipv6 != MulticastDNSIPv6)
                {
                    MulticastDNSIPv6 = ipv6;
                    changed.Add($"multicast DNS over IPv6 = {ipv6}");
                }

            }

            // The sockets were made with what was in effect before: let go of
            // them, and the next name makes them anew.
            if (changed.Count > 0)
                _ = LetGoOfMulticastDNSAsync();

            return changed;

        }

        #endregion

        #region (private) MulticastDNSClientAsync(CancellationToken)

        /// <summary>
        /// The client of Multicast DNS, made with what is in effect where there
        /// is none yet.
        /// </summary>
        private async Task<MulticastDNSClient> MulticastDNSClientAsync(CancellationToken CancellationToken)
        {

            await multicastDNSLock.WaitAsync(CancellationToken).ConfigureAwait(false);

            try
            {

                if (multicastDNSClient is not null)
                    return multicastDNSClient;

                var transport = MulticastDNSTransportFactory(new UDPMulticastDNSTransportOptions {
                                                                 EnableIPv4      = MulticastDNSIPv4,
                                                                 EnableIPv6      = MulticastDNSIPv6,
                                                                 InterfaceNames  = MulticastDNSInterfaces.Count > 0
                                                                                       ? MulticastDNSInterfaces
                                                                                       : null
                                                             });

                var client    = new MulticastDNSClient(transport, TimeProvider: TimeProvider);

                try
                {
                    await client.StartAsync(CancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await client.DisposeAsync().ConfigureAwait(false);
                    await StopTransportAsync(transport).ConfigureAwait(false);
                    throw;
                }

                multicastDNSTransport  = transport;
                multicastDNSClient     = client;

                Log.Info($"Multicast DNS asks on {(MulticastDNSInterfaces.Count > 0 ? String.Join(", ", MulticastDNSInterfaces) : "every interface that can multicast")}" +
                         $" over {(MulticastDNSIPv4 && MulticastDNSIPv6 ? "IPv4 and IPv6" : MulticastDNSIPv4 ? "IPv4" : "IPv6")}.",
                         "dns", "mdns");

                return client;

            }
            finally
            {
                multicastDNSLock.Release();
            }

        }

        #endregion

        #region (private) LetGoOfMulticastDNSAsync()

        /// <summary>
        /// Close the client of Multicast DNS and its sockets, where there are.
        /// </summary>
        private async Task LetGoOfMulticastDNSAsync()
        {

            await multicastDNSLock.WaitAsync().ConfigureAwait(false);

            try
            {

                var client     = multicastDNSClient;
                var transport  = multicastDNSTransport;

                multicastDNSClient     = null;
                multicastDNSTransport  = null;

                if (client is not null)
                    await client.DisposeAsync().ConfigureAwait(false);

                if (transport is not null)
                    await StopTransportAsync(transport).ConfigureAwait(false);

            }
            catch (Exception e)
            {
                Log.Warning($"Multicast DNS could not be closed: {e.Message}", "dns", "mdns");
            }
            finally
            {
                multicastDNSLock.Release();
            }

        }

        private static async Task StopTransportAsync(IMulticastDNSTransport Transport)
        {

            try
            {
                await Transport.StopAsync().ConfigureAwait(false);
            }
            finally
            {
                if (Transport is IAsyncDisposable disposable)
                    await disposable.DisposeAsync().ConfigureAwait(false);
            }

        }

        #endregion


        #region ResolveHostAsync(Name, CancellationToken = default)

        /// <summary>
        /// The addresses a host name stands for, the way this node finds the
        /// host to connect to: its name servers for a name, Multicast DNS for a
        /// name under ".local" where that is switched on - and an address as it
        /// is, with the interface after a "%" for one of IPv6.
        /// </summary>
        /// <param name="Name">A host name, an IPv4 address, or an IPv6 address - with or without brackets, and with "%" and the name or index of an interface.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        public async Task<HostAddresses> ResolveHostAsync(String             Name,
                                                          CancellationToken  CancellationToken = default)
        {

            var typed = Name?.Trim() ?? "";

            #region An address

            if (typed.Length == 0)
                return new HostAddresses(typed, [], "address", "Name a host or an address.");

            if (TryParseHostAddress(typed, out var address, out var problem))
                return new HostAddresses(typed, [ address ], "address");

            if (problem is not null)
                return new HostAddresses(typed, [], "address", problem);

            #endregion

            if (!DNSEnabled)
                return new HostAddresses(typed, [], "DNS", $"Name resolution is switched off on this {Kind.Name}.");

            if (!DNSServiceName.TryParse(typed, out var serviceName, out var invalid))
                return new HostAddresses(typed, [], "DNS", $"\"{typed}\" is not a host name: {invalid}");

            var multicast = MulticastDNS.IsLocalName(typed);

            if (multicast && !MulticastDNSEnabled)
                return new HostAddresses(typed, [], "Multicast DNS",
                                         $"'{typed}' is a name of Multicast DNS, which is switched off on this {Kind.Name} (dns.multicast.enabled).");

            try
            {

                IDNSClient asking = multicast
                                        ? await MulticastDNSClientAsync(CancellationToken).ConfigureAwait(false)
                                        : dnsClient;

                var answer   = await asking.Query(
                                         serviceName,
                                         [ DNSResourceRecordTypes.AAAA, DNSResourceRecordTypes.A ],
                                         CancellationToken: CancellationToken
                                     ).ConfigureAwait(false);

                var found    = answer.Answers.OfType<AAAA>().Select(record => (System.Net.IPAddress) record.IPv6Address).
                               Concat(answer.Answers.OfType<A>   ().Select(record => (System.Net.IPAddress) record.IPv4Address)).
                               Distinct().
                               ToArray();

                return found.Length > 0
                           ? new HostAddresses(typed, found, multicast ? "Multicast DNS" : "DNS")
                           : new HostAddresses(typed, [], multicast ? "Multicast DNS" : "DNS",
                                               answer.IsTimeout
                                                   ? $"Nobody answered for '{typed}' in time."
                                                   : $"'{typed}' has no address ({RCodeName(answer.ResponseCode)}).");

            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception e)
            {
                return new HostAddresses(typed, [], multicast ? "Multicast DNS" : "DNS", $"'{typed}' could not be resolved: {e.Message}");
            }

        }

        #endregion

        #region (static) TryParseHostAddress(Text, out Address, out Problem)

        /// <summary>
        /// An IPv4 or IPv6 address as somebody types it to reach a host: an
        /// IPv6 address with or without brackets, and with "%" and the name or
        /// the index of the network interface it is reached over - which one
        /// of the link-local addresses (fe80::/10) cannot do without.
        /// </summary>
        /// <param name="Text">What was typed.</param>
        /// <param name="Address">The address, with the index of its interface as its scope.</param>
        /// <param name="Problem">Why it is an address and still cannot be used; null where it is none at all, or can be.</param>
        /// <returns>Whether it is an address that can be used.</returns>
        public static Boolean TryParseHostAddress(String                    Text,
                                                  out System.Net.IPAddress  Address,
                                                  out String?               Problem)
        {

            Address  = System.Net.IPAddress.None;
            Problem  = null;

            var text = Text.Trim();

            if (text.StartsWith('[') && text.EndsWith(']'))
                text = text[1..^1];

            String? scope = null;
            var     at    = text.IndexOf('%');

            if (at >= 0)
            {
                scope = text[(at + 1)..];
                text  = text[..at];
            }

            if (!System.Net.IPAddress.TryParse(text, out var parsed) ||
                // "1234" is an IPv4 address to .NET, and a host name to anybody.
                (parsed.AddressFamily == AddressFamily.InterNetwork && text.Count(c => c == '.') != 3))
            {
                // Not an address: a name, unless it carried an interface, which
                // only an address of IPv6 can.
                if (scope is not null)
                    Problem = $"'{Text.Trim()}' names an interface, which only an IPv6 address can.";
                return false;
            }

            if (parsed.AddressFamily == AddressFamily.InterNetwork)
            {

                if (scope is not null)
                {
                    Problem = $"'{Text.Trim()}' names an interface, which only an IPv6 address can.";
                    return false;
                }

                Address = parsed;
                return true;

            }

            if (scope is not null)
            {

                if (scope.Length == 0)
                {
                    Problem = $"'{Text.Trim()}' has a '%' and no interface after it.";
                    return false;
                }

                if (InterfaceIndexOf(scope) is not Int64 index)
                {
                    Problem = $"This machine has no network interface '{scope}' for IPv6; it has {InterfacesForIPv6()}.";
                    return false;
                }

                parsed.ScopeId = index;

            }

            else if (parsed.IsIPv6LinkLocal)
            {
                Problem = $"'{Text.Trim()}' is a link-local address, which needs its interface: '{text}%<interface>', " +
                          $"with one of {InterfacesForIPv6()}.";
                return false;
            }

            Address = parsed;
            return true;

        }

        /// <summary>
        /// The IPv6 index of the network interface of the given name or
        /// index; null where this machine has none of it.
        /// </summary>
        private static Int64? InterfaceIndexOf(String NameOrIndex)
        {

            if (Int64.TryParse(NameOrIndex, out var index) && index >= 0)
                return index;

            foreach (var networkInterface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {

                if (!networkInterface.Name.Equals(NameOrIndex, StringComparison.OrdinalIgnoreCase) &&
                    !networkInterface.Id.  Equals(NameOrIndex, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    return networkInterface.GetIPProperties().GetIPv6Properties().Index;
                }
                catch (System.Net.NetworkInformation.NetworkInformationException)
                {
                    // An interface without IPv6.
                    return null;
                }

            }

            return null;

        }

        /// <summary>
        /// The network interfaces of this machine that have IPv6, as a list to
        /// say in a sentence.
        /// </summary>
        private static String InterfacesForIPv6()
        {

            var names = new List<String>();

            foreach (var networkInterface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                if (networkInterface.Supports(System.Net.NetworkInformation.NetworkInterfaceComponent.IPv6))
                    names.Add(networkInterface.Name);

            return names.Count > 0
                       ? String.Join(", ", names.Select(name => $"'{name}'"))
                       : "none";

        }

        #endregion


        #region (private) MulticastDNSJSON()

        /// <summary>
        /// How Multicast DNS is set, as the DNS page and the API read it.
        /// </summary>
        private JObject MulticastDNSJSON()

            => new (
                   new JProperty("enabled",     MulticastDNSEnabled),
                   new JProperty("interfaces",  new JArray(MulticastDNSInterfaces)),
                   new JProperty("ipv4",        MulticastDNSIPv4),
                   new JProperty("ipv6",        MulticastDNSIPv6)
               );

        #endregion

    }

}
