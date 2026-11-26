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

using org.GraphDefined.Vanaheimr.Hermod;
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
    /// The name resolution of a node as every connection it makes is given
    /// it: names under ".local" and the link-local reverse zones by Multicast
    /// DNS where the node has that switched on, every other name by the
    /// node's DNS client - and with Multicast DNS off, those too, which
    /// answers them NXDOMAIN without asking anybody (RFC 6762 section 22.1).
    /// </summary>
    /// <remarks>
    /// Asked at every query whether Multicast DNS is on, so that a connection
    /// made before a change follows it at its next attempt. Not disposed by
    /// whoever is given it: both clients behind it are the node's.
    /// </remarks>
    public sealed class NodeNameResolver : IDNSClientWithDNSSEC
    {

        private readonly WWCPNode node;

        internal NodeNameResolver(WWCPNode Node)
        {
            this.node = Node;
        }

        /// <summary>
        /// Whether the given name is one for Multicast DNS, and asked by it now.
        /// </summary>
        private Boolean ByMulticast(String Name)
            => node.MulticastDNSEnabled && MulticastDNS.IsLocalName(Name);

        public Boolean DnssecOK
        {
            get => node.DNSClient.DnssecOK;
            set => node.DNSClient.DnssecOK = value;
        }

        public Task<DNSInfo> Query(DomainName                           DomainName,
                                   IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                                   TimeSpan?                            Timeout             = null,
                                   Boolean?                             RecursionDesired    = null,
                                   Boolean?                             ForceUpdate         = false,
                                   CancellationToken                    CancellationToken   = default)

            => ByMulticast(DomainName.FullName)
                   ? node.QueryByMulticastDNSAsync(DNSServiceName.Parse(DomainName.FullName), ResourceRecordTypes, Timeout, ForceUpdate, CancellationToken)
                   : node.DNSClient.Query(DomainName, ResourceRecordTypes, Timeout, RecursionDesired, ForceUpdate, CancellationToken);

        public Task<DNSInfo> Query(DNSServiceName                       DNSServiceName,
                                   IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                                   TimeSpan?                            Timeout             = null,
                                   Boolean?                             RecursionDesired    = null,
                                   Boolean?                             ForceUpdate         = false,
                                   CancellationToken                    CancellationToken   = default)

            => ByMulticast(DNSServiceName.ToString())
                   ? node.QueryByMulticastDNSAsync(DNSServiceName, ResourceRecordTypes, Timeout, ForceUpdate, CancellationToken)
                   : node.DNSClient.Query(DNSServiceName, ResourceRecordTypes, Timeout, RecursionDesired, ForceUpdate, CancellationToken);

        public void Dispose()
        { }

        public ValueTask DisposeAsync()
            => ValueTask.CompletedTask;

        public override String ToString()
            => node.MulticastDNSEnabled
                   ? $"{node.Kind.Name} name resolution: .local by Multicast DNS, others by {node.DNSClient}"
                   : $"{node.Kind.Name} name resolution: {node.DNSClient}";

    }


    /// <summary>
    /// Names under ".local" asked for by Multicast DNS (RFC 6762) - off unless
    /// the "dns" section says "multicast": { "enabled": true }, on the network
    /// interfaces it names - and the node's own name answered there, where
    /// "multicast": { "responder": { "enabled": true } } says so
    /// (mDNS-Concept.md, B.1 to B.3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The client and the responder share one transport: one socket for each
    /// address family on port 5353, as RFC 6762 has a host keep. It is made at
    /// the first name that needs it, or when the node starts with its
    /// responder on - not before: a node that neither asks for a ".local" name
    /// nor answers for its own never binds port 5353, which the operating
    /// system's own responder may hold as well. A change of the settings lets
    /// go of all of it; the responder is started anew, the client at the next
    /// name.
    /// </para>
    /// <para>
    /// The responder publishes an A record for each IPv4 address and an AAAA
    /// record for each IPv6 address of the chosen interfaces, the loopback
    /// interface left out (Q5), under "&lt;hostName&gt;.local", and probes for
    /// the name first. Where another host has it, that is said and shown, and
    /// the node does not rename itself (Q3): a station was configured with the
    /// name.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        private readonly SemaphoreSlim             multicastDNSLock  = new (1, 1);
        private          MulticastDNSClient?        multicastDNSClient;
        private          IMulticastDNSTransport?    multicastDNSTransport;
        private          MulticastDNSResponder?     multicastDNSResponder;
        private          MulticastDNSPublication?   multicastDNSPublication;
        private          NodeNameResolver?          nameResolver;
        private          Boolean                    watchingAddresses;

        /// <summary>
        /// How the responder is doing: "off", "starting", the state of its
        /// publication ("Probing", "Announcing", "Published", "Conflict",
        /// "Withdrawn"), "no address" or "failed".
        /// </summary>
        private          String                     responderState    = "off";
        private          String?                    responderProblem;
        private          String[]                   responderAddresses  = [];

        /// <summary>
        /// The last names Multicast DNS answered or did not, newest first, for
        /// the DNS page.
        /// </summary>
        private readonly LinkedList<JObject>        multicastDNSAnswers  = new ();

        /// <summary>
        /// How many of them are kept.
        /// </summary>
        public const     Int32                      MaxMulticastDNSAnswersShown  = 10;

        /// <summary>
        /// The time to live of the address records the responder publishes:
        /// RFC 6762 section 10 recommends 120 seconds for records with a host
        /// name.
        /// </summary>
        public static readonly TimeSpan             MulticastDNSHostRecordTTL    = TimeSpan.FromSeconds(120);

        #endregion

        #region Properties

        /// <summary>
        /// The name resolution every connection this node makes is given: ".local"
        /// by Multicast DNS where that is switched on, everything else by
        /// <see cref="DNSClient"/>.
        /// </summary>
        public NodeNameResolver       NameResolver

            => nameResolver ??= new NodeNameResolver(this);

        /// <summary>
        /// Whether names under ".local" are asked for by Multicast DNS. Off
        /// unless the "dns" section says otherwise.
        /// </summary>
        public Boolean                MulticastDNSEnabled       { get; private set; }

        /// <summary>
        /// The network interfaces Multicast DNS asks and answers on, by name;
        /// none is every interface that is up and can multicast, the loopback
        /// interface left out.
        /// </summary>
        public IReadOnlyList<String>  MulticastDNSInterfaces    { get; private set; } = [];

        /// <summary>
        /// Whether the IPv4 group 224.0.0.251 is used.
        /// </summary>
        public Boolean                MulticastDNSIPv4          { get; private set; } = true;

        /// <summary>
        /// Whether the IPv6 group ff02::fb is used.
        /// </summary>
        public Boolean                MulticastDNSIPv6          { get; private set; } = true;

        /// <summary>
        /// Whether this node answers for its own name, <see cref="MulticastDNSHostName"/>.local.
        /// Off unless the "dns" section says otherwise.
        /// </summary>
        public Boolean                MulticastDNSResponderEnabled  { get; private set; }

        /// <summary>
        /// The name this node answers for, without ".local": the file's, or
        /// else the machine's name made a valid DNS label.
        /// </summary>
        public String                 MulticastDNSHostName      { get; private set; } = MulticastDNSConfiguration.DefaultHostName();

        /// <summary>
        /// The name this node answers for, with ".local".
        /// </summary>
        public String                 MulticastDNSLocalName

            => $"{MulticastDNSHostName}.local";

        /// <summary>
        /// What makes the transport of Multicast DNS from the options in
        /// effect: UDP on port 5353, unless a test has the node ask on a
        /// network of its own.
        /// </summary>
        public Func<UDPMulticastDNSTransportOptions, IMulticastDNSTransport>  MulticastDNSTransportFactory  { get; set; }

            = options => new UDPMulticastDNSTransport(options);

        /// <summary>
        /// The options of the responder: Hermod's, which follow RFC 6762, unless
        /// a test has it probe faster.
        /// </summary>
        public MulticastDNSResponderOptions?  MulticastDNSResponderOptions  { get; set; }

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

            if (Configuration.ResponderEnabled.HasValue && MulticastDNSResponderEnabled != Configuration.ResponderEnabled.Value)
            {
                MulticastDNSResponderEnabled = Configuration.ResponderEnabled.Value;
                changed.Add($"multicast DNS responder {(MulticastDNSResponderEnabled ? "switched on" : "switched off")}");
            }

            if (Configuration.HostName is not null && !String.Equals(MulticastDNSHostName, Configuration.HostName, StringComparison.OrdinalIgnoreCase))
            {
                MulticastDNSHostName = Configuration.HostName;
                changed.Add($"multicast DNS host name = {MulticastDNSLocalName}");
            }

            // The sockets were made with what was in effect before: let go of
            // them, start the responder anew where it is on, and the next name
            // makes the client anew.
            if (changed.Count > 0)
                _ = RestartMulticastDNSAsync();

            return changed;

        }

        #endregion

        #region (private) TransportLocked(CancellationToken)

        /// <summary>
        /// The transport both the client and the responder use, made and started
        /// where there is none yet. Called with the lock held.
        /// </summary>
        private async Task<IMulticastDNSTransport> TransportLocked(CancellationToken CancellationToken)
        {

            if (multicastDNSTransport is not null)
                return multicastDNSTransport;

            var transport = MulticastDNSTransportFactory(new UDPMulticastDNSTransportOptions {
                                                             EnableIPv4      = MulticastDNSIPv4,
                                                             EnableIPv6      = MulticastDNSIPv6,
                                                             InterfaceNames  = MulticastDNSInterfaces.Count > 0
                                                                                   ? MulticastDNSInterfaces
                                                                                   : null
                                                         });

            try
            {
                if (!transport.IsRunning)
                    await transport.StartAsync(CancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await StopTransportAsync(transport).ConfigureAwait(false);
                throw;
            }

            multicastDNSTransport = transport;

            Log.Info($"Multicast DNS uses {(MulticastDNSInterfaces.Count > 0 ? String.Join(", ", MulticastDNSInterfaces) : "every interface that can multicast")}" +
                     $" over {(MulticastDNSIPv4 && MulticastDNSIPv6 ? "IPv4 and IPv6" : MulticastDNSIPv4 ? "IPv4" : "IPv6")}.",
                     "dns", "mdns");

            return transport;

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

                var transport  = await TransportLocked(CancellationToken).ConfigureAwait(false);
                var client     = new MulticastDNSClient(transport, TimeProvider: TimeProvider);

                try
                {
                    await client.StartAsync(CancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await client.DisposeAsync().ConfigureAwait(false);
                    throw;
                }

                multicastDNSClient = client;

                return client;

            }
            finally
            {
                multicastDNSLock.Release();
            }

        }

        #endregion

        #region (internal) QueryByMulticastDNSAsync(Name, ResourceRecordTypes, Timeout, ForceUpdate, CancellationToken)

        /// <summary>
        /// Ask Multicast DNS, and keep what came of it for the DNS page.
        /// </summary>
        internal async Task<DNSInfo> QueryByMulticastDNSAsync(DNSServiceName                       Name,
                                                              IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                                                              TimeSpan?                            Timeout,
                                                              Boolean?                             ForceUpdate,
                                                              CancellationToken                    CancellationToken)
        {

            var client  = await MulticastDNSClientAsync(CancellationToken).ConfigureAwait(false);
            var answer  = await client.Query(Name, ResourceRecordTypes, Timeout, null, ForceUpdate, CancellationToken).ConfigureAwait(false);

            var addresses = answer.Answers.OfType<AAAA>().Select(record => record.IPv6Address.ToString()).
                            Concat(answer.Answers.OfType<A>().Select(record => record.IPv4Address.ToString())).
                            Distinct().
                            ToArray();

            lock (multicastDNSAnswers)
            {

                multicastDNSAnswers.AddFirst(new JObject(
                                                 new JProperty("at",         TimeProvider.GetUtcNow().ToString("o")),
                                                 new JProperty("name",       Name.ToString()),
                                                 new JProperty("addresses",  new JArray(addresses)),
                                                 new JProperty("answered",   answer.Answers.Any()),
                                                 new JProperty("timedOut",   answer.IsTimeout)
                                             ));

                while (multicastDNSAnswers.Count > MaxMulticastDNSAnswersShown)
                    multicastDNSAnswers.RemoveLast();

            }

            return answer;

        }

        #endregion

        #region (private) StartMulticastDNSResponderAsync()

        /// <summary>
        /// Answer for this node's own name, where the responder is on and this
        /// node runs: probe for it, then announce it. What goes wrong is said
        /// and shown, and never thrown - the node runs without it.
        /// </summary>
        private async Task StartMulticastDNSResponderAsync()
        {

            if (!MulticastDNSResponderEnabled || !started)
                return;

            await multicastDNSLock.WaitAsync().ConfigureAwait(false);

            try
            {

                if (multicastDNSResponder is not null || !MulticastDNSResponderEnabled)
                    return;

                responderState    = "starting";
                responderProblem  = null;

                var transport     = await TransportLocked(CancellationToken.None).ConfigureAwait(false);
                var responder     = new MulticastDNSResponder(transport, MulticastDNSResponderOptions, TimeProvider);

                responder.OnPublicationStateChanged += (timestamp, sender, publication, oldState, newState, cancellationToken) => {

                    // Only of the responder in use: the goodbye of one let go
                    // of comes after this node said "off".
                    if (!ReferenceEquals(sender, multicastDNSResponder) && multicastDNSResponder is not null)
                        return Task.CompletedTask;

                    if (multicastDNSResponder is null && newState == MulticastDNSPublicationState.Withdrawn)
                        return Task.CompletedTask;

                    responderState = newState.ToString();

                    if (newState == MulticastDNSPublicationState.Published)
                        Log.Notice($"Multicast DNS answers for {MulticastDNSLocalName} with {String.Join(", ", responderAddresses)}.", "dns", "mdns");

                    return Task.CompletedTask;

                };

                responder.OnNameConflict += (timestamp, sender, publication, ownRecord, conflictingRecord, source, cancellationToken) => {

                    responderState    = nameof(MulticastDNSPublicationState.Conflict);
                    responderProblem  = $"{source} answers for {MulticastDNSLocalName} as well ({conflictingRecord}); this {Kind.Name} does not " +
                                         "rename itself - give it another host name, or the other host.";

                    Log.Warning($"Multicast DNS: {responderProblem}", "dns", "mdns");

                    return Task.CompletedTask;

                };

                await responder.StartAsync().ConfigureAwait(false);

                multicastDNSResponder = responder;

                var name          = DomainName.Parse($"{MulticastDNSLocalName}.");
                var records       = new List<IDNSResourceRecord>();

                foreach (var address in transport.LocalAddresses.Distinct())
                {

                    if (MulticastDNSIPv4 && address.TryGetValue(out IPv4Address ipv4))
                        records.Add(new A   (name, DNSQueryClasses.IN, MulticastDNSHostRecordTTL, ipv4));

                    else if (MulticastDNSIPv6 && address.TryGetValue(out IPv6Address ipv6))
                        records.Add(new AAAA(name, DNSQueryClasses.IN, MulticastDNSHostRecordTTL, ipv6));

                }

                // What is published, and nothing else: not the addresses of a family
                // that is switched off.
                responderAddresses = [.. records.Select(record => record switch {
                                                                      A    a    => a.   IPv4Address.ToString(),
                                                                      AAAA aaaa => aaaa.IPv6Address.ToString(),
                                                                      _         => record.ToString()
                                                                  })];

                if (records.Count == 0)
                {
                    responderState    = "no address";
                    responderProblem  = $"None of the interfaces it answers on has an address to answer for {MulticastDNSLocalName} with.";
                    Log.Warning($"Multicast DNS: {responderProblem}", "dns", "mdns");
                    return;
                }

                multicastDNSPublication = await responder.PublishAsync(records).ConfigureAwait(false);
                responderState          = multicastDNSPublication.State.ToString();

            }
            catch (Exception e)
            {
                responderState    = "failed";
                responderProblem  = $"The responder for {MulticastDNSLocalName} could not be started: {e.Message}";
                Log.Error($"Multicast DNS: {responderProblem}", "dns", "mdns");
            }
            finally
            {
                multicastDNSLock.Release();
            }

        }

        #endregion

        #region (private) RestartMulticastDNSAsync()

        /// <summary>
        /// Let go of everything of Multicast DNS, and start the responder anew
        /// where it is on: after a change of the settings or of the addresses.
        /// </summary>
        private async Task RestartMulticastDNSAsync()
        {

            await LetGoOfMulticastDNSAsync().ConfigureAwait(false);
            await StartMulticastDNSResponderAsync().ConfigureAwait(false);

        }

        #endregion

        #region (private) WatchTheAddresses() / AddressesChanged(Sender, Arguments)

        /// <summary>
        /// Publish the addresses anew when those of this machine change: once,
        /// when the node starts.
        /// </summary>
        private void WatchTheAddresses()
        {

            if (watchingAddresses)
                return;

            try
            {
                System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += AddressesChanged;
                watchingAddresses = true;
            }
            catch (Exception e)
            {
                Log.Debug($"Multicast DNS: the addresses of this machine cannot be watched: {e.Message}", "dns", "mdns");
            }

        }

        private void AddressesChanged(Object? Sender, EventArgs Arguments)
        {
            if (multicastDNSResponder is not null)
                _ = RestartMulticastDNSAsync();
        }

        #endregion

        #region (private) LetGoOfMulticastDNSAsync()

        /// <summary>
        /// Say goodbye for this node's name, where it answered for it, and close
        /// the client, the responder and their sockets.
        /// </summary>
        private async Task LetGoOfMulticastDNSAsync()
        {

            await multicastDNSLock.WaitAsync().ConfigureAwait(false);

            try
            {

                var client       = multicastDNSClient;
                var responder    = multicastDNSResponder;
                var publication  = multicastDNSPublication;
                var transport    = multicastDNSTransport;

                multicastDNSClient       = null;
                multicastDNSResponder    = null;
                multicastDNSPublication  = null;
                multicastDNSTransport    = null;
                responderState           = "off";
                responderProblem         = null;
                responderAddresses       = [];

                if (responder is not null)
                {

                    // The goodbye of RFC 6762 section 10.1: whoever cached the
                    // name forgets it within a second, rather than in two minutes.
                    if (publication is not null)
                        try
                        {
                            await responder.WithdrawAsync(publication).ConfigureAwait(false);
                        }
                        catch (Exception e)
                        {
                            Log.Debug($"Multicast DNS: no goodbye for {MulticastDNSLocalName}: {e.Message}", "dns", "mdns");
                        }

                    await responder.DisposeAsync().ConfigureAwait(false);

                }

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

                var answer   = await NameResolver.Query(
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
                   new JProperty("ipv6",        MulticastDNSIPv6),
                   new JProperty("asking",      multicastDNSClient is not null),
                   new JProperty("answers",     MulticastDNSAnswersJSON()),
                   new JProperty("responder",   new JObject(
                       new JProperty("enabled",     MulticastDNSResponderEnabled),
                       new JProperty("hostName",    MulticastDNSHostName),
                       new JProperty("name",        MulticastDNSLocalName),
                       new JProperty("state",       responderState),
                       new JProperty("addresses",   new JArray(responderAddresses)),
                       new JProperty("problem",     responderProblem)
                   )),
                   new JProperty("available",   new JArray(MulticastInterfaces().Select(available => new JObject(
                                                    new JProperty("name",       available.Name),
                                                    new JProperty("addresses",  new JArray(available.Addresses))
                                                ))))
               );

        /// <summary>
        /// The network interfaces of this machine Multicast DNS may use: those
        /// that are up and can multicast, the loopback interface left out (Q5),
        /// each with its addresses - for the checklist of the DNS page.
        /// </summary>
        public static IReadOnlyList<(String Name, String[] Addresses)> MulticastInterfaces()
        {

            var found = new List<(String, String[])>();

            try
            {
                foreach (var networkInterface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {

                    if (networkInterface.OperationalStatus    != System.Net.NetworkInformation.OperationalStatus.Up        ||
                        networkInterface.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback ||
                        !networkInterface.SupportsMulticast)
                        continue;

                    found.Add((networkInterface.Name,
                               [.. networkInterface.GetIPProperties().UnicastAddresses.
                                                    Select(unicast => unicast.Address).
                                                    Where (address => !address.IsIPv6LinkLocal).
                                                    Select(address => address.ToString())]));

                }
            }
            catch (System.Net.NetworkInformation.NetworkInformationException)
            {
                // A machine that does not say: nothing to offer.
            }

            return found;

        }

        private JArray MulticastDNSAnswersJSON()
        {
            lock (multicastDNSAnswers)
                return new JArray(multicastDNSAnswers.Select(answer => answer.DeepClone()));
        }

        #endregion

    }

}
