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

using System.Collections.Concurrent;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// A service this node announces by DNS-SD (RFC 6763) beside its own name:
    /// its type - "_ocpp._tcp" -, the name of the instance, its port, and its
    /// TXT strings - "tls=1", "path=/".
    /// </summary>
    /// <param name="ServiceType">The service type, without ".local": "_ocpp._tcp", "_ocpp-ssh._tcp".</param>
    /// <param name="Instance">The name of this instance: one DNS label.</param>
    /// <param name="Port">The port it is reached at.</param>
    /// <param name="Text">Its TXT strings, "key=value" each.</param>
    public sealed record MulticastDNSService(String                 ServiceType,
                                             String                 Instance,
                                             IPPort                 Port,
                                             IReadOnlyList<String>  Text);


    /// <summary>
    /// A service another host on the link announced, as a search found it.
    /// </summary>
    /// <param name="ServiceType">Its type, without ".local".</param>
    /// <param name="Instance">The name of its instance.</param>
    /// <param name="Host">The host it is at, with ".local" - or null where it did not say yet.</param>
    /// <param name="Port">Its port - or null where it did not say yet.</param>
    /// <param name="Text">Its TXT strings.</param>
    /// <param name="Addresses">The addresses of its host, where they were said.</param>
    public sealed record FoundService(String                 ServiceType,
                                      String                 Instance,
                                      String?                Host,
                                      UInt16?                Port,
                                      IReadOnlyList<String>  Text,
                                      IReadOnlyList<String>  Addresses)
    {

        /// <summary>
        /// The value of the given key of its TXT strings - or null.
        /// </summary>
        public String? this[String Key]

            => Text.Select (text => text.Split('=', 2)).
                    Where  (pair => pair.Length == 2 && String.Equals(pair[0], Key, StringComparison.OrdinalIgnoreCase)).
                    Select (pair => pair[1]).
                    FirstOrDefault();

        /// <summary>
        /// The URL a connection to it is made with, where it says enough: ws://
        /// or wss:// - as "tls" says - with the "path" it names for OCPP, and
        /// ssh:// for OCPP-over-SSH (mDNS-Concept.md, Q8).
        /// </summary>
        public String? URL

            => Host is null || Port is null
                   ? null
                   : ServiceType == "_ocpp-ssh._tcp"
                         ? $"ssh://{Host.TrimEnd('.')}:{Port}"
                         : $"{(this["tls"] == "1" ? "wss" : "ws")}://{Host.TrimEnd('.')}:{Port}{this["path"] ?? "/"}";

        public JObject ToJSON()

            => new (
                   new JProperty("serviceType",  ServiceType),
                   new JProperty("instance",     Instance),
                   new JProperty("host",         Host),
                   new JProperty("port",         Port),
                   new JProperty("text",         new JArray(Text)),
                   new JProperty("addresses",    new JArray(Addresses)),
                   new JProperty("url",          URL)
               );

    }


    /// <summary>
    /// The services this node announces by DNS-SD beside its own name, and a
    /// search for those of the other hosts on the link (mDNS-Concept.md, B.6).
    /// </summary>
    /// <remarks>
    /// Announced only where the responder answers for the node's name: a
    /// service is at a host, and the host is that name. Found services are
    /// offered, never connected to by themselves: a connection made of one
    /// asks an admin to confirm the key of its server (Q2).
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        private readonly ConcurrentDictionary<String, MulticastDNSService> announcedServices = new ();

        /// <summary>
        /// The time to live of the PTR and TXT records of a service: RFC 6762
        /// section 10 recommends 75 minutes for records without a host name.
        /// </summary>
        public static readonly TimeSpan MulticastDNSServiceRecordTTL = TimeSpan.FromMinutes(75);

        /// <summary>
        /// How long a search listens for answers where nothing is said.
        /// </summary>
        public static readonly TimeSpan DefaultDiscoveryTime = TimeSpan.FromSeconds(3);

        #endregion

        #region Properties

        /// <summary>
        /// The services this node announces by DNS-SD, while its responder
        /// answers for its name.
        /// </summary>
        public IReadOnlyList<MulticastDNSService> AnnouncedServices

            => [.. announcedServices.Values.OrderBy(service => service.ServiceType).ThenBy(service => service.Instance)];

        #endregion


        #region AnnounceService(Service) / WithdrawService(ServiceType, Instance)

        /// <summary>
        /// Announce the given service by DNS-SD from now on, in place of one of
        /// the same type and instance - published anew where the responder runs.
        /// </summary>
        public void AnnounceService(MulticastDNSService Service)
        {

            var key = $"{Service.ServiceType}/{Service.Instance}";

            if (announcedServices.TryGetValue(key, out var was) &&
                was.Port == Service.Port &&
                was.Text.SequenceEqual(Service.Text))
                return;

            announcedServices[key] = Service;

            if (multicastDNSResponder is not null)
                _ = RestartMulticastDNSAsync();

        }

        /// <summary>
        /// Announce the given service no more. Whether it was announced.
        /// </summary>
        public Boolean WithdrawService(String  ServiceType,
                                       String  Instance)
        {

            if (!announcedServices.TryRemove($"{ServiceType}/{Instance}", out _))
                return false;

            if (multicastDNSResponder is not null)
                _ = RestartMulticastDNSAsync();

            return true;

        }

        #endregion

        #region (private) ServiceRecordsAt(Host)

        /// <summary>
        /// The PTR, SRV and TXT records of the services this node announces, at
        /// the given host name (RFC 6763 section 4 to 6).
        /// </summary>
        private IEnumerable<IDNSResourceRecord> ServiceRecordsAt(DomainName Host)
        {

            foreach (var service in AnnouncedServices)
            {

                var type      = DNSServiceName.Parse($"{service.ServiceType}.local.");
                var instance  = DNSServiceName.Parse($"{service.Instance}.{service.ServiceType}.local.");

                yield return new PTR(type,     DNSQueryClasses.IN, MulticastDNSServiceRecordTTL, instance);
                yield return new SRV(instance, DNSQueryClasses.IN, MulticastDNSHostRecordTTL,    0, 0, service.Port, Host);
                yield return new TXT(instance, DNSQueryClasses.IN, MulticastDNSServiceRecordTTL, service.Text.Count > 0 ? service.Text : [ "" ]);

            }

        }

        #endregion

        #region DiscoverAsync(ServiceType, Time = null, CancellationToken = default)

        /// <summary>
        /// The instances of the given DNS-SD service type the hosts on the link
        /// announce, listened for for the given time. Nothing where Multicast DNS
        /// is switched off - the search would be a question to the link nobody
        /// allowed.
        /// </summary>
        /// <param name="ServiceType">The service type, without ".local": "_ocpp._tcp".</param>
        /// <param name="Time">How long to listen; <see cref="DefaultDiscoveryTime"/> where nothing is said.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        public async Task<IReadOnlyList<FoundService>> DiscoverAsync(String             ServiceType,
                                                                     TimeSpan?          Time                = null,
                                                                     CancellationToken  CancellationToken   = default)
        {

            if (!MulticastDNSEnabled)
                return [];

            var client   = await MulticastDNSClientAsync(CancellationToken).ConfigureAwait(false);
            var browser  = await client.BrowseAsync(DNSServiceName.Parse($"{ServiceType}.local."), CancellationToken).ConfigureAwait(false);

            try
            {

                await Task.Delay(Time ?? DefaultDiscoveryTime, TimeProvider, CancellationToken).ConfigureAwait(false);

                return [.. browser.Instances.Select(instance => new FoundService(
                                                                    ServiceType,
                                                                    InstanceLabelOf(instance.InstanceName.ToString(), ServiceType),
                                                                    instance.HostName?.FullName,
                                                                    instance.Port?.ToUInt16(),
                                                                    instance.TXT?.Strings ?? [],
                                                                    [.. instance.Addresses.Select(address => address.ToString())]
                                                                ))];

            }
            finally
            {
                await browser.DisposeAsync().ConfigureAwait(false);
            }

        }

        /// <summary>
        /// The name of an instance without its service type and ".local".
        /// </summary>
        private static String InstanceLabelOf(String InstanceName, String ServiceType)
        {

            var suffix = $".{ServiceType}.local.";

            return InstanceName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                       ? InstanceName[..^suffix.Length]
                       : InstanceName;

        }

        #endregion

        #region (static) InstanceLabel(Text)

        /// <summary>
        /// The given text made one DNS label for the name of an instance: lower
        /// case, everything else than a letter, a digit or a hyphen a hyphen.
        /// </summary>
        public static String InstanceLabel(String Text)
        {

            var made = new String([.. Text.ToLowerInvariant().Select(c => Char.IsAsciiLetterOrDigit(c) ? c : '-')]).Trim('-');

            if (made.Length > 63)
                made = made[..63].TrimEnd('-');

            return made.Length > 0 ? made : "node";

        }

        #endregion

    }

}
