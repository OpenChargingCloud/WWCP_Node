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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// The "dns" section of the configuration file: how this node
    /// resolves names.
    /// </summary>
    /// <remarks>
    /// Every field is optional, and null means "the file does not say" rather
    /// than "the file says nothing": what is missing keeps whatever the node
    /// was given at construction, and a node given nothing keeps the system
    /// default. That is what makes a half-written file a legitimate thing to
    /// have - somebody who only cares about the name servers should not have to
    /// write down the retry count to say so. The one null that says something
    /// is "recursionDesired": null, "leave it to the server" - see
    /// <see cref="RemovesRecursionDesired"/>.
    /// </remarks>
    /// <param name="Enabled">Whether this node resolves names at all.</param>
    /// <param name="Servers">The name servers to ask; an empty list is not the same as none given.</param>
    /// <param name="QueryTimeout">How long one query may take.</param>
    /// <param name="RecursionDesired">Whether the RD bit is set; null leaves it to the server.</param>
    /// <param name="UseCache">Whether answers are remembered for as long as their time to live says.</param>
    /// <param name="DnssecOK">Whether the DO bit is set, i.e. whether signatures are asked for.</param>
    /// <param name="FollowCNAMEs">Whether a CNAME chain is followed.</param>
    /// <param name="MaxCNAMEFollows">How far.</param>
    /// <param name="MaxRetries">How often a server that did not answer, or answered SERVFAIL, is asked again.</param>
    /// <param name="Pins">What each of the servers reached over TLS or HTTPS is held to, beside what every one is held to - see <see cref="ServerPins"/>; only where the list of servers says so.</param>
    public sealed record DNSConfiguration(Boolean?                        Enabled               = null,
                                          IReadOnlyList<DNSServerConfig>? Servers               = null,
                                          TimeSpan?                       QueryTimeout          = null,
                                          Boolean?                        RecursionDesired      = null,
                                          Boolean?                        UseCache              = null,
                                          Boolean?                        DnssecOK              = null,
                                          Boolean?                        FollowCNAMEs          = null,
                                          Byte?                           MaxCNAMEFollows       = null,
                                          Byte?                           MaxRetries            = null,
                                          IReadOnlyDictionary<DNSServerConfig, ServerPins>?  Pins  = null)
    {

        #region Data

        /// <summary>
        /// The name of this section in the configuration file.
        /// </summary>
        public const String  SectionName          = "dns";

        /// <summary>
        /// The most name servers one node may be given. Not a rule of DNS -
        /// a query goes to all of them at once, and a hundred of them would be
        /// a hundred packets for every name this node ever looks up.
        /// </summary>
        public const Int32   MaxServers           = 16;

        /// <summary>
        /// The longest a query may be allowed to take, in seconds.
        /// </summary>
        public const Double  MaxQueryTimeoutSeconds = 120;

        #endregion

        #region Properties

        /// <summary>
        /// Whether this section takes the choice about recursion back - "leave
        /// it to the server" - rather than not mentioning it.
        /// </summary>
        /// <remarks>
        /// Said with "recursionDesired": null. Anywhere else in this section a
        /// null means "the file does not say"; here it is one of the three
        /// answers, and read as "not said" it made the page's "leave it to the
        /// server" a save that saved nothing once yes or no had been saved - as
        /// a null had done to the legal time authority, see
        /// <see cref="NTSConfiguration.RemovesLegalTimeAuthority"/>.
        /// </remarks>
        public Boolean  RemovesRecursionDesired  { get; init; }

        /// <summary>
        /// The keys a save of this section takes out of the file rather than
        /// leaving them as they are.
        /// </summary>
        public IEnumerable<String> RemovedKeys
        {
            get
            {
                if (RemovesRecursionDesired)
                    yield return "recursionDesired";
            }
        }

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The "dns" section, or the one sentence that says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JObject                                     JSON,
                                       [NotNullWhen(true)]  out DNSConfiguration?   Configuration,
                                       [NotNullWhen(false)] out String?             Error)
        {

            Configuration  = null;
            Error          = null;

            #region The name servers

            IReadOnlyList<DNSServerConfig>?                    servers  = null;
            Dictionary<DNSServerConfig, ServerPins>?          pins     = null;

            if (JSON["servers"] is JToken serversToken && serversToken.Type != JTokenType.Null)
            {

                if (serversToken is not JArray serverArray)
                {
                    Error = "'dns.servers' must be an array of name servers.";
                    return false;
                }

                if (serverArray.Count > MaxServers)
                {
                    Error = $"'dns.servers' may name at most {MaxServers} servers.";
                    return false;
                }

                var parsed = new List<DNSServerConfig>();

                pins       = [];

                for (var index = 0; index < serverArray.Count; index++)
                {

                    if (!TryParseServer(serverArray[index], index, out var server, out var held, out Error))
                        return false;

                    parsed.Add(server);

                    if (held is not null)
                        pins[server] = held;

                }

                servers = parsed;

            }

            #endregion

            if (!ConfigurationReader.TryReadBoolean(JSON, "enabled",              "dns", out var enabled,          out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "recursionDesired",     "dns", out var recursionDesired, out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "useCache",             "dns", out var useCache,         out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "dnssecOK",             "dns", out var dnssecOK,         out Error) ||
                !ConfigurationReader.TryReadBoolean(JSON, "followCNAMEs",         "dns", out var followCNAMEs,     out Error) ||
                !ConfigurationReader.TryReadByte   (JSON, "maxCNAMEFollows",      "dns", out var maxCNAMEFollows,  out Error) ||
                !ConfigurationReader.TryReadByte   (JSON, "maxRetries",           "dns", out var maxRetries,       out Error) ||
                !ConfigurationReader.TryReadSeconds(JSON, "queryTimeoutSeconds",  "dns", 0.1, MaxQueryTimeoutSeconds, out var queryTimeout, out Error))
            {
                return false;
            }

            Configuration = new DNSConfiguration(
                                enabled,
                                servers,
                                queryTimeout,
                                recursionDesired,
                                useCache,
                                dnssecOK,
                                followCNAMEs,
                                maxCNAMEFollows,
                                maxRetries,
                                pins
                            ) {
                                // Named, and null: "leave it to the server".
                                // See RemovesRecursionDesired.
                                RemovesRecursionDesired = recursionDesired is null &&
                                                          JSON.TryGetValue("recursionDesired", out var recursionToken) &&
                                                          recursionToken.Type == JTokenType.Null
                            };

            return true;

        }

        #endregion

        #region (static) TryParseServer(JSON, out Server, out Error)

        /// <summary>
        /// One name server: an address or a domain name, a port, a transport.
        /// </summary>
        /// <remarks>
        /// A plain string is accepted as well as an object, because "8.8.8.8"
        /// is what somebody writes when they mean a name server and nothing
        /// else about it.
        /// </remarks>
        public static Boolean TryParseServer(JToken                                   JSON,
                                             [NotNullWhen(true)]  out DNSServerConfig? Server,
                                             [NotNullWhen(false)] out String?           Error)
        {

            Server  = null;
            Error   = null;

            var json = JSON as JObject;

            var address = json is null
                              ? JSON.Value<String>()?.Trim()
                              : (json.Value<String>("address") ?? json.Value<String>("domainName"))?.Trim();

            if (String.IsNullOrEmpty(address))
            {
                Error = "Every name server needs an 'address' or a 'domainName'.";
                return false;
            }

            #region The transport, which decides the default port

            var transport = DNSTransport.UDP;

            var transportText = json?.Value<String>("transport")?.Trim();

            if (!String.IsNullOrEmpty(transportText))
            {

                if (!Enum.TryParse(transportText, ignoreCase: true, out transport))
                {
                    Error = $"'{transportText}' is not a DNS transport. Known transports: {String.Join(", ", Enum.GetNames<DNSTransport>())}.";
                    return false;
                }

            }

            #endregion

            #region The port, and the per-server timeout

            // Left at null when the file does not say, so that DNSServerConfig
            // picks the port of the transport - 53, 853, 443 - instead of this
            // file keeping its own second list of which port means what.
            var portNumber = json?.Value<UInt16?>("port");

            var port       = portNumber.HasValue
                                 ? IPPort.Parse(portNumber.Value)
                                 : (IPPort?) null;

            TimeSpan? queryTimeout = null;

            if (json is not null &&
                !ConfigurationReader.TryReadSeconds(json, "queryTimeoutSeconds", "dns.servers[]", 0.1, MaxQueryTimeoutSeconds, out queryTimeout, out Error))
            {
                return false;
            }

            #endregion

            // An address first, because a name server named by a name is a name
            // that something has to resolve, and the thing that would resolve it
            // is this client.
            if (org.GraphDefined.Vanaheimr.Hermod.IPAddress.TryParse(address, out var ipAddress))
                Server = new DNSServerConfig(ipAddress, port, transport, QueryTimeout: queryTimeout);

            else if (DomainName.TryParse(address, out var domainName, out var problem))
                Server = new DNSServerConfig(domainName, port, transport, QueryTimeout: queryTimeout);

            else
            {
                Error = $"'dns.servers': \"{address}\" is neither an IP address nor a domain name: {problem}";
                return false;
            }

            return true;

        }

        #endregion

        #region (static) TryParseServer(JSON, Index, out Server, out Pins, out Error)

        /// <summary>
        /// One name server, and what it is held to beside what every one is held
        /// to - see <see cref="ServerPins"/>.
        /// </summary>
        /// <remarks>
        /// Only a server reached over TLS or HTTPS shows a certificate, so only
        /// such a server can be held to one: a pin on a server asked over UDP
        /// would be a pin nobody ever compares, on a server its author believes
        /// to be held to something. That is refused, with the entry named.
        /// </remarks>
        /// <param name="JSON">The entry of the server.</param>
        /// <param name="Index">Its place in the list, to say which one is wrong.</param>
        public static Boolean TryParseServer(JToken                                   JSON,
                                             Int32                                    Index,
                                             [NotNullWhen(true)]  out DNSServerConfig? Server,
                                             out ServerPins?                           Pins,
                                             [NotNullWhen(false)] out String?           Error)
        {

            Pins = null;

            if (!TryParseServer(JSON, out Server, out Error))
                return false;

            if (JSON is not JObject json)
                return true;

            if (!ServerPins.TryParse(json, $"dns.servers[{Index}]", out Pins, out Error))
                return false;

            if (Pins is not null && !IsEncrypted(Server.Transport))
            {
                Error  = $"'dns.servers[{Index}]' is held to a certificate and asked over {Server.Transport}, which shows none: only a name server reached over TLS or HTTPS can be held to one.";
                Pins   = null;
                return false;
            }

            return true;

        }

        #endregion

        #region (static) IsEncrypted(Transport)

        /// <summary>
        /// Whether a name server asked over this transport shows a certificate.
        /// </summary>
        public static Boolean IsEncrypted(DNSTransport Transport)

            => Transport is DNSTransport.TLS
                         or DNSTransport.HTTPS
                         or DNSTransport.HTTPS_Binary
                         or DNSTransport.HTTPS_JSON
                         or DNSTransport.HTTPS_GET;

        #endregion

        #region (static) ServerJSON(Server)

        /// <summary>
        /// One name server as the file keeps it and the web interface reads it.
        /// </summary>
        public static JObject ServerJSON(DNSServerConfig Server)

            => new (
                   new JProperty("address",               Server.IPAddress?.ToString() ?? Server.DomainName?.ToString()),
                   new JProperty("port",                  Server.Port.ToUInt16()),
                   new JProperty("transport",             Server.Transport.ToString()),
                   new JProperty("queryTimeoutSeconds",   Server.QueryTimeout?.TotalSeconds)
               );

        /// <summary>
        /// One name server as the file keeps it, with what it is held to - in
        /// the keys the file writes it under, so that a page sending the entry
        /// back sends the pins back with it.
        /// </summary>
        public static JObject ServerJSON(DNSServerConfig  Server,
                                         ServerPins?      Pins)
        {

            var json = ServerJSON(Server);

            Pins?.WriteInto(json);

            return json;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as it is written to the file; what this node was not
        /// told about is not written, so that the file keeps saying "the system
        /// decides" rather than freezing today's system default.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Enabled.            HasValue)  json.Add("enabled",              Enabled.            Value);
            if (Servers is not null)           json.Add("servers",              new JArray(Servers.Select(server => ServerJSON(server, Pins?.GetValueOrDefault(server)))));
            if (QueryTimeout.       HasValue)  json.Add("queryTimeoutSeconds",  QueryTimeout.       Value.TotalSeconds);
            if (RecursionDesired.   HasValue)  json.Add("recursionDesired",     RecursionDesired.   Value);
            if (UseCache.           HasValue)  json.Add("useCache",             UseCache.           Value);
            if (DnssecOK.           HasValue)  json.Add("dnssecOK",             DnssecOK.           Value);
            if (FollowCNAMEs.       HasValue)  json.Add("followCNAMEs",         FollowCNAMEs.       Value);
            if (MaxCNAMEFollows.    HasValue)  json.Add("maxCNAMEFollows",      MaxCNAMEFollows.    Value);
            if (MaxRetries.         HasValue)  json.Add("maxRetries",           MaxRetries.         Value);

            return json;

        }

        #endregion

    }

}
