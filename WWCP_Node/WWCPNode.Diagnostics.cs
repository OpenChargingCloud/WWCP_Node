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

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Making this node try something, to find out whether it can:
    /// resolving a name, and asking its time server what time it is.
    /// </summary>
    /// <remarks>
    /// Both of these write to the event log as they go, and not only at the
    /// end. That is the point of them: somebody who cannot reach their time
    /// server wants to know which step failed - the name, the TLS handshake,
    /// the key exchange, the NTP packet - and a single line saying "it did not
    /// work" tells them to go and find out somewhere else.
    ///
    /// Because they are in the log, they are also in the live stream every open
    /// browser is hanging on. So the Logs page of somebody watching shows what
    /// somebody else pressed, which is the right way round for a machine that
    /// several people look after.
    /// </remarks>
    public partial class WWCPNode : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// The most record types one test query may ask for at a time.
        /// </summary>
        public const Int32  MaxQueryRecordTypes  = 8;

        /// <summary>
        /// The most answers one test query reports. A zone transfer is not a
        /// test, and a browser is not a place to render one.
        /// </summary>
        public const Int32  MaxQueryAnswers      = 200;

        #endregion


        #region (static) AsAQuestion(Text, out Name, out Says)

        /// <summary>
        /// What somebody typed, turned into something that can actually be
        /// asked.
        /// </summary>
        /// <remarks>
        /// An address is a perfectly reasonable thing to type into a box that
        /// asks for a name, and it is nearly always a reverse lookup that was
        /// meant - "who is 192.168.178.1". Asking for it as written would send
        /// "192.168.178.1" out as a domain name and come back with nothing,
        /// which looks like a broken resolver rather than a misunderstanding.
        ///
        /// So it is turned around here and said out loud: what came back names
        /// the question that was actually asked, because a page that quietly
        /// asked something else is worse than one that refused.
        /// </remarks>
        public static Boolean AsAQuestion(String                           Text,
                                          out String                       Name,
                                          out String?                      Says)
        {

            Name  = Text.Trim();
            Says  = null;

            if (!System.Net.IPAddress.TryParse(Name, out var address))
                return false;

            var bytes = address.GetAddressBytes();

            Name = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6

                       // Each nibble, lowest first, one label each (RFC 3596 section 2.5).
                       // High nibble then low, so that reversing the whole
                       // sequence puts the lowest nibble of the last byte
                       // first - which is the order, and the one that is easy
                       // to write backwards.
                       ? String.Join(".", bytes.SelectMany(one => new[] { one >> 4, one & 0x0F }).
                                                Reverse().
                                                Select(nibble => nibble.ToString("x"))) + ".ip6.arpa"

                       // Each octet, lowest first (RFC 1035 section 3.5).
                       : String.Join(".", bytes.Reverse()) + ".in-addr.arpa";

            Says = $"'{Text.Trim()}' is an address, so it was turned around and '{Name}' was asked for instead.";

            return true;

        }

        #endregion

        #region ResolveAsync(Name, RecordTypes, Server = null, CancellationToken = default)

        /// <summary>
        /// Look a name up, and say what came back.
        /// </summary>
        /// <param name="Name">The name to resolve.</param>
        /// <param name="RecordTypes">What to ask for; A and AAAA when nothing is said.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        /// <param name="Server">
        /// Which of the configured name servers to ask, by its place in the
        /// list - or null for all of them, the way this node resolves
        /// anything else.
        /// </param>
        /// <remarks>
        /// What comes back is one answer for the web interface, the command
        /// line and OCPP's QueryDNS alike, so that the three cannot disagree
        /// about what a name server said. Where nothing was asked at all, it
        /// says why in "refused", in one of the reason codes of QueryDNS -
        /// see <see cref="DNSQueryRefusals"/>: a question that was put and
        /// came back with nothing is a different thing from one that never
        /// left, and only OCPP's Rejected may stand for the second.
        /// </remarks>
        public async Task<JObject> ResolveAsync(String                                Name,
                                                IEnumerable<DNSResourceRecordTypes>?  RecordTypes         = null,
                                                Int32?                                Server              = null,
                                                CancellationToken                     CancellationToken   = default)
        {

            var typed        = Name?.Trim() ?? "";
            var turnedAround = AsAQuestion(typed, out var name, out var saying);

            var recordTypes  = RecordTypes?.Distinct().ToArray() is { Length: > 0 } given
                                   ? given
                                   // An address asked about by itself means
                                   // "who is this", and that is a PTR.
                                   : turnedAround
                                         ? [ DNSResourceRecordTypes.PTR ]
                                         : [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ];

            var asked        = String.Join(", ", recordTypes);

            // Read once: a change of the name servers while this runs must not
            // make the place asked for point at another server than its id.
            var servers      = configuredDNSServers;
            var ids          = DNSConfiguration.IdsOf(servers.Select((_, index) => dnsServerIdsGiven.ElementAtOrDefault(index)));

            String? serverId = null;

            if (!DNSEnabled)
            {
                Log.Warning($"DNS test for '{name}' was not run: name resolution is switched off.", "dns", "test");
                return Failed(name, $"Name resolution is switched off on this {Kind.Name}.", DNSQueryRefusals.Disabled);
            }

            #region One server, or all of them

            DNSServerConfig? only = null;

            if (Server is Int32 which)
            {

                if (which < 0 || which >= servers.Count)
                    return Failed(name, $"This {Kind.Name} has no name server number {which + 1}.", DNSQueryRefusals.UnknownServer);

                only      = servers[which];
                serverId  = ids[which];

                if (only.IPAddress is null)
                    return Failed(name,
                                  $"'{only}' is configured by name rather than by address, so it cannot be asked on its own " +
                                   "without first resolving it - which is the thing being tested.",
                                  DNSQueryRefusals.ServerByName);

            }

            #endregion

            if (!DNSServiceName.TryParse(name, out var serviceName, out var problem))
            {
                Log.Warning($"DNS test: \"{name}\" is not a name that can be looked up: {problem}", "dns", "test");
                return Failed(name, $"\"{name}\" is not a name that can be looked up: {problem}", DNSQueryRefusals.InvalidName);
            }

            Log.Info(
                only is null
                    ? $"DNS test: asking {AskedDNSServers.Count} server(s) for {asked} of '{serviceName}' ..."
                    : $"DNS test: asking {only} alone for {asked} of '{serviceName}' ...",
                "dns", "test"
            );

            var stopwatch   = Stopwatch.StartNew();

            // What was made of the certificates of the servers asked over TLS or
            // HTTPS during this test - and of those alone: a judgement from
            // before it would be about another handshake.
            var judgedFrom  = TimeProvider.GetUtcNow();

            JArray CertificatesJudged()

                => new (judgements.Values.
                                   Where  (judgement => judgement.Service == CertificateUsages.DNS && judgement.At >= judgedFrom).
                                   OrderBy(judgement => judgement.At).
                                   Select (judgement => {
                                       var json = judgement.ToJSON();
                                       json.Add("steps", new JArray(judgement.Steps.Select(step => new JObject(
                                                                                               new JProperty("level", step.Level),
                                                                                               new JProperty("text",  step.Text)
                                                                                           ))));
                                       return json;
                                   }));

            // And of the servers asked over SSH, by the same rule: what an
            // attempt during this test came to.
            JArray SSHAttempts()

                => new (servers.Where  (server => NameServerSSHStateOf(server) is { } state && state.At >= judgedFrom).
                                Select (server => {
                                    var json = NameServerSSHStateOf(server)!.ToJSON();
                                    json.AddFirst(new JProperty("server", NameOf(server)));
                                    return json;
                                }));

            try
            {

                // A client of its own when one server is meant - see
                // ClientFor() - and given back when the answer is in.
                using var alone  = only is null
                                       ? null
                                       : ClientFor(only);

                var asking   = alone ?? dnsClient;

                var answer   = await asking.Query(
                                         serviceName,
                                         recordTypes,
                                         RecursionDesired:   dnsClient.RecursionDesired,
                                         ForceUpdate:        only is not null,
                                         CancellationToken:  CancellationToken
                                     );

                stopwatch.Stop();

                var records  = answer.Answers.Take(MaxQueryAnswers).ToArray();

                Log.Notice(
                    $"DNS test: '{serviceName}' {asked} -> {RCodeName(answer.ResponseCode)} from {answer.Origin}, " +
                    $"{answer.Answers.Count()} answer(s) in {stopwatch.ElapsedMilliseconds} ms" +
                    (records.Length > 0
                         ? $": {String.Join("; ", records.Select(record => record.ToString()))}"
                         : "."),
                    "dns", "test"
                );

                return new JObject(

                           new JProperty("name",             serviceName.ToString()),
                           new JProperty("asked",            only?.ToString()),
                           new JProperty("serverId",         serverId),
                           new JProperty("turnedAround",     saying),
                           new JProperty("reverseLookupOf",  turnedAround ? typed : null),
                           new JProperty("recordTypes",      new JArray(recordTypes.Select(RecordTypeName))),
                           new JProperty("ok",               answer.ResponseCode == DNSResponseCodes.NoError),
                           new JProperty("responseCode",     RCodeName(answer.ResponseCode)),
                           new JProperty("server",           answer.Origin.ToString()),
                           new JProperty("answeredBy",       AddressOf(answer.Origin)),
                           new JProperty("runtime_ms",       stopwatch.ElapsedMilliseconds),
                           new JProperty("authoritative", answer.AuthoritativeAnswer),
                           new JProperty("truncated",     answer.IsTruncated),
                           new JProperty("dnssec",        answer.DNSSECStatus?.ToString()),
                           new JProperty("timedOut",      answer.IsTimeout),

                           new JProperty("answers",       new JArray(
                               records.Select(record => new JObject(
                                   new JProperty("name",         record.DomainName.ToString()),
                                   new JProperty("type",         RecordTypeName(record.Type)),
                                   new JProperty("timeToLive",   (Int64) record.TimeToLive.TotalSeconds),
                                   new JProperty("value",        RDataOf(record))
                               ))
                           )),

                           new JProperty("more",          Math.Max(0, answer.Answers.Count() - records.Length)),

                           new JProperty("certificates",  CertificatesJudged()),

                           new JProperty("ssh",           SSHAttempts())

                       );

            }
            catch (Exception e)
            {

                stopwatch.Stop();

                Log.Error($"DNS test for '{serviceName}' failed after {stopwatch.ElapsedMilliseconds} ms: {e.Message}", "dns", "test");

                // A refused certificate is the most likely reason a server over
                // TLS answered nothing, and the one most worth seeing.
                var failed = Failed(serviceName.ToString(), e.Message);
                failed.Add("runtime_ms",    stopwatch.ElapsedMilliseconds);
                failed.Add("certificates",  CertificatesJudged());
                failed.Add("ssh",           SSHAttempts());

                return failed;

            }


            // What was asked, beside why nothing came of it - and, where
            // nothing was asked at all, why not.
            JObject Failed(String Name, String Error, String? Refused = null)

                => JSONObject.Create(
                       new JProperty("name",             Name),
                       serverId is not null
                           ? new JProperty("serverId",         serverId)
                           : null,
                       turnedAround
                           ? new JProperty("reverseLookupOf",  typed)
                           : null,
                       new JProperty("recordTypes",      new JArray(recordTypes.Select(RecordTypeName))),
                       new JProperty("ok",               false),
                       new JProperty("error",            Error),
                       Refused is not null
                           ? new JProperty("refused",          Refused)
                           : null,
                       new JProperty("answers",          new JArray())
                   );

        }

        #endregion

        #region DNSServerIndexOf(Server)

        /// <summary>
        /// The place in the list of the configured name server somebody named:
        /// by its id, by its place counted from 1, or by its address - with or
        /// without its transport and port, as "192.0.2.53",
        /// "192.0.2.53:853" or "tls://192.0.2.53:853". Null when it names none.
        /// </summary>
        /// <remarks>
        /// Its id is what a CSMS knows it by, its place what the page and the
        /// log count, and its address what somebody reading the configuration
        /// file sees. An id begins with a letter, so a number is never one.
        /// An address that two servers share - the same resolver over UDP and
        /// over TLS - is the first of them, unless its transport is said.
        /// </remarks>
        /// <param name="Server">The name server, as somebody named it.</param>
        public Int32? DNSServerIndexOf(String? Server)
        {

            var wanted   = Server?.Trim() ?? "";

            if (wanted.Length == 0)
                return null;

            var servers  = configuredDNSServers;
            var ids      = DNSConfiguration.IdsOf(servers.Select((_, index) => dnsServerIdsGiven.ElementAtOrDefault(index)));

            for (var index = 0; index < ids.Count; index++)
                if (String.Equals(ids[index], wanted, StringComparison.OrdinalIgnoreCase))
                    return index;

            if (Int32.TryParse(wanted, NumberStyles.None, CultureInfo.InvariantCulture, out var place))
                return place >= 1 && place <= servers.Count
                           ? place - 1
                           : null;

            for (var index = 0; index < servers.Count; index++)
            {

                var server   = servers[index];
                var address  = AddressOf(server);
                var host     = HostOf(server);
                var hostPort = $"{host}:{server.Port}";

                if (String.Equals(address,  wanted,               StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(hostPort, wanted,               StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(host,     wanted.Trim('[', ']'), StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(host.Trim('[', ']'), wanted.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                {
                    return index;
                }

            }

            return null;

        }

        #endregion

        #region (static) AddressOf(Server)

        /// <summary>
        /// A name server as "transport://address:port", e.g.
        /// "tls://192.0.2.53:853" or "udp://[2001:db8::53]:53" - which is what
        /// QueryDNS says an answer came from.
        /// </summary>
        /// <remarks>
        /// Not its ToString(), which adds its query timeout: a fact about how
        /// long it is waited for, and none about where it is.
        /// </remarks>
        /// <param name="Server">A name server.</param>
        public static String AddressOf(DNSServerConfig Server)

            => $"{Server.Transport.ToString().ToLowerInvariant()}://{HostOf(Server)}:{Server.Port}";


        /// <summary>
        /// The address of a name server, an IPv6 address shortened and in
        /// brackets, or its name where it is configured by name.
        /// </summary>
        /// <remarks>
        /// The server an answer came from is the far end of the socket it came
        /// over, which a dual-stack socket gives as an IPv4 address mapped into
        /// IPv6: 127.0.0.1 came back as
        /// "[0000:0000:0000:0000:0000:ffff:7f00:0001]". It is the address that
        /// was configured, and it is said as that.
        /// </remarks>
        private static String HostOf(DNSServerConfig Server)
        {

            if (Server.IPAddress is IIPAddress address &&
                System.Net.IPAddress.TryParse(address.ToString(), out var ip))
            {

                if (ip.IsIPv4MappedToIPv6)
                    ip = ip.MapToIPv4();

                return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                           ? $"[{ip}]"
                           : ip.ToString();

            }

            return Server.DomainName?.ToString().TrimEnd('.') ?? "";

        }

        #endregion

        #region (static) RDataOf(Record)

        /// <summary>
        /// The data of a record in presentation format (RFC 1035 section 5.1):
        /// "192.0.2.80", "10 5 4460 ntp.example.org." - what a zone file has
        /// after the type.
        /// </summary>
        /// <remarks>
        /// Taken from the record's line of a zone file, whose first four fields
        /// - name, time to live, class and type - hold no whitespace. Not its
        /// RText, which an A or AAAA record leaves empty, and not its
        /// ToString(), which the page used to show for those: the address,
        /// followed by its name, type, class, time to live and the moment it
        /// expires, in the machine's language.
        ///
        /// A record that has no line of a zone file - an OPT, which RFC 6891
        /// keeps out of them - says what it can.
        /// </remarks>
        /// <param name="Record">A resource record.</param>
        public static String RDataOf(IDNSResourceRecord Record)
        {

            try
            {

                var fields = Record.ToZoneFileString().Split((Char[]?) null, 5, StringSplitOptions.RemoveEmptyEntries);

                if (fields.Length == 5)
                    return fields[4].Trim();

            }
            catch (Exception)
            { }

            return Record.RText ?? Record.ToString() ?? "";

        }

        #endregion

        #region (static) RCodeName(ResponseCode)

        /// <summary>
        /// The name the IANA registry of DNS RCODEs gives a response code -
        /// "NoError", "NXDomain", "ServFail", "Refused" - or its number where
        /// it gives none.
        /// </summary>
        /// <remarks>
        /// The registry's names and not Hermod's: "NameError" is what RFC 1035
        /// called it, and "NXDOMAIN" what everybody looking at a resolver
        /// searches for. One name for the page, the command line and QueryDNS,
        /// which says it is the registry's.
        ///
        /// 16 is BADVERS where it is the RCODE of a message, and BADSIG only
        /// in a TSIG record, which this is never asked about.
        /// </remarks>
        /// <param name="ResponseCode">A response code.</param>
        public static String RCodeName(DNSResponseCodes ResponseCode)

            => (Int32) ResponseCode switch {
                   0   => "NoError",
                   1   => "FormErr",
                   2   => "ServFail",
                   3   => "NXDomain",
                   4   => "NotImp",
                   5   => "Refused",
                   6   => "YXDomain",
                   7   => "YXRRSet",
                   8   => "NXRRSet",
                   9   => "NotAuth",
                   10  => "NotZone",
                   11  => "DSOTYPENI",
                   16  => "BADVERS",
                   17  => "BADKEY",
                   18  => "BADTIME",
                   19  => "BADMODE",
                   20  => "BADNAME",
                   21  => "BADALG",
                   22  => "BADTRUNC",
                   23  => "BADCOOKIE",
                   var number => number.ToString(CultureInfo.InvariantCulture)
               };

        #endregion

        #region (static) CertificateStatusOf(Outcome)

        /// <summary>
        /// The outcome of a judgement of a name server's certificate as the
        /// value of DNSServerController.CertificateStatus that it is:
        /// "pinMismatch" is "PinMismatch" - which is what the command line
        /// and QueryDNS say.
        /// </summary>
        /// <param name="Outcome">The outcome of a judgement, as its JSON has it.</param>
        public static String CertificateStatusOf(String? Outcome)

            => String.IsNullOrEmpty(Outcome)
                   ? "Unknown"
                   : Char.ToUpperInvariant(Outcome[0]) + Outcome[1..];

        #endregion

        #region (static) RecordTypeName(RecordType)

        /// <summary>
        /// The mnemonic of a record type, or the generic form of RFC 3597
        /// section 5 where Hermod has none for it: a type asked for by number
        /// comes back as "TYPE" and that number, which is what a zone file
        /// writes and what is read back - see ADNSResourceRecord.TypeName.
        /// </summary>
        /// <param name="RecordType">A record type.</param>
        public static String RecordTypeName(DNSResourceRecordTypes RecordType)

            => ADNSResourceRecord.TypeName(RecordType);

        #endregion

        #region (private) ClientFor(Server)

        /// <summary>
        /// A client that asks the given name server and nobody else, the way
        /// this node's own client asks it.
        /// </summary>
        /// <remarks>
        /// Without a cache: an answer out of the cache says nothing about
        /// whether that server would have given it, which is the whole
        /// question being asked. Everything else is the node's, so what is
        /// tested is this node's settings and not a fresh set of defaults.
        ///
        /// The server itself is handed over, not its address and port: made
        /// from those two, the client asked over UDP whatever the server was
        /// configured with, and a name server reached over TCP, TLS or HTTPS
        /// was tested on a transport it need not even listen on. And it is
        /// told how often to ask, which a new client does not know: left at
        /// Hermod's own one retry, a server that does not answer was asked
        /// twice on a node told to ask it once - measured, 6.2 seconds for a
        /// timeout of three.
        ///
        /// One place, so that whatever else a node will want to say about a
        /// server it asks on its own - how to check the certificate of one
        /// reached over TLS or HTTPS, say - is said here. One asked over SSH
        /// is asked on the connection the node hands out for it, which is the
        /// one its own client asks it on: one login, and one verdict.
        /// </remarks>
        /// <param name="Server">One of the configured name servers.</param>
        private DNSClient ClientFor(DNSServerConfig Server)

            => new ([ WithSSH(Server) ],
                    QueryTimeout:   Server.QueryTimeout ?? dnsClient.QueryTimeout,
                    UseQueryCache:  false) {

                   RecursionDesired            = dnsClient.RecursionDesired,
                   DnssecOK                    = dnsClient.DnssecOK,
                   FollowCNAMEs                = dnsClient.FollowCNAMEs,
                   MaxCNAMEFollows             = dnsClient.MaxCNAMEFollows,
                   MaxRetries                  = dnsClient.MaxRetries,

                   // Held to what the node's own client holds it to: a server
                   // tested on its own is judged as it is when it is asked for
                   // anything else.
                   RemoteCertificateValidator  = dnsClient.RemoteCertificateValidator

               };

        #endregion

        #region TryParseRecordTypes(JSON, out RecordTypes, out Error)

        /// <summary>
        /// The record types of a test query, as the web interface names them.
        /// </summary>
        /// <remarks>
        /// By name or by number, because the several hundred that exist are not
        /// all in this enumeration and somebody testing a resolver may well want
        /// one that is not.
        /// </remarks>
        public static Boolean TryParseRecordTypes(JToken?                                                 JSON,
                                                  out IEnumerable<DNSResourceRecordTypes>?                RecordTypes,
                                                  [NotNullWhen(false)] out String?                        Error)
        {

            RecordTypes  = null;
            Error        = null;

            if (JSON is null || JSON.Type == JTokenType.Null)
                return true;

            if (JSON is not JArray array)
            {
                Error = "'recordTypes' must be an array.";
                return false;
            }

            return TryParseRecordTypes(array.Select(token => token.Type == JTokenType.String || token.Type == JTokenType.Integer
                                                                 ? token.Value<String>() ?? ""
                                                                 : token.ToString()),
                                       out RecordTypes,
                                       out Error,
                                       out _);

        }

        #endregion

        #region TryParseRecordTypes(Texts, out RecordTypes, out Error, out Refused)

        /// <summary>
        /// The record types of a test query, as the command line and QueryDNS
        /// name them: at most <see cref="MaxQueryRecordTypes"/>, each a
        /// mnemonic or a number - see <see cref="TryParseRecordType"/>.
        /// </summary>
        /// <param name="Texts">The record types, as somebody wrote them; empty ones are left out.</param>
        /// <param name="RecordTypes">The record types, or null where none was given.</param>
        /// <param name="Error">Why they could not be read, in words.</param>
        /// <param name="Refused">And as a reason code of QueryDNS - see <see cref="DNSQueryRefusals"/>.</param>
        public static Boolean TryParseRecordTypes(IEnumerable<String>?                                    Texts,
                                                  out IEnumerable<DNSResourceRecordTypes>?                RecordTypes,
                                                  [NotNullWhen(false)] out String?                        Error,
                                                  [NotNullWhen(false)] out String?                        Refused)
        {

            RecordTypes  = null;
            Error        = null;
            Refused      = null;

            var texts    = (Texts ?? []).Select(text => text?.Trim() ?? "").Where(text => text.Length > 0).ToArray();

            if (texts.Length > MaxQueryRecordTypes)
            {
                Error    = $"One query may ask for at most {MaxQueryRecordTypes} record types.";
                Refused  = DNSQueryRefusals.TooManyRecordTypes;
                return false;
            }

            var parsed   = new List<DNSResourceRecordTypes>();

            foreach (var text in texts)
            {

                if (!TryParseRecordType(text, out var recordType))
                {
                    Error    = $"'{text}' is not a DNS resource record type.";
                    Refused  = DNSQueryRefusals.InvalidRecordType;
                    return false;
                }

                parsed.Add(recordType);

            }

            RecordTypes = parsed.Count > 0 ? parsed : null;
            return true;

        }

        #endregion

        #region TryParseRecordType(Text, out RecordType)

        /// <summary>
        /// One record type of a test query: its mnemonic, in any case, or its
        /// number.
        /// </summary>
        /// <remarks>
        /// A number is not taken as a mnemonic's spelling: Enum.TryParse reads
        /// "1" as the member whose value is 1 and "99999" as no error at all,
        /// so digits are read as a number of 16 bits and nothing else, and a
        /// mnemonic only where the enumeration has it.
        /// </remarks>
        /// <param name="Text">The record type, as somebody wrote it.</param>
        /// <param name="RecordType">The record type.</param>
        public static Boolean TryParseRecordType(String                      Text,
                                                 out DNSResourceRecordTypes  RecordType)
        {

            var text = Text.Trim();

            // The generic form of RFC 3597 section 5, for a type that has no
            // mnemonic yet: "TYPE65" is 65.
            if (text.Length > 4 && text.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase) && text[4..].All(Char.IsAsciiDigit))
                text = text[4..];

            if (text.Length > 0 && text.All(Char.IsAsciiDigit))
            {
                var isNumber = UInt16.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number);
                RecordType   = (DNSResourceRecordTypes) number;
                return isNumber;
            }

            if (text.Length > 0 &&
                Char.IsAsciiLetter(text[0]) &&
                Enum.TryParse(text, ignoreCase: true, out RecordType) &&
                Enum.IsDefined(RecordType))
            {
                return true;
            }

            RecordType = default;
            return false;

        }

        #endregion


        #region SyncTimeAsync(CancellationToken = default)

        /// <summary>
        /// Ask the time server what time it is: the key exchange first, then
        /// one authenticated NTP request, with every step in the log.
        /// </summary>
        /// <remarks>
        /// The clock of this node is not set from the answer, and that is
        /// deliberate: this says whether the time source can be reached and
        /// what it thinks of the local clock, which is what somebody pressing a
        /// button called "Sync now" in a web interface actually wants to know.
        /// Stepping the clock of a running node is a different
        /// thing, with meter readings and certificates hanging off it, and it
        /// is not something a button does by surprise.
        /// </remarks>
        #region (static) TLSSteps(TLS, Now)

        /// <summary>
        /// What a time server's TLS session and certificate say, and whether that
        /// held up - as steps of a server's test, from the session to the verdict.
        /// </summary>
        /// <remarks>
        /// Every certificate of the chain with both ends of its validity and the
        /// days that are left: the root's as much as the server's. A root can be
        /// pinned, and a pinned root that runs out stops whatever relies on it,
        /// however new the server's certificate is. The root also comes with its
        /// SHA-256 fingerprint, which is what a pin is compared with.
        ///
        /// The chain is the one this node built, not the one the server sent -
        /// see NTSKE_TLSInfo.ValidatedChain. Where none was built, the server's
        /// certificates are shown as they came.
        ///
        /// The verdict is Norn's, taken from what its validation decided; the
        /// reasons are its chain's, in words, because the platform's own texts
        /// for them are in whatever language the machine speaks.
        ///
        /// Of revocation it says what the key exchange asked, and only that. A
        /// key exchange this node judges leaves revocation to the node and asks
        /// nothing, so nothing is said of it here; the node's judgement, which
        /// follows, says what it found. One that asked online says so, and a
        /// status it could not have is not held against the certificate, so it
        /// is no reason why a chain did not validate either.
        /// </remarks>
        /// <param name="TLS">What the key exchange kept of its TLS session.</param>
        /// <param name="Now">The moment the days that are left are counted from.</param>
        public static IEnumerable<(String Level, String Text)> TLSSteps(NTSKE_TLSInfo   TLS,
                                                                         DateTimeOffset  Now)
        {

            var session = new[] {
                              TLS.NegotiatedTLSVersion,
                              TLS.NegotiatedCipherSuite,
                              TLS.NegotiatedApplicationProtocol is String protocol ? $"ALPN {protocol}" : null
                          }.Where(part => part is not null).ToArray();

            if (session.Length > 0)
                yield return ("info", $"{String.Join(", ", session)}.");

            if (TLS.ServerCertificate is null)
                yield break;

            IReadOnlyList<X509Certificate2> chain = TLS.ValidatedChain.  Count > 0 ? TLS.ValidatedChain
                                                  : TLS.CertificateChain.Count > 0 ? TLS.CertificateChain
                                                  : [ TLS.ServerCertificate ];

            for (var position = 0; position < chain.Count; position++)
            {

                var certificate = chain[position];
                var selfSigned  = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
                var last        = position == chain.Count - 1;

                var what        = position == 0  ? selfSigned ? "Server certificate, self-signed" : "Server certificate"
                                : !last          ? "Intermediate CA"
                                : selfSigned     ? "Root CA"
                                :                  "Last in the chain, and no root";

                var (level, validity) = Validity(certificate, Now);

                yield return (level,
                              String.Concat(
                                  $"{what}: {certificate.Subject}",
                                  position == 0 && NamesOf(certificate) is String names ? $", for {names}"               : "",
                                  last && !selfSigned                                   ? $", issued by {certificate.Issuer}" : "",
                                  $"; {CertificateEntry.KeyAlgorithmOf(certificate)}, {certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value}",
                                  $"; {validity}."
                              ));

                // What a pin is compared with: the server's own certificate,
                // and the certificate the chain ends at - one line where they
                // are the same, because the server signed its own.
                if (position == 0 || (last && selfSigned))
                    yield return ("info", $"{(position == 0 ? "Its" : "The root's")} SHA-256 fingerprint: {CertificateEntry.ThumbprintOf(certificate)}.");

            }

            var host     = TLS.CheckedHostname?.Trimmed;
            var errors   = TLS.CertificatePolicyErrors ?? SslPolicyErrors.None;
            var online   = TLS.RevocationMode == X509RevocationMode.Online;
            var unknown  = TLS.ChainStatus.Any(UnknownRevocation);

            if (errors == SslPolicyErrors.None)
            {

                yield return ("notice", String.Concat(
                                            "Validated: the chain ends at a root this machine trusts",
                                            online && !unknown ? ", nothing in it is revoked (asked online)"                : "",
                                            host is not null   ? $", and '{host}' is one of the server certificate's names" : "",
                                            "."
                                        ));

                if (online && unknown)
                    yield return ("notice", "Whether its chain is revoked could not be asked, which is not held against it.");

            }

            else
            {

                var reasons = TLS.ChainStatus.Where(status => !UnknownRevocation(status)).Select(ReasonFor).Distinct().ToList();

                if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && reasons.Count == 0)
                    reasons.Add("its chain did not validate");

                if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                    reasons.Add(host is not null
                                    ? $"'{host}' is not one of the server certificate's names"
                                    : "it was issued for another name");

                if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                    reasons.Add("no certificate came");

                yield return ("error", $"Not validated: {String.Join("; ", reasons)}.");

            }

        }

        /// <summary>
        /// Both ends of a certificate's validity, and where the given moment is
        /// between them - with the level that deserves.
        /// </summary>
        /// <remarks>
        /// A week's warning, as Norn's monitoring gives by default. Inside its
        /// validity is information; outside it, on either side, is an error.
        /// </remarks>
        private static (String Level, String Text) Validity(X509Certificate2  Certificate,
                                                            DateTimeOffset    Now)
        {

            var notBefore  = new DateTimeOffset(Certificate.NotBefore.ToUniversalTime());
            var notAfter   = new DateTimeOffset(Certificate.NotAfter. ToUniversalTime());
            var span       = String.Create(CultureInfo.InvariantCulture, $"valid {notBefore:yyyy-MM-dd HH:mm:ss} to {notAfter:yyyy-MM-dd HH:mm:ss} UTC");

            if (Now < notBefore)
                return ("error",   $"{span}, not valid for another {Days(notBefore - Now)} day(s)");

            if (Now > notAfter)
                return ("error",   $"{span}, expired {Days(Now - notAfter)} day(s) ago");

            var left = Days(notAfter - Now);

            return (left <= 7 ? "warning" : "info",
                    $"{span}, {left} day(s) left");

            static Int32 Days(TimeSpan Span)
                => (Int32) Math.Floor(Span.TotalDays);

        }

        /// <summary>
        /// The names a certificate is for - its subject alternative names, which
        /// are the only ones a host name is matched against - or null when it
        /// names none.
        /// </summary>
        private static String? NamesOf(X509Certificate2 Certificate)
        {

            var alternative = Certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();

            if (alternative is null)
                return null;

            var names = alternative.EnumerateDnsNames().
                            Concat(alternative.EnumerateIPAddresses().Select(address => address.ToString())).
                            ToArray();

            return names.Length == 0 ? null
                 : names.Length <= 4 ? String.Join(", ", names)
                 :                     $"{String.Join(", ", names.Take(4))} and {names.Length - 4} more";

        }

        /// <summary>
        /// Whether a chain's status says only that whether a certificate in it
        /// is revoked could not be had - which is held against no certificate.
        /// </summary>
        private static Boolean UnknownRevocation(X509ChainStatusFlags Status)

            => Status is X509ChainStatusFlags.RevocationStatusUnknown
                      or X509ChainStatusFlags.OfflineRevocation;

        /// <summary>
        /// Why a chain did not validate, in words.
        /// </summary>
        private static String ReasonFor(X509ChainStatusFlags Status)

            => Status switch {
                   X509ChainStatusFlags.UntrustedRoot            => "its root is not one this machine trusts",
                   X509ChainStatusFlags.PartialChain             => "no chain up to a root could be built",
                   X509ChainStatusFlags.NotTimeValid             => "a certificate in it is outside its validity",
                   X509ChainStatusFlags.Revoked                  => "a certificate in it has been revoked",
                   X509ChainStatusFlags.NotSignatureValid        => "a signature in it does not verify",
                   X509ChainStatusFlags.NotValidForUsage         => "a certificate in it is not meant for this use",
                   X509ChainStatusFlags.Cyclic                   => "the chain runs in a circle",
                   _                                             => Status.ToString()
               };

        #endregion

        #region TestTimeServerAsync(Host = null, CancellationToken = default)

        /// <summary>
        /// Ask one time server everything there is to ask, and write down each
        /// answer as it comes.
        /// </summary>
        /// <remarks>
        /// "Sync now" says whether the whole thing worked. This says where it
        /// got to: the name resolved to these addresses, the TCP connection
        /// took this long, the TLS handshake that long, the key exchange
        /// agreed on this algorithm and handed over that many cookies and
        /// named these NTP servers, and the authenticated NTP request went to
        /// this endpoint and came back that far off. A server that fails does
        /// so at one of those, and which one is the whole of what somebody
        /// needs.
        ///
        /// <b>Two kinds of "which server".</b> A name that is not the
        /// configured one is treated as a time server in its own right: its own
        /// key exchange, its own time request. An address is treated as one of
        /// the servers the configured exchange named - the key exchange happens
        /// where it must, with the host that has a certificate, and the
        /// authenticated request is then directed at that address with the
        /// cookies that exchange issued. Which is what RFC 8915 section 4.1.7
        /// describes: the negotiated server is the one "that will accept the
        /// supplied cookies".
        ///
        /// An address cannot have a key exchange of its own - the TLS
        /// certificate has to be checked against a name - and a key exchange
        /// very commonly names addresses, so this is the ordinary case rather
        /// than the awkward one.
        ///
        /// The clock of this node is not stepped by any of it, the same as
        /// "Sync now".
        ///
        /// <b>Stages.</b> Every step says which of the stages of the white paper
        /// "Secure Time Synchronization", section 3.2.7, it belongs to - see
        /// <see cref="TimeServerTestStages"/> - and a test that ends without a
        /// time says in "failedAt" which one it ended at, so that a CSMS or a
        /// diagnostic agent need not read it out of the sentences. Beside them
        /// the offset and the round trip the answer gave, and the id of the
        /// server where it is one of the group's: what OCPP's TestTimeServer
        /// tells.
        /// </remarks>
        /// <param name="Host">
        /// Which time server: a name to ask in its own right, an address to ask
        /// among the ones the configured exchange named, or nothing for the
        /// configured server itself.
        /// </param>
        public Task<JObject> TestTimeServerAsync(String?            Host                = null,
                                                 CancellationToken  CancellationToken   = default)

            => TestTimeServerAsync(LegalTime, Host, CancellationToken);


        /// <summary>
        /// Ask one time server of a group everything there is to ask, and write
        /// down each answer as it comes - see
        /// <see cref="TestTimeServerAsync(String, CancellationToken)"/>.
        /// </summary>
        /// <param name="Group">The group whose client and servers the test starts from.</param>
        /// <param name="Host">Which time server, as there.</param>
        public async Task<JObject> TestTimeServerAsync(NTSGroup           Group,
                                                       String?            Host                = null,
                                                       CancellationToken  CancellationToken   = default)
        {

            var clock  = Stopwatch.StartNew();
            var steps  = new JArray();

            // Where the test has got to - one of the stages of the white paper
            // "Secure Time Synchronization", section 3.2.7 - which every step
            // is written down with, and which a test that ends without a time
            // ended at. Set as the test gets there, and not worked out from the
            // steps afterwards: a chain the machine does not trust is an error
            // step at the server's authentication, and the test still goes on
            // where the node trusts the root itself.
            var stage      = TimeServerTestStages.Configuration;
            Double? offset_ms     = null;
            Double? roundTrip_ms  = null;
            String? clientId      = null;

            void Step(String Level, String Text)
                => steps.Add(new JObject(
                       new JProperty("at_ms",  clock.ElapsedMilliseconds),
                       new JProperty("stage",  stage),
                       new JProperty("level",  Level),
                       new JProperty("text",   Text)
                   ));

            JObject Done(String Where, Boolean OK)
            {
                clock.Stop();
                return new JObject(
                           new JProperty("host",          Where),
                           new JProperty("id",            clientId),
                           new JProperty("ok",            OK),
                           new JProperty("failedAt",      OK ? null : stage),
                           new JProperty("runtime_ms",    clock.ElapsedMilliseconds),
                           new JProperty("offset_ms",     offset_ms),
                           new JProperty("roundTrip_ms",  roundTrip_ms),
                           new JProperty("steps",         steps)
                       );
            }

            #region Which server, and with which settings

            if (!Group.Enabled)
            {
                Step("error", $"Time synchronisation is switched off on this {Kind.Name}, so nothing was asked.");
                return Done(Host ?? "", false);
            }

            if (Group.Client is not NTSClient configured)
            {
                Step("error", $"NTS group '{Group.Id}' names no time server, so nothing was asked.");
                return Done(Host ?? "", false);
            }

            var wanted      = Host?.Trim();
            var host        = configured.Hostname;

            /// Set when the time request is to go somewhere other than the host
            /// the key exchange happens with.
            String? directedAt = null;

            if (!String.IsNullOrEmpty(wanted) &&
                !String.Equals(wanted.TrimEnd('.'), host.ToString().TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
            {

                if (System.Net.IPAddress.TryParse(wanted.Trim('[', ']'), out _))
                    // An address cannot have a key exchange of its own: the TLS
                    // certificate is issued for a name. So the exchange stays
                    // with the configured host, and the time request is
                    // directed at this address with the cookies that exchange
                    // issued - which is what a negotiated server is for.
                    directedAt = wanted.Trim('[', ']');

                else if (!DomainName.TryParse(wanted.TrimEnd('.'), out var other, out _))
                {
                    Step("error", $"'{wanted}' is neither a name nor an address that can be asked.");
                    return Done(wanted, false);
                }

                else
                    host = other;

            }

            var where = directedAt ?? $"{host}";

            // The name as people read it, for every sentence below - the steps
            // and the log alike. Without the root's dot: "ptbtime1.ptb.de." is
            // the name exactly, and in the middle of a line it reads like a
            // typing mistake, which is why everything else this node prints
            // leaves it out.
            var name  = host.Trimmed;

            // A server of the group is asked on its own ports, which need not
            // be those of the client above: the page tests each server from
            // its own row, and a server with a port of its own was asked on
            // the usual one and reported as not answering.
            var entry      = directedAt is null
                                 ? Group.Sources.Sources.FirstOrDefault(source => source.Hostname.Equals(host))
                                 : null;

            var ntsKEPort  = entry?.NTSKEPort ?? configured.NTSKE_Port;
            var ntpPort    = entry?.NTPPort   ?? configured.NTP_Port;

            // Its id, which OCPP names it by: the instance of its
            // NTPClientController. Only for a server of the group.
            clientId       = entry is not null
                                 ? ServerIdOf(Group, entry)
                                 : null;

            Step("info", directedAt is null
                             ? String.Format(System.Globalization.CultureInfo.InvariantCulture,
                                             "Asking {0}: key exchange on port {1}, time on port {2}, {3:0.#} second(s) allowed.",
                                             name, ntsKEPort, ntpPort, configured.Timeout?.TotalSeconds ?? 0)
                             : $"Asking {directedAt} for the time, with cookies from a key exchange with {name} - " +
                                "an address cannot have a key exchange of its own, because the TLS certificate is " +
                                "issued for a name.");

            Log.Info($"NTS test: asking {name} ...", "nts", "test");

            #endregion

            #region Does the name resolve

            stage = TimeServerTestStages.NameResolution;

            // Whether the name found no address here. The key exchange is asked
            // anyway - its own lookup is the one that counts - but where it then
            // connects to nothing, it is the name the test ended at, not the key
            // exchange: it used to say "failedAt": "KeyExchange" after waiting its
            // whole timeout for the same name servers.
            var unresolved = false;

            if (!System.Net.IPAddress.TryParse(host.ToString().TrimEnd('.'), out _))
            {
                try
                {

                    var lookedUp  = await dnsClient.Query(
                                              DNSServiceName.Parse(host.ToString()),
                                              [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                              CancellationToken: CancellationToken
                                          );

                    // The address and not the whole record. A resource
                    // record writes itself out with its class, its time to
                    // live and the moment it expires, which in a line that is
                    // about "does this name resolve" is four facts nobody
                    // asked for and one they did.
                    var addresses = lookedUp.Answers.Take(8).
                                        Select(record => (record.RText ?? record.ToString()).Split(',')[0].Trim()).
                                        ToArray();

                    unresolved = addresses.Length == 0;

                    // A query nobody answered says so: it used to read
                    // "resolved to nothing (ServerFailure)", which is what a
                    // name server says, and none had said anything.
                    Step(addresses.Length > 0 ? "info" : "warning",
                         addresses.Length > 0  ? $"'{name}' resolves to {String.Join(", ", addresses)}."
                       : lookedUp.IsTimeout    ? $"'{name}' could not be looked up here: its name servers did not answer, the query timed out. Asking anyway."
                                               : $"'{name}' resolved to nothing ({lookedUp.ResponseCode}). Asking anyway.");

                }
                catch (Exception e)
                {
                    unresolved = true;
                    Step("warning", $"'{name}' could not be looked up here: {e.Message}. Asking anyway.");
                }
            }

            #endregion

            // The configured client itself when the exchange is with the host it
            // was built for, and a fresh one only when this test was pointed at
            // a different name.
            //
            // A throwaway client per test spent its cookies into the bin: the
            // NTS page reported zero cookies and "no key exchange has happened
            // yet" however often somebody pressed the button, which is a page
            // describing nothing while looking like a measurement. Reusing the
            // configured client is what makes those numbers mean something, and
            // it is also what a second test now shows - an exchange being
            // renegotiated over a pool that already holds cookies, which is the
            // case that used to answer NTSN.
            //
            // Equals and not ==: both sides are DomainName here so the operator
            // would bind correctly, but this comparison is one refactoring away
            // from being made against IDomainName, where == is reference
            // equality and silently answers "different" for the same name.
            //
            // And offering what the server is to be offered, as every round
            // does: a client offering something else would test a key exchange
            // the group never makes.
            var offer  = AEADOffer(host);

            // And at its key exchange server, where it has one of its own,
            // asking for it as the NTP server, as every round does.
            var ownKeyExchange = KeyExchangeHostOf(host);

            var asking = ownKeyExchange is null &&
                         host.Equals(configured.Hostname) &&
                         ntsKEPort == configured.NTSKE_Port   &&
                         ntpPort   == configured.NTP_Port     &&
                         Offers(configured, offer)
                             ? configured
                             : new NTSClient(
                                   ownKeyExchange ?? host,
                                   NTSKE_Port:                  ntsKEPort,
                                   NTP_Port:                    ntpPort,
                                   RemoteCertificateValidator:  TimeServerValidator(host),
                                   Timeout:                     configured.Timeout,
                                   DNSClient:                   dnsClient,
                                   OfferedAEADAlgorithms:       offer,
                                   TimeProvider:                TimeProvider,
                                   RequestedNTPServer:          ownKeyExchange is null ? null : host
                               );

            try
            {

                #region The key exchange

                var judgedFrom  = TimeProvider.GetUtcNow();
                var overTLS     = false;
                NTSKEResult keyExchange;

                // Over SSH, where the server's entry says so, as every round
                // makes it: on a connection of its own, its host key judged, and
                // with a client that never renews its cookies over TLS.
                stage = TimeServerTestStages.Connection;

                if (SSHOf(host) is NTSServerSSH overSSH)
                {

                    Step("info", $"Key exchange over SSH, {overSSH.TextFor(host.Trimmed)} ...");

                    asking = new NTSClient(
                                 host,
                                 NTP_Port:               ntpPort,
                                 Timeout:                configured.Timeout,
                                 DNSClient:              dnsClient,
                                 OfferedAEADAlgorithms:  offer,
                                 TimeProvider:           TimeProvider,
                                 CookiePoolPolicy:       new NTSCookiePoolPolicy { RenegotiateWhenExhausted = false }
                             );

                    // The shared connection, where the entry says so, goes on after
                    // the test; one of the test's own does not.
                    SshClient? own = null;

                    try
                    {

                        var ssh = overSSH.IsShared
                                      ? await SharedSSHConnectionTo(host, NTSKE_SSH.SubsystemName, CancellationToken)
                                      : own = await ConnectToTimeServerOverSSH(host, overSSH, CancellationToken);

                        stage = TimeServerTestStages.ServerAuthentication;

                        if (overSSH.IsShared)
                            Step("info", $"It shows the SSH host key {SshFingerprint.Sha256(ssh.ServerHostKey)}, which the shared connection is held to.");

                        else if (HostKeyJudgementOf(host) is TimeServerHostKeyJudgement shown && shown.At >= judgedFrom)
                            Step(shown.Matched ? "info" : "warning", $"It showed the SSH host key {shown.Shown}: {shown.Why}.");

                        stage = TimeServerTestStages.KeyExchange;

                        keyExchange = await asking.GetNTSKERecordsOverSSH(ssh, CancellationToken: CancellationToken);

                    }
                    catch (Exception e) when (!CancellationToken.IsCancellationRequested)
                    {

                        // A host key that was refused is why there is no
                        // connection, and the stage the test ended at.
                        if (HostKeyJudgementOf(host) is TimeServerHostKeyJudgement refused && refused.At >= judgedFrom && !refused.Accepted)
                        {
                            stage = TimeServerTestStages.ServerAuthentication;
                            Step("error", $"It showed the SSH host key {refused.Shown}, but {refused.Why}: refused.");
                        }

                        // A connection of its own to a name that has no address
                        // here never was one: the test ended at the name.
                        else if (unresolved &&
                                 !overSSH.IsShared &&
                                 stage == TimeServerTestStages.Connection)
                        {
                            stage = TimeServerTestStages.NameResolution;
                        }

                        Step("error", $"No SSH connection for the key exchange: {e.Message}");
                        Log.Warning($"NTS test: the key exchange over SSH with {name} failed: {e.Message}", "nts", "ntske", "ssh", "test");
                        return Done(where, false);

                    }
                    finally
                    {
                        if (own is not null)
                            await own.DisposeAsync();
                    }

                }
                else
                {
                    Step("info", "Key exchange over TLS ...");
                    keyExchange = await asking.GetNTSKERecords(CancellationToken: CancellationToken);
                    overTLS     = true;
                }

                if (keyExchange.Response?.TimingInfo is NTSKE_TimingInfo timing)
                {

                    stage = TimeServerTestStages.Connection;

                    if (timing.ConnectedIPAddress is not null)
                        Step("info", $"Connected to {timing.ConnectedIPAddress}" +
                                     (timing.ResolvedIPAddresses.Any()
                                          ? $", of {timing.ResolvedIPAddresses.Count()} address(es) that were offered"
                                          : "") + ".");

                    var went = new[] {
                                   timing.DNSLookupDuration      is TimeSpan dns  ? $"name {dns.TotalMilliseconds:0} ms"      : null,
                                   timing.TCPConnectDuration     is TimeSpan tcp  ? $"TCP {tcp.TotalMilliseconds:0} ms"       : null,
                                   timing.TLSHandshakeDuration   is TimeSpan tls  ? $"TLS {tls.TotalMilliseconds:0} ms"       : null,
                                   timing.NTSKEProtocolDuration  is TimeSpan ke   ? $"key exchange {ke.TotalMilliseconds:0} ms" : null
                               }.Where(one => one is not null).ToArray();

                    // Nothing timed is nothing to say: it used to say "Where the
                    // time went: ." for an exchange that got nowhere.
                    if (went.Length > 0)
                        Step("info", $"Where the time went: {String.Join(", ", went)}.");

                }

                // Before the verdict on the exchange, and whichever way it went:
                // a certificate that was refused is the one to see most of all.
                stage = TimeServerTestStages.ServerAuthentication;

                if (keyExchange.TLSInfo is NTSKE_TLSInfo tlsInfo)
                    foreach (var (level, text) in TLSSteps(tlsInfo, TimeProvider.GetUtcNow()))
                        Step(level, text);

                // And what this node made of it, beyond what the machine did: a
                // root of its own, and what the server is held to. From this
                // key exchange only - a judgement from before it would be about
                // another handshake.
                if (asking.RemoteCertificateValidator is not null &&
                    LastJudgementOf(asking.Hostname) is ServerJudgement judgement &&
                    judgement.At >= judgedFrom)
                {
                    foreach (var (level, text) in judgement.Steps)
                        Step(level, text);
                }

                if (!keyExchange.Success || keyExchange.Response is null)
                {

                    // Over TLS with the server itself, to a name that found no
                    // address here, and connected to nothing: the name is where
                    // the test ended, whatever the exchange calls its timeout.
                    var atTheName = overTLS                &&
                                    unresolved             &&
                                    ownKeyExchange is null &&
                                    keyExchange.Response?.TimingInfo?.ConnectedIPAddress is null;

                    stage = atTheName
                                ? TimeServerTestStages.NameResolution
                                : TimeServerTestStages.Of(keyExchange.ErrorCategory);

                    Step("error", $"The key exchange failed ({keyExchange.ErrorCategory}): {keyExchange.ErrorMessage}");

                    // Said where the exchange does not say it itself: a DNS error
                    // of its own already names the name, a timeout does not.
                    if (atTheName && TimeServerTestStages.Of(keyExchange.ErrorCategory) != TimeServerTestStages.NameResolution)
                        Step("error", $"It connected to nothing: '{name}' has no address here, and that is where this test ended.");

                    Log.Warning($"NTS test: the key exchange with {name} failed: {keyExchange.ErrorMessage}", "nts", "ntske", "test");
                    return Done(where, false);
                }

                stage = TimeServerTestStages.KeyExchange;

                var response = keyExchange.Response;

                foreach (var warning in response.WarningMessages)
                    Step("warning", $"The key exchange warned: {warning}");

                Step("notice", $"The key exchange succeeded: {response.AEADAlgorithm}, {response.Cookies.Count()} cookie(s).");

                Step("info", response.NTPv4ServerNames.Any()
                                 ? $"It named these NTP servers: {String.Join(", ", response.NTPv4ServerNames)}."
                                 : "It named no NTP server of its own, so the time is asked of this host.");

                if (directedAt is not null &&
                    !response.NTPv4ServerNames.Any(named => String.Equals(named.Trim('[', ']').TrimEnd('.'),
                                                                          directedAt,
                                                                          StringComparison.OrdinalIgnoreCase)))
                {
                    Step("error", $"This exchange did not name {directedAt}, so the cookies it issued were not said to be " +
                                   "accepted there. Nothing was sent: a cookie spent on a server holding different master " +
                                   "keys is wasted, and the refusal it earns is reported against the wrong machine.");
                    return Done(where, false);
                }

                #endregion

                #region The authenticated time request

                stage = TimeServerTestStages.TimeRequest;

                Step("info", "Authenticated NTP request ...");

                var query = await asking.QueryTime(NTSKEResponse:      response,
                                                   NTPServer:          directedAt,
                                                   CancellationToken:  CancellationToken);

                if (!query.Success || query.Response is null)
                {
                    stage = TimeServerTestStages.Of(query.ErrorCategory);
                    Step("error", $"The NTP request to {query.RemoteDescription} failed " +
                                  $"({query.ErrorCategory}): {query.ErrorMessage}");
                    Log.Warning($"NTS test: the NTP request to {name} failed: {query.ErrorMessage}", "nts", "ntp", "test");
                    return Done(where, false);
                }

                Step("info", $"Answered by {query.RemoteDescription}" +
                             (query.Attempts > 1 ? $", after {query.Attempts} attempts" : "") +
                             $"; {query.RemainingCookiesAfterQuery} cookie(s) left" +
                             (query.NewCookieReceived ? ", and a fresh one came back" : "") + ".");

                if (query.StopwatchRoundTripTime is TimeSpan roundTrip)
                {
                    roundTrip_ms = roundTrip.TotalMilliseconds;
                    Step("info", String.Format(System.Globalization.CultureInfo.InvariantCulture,
                                               "Round trip {0:0.0} ms.", roundTrip.TotalMilliseconds));
                }

                var offset = query.Response.ClockOffset;

                offset_ms = offset?.TotalMilliseconds;

                // Invariant, so that a decimal point stays a point: these
                // sentences are English, and a node in a German locale
                // otherwise wrote "+148,0 ms" in the middle of one.
                Step("notice", offset.HasValue
                                   ? String.Format(System.Globalization.CultureInfo.InvariantCulture,
                                                   "This {2}'s clock is {0:+0.0;-0.0;0} ms off what {1} says.",
                                                   offset.Value.TotalMilliseconds, name, Kind.Name)
                                   : $"{name} answered, but said nothing this {Kind.Name} could take an offset from.");

                #endregion

                Step("info", "The clock was not stepped: that is a different thing, with meter readings and " +
                             "certificates hanging off it, and not something a test does by surprise.");

                Log.Notice($"NTS test: {name} answered in {clock.ElapsedMilliseconds} ms.", "nts", "test");

                return Done(where, true);

            }
            catch (Exception e)
            {
                Step("error", $"{e.GetType().Name}: {e.Message}");
                Log.Warning($"NTS test: asking {name} failed: {e.Message}", "nts", "test");
                return Done(where, false);
            }

        }

        #endregion

        /// <summary>
        /// Ask this node's group of time servers what the time is.
        /// </summary>
        /// <remarks>
        /// The group and not the single client, because a clock that a charge
        /// is billed by should not move on the word of one server. What comes
        /// back is the group's verdict - the median of the servers that
        /// answered and authenticated, how many there were, how far apart they
        /// were - and a line for each server, because a log book records what
        /// was asked and what each one said, not only the conclusion.
        ///
        /// The detailed test beside this is the other question and keeps its
        /// own path: one server, its key exchange, its cookies, its round trip.
        /// A group cannot answer that, having four of each.
        /// </remarks>
        public Task<JObject> SyncTimeAsync(CancellationToken CancellationToken = default)

            => SyncTimeAsync(LegalTime, CancellationToken);


        /// <summary>
        /// Ask a group of time servers what the time is - see
        /// <see cref="SyncTimeAsync(CancellationToken)"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Counted as running against the group until the task it returns has
        /// completed, so that taking the group away waits for it; and asked with
        /// a token that taking it away cancels, so that it does not have to wait
        /// long. What was cancelled that way is written down nowhere - not into
        /// the group, which nobody has any more, and not into the log, which says
        /// the group was removed.
        /// </para>
        /// <para>
        /// Until the task has completed, and not only until the asking is done.
        /// Counted down in a finally of the asking, the check told the group it
        /// had ended while its task was still to be completed, and taking the
        /// group away, which goes on on a thread of its own, could return before
        /// it was. A continuation of the task counts it down instead, and a
        /// continuation runs only once its task has completed.
        /// </para>
        /// </remarks>
        /// <param name="Group">The group of time servers.</param>
        public Task<JObject> SyncTimeAsync(NTSGroup           Group,
                                           CancellationToken  CancellationToken = default)
        {

            if (!Group.TryBegin())
                return Task.FromResult(Removed());

            var asked = AskAsync();

            _ = asked.ContinueWith(_ => Group.End(),
                                   CancellationToken.None,
                                   TaskContinuationOptions.ExecuteSynchronously,
                                   TaskScheduler.Default);

            return asked;


            async Task<JObject> AskAsync()
            {
                try
                {

                    using var asking = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, Group.Stopping);

                    return await AskTheGroupAsync(Group, asking.Token);

                }
                catch (OperationCanceledException) when (Group.Stopping.IsCancellationRequested)
                {
                    return Removed();
                }
            }


            JObject Removed()

                => new (
                       new JProperty("ok",      false),
                       new JProperty("server",  Group.Id),
                       new JProperty("at",      TimeProvider.GetUtcNow().ToString("o")),
                       new JProperty("error",   $"NTS group '{Group.Id}' was removed.")
                   );

        }

        /// <summary>
        /// What <see cref="SyncTimeAsync(NTSGroup, CancellationToken)"/> does
        /// once it counts as running.
        /// </summary>
        private async Task<JObject> AskTheGroupAsync(NTSGroup           Group,
                                                     CancellationToken  CancellationToken)
        {

            if (!Group.Enabled)
            {
                Log.Warning($"Time synchronisation was not run: NTS is switched off on this {Kind.Name}.", "nts", "test");
                return Failed($"NTS is switched off on this {Kind.Name}.");
            }

            var group      = Group.Sources;
            var asked      = group.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()).ToArray();
            var asking     = asked.Select(hostname => hostname.TrimEnd('.')).ToArray();
            var stopwatch  = Stopwatch.StartNew();

            Log.Info($"NTS: asking the {asked.Length} time server(s) of group '{group.Name}' ...", "nts", "test");

            try
            {

                // Its servers first sent a query whose answer is ignored, where
                // the group has not asked them for its Preflight.
                var preflight = Group.BeginRound(TimeProvider.GetUtcNow());

                var verdict = await group.Measure(timeEngine, dnsClient, CancellationToken, preflight);

                // Taken away while its servers were being asked: whatever came
                // back - a server cut off in the middle reads as one that did
                // not answer - belongs to nobody.
                Group.Stopping.ThrowIfCancellationRequested();

                stopwatch.Stop();

                // Every signed response, as evidence - see
                // WWCPNode.TimeServerSignedResponses.cs.
                WriteDownSignedResponses(verdict.Results);

                #region What the group concluded, and what each server said

                var servers = new JArray(
                                  verdict.Results.Select(result => new JObject(
                                      new JProperty("hostname",       result.ServerHostname.ToString()),
                                      new JProperty("id",             ServerIdOf(Group, result.ServerHostname)),
                                      new JProperty("ok",             TimeSyncVerdict.CanBeTrusted(result)),
                                      new JProperty("offset_ms",      result.NTP?.Offset.TotalMilliseconds),
                                      new JProperty("roundTrip_ms",   result.NTP?.RoundTripDelay.TotalMilliseconds),
                                      new JProperty("authenticated",  result.NTP?.NTSAuthenticationValid),
                                      new JProperty("keyExchange",    result.NTSKEFromCache ? "reused" : "new"),
                                      new JProperty("preflight",      result.PreflightSent),
                                      new JProperty("signed",         result.SignedResponse is { } signed
                                                                          ? new JObject(
                                                                                new JProperty("ok",        signed.Success),
                                                                                new JProperty("keyId",     signed.KeyId),
                                                                                new JProperty("verified",  signed.Verified)
                                                                            )
                                                                          : null),
                                      new JProperty("error",          result.ErrorMessage?.ToString())
                                  ))
                              );

                var groupJSON = new JObject(
                                    new JProperty("name",               group.Name),
                                    new JProperty("answered",           verdict.Answered),
                                    new JProperty("required",           verdict.Required),
                                    new JProperty("agreeing",           verdict.Agreeing),
                                    new JProperty("offset_ms",          verdict.Offset?.TotalMilliseconds),
                                    new JProperty("spread_ms",          verdict.Spread?.TotalMilliseconds),
                                    new JProperty("deviationExceeded",  verdict.DeviationExceeded)
                                );

                #endregion

                if (!verdict.IsUsable)
                {

                    // Before the failure, so that the log reads "disagree by ...",
                    // then "produced no time": the spread is written down whether
                    // the round has a time or not.
                    if (verdict.DeviationExceeded)
                        LogTime(Group, LogLevel.Warning, DeviationWarning(group.Name, verdict.Spread!.Value, group.MaxDeviation), "nts", "test");

                    var failure = Failed(
                                      NoTimeReason(verdict),
                                      new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                                      new JProperty("group",       groupJSON),
                                      new JProperty("servers",     servers)
                                  );

                    // Into the metrological log with what each server said: a
                    // clock that could not be checked is a fact about the time
                    // this node stamps everything with, and why is part of it.
                    LogTime(Group, LogLevel.Error,
                            $"NTS: group '{group.Name}' produced no time after {stopwatch.ElapsedMilliseconds} ms: {verdict}.",
                            (JObject) failure.DeepClone(),
                            "nts", "test");

                    CountTheFailure(Group);

                    return Remember(failure);

                }

                // What the asking was actually for. The clock of this node is
                // not stepped by it - see WWCPNode.Clock.cs - so the
                // offset is the whole of the result: it is the difference
                // between what this node believes and what servers that know
                // were saying at the same moment.
                // A name only where naming one is the truth. Four servers
                // answering is not "checked against ptbtime1", and picking one
                // of them to print would be the nicer-looking lie. Nor is it
                // "legal (2 of 4 server(s))", which is what this used to say:
                // a screen puts it behind "checked against" in its own
                // language, and the numbers are what it says it with.
                Group.Checked(TimeProvider.GetUtcNow(),
                              verdict.Offset,
                              asked.Length,
                              verdict.Answered,
                              asked.Length == 1
                                  ? asking[0]
                                  : null);

                // Written down, which is what the white paper asks for: the
                // disagreement belongs in the metrological log book. That there
                // is a time all the same means a majority of the servers agreed
                // and outvoted the rest (section 3.2.3, "Agreement"); without
                // one the round has failed above. Both lines read the same
                // under every culture - see DeviationWarning.
                if (verdict.DeviationExceeded)
                    LogTime(Group, LogLevel.Warning, DeviationWarning(group.Name, verdict.Spread!.Value, group.MaxDeviation), "nts", "test");

                var answer = new JObject(
                                 new JProperty("ok",          true),
                                 new JProperty("server",      $"{group.Name}: {String.Join(", ", asking)}"),
                                 new JProperty("at",          TimeProvider.GetUtcNow().ToString("o")),
                                 new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                                 new JProperty("offset_ms",   verdict.Offset?.TotalMilliseconds),
                                 new JProperty("group",       groupJSON),
                                 new JProperty("servers",     servers)
                             );

                // With what each server said, which is what a log book records:
                // what was asked and what each one answered, and not only the
                // conclusion.
                LogTime(Group, LogLevel.Notice,
                        AnsweredLine(group.Name, stopwatch.ElapsedMilliseconds, verdict),
                        (JObject) answer.DeepClone(),
                        "nts", "test");

                // After the line saying what it found, so that the log reads
                // "answered", then "a time again after ...".
                CountTheSuccess(Group);

                // And then whether what it found is reported.
                ReportTheOffset(Group, verdict.Offset);

                return Remember(answer);

            }
            catch (OperationCanceledException) when (Group.Stopping.IsCancellationRequested)
            {
                // See SyncTimeAsync(Group, CancellationToken).
                throw;
            }
            catch (Exception e)
            {
                stopwatch.Stop();
                LogTime(Group, LogLevel.Error, $"NTS: asking group '{group.Name}' failed after {stopwatch.ElapsedMilliseconds} ms: {e.Message}", "nts", "test");
                CountTheFailure(Group);
                return Remember(Failed(e.Message));
            }


            JObject Failed(String Error, params JProperty[] More)
            {

                var json = new JObject(
                               new JProperty("ok",      false),
                               new JProperty("server",  Group.Sources.Name),
                               new JProperty("at",      TimeProvider.GetUtcNow().ToString("o")),
                               new JProperty("error",   Error)
                           );

                foreach (var property in More)
                    json.Add(property);

                return json;

            }

            JObject Remember(JObject Result)

                => Group.Synced(Result);

        }

        #endregion


        #region (static) ServerIdOf(Group, Server)

        /// <summary>
        /// The id of a server of a group - what OCPP names it by, the instance
        /// of its NTPClientController - or null where it is none of the group's.
        /// </summary>
        /// <param name="Group">The group.</param>
        /// <param name="Server">One of its servers.</param>
        public static String? ServerIdOf(NTSGroup           Group,
                                         NTSServerEndpoint  Server)
        {

            var index = 0;

            foreach (var source in Group.Sources.Sources)
            {

                if (ReferenceEquals(source, Server))
                    return index < Group.ServerIds.Count ? Group.ServerIds[index] : null;

                index++;

            }

            return null;

        }

        /// <summary>
        /// The id of the first server of a group with the given host name, or
        /// null where the group has none: the host name is what a round's
        /// measurement says which server it was.
        /// </summary>
        /// <param name="Group">The group.</param>
        /// <param name="Hostname">The host name of one of its servers.</param>
        public static String? ServerIdOf(NTSGroup    Group,
                                         DomainName  Hostname)

            => Group.Sources.Sources.FirstOrDefault(source => source.Hostname.Equals(Hostname)) is NTSServerEndpoint server
                   ? ServerIdOf(Group, server)
                   : null;

        #endregion

        #region (static) NoTimeReason(Verdict)

        /// <summary>
        /// Why a round produced no time, as the error of its result.
        /// </summary>
        /// <remarks>
        /// Three different things to go and look at: nobody answered, too few
        /// answered, or enough answered and they contradict each other.
        /// </remarks>
        /// <param name="Verdict">What the group concluded.</param>
        public static String NoTimeReason(TimeSyncVerdict Verdict)

            => Verdict.Outcome switch {

                   TimeSyncOutcome.NothingAnswered
                       => "No time server answered.",

                   TimeSyncOutcome.ServersDisagree
                       => $"The time servers disagree: only {Verdict.Agreeing} of the {Verdict.Answered} that answered lie within the agreed deviation.",

                   _   => $"Only {Verdict.Answered} of {Verdict.Required} time server(s) answered."

               };

        #endregion

        #region (static) AnsweredLine(GroupName, Milliseconds, Verdict)

        /// <summary>
        /// The line a synchronisation that produced a time is logged with.
        /// </summary>
        /// <param name="GroupName">The group that was asked.</param>
        /// <param name="Milliseconds">How long asking it took.</param>
        /// <param name="Verdict">What the group concluded.</param>
        public static String AnsweredLine(String           GroupName,
                                          Int64            Milliseconds,
                                          TimeSyncVerdict  Verdict)

            => $"NTS: group '{GroupName}' answered in {Milliseconds} ms - {Verdict}.";

        #endregion

        #region (static) DeviationWarning(GroupName, Spread, MaxDeviation)

        /// <summary>
        /// The warning a synchronisation writes when the servers that answered
        /// were further apart than the group allows.
        /// </summary>
        /// <remarks>
        /// Invariant, like the verdict it is logged beside: under a German
        /// culture it read "disagree by 2,2 ms". And the agreed deviation with
        /// as many places as it has - it may be set as low as a millisecond,
        /// and a whole-second format wrote that as "0 s".
        /// </remarks>
        /// <param name="GroupName">The group that was asked.</param>
        /// <param name="Spread">How far apart the servers that answered were.</param>
        /// <param name="MaxDeviation">How far apart the group allows them to be.</param>
        public static String DeviationWarning(String    GroupName,
                                              TimeSpan  Spread,
                                              TimeSpan  MaxDeviation)

            => String.Format(CultureInfo.InvariantCulture,
                             "NTS: the time servers of group '{0}' disagree by {1:F1} ms, " +
                             "which reaches the agreed deviation of {2:0.###} s.",
                             GroupName,
                             Spread.TotalMilliseconds,
                             MaxDeviation.TotalSeconds);

        #endregion

    }

}
