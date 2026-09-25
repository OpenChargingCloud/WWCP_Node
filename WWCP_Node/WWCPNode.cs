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
using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using NullMailer = org.GraphDefined.Vanaheimr.Hermod.SMTP.NullMailer;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What every one of these programs is before it is anything in
    /// particular: a log, a configuration file, name resolution and the time,
    /// a certificate store, an HTTP server with accounts in front of it and a
    /// web interface behind it. A vehicle, a station or a meter is one of
    /// these with its own sections in the same file, its own JSON API below
    /// <see cref="HTTPRootPath"/> and its own bundle to serve - and on its
    /// own, with none of that, it is what the tests construct.
    /// </summary>
    public partial class WWCPNode : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// How the last time synchronisation went, as the web interface reads
        /// it, or null while none has been asked for.
        /// </summary>
        protected JObject? lastTimeSync;

        /// <summary>
        /// The record types the DNS test offers, of the several hundred that
        /// exist. Anything else may still be typed - this is the list of what
        /// somebody is likely to want, not of what is allowed.
        /// </summary>
        private static readonly DNSResourceRecordTypes[] commonRecordTypes = [
            DNSResourceRecordTypes.A,
            DNSResourceRecordTypes.AAAA,
            DNSResourceRecordTypes.CNAME,
            DNSResourceRecordTypes.MX,
            DNSResourceRecordTypes.NS,
            DNSResourceRecordTypes.TXT,
            DNSResourceRecordTypes.SOA,
            DNSResourceRecordTypes.SRV,
            DNSResourceRecordTypes.PTR,
            DNSResourceRecordTypes.CAA,
            DNSResourceRecordTypes.TLSA,
            DNSResourceRecordTypes.DNSKEY,
            DNSResourceRecordTypes.DS,
            DNSResourceRecordTypes.HTTPS,
            DNSResourceRecordTypes.SVCB
        ];

        /// <summary>
        /// Whether <see cref="Start"/> has run and <see cref="Stop"/> has not.
        /// </summary>
        protected           Boolean                         started;

        /// <summary>
        /// Serialises changes to what this node is, so that two browsers
        /// saving at the same moment do not build half a node each.
        /// </summary>
        protected readonly  SemaphoreSlim                   reconfigureLock = new (1, 1);


        /// <summary>
        /// Where the accounts live, unless another directory is given.
        /// </summary>
        public const            String          DefaultAccountsPath           = "accounts";

        /// <summary>
        /// Where the log files go, unless another directory is given.
        /// </summary>
        public const            String          DefaultLogPath                = "logs";

        /// <summary>
        /// The accounts themselves, inside that directory.
        /// </summary>
        public const            String          DefaultAccountsDatabaseFile   = "users.db";


        /// <summary>
        /// Where the HTTPExt API answers: accounts, groups and API keys.
        /// </summary>
        /// <remarks>
        /// Beside "/api" rather than under it, because it is not this
        /// node's API: it is Hermod's, with its own routes and its own
        /// vocabulary, and putting it under /api/v1 would promise that this
        /// node versions it.
        /// </remarks>
        public static readonly  HTTPPath        ExtAPIPath                    = HTTPPath.Parse("/ext");

        /// <summary>
        /// Where the JSON API of a node answers below its base path, unless
        /// another path is given: "/api", beside the "/ext" above.
        /// </summary>
        public static readonly  HTTPPath        DefaultAPIPath                = HTTPPath.Parse("/api");

        /// <summary>
        /// The account made at a first start.
        /// </summary>
        public const            String          DefaultAdminUser              = "root";

        /// <summary>
        /// The role that account is put in, and which every kind of node knows.
        /// </summary>
        /// <remarks>
        /// The one role that is not the kind's to name: every one of these
        /// programs names its administrators alike, which is what lets one set
        /// of accounts shared between several of them have one kind of
        /// administrator - an account in "systemadmin" is an administrator of
        /// every one of them.
        /// </remarks>
        public const            String          AdminRole                     = "systemadmin";


        /// <summary>
        /// The TCP port a node of no particular kind listens on. A kind of
        /// node has a port of its own, and passes it.
        /// </summary>
        public static readonly  IPPort          DefaultHTTPPort               = IPPort.Parse(2593);

        /// <summary>
        /// The file of the bundle that is the web interface; its presence is
        /// what says there is one to serve at all.
        /// </summary>
        public const String  IndexFile           = "index.html";

        /// <summary>
        /// The icon of the bundle, which /favicon.ico is pointed at.
        /// </summary>
        public const String  FaviconSVG          = "favicon.svg";

        private readonly  DNSClient                       dnsClient;
        private           NTSClient                       ntsClient;

        /// <summary>
        /// The log on the console, in a file, and what the libraries below
        /// write with DebugX - each where it was asked for.
        /// </summary>
        protected readonly  ConsoleLog?                   consoleLog;
        protected readonly  FileLog?                      fileLog;
        protected readonly  TraceBridge?                  traceBridge;

        /// <summary>
        /// When this node last managed to check its clock, what it found,
        /// and against whom.
        /// </summary>
        /// <remarks>
        /// Separate fields rather than one object because they are written from
        /// one place and read from another, and the alternative - digging them
        /// back out of the JSON of the last check - would make a page or a
        /// screen depend on the shape of a diagnostic.
        ///
        /// The server is a host name only where there is one of them. A group
        /// of four is counted instead, in numbers, because a screen puts this
        /// behind "checked against" in whichever language it is showing, and a
        /// phrase assembled here would arrive in the wrong one.
        /// </remarks>
        private           DateTimeOffset?                 lastTimeCheck;
        private           TimeSpan?                       lastTimeCheckOffset;
        private           String?                         lastTimeCheckServer;
        private           Int32?                          lastTimeCheckAsked;
        private           Int32?                          lastTimeCheckAnswered;

        /// <summary>
        /// The clock that makes this node check its own, when NTS is on.
        /// </summary>
        private           ITimer?                         timeCheckTimer;

        /// <summary>
        /// What the file said about the time client, kept because the parts of
        /// it that are not the client itself - how often to check, and what the
        /// operator claims about the server - are read long afterwards.
        /// </summary>
        private           NTSConfiguration?               ntsSettings;


        #endregion

        #region Properties

        /// <summary>
        /// What kind of node this is: how it names itself in its own log, and
        /// what it calls the things it makes for itself.
        /// </summary>
        public NodeKind               Kind                         { get; }

        /// <summary>
        /// The version of the assembly this node is.
        /// </summary>
        public String                 Version                      { get; }

        /// <summary>
        /// Where everything this node can be told in writing lives between
        /// starts: its name resolution, its time source, its certificates -
        /// and, in the same file, whatever a node of a particular kind adds.
        /// </summary>
        public WWCPConfigFile         ConfigFile                   { get; }

        /// <summary>
        /// The file as it was read when this node was made, every section of
        /// it.
        /// </summary>
        /// <remarks>
        /// For the sections this class does not know: a vehicle takes its
        /// battery and its link from here rather than reading the file a second
        /// time, and what one reader passes over is what the other one is for.
        /// A snapshot, and only that - what is written later goes through
        /// <see cref="ConfigFile"/>, which reads the file again.
        /// </remarks>
        protected JObject             ConfigurationDocument        { get; }

        /// <summary>
        /// Everything this node believes and everything it presents: the
        /// certificates, in one store beside the configuration file.
        /// </summary>
        public CertificateStore       Certificates                 { get; }

        /// <summary>
        /// The clock this node reads. Its own, not the one NTS reports.
        /// </summary>
        public TimeProvider           TimeProvider                 { get; }

        /// <summary>
        /// When this node was made.
        /// </summary>
        public DateTimeOffset         CreatedAt                    { get; }



        /// <summary>
        /// Everything that happens inside this node.
        /// </summary>
        public EventLog               Log                          { get; }

        /// <summary>
        /// The directory the log files are written to, one per day, or null
        /// when this node writes none.
        /// </summary>
        public String?                LogPath
            => fileLog?.Directory;

        /// <summary>
        /// The HTTP server everything of this node is registered within: its
        /// own, or one it was handed and shares.
        /// </summary>
        public HTTPServer             HTTPServer                   { get; }

        /// <summary>
        /// Where the JSON API of this node sits: "/api" below the base path,
        /// unless it was told otherwise. The node puts nothing there itself;
        /// the kind of node it is does.
        /// </summary>
        public HTTPPath               HTTPRootPath                 { get; }

        /// <summary>
        /// Who may open the web interface: the accounts, the groups they are
        /// in, and the sessions and API keys they hold.
        /// </summary>
        public HTTPExtAPI             ExtAPI                       { get; }

        /// <summary>
        /// Whether those accounts are this node's own, or somebody else's
        /// that it was handed.
        /// </summary>
        /// <remarks>
        /// It decides two things. What is shut down when this node is: an
        /// HTTPExt API handed in outlives it, and disposing of somebody else's
        /// would take the sign-in away from whoever else is using it. And what
        /// this node may say about the accounts on its Configuration page -
        /// shared accounts are not its to describe as "the accounts of this
        /// node".
        /// </remarks>
        public Boolean                OwnsExtAPI                   { get; }

        /// <summary>
        /// Whether the HTTP server is this node's own, or one it was handed
        /// and shares with somebody else.
        /// </summary>
        /// <remarks>
        /// A shared server is started and stopped by whoever made it. A node
        /// that started one it did not make would take the same socket twice
        /// where several of these programs are on it, and a node that
        /// stopped one would close the web interface of every other program
        /// registered within it.
        /// </remarks>
        public Boolean                OwnsHTTPServer               { get; }

        /// <summary>
        /// Everything of this node - its web interface, its JSON API and,
        /// where the accounts are its own, those too - sits below this.
        /// </summary>
        /// <remarks>
        /// The root, which is what a node on a port of its own wants and
        /// what it always used to be. It is something else only where several
        /// of these programs share one HTTP server and are told apart by the
        /// first path segment rather than by the port.
        /// </remarks>
        public HTTPPath               BasePath                     { get; }

        /// <summary>
        /// The base path as it is written into a URL: the empty string at the
        /// root, and "/EV" or the like below one.
        /// </summary>
        /// <remarks>
        /// Its own property because the two forms are not interchangeable and
        /// the difference is exactly one character: <c>HTTPPath.Root</c> writes
        /// itself as "/", and "/" + "/index.html" is a URL nothing serves.
        /// </remarks>
        public String                 BasePathText
            => BasePath == HTTPPath.Root
                   ? ""
                   : BasePath.ToString().TrimEnd('/');

        /// <summary>
        /// The directory the accounts live in between starts.
        /// </summary>
        public String                 AccountsPath                 { get; }

        /// <summary>
        /// The roles this node knows, by the names of the user groups that
        /// carry them: the roles of its kind, and <see cref="AdminRole"/>
        /// among them whatever the kind said.
        /// </summary>
        /// <remarks>
        /// Names and nothing else, because that is all the node does with a
        /// role: it makes the group of that name at every start. What a role
        /// lets somebody do is the kind of node's to say and to enforce - a
        /// vehicle's driver may start a session, a charging station's installer
        /// may raise a power limit, and neither sentence means anything to the
        /// other kind.
        /// </remarks>
        public IReadOnlyList<String>  Roles                        { get; }

        /// <summary>
        /// The password made up at a first start and shown once, or null when
        /// accounts were already there.
        /// </summary>
        /// <remarks>
        /// Set by <see cref="Start"/> rather than by the constructor, because
        /// creating the account is asynchronous and a constructor that waited
        /// on it would be a constructor that can deadlock.
        /// </remarks>
        public String?                GeneratedPassword            { get; private set; }

        /// <summary>
        /// Where the web interface comes from: the bundle embedded in this
        /// assembly, or a directory somebody pointed this node at.
        /// </summary>
        public IStaticContentSource   Frontend                     { get; }

        /// <summary>
        /// The web interface at "/", or null when there is no bundle to serve.
        /// </summary>
        public HTTPAPI?               WebInterface                 { get; }

        /// <summary>
        /// The TCP port the web interface listens on.
        /// </summary>
        public IPPort                 HTTPPort                     { get; }

        /// <summary>
        /// Where to point a browser.
        /// </summary>
        public URL                    WebInterfaceURL              { get; }

        /// <summary>
        /// The JSON API as a browser would type it: the server and the API's
        /// root path, which already carries the base path, with a slash at the end.
        /// </summary>
        public URL                    APIURL                       { get; }


        /// <summary>
        /// How this node resolves names.
        /// </summary>
        public DNSClient              DNSClient                    => dnsClient;

        /// <summary>
        /// Where this node reads the time.
        /// </summary>
        public NTSClient              NTSClient                    => ntsClient;

        /// <summary>
        /// The time servers of this node, as a group.
        /// </summary>
        public TimeSourceGroup        TimeSources                  => timeSources;

        /// <summary>
        /// Whether this node resolves names at all.
        /// </summary>
        public Boolean                DNSEnabled                   { get; private set; } = true;

        /// <summary>
        /// Whether this node asks a time server at all.
        /// </summary>
        public Boolean                NTSEnabled                   { get; private set; } = true;

        /// <summary>
        /// Every time server of this node, and the rules for believing them.
        /// </summary>
        /// <remarks>
        /// Beside the single client rather than instead of it, because the two
        /// answer different questions. The group answers "what is the time",
        /// which several servers should agree on before a clock moves. The
        /// client answers "what is that one server doing", which is what the
        /// detailed test on the page asks and which a group would only blur.
        /// </remarks>
        private           TimeSourceGroup                 timeSources;

        /// <summary>
        /// How many of those servers this node was told must answer: by the
        /// last section that named "minServers", or the default of two.
        /// </summary>
        /// <remarks>
        /// Kept apart from the group's own quorum, which cannot be more than the
        /// servers it has switched on. A lone hostname holds a group to one, and
        /// if that one were all that was remembered, a list of four arriving
        /// afterwards would be held to one as well - where the same file, read
        /// at the next start, holds it to two.
        /// </remarks>
        private           Byte                            ntsQuorum       = NTSConfiguration.DefaultMinServers;

        /// <summary>
        /// What actually asks the servers of a group.
        /// </summary>
        /// <remarks>
        /// One engine for the life of this node, and that is not tidiness: it
        /// holds the key exchange of each server between rounds, and a new
        /// engine per synchronisation would pay a TLS handshake to every server
        /// every time and throw the cookies away unspent. It refreshes an
        /// exchange when it is older than half an hour or down to its last
        /// cookie, which is the same discipline the single client follows.
        /// </remarks>
        private readonly  MeasurementEngine               timeEngine;

        /// <summary>
        /// The name servers this node would ask, whether or not name
        /// resolution is switched on at the moment.
        /// </summary>
        /// <remarks>
        /// Kept beside the DNS client because switching name resolution off is
        /// done by taking its servers away - which is what being switched off
        /// actually means, for everything holding that client and not only for
        /// the parts of this node that remember to ask first. Switching it
        /// back on needs the list back, and this is where it waited.
        /// </remarks>
        private           IReadOnlyList<DNSServerConfig>  configuredDNSServers;


        #endregion

        #region Constructor(s)

        /// <summary>
        /// One node: its log, its configuration, its clients, its certificates
        /// and its web interface. Everything a kind of node is before it is
        /// that kind - and, told nothing, a node of no particular kind.
        /// </summary>
        /// <param name="Kind">What kind of node this is; one of no particular kind by default.</param>
        /// <param name="Version">The version of the assembly the node is; this assembly's by default.</param>
        /// <param name="HTTPPort">The TCP port the web interface listens on; <see cref="DefaultHTTPPort"/> by default. A kind of node has a default of its own, and passes it.</param>
        /// <param name="HTTPHostname">The address the web interface listens on; 127.0.0.1 by default.</param>
        /// <param name="HTTPServer">An HTTP server to register within, or null to make one.</param>
        /// <param name="BasePath">What everything of this node sits below; the root by default. Something else only where several of these programs share one HTTP server.</param>
        /// <param name="HTTPRootPath">Where the JSON API sits; "/api" below <paramref name="BasePath"/> by default.</param>
        /// <param name="ExtAPI">An HTTPExt API to sign in against, or null for one of this node's own. Handing one in is what makes one sign-in open several of these programs at once.</param>
        /// <param name="AccountsPath">The directory the accounts live in between starts.</param>
        /// <param name="Roles">The roles of this kind of node, by the names of the user groups that carry them; <see cref="UserRole.All"/> by default. <see cref="AdminRole"/> is one of them whatever is handed in.</param>
        /// <param name="ConfigFile">Where the configuration lives between starts.</param>
        /// <param name="DNSClient">How to resolve names, or null to make a client.</param>
        /// <param name="NTSClient">Where to read the time, or null to make a client.</param>
        /// <param name="Frontend">Where the web interface comes from, or null for a node that has none.</param>
        /// <param name="CertificatesPath">The directory the certificate store lives in between starts; what the file says, or "certificates" beside it, by default.</param>
        /// <param name="CertificateKinds">The kinds of certificate the store of this kind of node keeps; all of them by default. None, and there is no store directory at all.</param>
        /// <param name="Log">Where everything that happens is written, or null to make a log.</param>
        /// <param name="LogToConsole">Whether the log is also written to the console.</param>
        /// <param name="ConsoleLogLevel">How much of it reaches the console.</param>
        /// <param name="LogPath">The directory the log files are written to, or null to write none.</param>
        /// <param name="BridgeDebugLog">Whether what the libraries below write with DebugX is picked up.</param>
        /// <param name="TraceTags">What a line picked up that way has to contain to be tagged, needle and tag: the kind of node's own table, or null for <see cref="TraceBridge.DefaultTags"/>.</param>
        /// <param name="TimeProvider">The clock, or null for the system one.</param>
        public WWCPNode(NodeKind?                                  Kind               = null,
                        String?                                    Version            = null,
                        IPPort?                                    HTTPPort           = null,
                        IIPAddress?                                HTTPHostname       = null,
                        HTTPServer?                                HTTPServer         = null,
                        HTTPPath?                                  BasePath           = null,
                        HTTPPath?                                  HTTPRootPath       = null,
                        HTTPExtAPI?                                ExtAPI             = null,
                        String?                                    AccountsPath       = null,
                        IEnumerable<String>?                       Roles              = null,
                        WWCPConfigFile?                            ConfigFile         = null,
                        DNSClient?                                 DNSClient          = null,
                        NTSClient?                                 NTSClient          = null,
                        IStaticContentSource?                      Frontend           = null,
                        String?                                    CertificatesPath   = null,
                        IEnumerable<CertificateKind>?              CertificateKinds   = null,
                        EventLog?                                  Log                = null,
                        Boolean                                    LogToConsole       = true,
                        LogLevel                                   ConsoleLogLevel    = LogLevel.Info,
                        String?                                    LogPath            = null,
                        Boolean                                    BridgeDebugLog     = true,
                        IEnumerable<(String Needle, String Tag)>?  TraceTags          = null,
                        TimeProvider?                              TimeProvider       = null)

        {

            this.Kind     = Kind    ?? NodeKind.Default;
            this.Version  = Version ?? typeof(WWCPNode).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

            #region The clock, before anything that wants to know the time

            // First of all, and not for tidiness: the event log below stamps
            // every entry with this, so a clock set afterwards would leave the
            // log reading the system one - and a log on a different clock than
            // the node it belongs to cannot be held against anything.
            this.TimeProvider  = TimeProvider ?? TimeProvider.System;
            this.CreatedAt     = this.TimeProvider.GetUtcNow();

            #endregion

            #region The log, next - everything below it may want to say something

            this.Log          = Log ?? new EventLog(TimeProvider: this.TimeProvider);

            this.consoleLog   = LogToConsole
                                    ? new ConsoleLog(this.Log, ConsoleLogLevel)
                                    : null;

            // Everything, and not what the console was told to show: a level
            // is chosen to keep a console readable, and a file nobody is
            // reading has no such problem. What is left out here cannot be
            // asked for afterwards.
            this.fileLog      = LogPath is not null
                                    ? new FileLog(this.Log, LogPath, this.Kind.LogFilePrefix)
                                    : null;

            // What the log says about itself - a listener that failed, a file
            // that cannot be written - goes to stderr, and through the same
            // block as the entries, so that it cannot land in the middle of
            // one. ShareConsoleWith moves both along together.
            if (consoleLog is not null)
                this.Log.ComplaintBlock = consoleLog.WriteBlock;

            // Attached before anything else is built, so that what the DNS
            // client and the HTTP server say while they are being made is
            // already in the log a browser will see later - and tagged by the
            // kind's own table where it brought one, because which protocols
            // are worth a tag depends on what the node overhears.
            this.traceBridge  = BridgeDebugLog
                                    ? TraceBridge.Attach(this.Log, TraceTags)
                                    : null;

            // The first entry, before anything below has had a word: what is
            // starting, and which build of it.
            this.Log.Notice($"{this.Kind.CapitalisedName} v{this.Version} starting up.", this.Kind.Tag);

            #endregion

            #region What the configuration file says

            this.ConfigFile = ConfigFile ?? new WWCPConfigFile(WWCPConfigFile.DefaultFileName);

            // A file that is there but cannot be read is not something to
            // paper over with defaults: somebody wrote down what their node
            // is and got it wrong, and quietly running as something else
            // instead would be worse than stopping.
            if (!this.ConfigFile.TryLoadDocument(out var document, out var readError))
                throw new InvalidOperationException($"{readError} Repair or remove '{this.ConfigFile.Path}' and start again.");

            this.ConfigurationDocument = document;

            // The sections every node has. The document is kept for the ones
            // it does not, which a node of a particular kind reads itself.
            if (!WWCPConfiguration.TryParse(document, out var configuration, out var problem))
                throw new InvalidOperationException($"'{this.ConfigFile.Path}': {problem} Repair or remove '{this.ConfigFile.Path}' and start again.");

            if (!configuration.IsEmpty)
                this.Log.Info($"Configuration from '{this.ConfigFile.Path}': {configuration}.", "config");

            #endregion

            #region Where the accounts live

            // Ending in a separator, because the HTTPExt API builds the paths
            // of its files by putting strings together rather than with
            // Path.Combine: a directory that does not end in one would give it
            // "...accountsUsersAPI" and not "...accounts/UsersAPI".
            this.AccountsPath = AccountsPath ?? DefaultAccountsPath;

            if (!this.AccountsPath.EndsWith(Path.DirectorySeparatorChar))
                this.AccountsPath += Path.DirectorySeparatorChar;

            // The kind's roles, and the administrators' among them whatever the
            // kind said: the first account goes into that group, and a group
            // that was never made would leave it able to do nothing at all.
            // Told apart regardless of case, as the accounts tell groups apart.
            this.Roles = [.. (Roles ?? UserRole.All.Select(role => role.Name)).
                                 Append(AdminRole).
                                 Distinct(StringComparer.OrdinalIgnoreCase)];

            #endregion

            #region The clients everything below shares

            this.dnsClient             = DNSClient ?? new DNSClient();
            this.configuredDNSServers  = [.. dnsClient.DNSServers];

            // The clock goes to the time client too: a node that reads one
            // clock itself and disciplines another would have two, which is one
            // more than a node may have.
            this.ntsClient     = NTSClient ?? new NTSClient(
                                                  DomainName.Parse(NTSConfiguration.DefaultHostname),
                                                  Timeout:       TimeSpan.FromSeconds(10),
                                                  DNSClient:     dnsClient,
                                                  TimeProvider:  this.TimeProvider
                                              );

            this.timeEngine    = new MeasurementEngine(
                                     new MonitoringConfig {
                                         DroneId       = this.Kind.Tag,
                                         NTPTimeout    = TimeSpan.FromSeconds(5),
                                         NTSKETimeout  = TimeSpan.FromSeconds(10)
                                     },
                                     this.TimeProvider
                                 );

            // The four this node asks when nobody says otherwise - but only
            // when nobody handed it a client either. A caller that named its
            // own server means that server, and a group naming four others
            // beside it would be a report about somebody else's clock.
            this.timeSources   = NTSClient is null
                                     ? NTSConfiguration.DefaultGroup()
                                     : new TimeSourceGroup(
                                           "legal",
                                           [ new NTSServerEndpoint(
                                                 ntsClient.Hostname,
                                                 ntsClient.NTSKE_Port,
                                                 ntsClient.NTP_Port
                                             ) ]
                                       );

            // Last, and that is the whole precedence rule: what this
            // constructor was handed holds until the file says otherwise, and
            // what the file does not mention is left exactly as it was.
            if (configuration.DNS is not null)
                ApplyDNSConfiguration(configuration.DNS);

            if (configuration.NTS is not null)
            {

                // Checked here rather than when the file was read: a quorum
                // on its own is about the servers in effect, and which those
                // are is only known now.
                if (!TryCheckNTSQuorum(configuration.NTS, out var quorumError))
                    throw new InvalidOperationException($"{quorumError} Repair or remove '{this.ConfigFile.Path}' and start again.");

                ApplyNTSConfiguration(configuration.NTS);

            }

            this.ntsSettings = configuration.NTS;

            #endregion

            #region The certificate store, before anything that chooses from it

            // What was handed in wins over what the file says, which is the
            // precedence a command line expects. Made here, before a node of a
            // particular kind reads its own sections, because those may name
            // certificates in it.
            //
            // A relative path is measured from the configuration file rather
            // than from wherever the process happens to have been started, and
            // that is not tidiness. The default is the bare name "certificates",
            // so measuring it from the current directory would put this node's
            // private keys wherever somebody typed "dotnet run" from - which,
            // for a published binary, is beside the executable in bin/, where
            // the next "dotnet clean" takes them with it. Accounts avoid that
            // by being resolved against the repository root before they are
            // handed over; certificates cannot be told to, because a store that
            // moved when the working directory changed would be a different
            // store. So the file that names it is what it is measured from, and
            // a caller that means somewhere else says so absolutely.
            this.Certificates = new CertificateStore(
                                    Beside(
                                        this.ConfigFile.Path,
                                        CertificatesPath
                                            ?? configuration.Certificates?.Directory
                                            ?? CertificatesConfiguration.DefaultDirectory
                                    ),
                                    this.Log,
                                    CertificateKinds,
                                    this.Kind.Name
                                );

            this.Certificates.Reload();
            this.Certificates.WarnAboutStoredKeys();

            #endregion

            #region The HTTP server, the accounts and the web interface

            var address          = HTTPHostname ?? IPv4Address.Localhost;
            var port             = HTTPPort     ?? DefaultHTTPPort;
            var product          = $"OpenChargingCloud {this.Kind.Product} v{this.Version}";

            this.OwnsHTTPServer  = HTTPServer is null;

            this.HTTPServer      = HTTPServer   ?? new HTTPServer(
                                                       IPAddress:       address,
                                                       TCPPort:         port,
                                                       HTTPServerName:  product,
                                                       DNSClient:       dnsClient
                                                   );

            // The root unless somebody is putting several of these programs on
            // one server, where the first path segment is what tells them
            // apart. Everything below is relative to it, which is the whole
            // reason it is settled here and read rather than repeated.
            this.BasePath      = BasePath     ?? HTTPPath.Root;

            // "/api" below the base path, which is where the JSON API of every
            // one of these programs answers unless a caller puts it elsewhere.
            // The API itself is a node of a particular kind's to add there.
            this.HTTPRootPath  = HTTPRootPath ?? this.BasePath + DefaultAPIPath;

            this.HTTPPort        = port;
            this.WebInterfaceURL = URL.Parse($"http://{address}:{port}{this.BasePath.ToString().TrimEnd('/')}/");

            // From the server rather than from the web interface's URL: the API's
            // root path already carries the base path, and behind a URL that ends
            // in the base path it would be named twice.
            this.APIURL          = URL.Parse($"http://{address}:{port}/{this.HTTPRootPath.ToString().Trim('/')}/");

            // 1) The HTTPExt API at "/ext". First of the three, because it is
            //    the one with a database behind it: whatever it finds wrong
            //    with its files, it should say so before a port is opened and
            //    before anybody is let in against accounts that were not read.
            //
            //    Or the one that was handed in, which is how several of these
            //    programs come to have one sign-in between them: the groups
            //    each of them makes as it starts land in one set of accounts,
            //    and the names overlap on purpose - an account in
            //    "systemadmin" is an administrator of every one of them.
            this.OwnsExtAPI    = ExtAPI is null;

            this.ExtAPI        = ExtAPI ?? new HTTPExtAPI(
                                     HTTPServer:             this.HTTPServer,
                                     RootPath:               this.BasePath + ExtAPIPath,
                                     HTTPServerName:         product,
                                     HTTPServiceName:        product,
                                     APIRobotEMailAddress:   EMailAddress.Parse($"OpenChargingCloud {this.Kind.Product} Robot <robot@charging.cloud>"),
                                     APIRobotGPGPassphrase:  "",

                                     // Nothing here sends mail. A node that
                                     // notifies by e-mail is told so by whoever
                                     // runs it, with a submission client of
                                     // their own; until then a mailer that
                                     // swallows what it is given is better than
                                     // one that quietly retries against a host
                                     // nobody configured.
                                     SMTPSubmissionClient:   new NullMailer(),
                                     DisableNotifications:   true,

                                     // The cookie has to reach "/api", and its
                                     // path would otherwise be the root path of
                                     // this API - "/ext" - so a browser signed
                                     // in at /ext/login would send nothing to
                                     // the API and look signed out everywhere
                                     // else.
                                     HTTPCookiePath:         "/",

                                     // A secure cookie is dropped by a browser
                                     // over plain HTTP, and a node on a
                                     // bench is reached over plain HTTP. Tied
                                     // to the TLS the server is actually using
                                     // rather than switched off: on a node
                                     // with a certificate this stays on.
                                     UseSecureCookies:       false,

                                     // The shortest name a role of this node has,
                                     // because that is what a group identification has
                                     // to be allowed to be. Hermod's own floor is four
                                     // characters, and a charging station's "cpo" is
                                     // three - so the group is refused, by a returned
                                     // result rather than an exception, which is a
                                     // refusal nobody is obliged to notice, and the
                                     // role it carries can never be held by anybody.
                                     MinUserGroupIdLength:   (Byte) this.Roles.Min(role => role.Length),

                                     LoggingPath:            AccountsPath,
                                     DatabaseFileName:       DefaultAccountsDatabaseFile,

                                     // Left on, and that is what makes the
                                     // directory above: switching it off skips
                                     // the CreateDirectory that the accounts
                                     // file is written into, and the first
                                     // account created would fail on a path
                                     // that was never made.
                                     DisableLogging:         false
                                 );

            // 2) The web interface at "/": the files of the bundle, and the
            //    single-page-application stub for every other page URL, so
            //    that a reload on /logs and a bookmark to it both work. The
            //    JSON API between the two - below HTTPRootPath, and the more
            //    specific of the two - is added by the kind of node this is,
            //    before anybody starts it.
            this.Frontend      = Frontend ?? new NoWebInterface();

            if (this.Frontend.TryGet(IndexFile, out _))
            {

                this.WebInterface = this.HTTPServer.AddHTTPAPI(this.BasePath);

                this.WebInterface.MapSinglePageApplication(
                    this.Frontend,
                    new SinglePageAppOptions {

                        // Three placeholders and not one. The bundle reads
                        // where it is and where its API is out of <meta> tags
                        // rather than assuming "/" and "/api/v1", because
                        // under a base path both of those are wrong - and a
                        // single-page application that guesses its own base
                        // path is one that works until somebody mounts it
                        // somewhere.
                        IndexTransform = html => html.
                                                     Replace("{{ServerVersion}}", $"v{Version}",         StringComparison.Ordinal).
                                                     Replace("{{BasePath}}",      BasePathText,          StringComparison.Ordinal).
                                                     Replace("{{APIBase}}",       $"{this.HTTPRootPath.ToString().TrimEnd('/')}/v1", StringComparison.Ordinal).
                                                     Replace("{{ExtBase}}",       this.ExtAPI.RootPath.ToString().TrimEnd('/'), StringComparison.Ordinal)

                    }
                );

                // Browsers ask for /favicon.ico whatever the page says, and a
                // bundle built by webpack carries an SVG. A literal route wins
                // over the catch-all, so this answers before the stub would -
                // and beats a 404 on every visit, which is a line in the log
                // and a broken icon in the tab.
                if (this.Frontend.TryGet(FaviconSVG, out _))
                    this.WebInterface.AddHandler(
                        HTTPPath.Parse("/favicon.ico"),
                        request => Task.FromResult(
                                       new HTTPResponse.Builder(request) {
                                           HTTPStatusCode  = HTTPStatusCode.TemporaryRedirect,
                                           Location        = Location.From(HTTPPath.Parse($"{BasePathText}/{FaviconSVG}")),
                                           CacheControl    = "public, max-age=3600"
                                       }.AsImmutable
                                   ),
                        HTTPMethod.GET
                    );

            }

            // A node that was handed nothing has no web interface, and that
            // is what it is; one that was handed a source with no bundle in
            // it was meant to have one, and that is a fault to say so about.
            else if (Frontend is null)
                this.Log.Info("No web interface: nothing was handed in to serve, so a browser gets nothing here.", "web");

            else
                this.Log.Error(
                    $"No web interface to serve ({this.Frontend.Description}): the JSON API answers, the browser gets nothing. " +
                    $"Build the bundle, or point the {this.Kind.Name} at a directory that has one.",
                    "web"
                );

            #region Every request, into the log

            this.HTTPServer.OnHTTPRequest  += (server, request, cancellationToken) => {

                // The event stream is one request that stays open for as long
                // as a browser has the page open; logging it would say nothing
                // and logging its response would say it at the wrong moment.
                if (!IsEventStream(request))
                    this.Log.Debug($"{request.HTTPMethod} {request.Path} from {request.RemoteSocket}", "http");

                return Task.CompletedTask;

            };

            // Only OnHTTPResponse, and not OnHTTPError beside it: Hermod raises
            // both for the same response, and one line per request is what a
            // log is for.
            this.HTTPServer.OnHTTPResponse += (server, request, response, cancellationToken) => {

                if (IsEventStream(request))
                    return Task.CompletedTask;

                var code = response.HTTPStatusCode.Code;

                this.Log.Log(
                    code >= 500 ? LogLevel.Error
                        // A 401 is how the web interface asks whether anybody
                        // is signed in, and the answer "nobody" is not a fault.
                        : code == 401 ? LogLevel.Debug
                        : code >= 400 ? LogLevel.Warning
                        : LogLevel.Debug,
                    $"{code} {response.HTTPStatusCode.Name} for {request.HTTPMethod} {request.Path}",
                    "http"
                );

                return Task.CompletedTask;

            };

            #endregion

            #endregion

        }

        #endregion


        #region (private static) IsEventStream(Request)

        /// <summary>
        /// Whether this request is a browser hanging on the event stream.
        /// </summary>
        private static Boolean IsEventStream(HTTPRequest Request)
            => Request.Path.ToString().EndsWith("/events", StringComparison.Ordinal);

        #endregion


        #region (private) EnsureAccounts()

        /// <summary>
        /// Make the group of every role this node knows and, at a first start,
        /// the one account, which is put in <see cref="AdminRole"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The groups are made every start rather than only the first, because
        /// they are this node's vocabulary and not somebody's data: a group
        /// deleted by hand would otherwise leave a role that can never be held
        /// again, and the routes asking for it would refuse everybody with no
        /// way to put it right.
        /// </para>
        /// <para>
        /// The account is made only when there is none at all. Nobody can sign
        /// in to a web interface whose accounts are empty, and an
        /// unauthenticated setup page would be a door of its own - so the
        /// password is made up here and shown once, on the console, to whoever
        /// started the process. It is never written down: what the accounts
        /// hold is the hash the HTTPExt API makes of it.
        /// </para>
        /// <para>
        /// The membership edge is put on the group <em>before</em> the group is
        /// stored, so that both go to disk in one write. Adding it afterwards
        /// would leave a group that is right in memory and wrong in the file,
        /// and the next start would read the file.
        /// </para>
        /// </remarks>
        private async Task EnsureAccounts()
        {

            // Read what is on disk first. The HTTPExt API writes its accounts
            // as it goes but does not read them back when it is built, so a
            // node that skipped this would find no accounts at every start,
            // make a second root beside the first, and refuse the password its
            // owner already has.
            await ExtAPI.LoadDatabase();

            var firstStart  = !ExtAPI.Users.Any();

            IUser?  admin   = null;

            #region The one account, when there is none

            if (firstStart)
            {

                var password  = RandomExtensions.RandomString(24);
                var userId    = User_Id.Parse(DefaultAdminUser);

                // CreateUser rather than AddUser: the password is set from
                // inside the OnAdded callback, where the user already has its
                // API back-reference, and that is the only place the password
                // store can be reached. AddUser followed by ChangePassword
                // looks equivalent and writes the account without one - which
                // is an account nobody can sign in to, and nothing says so.
                var organization  = await ExtAPI.CreateOrganizationIfNotExists(
                                              Organization_Id.Parse(Kind.Organization),
                                              I18NString.Create(Languages.en, Kind.Organization)
                                          );

                if (organization is not Organization nodeOrganization)
                    throw new InvalidOperationException($"The organization of this {Kind.Name} could not be created, and an account outside one cannot sign in.");

                admin         = await ExtAPI.CreateUser(
                                          userId,
                                          I18NString.Create(Languages.en, DefaultAdminUser),
                                          SimpleEMailAddress.Parse($"{DefaultAdminUser}@localhost"),
                                          User2OrganizationEdgeLabel.IsAdmin,
                                          nodeOrganization,
                                          Password:                  password,

                                          // Nothing is sent and nobody is told:
                                          // a node has no mail server, no
                                          // second user to notify, and the one
                                          // account it makes is announced on the
                                          // console it was started from.
                                          SkipDefaultNotifications:  true,
                                          SkipNewUserEMail:          true,
                                          SkipNewUserNotifications:  true,

                                          // Without this nobody can sign in, and
                                          // nothing says why: the sign-in paths
                                          // require an accepted EULA and refuse a
                                          // correct password without one. There is
                                          // no agreement to show here - whoever
                                          // started the process owns the node -
                                          // so it is accepted at the moment the
                                          // account is made.
                                          AcceptedEULA:              TimeProvider.GetUtcNow().AddSeconds(-1),

                                          IsAuthenticated:           true
                                      );

                if (admin is null)
                    throw new InvalidOperationException($"The account of this {Kind.Name} could not be created, so nobody could sign in to it.");

                GeneratedPassword = password;

                Log.Notice($"No accounts were found, so '{DefaultAdminUser}' was made up and put in the {AdminRole} group.",
                           "web", "auth");

            }

            #endregion

            #region The group of every role

            foreach (var role in Roles)
            {

                var groupId = UserGroup_Id.Parse(role);

                if (ExtAPI.TryGetUserGroup(groupId, out _))
                    continue;

                var added = await ExtAPI.AddUserGroup(
                                      new UserGroup(
                                          groupId,
                                          I18NString.Create(Languages.en, role)
                                      )
                                  );

                // Looked at, and that is the point: this answers with a result
                // rather than throwing, so a group it declined to make would
                // otherwise leave a role nobody can ever hold - and every route
                // asking for it refusing everybody, with nothing anywhere to
                // say why. Better to stop before the port opens.
                if (added.Result != CommandResult.Success)
                    throw new InvalidOperationException(
                              $"The user group '{groupId}' of this {Kind.Name} could not be made: " +
                              $"{added.Description.FirstText()} A role without its group is a role nobody can hold."
                          );

            }

            #endregion

            #region The one account joins the one group that can fix the rest

            // Through AddUserToUserGroup, which writes a command of its own.
            // Putting the edge on the group object before storing it looks
            // equivalent and is not: what AddUserGroup writes is the group,
            // and a group's stored form does not carry its members - so the
            // membership was there until the next start and gone after it,
            // which is the worst shape a permission can have.
            if (admin is not null)
            {

                if (!ExtAPI.TryGetUser     (admin.Id,                         out var storedAdmin) ||
                    !ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(AdminRole),    out var adminGroup)  ||
                     storedAdmin is not User      user ||
                     adminGroup  is not UserGroup group)
                {
                    throw new InvalidOperationException(
                              $"The account of this {Kind.Name} could not be put in the {AdminRole} group, " +
                               "so the one account it has would be allowed to do nothing at all."
                          );
                }

                var joined = await ExtAPI.AddUserToUserGroup(
                                       user,
                                       User2UserGroupEdgeLabel.IsAdmin,
                                       group
                                   );

                // Looked at for the same reason as the group above: this
                // answers with a result too, and a membership it declined to
                // write leaves the one account able to do nothing at all -
                // with a password about to be printed that opens nothing.
                // A different result type from AddUserGroup's, and so a
                // different question: IsSuccess rather than Result.
                if (!joined.IsSuccess)
                    throw new InvalidOperationException(
                              $"The account '{DefaultAdminUser}' could not be put in the {AdminRole} group: " +
                              $"{joined.ErrorDescription?.FirstText()} It would be able to do nothing at all."
                          );

            }

            #endregion

        }

        #endregion


        #region DNS

        #region DNSConfigurationJSON()

        /// <summary>
        /// How this node resolves names.
        /// </summary>
        public JObject DNSConfigurationJSON()

            => new (

                   new JProperty("enabled",           DNSEnabled),

                   // The servers this node would ask, which is not the same
                   // as the ones the client holds: switched off, it holds none.
                   new JProperty("servers",           new JArray(
                       configuredDNSServers.Select(DNSConfiguration.ServerJSON)
                   )),

                   new JProperty("settings",          new JObject(
                       new JProperty("queryTimeoutSeconds",  dnsClient.QueryTimeout.TotalSeconds),
                       new JProperty("recursionDesired",     dnsClient.RecursionDesired),
                       new JProperty("useCache",             dnsClient.UseCache),
                       new JProperty("dnssecOK",             dnsClient.DnssecOK),
                       new JProperty("followCNAMEs",         dnsClient.FollowCNAMEs),
                       new JProperty("maxCNAMEFollows",      dnsClient.MaxCNAMEFollows),
                       new JProperty("maxRetries",           dnsClient.MaxRetries)
                   )),

                   // What was decided when the client was made and is not on
                   // offer here; shown so that the page does not read as if
                   // these were the only settings there are.
                   new JProperty("fixed",             new JObject(
                       new JProperty("udpPayloadSize",       dnsClient.UDPPayloadSize),
                       new JProperty("ednsOptions",          dnsClient.EDNSOptions.Count),
                       new JProperty("clientSubnet",         dnsClient.ClientSubnet is null
                                                                 ? null
                                                                 : $"{dnsClient.ClientSubnet.Address}/{dnsClient.ClientSubnet.SourcePrefixLength}"),
                       new JProperty("cacheCleanUpEvery",    dnsClient.DNSCache.CleanUpEvery.    ToString()),
                       new JProperty("negativeCacheTTL",     dnsClient.DNSCache.NegativeCacheTTL.ToString())
                   )),

                   new JProperty("limits",            new JObject(
                       new JProperty("maxServers",           DNSConfiguration.MaxServers),
                       new JProperty("maxQueryTimeout",      DNSConfiguration.MaxQueryTimeoutSeconds),
                       new JProperty("transports",           new JArray(Enum.GetNames<DNSTransport>())),
                       new JProperty("recordTypes",          new JArray(commonRecordTypes.Select(recordType => recordType.ToString())))
                   )),

                   new JProperty("file",              ConfigFile.Path)

               );

        #endregion

        #region TryUpdateDNSConfiguration(JSON, out Error)

        /// <summary>
        /// Change how this node resolves names, at once and for everything
        /// that was handed its DNS client.
        /// </summary>
        /// <remarks>
        /// The request has the same shape as the "dns" section of the
        /// configuration file, on purpose: one vocabulary for the file and for
        /// the web interface means one parser, and nothing that is expressible
        /// in one and not in the other.
        ///
        /// What the request does not mention is not changed and not erased from
        /// the file - a page that only offers the checkboxes may send only the
        /// checkboxes without taking the name servers with it.
        /// </remarks>
        public Boolean TryUpdateDNSConfiguration(JObject                           JSON,
                                                 [NotNullWhen(false)] out String?  Error)
        {

            if (!DNSConfiguration.TryParse(JSON, out var configuration, out Error))
                return false;

            if (configuration.Servers is { Count: 0 })
            {
                Error = $"Without a name server this {Kind.Name} cannot reach anything. Switch name resolution off instead of emptying the list.";
                return false;
            }

            // Under the same lock as every other change to this node:
            // writing a section is a read, a change and a write of one file,
            // and two browsers saving different sections at the same moment
            // would otherwise leave one of the two changes in neither.
            reconfigureLock.Wait();

            try
            {

                if (!ConfigFile.TryMergeSection(DNSConfiguration.SectionName, configuration.ToJSON(), out Error))
                    return false;

                ApplyDNSConfiguration(configuration);

                return true;

            }
            finally
            {
                reconfigureLock.Release();
            }

        }

        #endregion

        #region (private) ApplyDNSConfiguration(Configuration)

        /// <summary>
        /// Put a DNS section into effect. What it does not mention is left as
        /// it is.
        /// </summary>
        private void ApplyDNSConfiguration(DNSConfiguration Configuration)
        {

            var changed = new List<String>();

            if (Configuration.Servers is not null &&
                !configuredDNSServers.SequenceEqual(Configuration.Servers))
            {
                configuredDNSServers = Configuration.Servers;
                changed.Add($"servers = {String.Join(", ", configuredDNSServers)}");
            }

            if (Configuration.Enabled.HasValue && DNSEnabled != Configuration.Enabled.Value)
            {
                DNSEnabled = Configuration.Enabled.Value;
                changed.Add(DNSEnabled ? "switched on" : "switched off");
            }

            // Always, not only when one of the two above changed: the client
            // must end up holding exactly the servers this node means it to
            // hold, and working that out from which halves changed is how the
            // two drift apart.
            dnsClient.SetDNSServers(DNSEnabled ? configuredDNSServers : []);

            if (Configuration.QueryTimeout.HasValue && dnsClient.QueryTimeout != Configuration.QueryTimeout.Value)
            {
                dnsClient.QueryTimeout = Configuration.QueryTimeout.Value;
                changed.Add($"query timeout = {dnsClient.QueryTimeout}");
            }

            if (Configuration.RecursionDesired.HasValue && dnsClient.RecursionDesired != Configuration.RecursionDesired)
            {
                dnsClient.RecursionDesired = Configuration.RecursionDesired;
                changed.Add($"recursion desired = {Configuration.RecursionDesired}");
            }

            if (Configuration.UseCache.HasValue && dnsClient.UseCache != Configuration.UseCache.Value)
            {
                dnsClient.UseCache = Configuration.UseCache.Value;
                changed.Add($"use cache = {dnsClient.UseCache}");
            }

            if (Configuration.DnssecOK.HasValue && dnsClient.DnssecOK != Configuration.DnssecOK.Value)
            {
                dnsClient.DnssecOK = Configuration.DnssecOK.Value;
                changed.Add($"DNSSEC OK = {dnsClient.DnssecOK}");
            }

            if (Configuration.FollowCNAMEs.HasValue && dnsClient.FollowCNAMEs != Configuration.FollowCNAMEs.Value)
            {
                dnsClient.FollowCNAMEs = Configuration.FollowCNAMEs.Value;
                changed.Add($"follow CNAMEs = {dnsClient.FollowCNAMEs}");
            }

            if (Configuration.MaxCNAMEFollows.HasValue && dnsClient.MaxCNAMEFollows != Configuration.MaxCNAMEFollows.Value)
            {
                dnsClient.MaxCNAMEFollows = Configuration.MaxCNAMEFollows.Value;
                changed.Add($"max CNAME follows = {dnsClient.MaxCNAMEFollows}");
            }

            if (Configuration.MaxRetries.HasValue && dnsClient.MaxRetries != Configuration.MaxRetries.Value)
            {
                dnsClient.MaxRetries = Configuration.MaxRetries.Value;
                changed.Add($"max retries = {dnsClient.MaxRetries}");
            }

            if (changed.Count > 0)
                Log.Notice($"DNS configuration changed: {String.Join(", ", changed)}.", "dns", "config");

        }

        #endregion

        #endregion

        #region NTS

        #region NTSConfigurationJSON()

        /// <summary>
        /// Where this node gets the time from, and how the key exchange
        /// behind it is doing.
        /// </summary>
        /// <remarks>
        /// The group, and nothing about the single client the detailed test
        /// starts from. This answer used to carry that client's host, its
        /// cookie pool and its last key exchange as "server", "cookies" and
        /// "keyExchange" - which read as the node's time server and the
        /// cookies it synchronises with, and were neither: the group asks its
        /// servers with key exchanges of its own, one per server, and those
        /// are what each server's entry below reports.
        /// </remarks>
        public JObject NTSConfigurationJSON()
        {

            return new JObject(

                       new JProperty("enabled",      NTSEnabled),

                       // What may be changed about the group and the test, as
                       // it is in effect. The quorum is the one this node
                       // was told; the group's own, below, can be lower when it
                       // has fewer servers switched on.
                       new JProperty("settings",     new JObject(
                           new JProperty("timeoutSeconds",        ntsClient.Timeout?.TotalSeconds),
                           new JProperty("checkEverySeconds",     TimeCheckEvery.TotalSeconds),
                           new JProperty("minServers",            ntsQuorum),
                           new JProperty("maxDeviationSeconds",   timeSources.MaxDeviation.TotalSeconds)
                       )),

                       // What any new client starts with, the group's and the
                       // test's alike.
                       new JProperty("policy",       new JObject(
                           new JProperty("targetCookieCount",             ntsClient.CookiePoolPolicy.TargetCookieCount),
                           new JProperty("maxPlaceholders",               ntsClient.CookiePoolPolicy.MaxPlaceholders),
                           new JProperty("renegotiateWhenExhausted",      ntsClient.CookiePoolPolicy.RenegotiateWhenExhausted),
                           new JProperty("minimumRenegotiationInterval",  ntsClient.CookiePoolPolicy.MinimumRenegotiationInterval.ToString())
                       )),

                       // What the group is actually doing, which is what
                       // synchronises this node's clock: each server's key
                       // exchange and the cookies left from it are what a
                       // synchronisation spends.
                       //
                       // Every server, in the order they were configured, the
                       // switched-off ones included: this is the list the page
                       // edits and sends back whole, and a server missing from it
                       // because it was switched off would be deleted by the next
                       // save of anything else.
                       new JProperty("timeSources",  new JArray(
                           timeSources.Sources.Select(source => {

                               var held = timeEngine.KeyExchanges.TryGetValue(source.Hostname, out var state) ? state : null;

                               return new JObject(
                                          new JProperty("hostname",       source.Hostname.ToString()),
                                          new JProperty("priority",       source.Priority),
                                          new JProperty("ntsKEPort",      source.NTSKEPort.ToUInt16()),
                                          new JProperty("ntpPort",        source.NTPPort.  ToUInt16()),
                                          new JProperty("enabled",        source.Enabled),
                                          new JProperty("cookies",        held?.RemainingCookies),
                                          new JProperty("lastExchange",   held?.LastRefreshed.ToString("o")),
                                          new JProperty("aeadAlgorithm",  held?.NTSKEResponse?.AEADAlgorithm.ToString()),
                                          new JProperty("rootCA",         RootCAJSON(held?.NTSKEResponse?.TLSInfo))
                                      );

                           })
                       )),
                       new JProperty("group",        new JObject(
                           new JProperty("name",                 timeSources.Name),
                           new JProperty("minServers",           timeSources.MinServers),
                           new JProperty("maxDeviationSeconds",  timeSources.MaxDeviation.TotalSeconds)
                       )),
                       new JProperty("lastSync",     lastTimeSync),

                       new JProperty("limits",       new JObject(
                           new JProperty("maxTimeout",         NTSConfiguration.MaxTimeoutSeconds),
                           new JProperty("minCheckEvery",      NTSConfiguration.MinCheckEverySeconds),
                           new JProperty("maxCheckEvery",      NTSConfiguration.MaxCheckEverySeconds),
                           new JProperty("minDeviation",       NTSConfiguration.MinDeviationSeconds),
                           new JProperty("maxDeviation",       NTSConfiguration.MaxDeviationSeconds),
                           new JProperty("defaultNTSKEPort",   NTSClient.DefaultNTSKE_Port.ToUInt16()),
                           new JProperty("defaultNTPPort",     NTSClient.DefaultNTP_Port.  ToUInt16())
                       )),

                       new JProperty("file",         ConfigFile.Path)

                   );

        }

        #endregion

        #region TryUpdateNTSConfiguration(JSON, out Error)

        /// <summary>
        /// Change where this node reads the time.
        /// </summary>
        /// <remarks>
        /// Pointing the node at another server replaces the client rather
        /// than reconfiguring it: the cookies and the keys an NTS client holds
        /// were issued by the host it was made for, and carrying them to a
        /// different one would at best fail and at worst send one server the
        /// key material of another.
        /// </remarks>
        public Boolean TryUpdateNTSConfiguration(JObject                           JSON,
                                                 [NotNullWhen(false)] out String?  Error)
        {

            if (!NTSConfiguration.TryParse(JSON, out var configuration, out Error))
                return false;

            reconfigureLock.Wait();

            try
            {

                // Before the file, so that what is refused is not written down
                // either - and inside the lock, because the servers a quorum on
                // its own is checked against are the ones in effect.
                if (!TryCheckNTSQuorum(configuration, out Error))
                    return false;

                // And the file as the next start will read it. Each half can
                // be fine and the two together not: the quorum the file holds
                // and a list saved now that is shorter than it would be a
                // section the next start refuses, and a node that does not
                // start because of a save that was accepted.
                if (!ConfigFile.TryPreviewSection(NTSConfiguration.SectionName, configuration.ToJSON(), out var merged, out Error))
                    return false;

                if (!NTSConfiguration.TryParse(merged, out _, out var mergedError))
                {
                    Error = $"{mergedError} Nothing was changed.";
                    return false;
                }

                if (!ConfigFile.TryMergeSection(NTSConfiguration.SectionName, configuration.ToJSON(), out Error))
                    return false;

                ApplyNTSConfiguration(configuration);

                return true;

            }
            finally
            {
                reconfigureLock.Release();
            }

        }

        #endregion

        #region (static) RootCAJSON(TLS)

        /// <summary>
        /// The root CA a key exchange's certificate chain ended at, for the NTS
        /// page's list: a name to call it by, its whole subject, and its SHA-256
        /// fingerprint - or null where there was no key exchange yet.
        /// </summary>
        /// <remarks>
        /// The end of the chain this machine built, not of the one the server
        /// sent, because that is the root the certificate was judged by - and
        /// the one a pinned root would be compared with, by this fingerprint.
        /// The name is the root's common name: "ISRG Root X1" says which root
        /// it is, where its whole subject is mostly the organisation again.
        /// </remarks>
        /// <param name="TLS">What a key exchange kept of its TLS session.</param>
        public static JObject? RootCAJSON(NTSKE_TLSInfo? TLS)
        {

            var root = TLS?.ValidatedChain.LastOrDefault();

            return root is null
                       ? null
                       : new JObject(
                             new JProperty("name",         CertificateEntry.CommonNameOf(root)),
                             new JProperty("subject",      root.Subject),
                             new JProperty("fingerprint",  CertificateEntry.ThumbprintOf(root))
                         );

        }

        #endregion

        #region (static) LastSyncSaid(Sync)

        /// <summary>
        /// How the last synchronisation went, in a few words: that it
        /// succeeded and how far off the clock was, or why it did not.
        /// </summary>
        /// <remarks>
        /// Said beside when it happened, because the moment alone reads as a
        /// success: a synchronisation that found no server has a time just as
        /// much as one that set the record straight.
        /// </remarks>
        /// <param name="Sync">The last synchronisation, or null while there has been none.</param>
        public static String? LastSyncSaid(JObject? Sync)
        {

            if (Sync is null)
                return null;

            if (Sync.Value<Boolean>("ok"))
                return Sync.Value<Double?>("offset_ms") is Double offset
                           ? String.Format(System.Globalization.CultureInfo.InvariantCulture,
                                           "succeeded, the clock is {0:+0.0;-0.0;0.0} ms off", offset)
                           : "succeeded";

            return $"failed: {Sync.Value<String>("error") ?? "no reason was given"}";

        }

        #endregion

        #region (private) TryCheckNTSQuorum(Configuration, out Error)

        /// <summary>
        /// Whether a quorum named on its own can be met by the servers this
        /// node asks.
        /// </summary>
        /// <remarks>
        /// A section naming its servers as well had its quorum checked against
        /// them when it was read. One naming only the quorum is about the
        /// servers in effect, which the section cannot know and this node
        /// does.
        /// </remarks>
        private Boolean TryCheckNTSQuorum(NTSConfiguration                  Configuration,
                                          [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            if (Configuration.MinServers is Byte quorum &&
                Configuration.Servers    is null        &&
                Configuration.Hostname   is null)
            {

                var asked = timeSources.Sources.Count(source => source.Enabled);

                if (quorum > asked)
                {
                    Error = $"'nts.minServers' is {quorum}, which is more servers than the {asked} this {Kind.Name} asks.";
                    return false;
                }

            }

            return true;

        }

        #endregion

        #region (private) ApplyNTSConfiguration(Configuration)

        /// <summary>
        /// Put an NTS section into effect. What it does not mention is left as
        /// it is.
        /// </summary>
        private void ApplyNTSConfiguration(NTSConfiguration Configuration)
        {

            // Kept whole: what this method does with the client is only half of
            // it, and the other half - how often to check, and what the
            // operator claims about the server - is read from elsewhere and
            // much later. See WWCPNode.Clock.cs.
            //
            // Laid over what was kept rather than put in its place. A save sends
            // part of the section - the switch on the page sends "enabled" and
            // nothing else - and replaced by that, how often to check and who
            // stands behind the time went back to their defaults until the
            // next start read them from the file again.
            var wasCheckingEvery  = TimeCheckEvery;
            var wasEnabled        = NTSEnabled;

            ntsSettings = ntsSettings?.OverriddenBy(Configuration) ?? Configuration;

            var changed  = new List<String>();

            #region The group of time servers

            var wasServers    = timeSources.Describe();
            var wasQuorum     = timeSources.MinServers;
            var wasDeviation  = timeSources.MaxDeviation;

            if (Configuration.MinServers.HasValue)
                ntsQuorum = Configuration.MinServers.Value;

            // The servers only when the section says something about them. That
            // is this method's rule everywhere else, and it earns its place here
            // now that the servers have a default worth keeping: a section
            // mentioning nothing but "enabled" would otherwise quietly reduce
            // four servers to one.
            //
            // Rebuilt from the section rather than patched when it does: it is a
            // list, and working out which entry changed in order to report it
            // would say less than naming the servers, which is what happens
            // below.
            var sources       = Configuration.Servers  is not null ||
                                Configuration.Hostname is not null
                                    ? Configuration.ToGroup(Configuration.Hostname ?? ntsClient.Hostname).Sources
                                    : timeSources.Sources;

            // The quorum and the deviation by the same rule, and on their own as
            // well. They used to count only beside a list or a hostname, so a
            // section saying nothing but "minServers": 3 was read, reported as
            // NTS configuration, and changed nothing; and a list without a
            // quorum was held to one, whatever had been agreed before.
            timeSources       = new TimeSourceGroup(
                                    timeSources.Name,
                                    sources,
                                    NTSConfiguration.QuorumFor(ntsQuorum, sources),
                                    Configuration.MaxDeviation ?? timeSources.MaxDeviation
                                );

            var nowServers    = timeSources.Describe();

            if (wasServers != nowServers)
                changed.Add($"time servers = {nowServers}");

            if (wasQuorum != timeSources.MinServers)
                changed.Add($"quorum = {timeSources.MinServers}");

            if (wasDeviation != timeSources.MaxDeviation)
                changed.Add($"agreed deviation = {timeSources.MaxDeviation.TotalSeconds.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture)} s");

            #endregion

            var hostname = Configuration.Hostname  ?? ntsClient.Hostname;
            var ntsKE    = Configuration.NTSKEPort ?? ntsClient.NTSKE_Port;
            var ntp      = Configuration.NTPPort   ?? ntsClient.NTP_Port;

            if (hostname != ntsClient.Hostname ||
                ntsKE    != ntsClient.NTSKE_Port ||
                ntp      != ntsClient.NTP_Port)
            {

                ntsClient = new NTSClient(
                                hostname,
                                NTSKE_Port:    ntsKE,
                                NTP_Port:      ntp,
                                Timeout:       Configuration.Timeout ?? ntsClient.Timeout,
                                DNSClient:     dnsClient,
                                TimeProvider:  TimeProvider
                            );

                // The old client's cookies went with it, so what the page shows
                // about the last exchange belongs to a server this node no
                // longer asks.
                lastTimeSync = null;

                // Without the root's dot, as every other sentence names a
                // server; what goes into the file keeps it.
                changed.Add($"server = {hostname.Trimmed}:{ntsKE} (NTS-KE), :{ntp} (NTP)");

            }

            else if (Configuration.Timeout.HasValue && ntsClient.Timeout != Configuration.Timeout.Value)
            {
                ntsClient.Timeout = Configuration.Timeout.Value;
                changed.Add($"timeout = {Configuration.Timeout.Value}");
            }

            if (Configuration.Enabled.HasValue && NTSEnabled != Configuration.Enabled.Value)
            {
                NTSEnabled = Configuration.Enabled.Value;
                changed.Add(NTSEnabled ? "switched on" : "switched off");
            }

            if (TimeCheckEvery != wasCheckingEvery)
                changed.Add($"clock checked every {TimeCheckEvery.TotalSeconds.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture)} s");

            if (changed.Count > 0)
                Log.Notice($"NTS configuration changed: {String.Join(", ", changed)}.", "nts", "config");

            // The clock is checked on a timer set when the node started, so
            // whether and how often it is checked has to be put into that timer
            // here - otherwise the page says "in effect" about something that
            // waits for the next start. Before the start there is no timer yet,
            // and the start sets one from what this left behind.
            if (started &&
               (TimeCheckEvery != wasCheckingEvery || NTSEnabled != wasEnabled))
            {
                StartCheckingTheClock();
            }

        }

        #endregion

        #endregion


        #region (class) NoWebInterface

        /// <summary>
        /// The web interface of a node that has none: nothing to serve, and
        /// a description that says so.
        /// </summary>
        private sealed class NoWebInterface : IStaticContentSource
        {

            public String   Description
                => "no web interface";

            public Boolean  IsImmutable
                => true;

            public Boolean  TryGet(String                               RelativePath,
                                   [NotNullWhen(true)] out StaticFile?  File)
            {
                File = null;
                return false;
            }

        }

        #endregion


        #region ConfigurationJSON()

        /// <summary>
        /// What this node is, as the Configuration page of the web interface
        /// reads it: its web server and its accounts, its log, and its time.
        /// A kind of node adds what it is on top.
        /// </summary>
        /// <remarks>
        /// Read-only: it answers "what am I running", not "change it". Nothing
        /// here is a secret - the accounts appear as the path they live at and
        /// the route to sign in, and never as anything about a password.
        /// </remarks>
        public virtual JObject ConfigurationJSON()

            => new (

                   new JProperty("http",       new JObject(
                       new JProperty("serverName",     HTTPServer.HTTPServerName),
                       new JProperty("url",            WebInterfaceURL.ToString()),
                       new JProperty("basePath",       BasePath.ToString()),
                       new JProperty("apiPath",        HTTPRootPath.ToString()),
                       new JProperty("sharedServer",   !OwnsHTTPServer),
                       new JProperty("running",        started),
                       new JProperty("frontend",       Frontend.Description),
                       new JProperty("webInterface",   WebInterface is not null)
                   )),

                   new JProperty("web",        new JObject(
                       new JProperty("accountsPath",   AccountsPath),
                       new JProperty("sharedAccounts", !OwnsExtAPI),
                       new JProperty("signInAt",       $"{ExtAPI.RootPath.ToString().TrimEnd('/')}/login"),
                       new JProperty("users",          ExtAPI.Users.     Count()),
                       new JProperty("groups",         ExtAPI.UserGroups.Count()),
                       new JProperty("cookie",         ExtAPI.SessionCookieName.ToString()),
                       new JProperty("maxLifetime",    ExtAPI.MaxSignInSessionLifetime.ToString())
                   )),

                   new JProperty("log",        new JObject(
                       new JProperty("capacity",       Log.Capacity),
                       new JProperty("entries",        Log.Count),
                       new JProperty("lastId",         Log.LastId),
                       new JProperty("debugBridge",    traceBridge is not null),
                       new JProperty("console",        consoleLog  is not null),
                       new JProperty("files",          LogPath),
                       new JProperty("tags",           new JArray(Log.KnownTags))
                   )),

                   // The group, which is what sets the clock: every server,
                   // named the way the log names them when they change and the
                   // switched-off ones included - and the last synchronisation,
                   // the button's, the prompt's or the clock check's, when it
                   // happened and how it went, or nothing while there has been
                   // none.
                   new JProperty("time",       new JObject(
                       new JProperty("ntsEnabled",      NTSEnabled),
                       new JProperty("timeServers",     timeSources.Describe()),
                       new JProperty("minServers",      timeSources.MinServers),
                       new JProperty("checkedEvery",    TimeCheckEvery.ToString()),
                       new JProperty("lastSync",        lastTimeSync?.Value<String>("at")),
                       new JProperty("lastSyncResult",  LastSyncSaid(lastTimeSync)),
                       new JProperty("now",             TimeProvider.GetUtcNow().ToString("o"))
                   ))

               );

        #endregion


        #region Start()

        /// <summary>
        /// Start listening.
        /// </summary>
        /// <remarks>
        /// The accounts first, then the port - the node's own, and then those
        /// a kind of node takes in its <see cref="OnListening"/> - then the
        /// clock. What a kind of node has to say once it is up comes from its
        /// <see cref="OnStarted"/>, after the line saying that it is.
        /// </remarks>
        public async Task Start()
        {

            if (started)
                return;

            // Before the port opens, and that order is the point: a web
            // interface reachable before its accounts exist is a door with
            // nobody behind it.
            await EnsureAccounts();

            if (OwnsHTTPServer)
            {
                try
                {
                    await HTTPServer.Start();
                }
                catch (SocketException problem)
                {
                    throw new PortUnavailableException(HTTPPort, problem);
                }
            }

            try
            {
                await OnListening();
            }
            catch
            {

                // The node's own port is had by now. Nothing is left behind by
                // a process that is about to end anyway, but a caller that
                // catches this and carries on - a test, or a node that tries
                // another port - should not be holding a socket it never got
                // to use.
                //
                // Only where it is this node's, though: a shared server carries
                // other programs' web interfaces too, and closing it because a
                // port of this one could not be had would take all of them down
                // with it.
                if (OwnsHTTPServer)
                    await HTTPServer.Stop();

                throw;

            }

            StartCheckingTheClock();

            started = true;

            Log.Notice(WebInterface is not null
                           ? $"The web interface is listening on {WebInterfaceURL}"
                           : $"Listening on {WebInterfaceURL}, with no web interface to serve.",
                       "web", "http");

            await OnStarted();

        }

        #endregion

        #region (protected virtual) OnListening()

        /// <summary>
        /// What a node of a particular kind listens on beside the node's own
        /// port: nothing, unless it overrides this.
        /// </summary>
        /// <remarks>
        /// Asked once the node's own port is had and before the node calls
        /// itself started - so that all of its ports are had before its log
        /// says that it is listening, and before its clock is checked. A port
        /// that cannot be had is said as a <see cref="PortUnavailableException"/>
        /// naming what it was for, which is what the start then ends with; the
        /// node lets go of its own port again on the way out.
        /// </remarks>
        protected virtual Task OnListening()
            => Task.CompletedTask;

        #endregion

        #region (protected virtual) OnStarted()

        /// <summary>
        /// What a node of a particular kind does, or says, once it is up:
        /// nothing, unless it overrides this.
        /// </summary>
        protected virtual Task OnStarted()
            => Task.CompletedTask;

        #endregion

        #region Stop()

        /// <summary>
        /// Stop listening.
        /// </summary>
        /// <remarks>
        /// What a node of a particular kind holds open beyond the server is
        /// ended by its <see cref="OnStopping"/>, which runs before the server
        /// stops: the server waits for every request it started, and a request
        /// waiting for something other than its socket is not woken by closing
        /// the sockets.
        /// </remarks>
        public async Task Stop()
        {

            if (!started)
                return;

            Log.Notice($"The {Kind.Name} is shutting down.", Kind.Tag);

            timeCheckTimer?.Dispose();
            timeCheckTimer = null;

            await OnStopping();

            // The socket is closed only where it is this node's own: a shared
            // server is stopped by whoever made it.
            if (OwnsHTTPServer)
                await HTTPServer.Stop();

            started = false;

        }

        #endregion

        #region (protected virtual) OnStopping()

        /// <summary>
        /// What a node of a particular kind ends before the server stops:
        /// nothing, unless it overrides this.
        /// </summary>
        protected virtual Task OnStopping()
            => Task.CompletedTask;

        #endregion


        #region ShareConsoleWith(WriteBlock)

        /// <summary>
        /// Let somebody else decide when this node's log may write on the
        /// console, because they are writing on it too.
        /// </summary>
        /// <remarks>
        /// A node at a console assumes the console is its own and writes an
        /// entry whenever one happens, from whichever thread it happened on.
        /// That assumption stops holding the moment somebody is typing a command
        /// on the same screen: an entry arriving mid-word puts half a log line
        /// into the middle of a half-typed command and ruins both.
        ///
        /// So the writing is handed over rather than suppressed. Whoever owns
        /// the line takes the entry, clears what is being typed, writes the
        /// entry as one piece and puts the line back. Nothing is lost and
        /// nothing is delayed, which is what makes this better than the obvious
        /// alternative of going quiet while a command line is open.
        ///
        /// The same goes for the few things the log says on stderr about
        /// itself - a listener that failed, a log file that cannot be written.
        /// They are rare, which is how they came to be written past the command
        /// line for a while without anybody noticing, and they are handed over
        /// too - even by a node whose entries do not reach the console.
        /// </remarks>
        /// <param name="WriteBlock">Runs what it is given with the console to itself.</param>
        public void ShareConsoleWith(Action<Action> WriteBlock)
        {

            if (consoleLog is not null)
                consoleLog.WriteBlock = WriteBlock;

            Log.ComplaintBlock = WriteBlock;

        }

        #endregion


        #region DisposeAsync()

        /// <summary>
        /// Stop listening and let go of the console, the log file and the
        /// debug bridge.
        /// </summary>
        /// <remarks>
        /// A node of a particular kind that has something of its own to let go
        /// of does so and then calls this. Stopping is done here, and doing it
        /// there as well, first, does no harm.
        /// </remarks>
        public virtual async ValueTask DisposeAsync()
        {

            await Stop();

            traceBridge?.   Dispose();
            consoleLog?.    Dispose();
            fileLog?.       Dispose();

            reconfigureLock.Dispose();

            GC.SuppressFinalize(this);

        }

        #endregion

        #region (private static) Beside(File, Path)

        /// <summary>
        /// A path as given where it is absolute, and otherwise measured from the
        /// directory the given file is in.
        /// </summary>
        /// <remarks>
        /// So that "certificates" means "beside the configuration file" rather
        /// than "beside whatever the working directory happened to be". An
        /// absolute path is left alone, because somebody who wrote one meant it.
        /// </remarks>
        private static String Beside(String  File,
                                     String  Path)

            => System.IO.Path.IsPathRooted(Path)
                   ? Path
                   : System.IO.Path.Combine(
                         System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(File)) ?? ".",
                         Path
                     );

        #endregion

    }

}
