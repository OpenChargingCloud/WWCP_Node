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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

using HermodDNSServer = org.GraphDefined.Vanaheimr.Hermod.DNS.DNSServer;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Names and time for the logins of a kind of node - a local controller's charging stations -
    /// over the SSH connection they sign in with: "ssh.dns" and "ssh.nts" of the configuration
    /// file, each off where it says nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Names.</b> DNS-over-SSH, the subsystem "dns@open.charging.cloud": this node answers no
    /// name itself, it passes every question on to its own name servers - those of the "dns"
    /// section, over whatever they are reached by - and hands back what they answer, as a
    /// forwarder does (<see cref="ForwardingDNSRequestHandler"/>).
    /// </para>
    /// <para>
    /// <b>Time.</b> A time server of this node's own: NTS key establishment over SSH, the
    /// subsystem "ntske/1@open.charging.cloud", and NTP with NTS on a UDP port of this node, 123
    /// unless "ssh.nts.ntpPort" says another - and plain NTP only where "ssh.nts.plainNTP" says
    /// so. Its time is the system clock of this machine, and what it says about that clock -
    /// stratum, reference, whether it is synchronised at all - is what the check of the clock
    /// against the legal group found, see <see cref="TimeServerClock"/>. It
    /// has no key exchange over TLS: the cookies come over SSH alone, under the key the login
    /// signed in with. Its master keys are kept beside the SSH host key, so that the cookies a
    /// station holds stay good across a restart.
    /// </para>
    /// <para>
    /// <b>Who.</b> The logins of a kind alone, never an account: a station whose login group gives
    /// it the channel - "dns@open.charging.cloud" or "ntske/1@open.charging.cloud" among its SSH
    /// channels - and whom the SSH access rules let have it.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What DNS-over-SSH is called in the log and on the SSH page.
        /// </summary>
        public const String DNSOverSSHLabel         = "DNS";

        /// <summary>
        /// What the file of the master keys of the time server of the SSH logins is called,
        /// beside the SSH host key.
        /// </summary>
        public const String NTSMasterKeysFileName   = "nts_master_keys.json";

        private readonly SemaphoreSlim                 namesAndTimeLock       = new (1, 1);
        private          HermodDNSServer?              loginNameServer;
        private          NTSServer?                    loginTimeServer;
        private          SSHTimeServiceConfiguration?  loginTimeServerAs;
        private          String?                       loginNamesAndTimeProblem;
        private          ITimer?                       loginTimeServerDescriber;
        private          TimeServerClock?              loginTimeServerClock;
        private volatile TimeServerUpstream?           legalTimeUpstream;

        #endregion

        #region Properties

        /// <summary>
        /// Whether names are resolved for the SSH logins now: DNS-over-SSH, passed on to the name
        /// servers of this node.
        /// </summary>
        public Boolean      ServesNamesToSSHLogins
            => loginNameServer is not null;

        /// <summary>
        /// The time server of the SSH logins while it runs, or null.
        /// </summary>
        public NTSServer?   TimeServerOfSSHLogins
            => loginTimeServer;

        /// <summary>
        /// What the time server of the SSH logins says about its clock now, or null where it
        /// says what it says by default - the clock is not checked - or does not run.
        /// </summary>
        public TimeServerClock?     TimeServerOfSSHLoginsClock
            => loginTimeServer is not null
                   ? loginTimeServerClock
                   : null;

        /// <summary>
        /// The server of the legal group the last good check of the clock rests on, or null.
        /// </summary>
        public TimeServerUpstream?  LegalTimeUpstream
            => legalTimeUpstream;

        /// <summary>
        /// Why names or time are not served to the SSH logins as the file says, or null where they are.
        /// </summary>
        public String?      SSHNamesAndTimeProblem
            => loginNamesAndTimeProblem;

        /// <summary>
        /// The file the time server of the SSH logins keeps its master keys in.
        /// </summary>
        public String       NTSMasterKeysPath
            => Beside(ConfigFile.Path, Path.Combine(DefaultSSHDirectory, NTSMasterKeysFileName));

        #endregion


        #region (private) ApplySSHNamesAndTime(File)

        /// <summary>
        /// Serve names and time to the SSH logins as the given "ssh" section says - and no more
        /// than that. Answers why something could not be served as it says, or null.
        /// </summary>
        private async Task<String?> ApplySSHNamesAndTime(SSHConfiguration? File)
        {

            await namesAndTimeLock.WaitAsync();

            try
            {

                var problems = new List<String>();

                if (ApplySSHNames(File?.DNS?.Enabled == true) is String namesProblem)
                    problems.Add(namesProblem);

                if (await ApplySSHTime(File?.NTS?.Enabled == true ? File.NTS : null) is String timeProblem)
                    problems.Add(timeProblem);

                loginNamesAndTimeProblem = problems.Count > 0
                                               ? String.Join(" ", problems)
                                               : null;

                return loginNamesAndTimeProblem;

            }
            finally
            {
                namesAndTimeLock.Release();
            }

        }

        #endregion

        #region (private) ApplySSHNames(Wanted)

        private String? ApplySSHNames(Boolean Wanted)
        {

            if (Wanted && loginNameServer is null)
            {

                var server = new HermodDNSServer(
                                 new ForwardingDNSRequestHandler(() => DNSClient)
                             );

                try
                {
                    AddSSHSubsystem(new SSHSubsystem(HermodDNSServer.SSHSubsystemName,
                                                     DNSOverSSHLabel,
                                                     server.ServeSSHSubsystemAsync));
                }
                catch (ArgumentException)
                {
                    // A kind that answers DNS-over-SSH itself - a name server - has it already.
                    var said = $"Names are not passed on for the SSH logins (ssh.dns): this {Kind.Name} serves {HermodDNSServer.SSHSubsystemName} itself.";
                    Log.Warning(said, "ssh", "dns");
                    return said;
                }

                loginNameServer = server;

                Log.Notice($"Names are resolved for the SSH logins of this {Kind.Name} over their SSH connection ({HermodDNSServer.SSHSubsystemName}): " +
                           $"passed on to its name servers, {DNSClient}. A login group gives it with the channel {HermodDNSServer.SSHSubsystemName}.",
                           "ssh", "dns");

            }

            else if (!Wanted && loginNameServer is not null)
            {

                loginNameServer = null;

                RemoveSSHSubsystem(HermodDNSServer.SSHSubsystemName);

                Log.Notice("Names are no longer resolved for the SSH logins.", "ssh", "dns");

            }

            return null;

        }

        #endregion

        #region (private) ApplySSHTime(Wanted)

        private async Task<String?> ApplySSHTime(SSHTimeServiceConfiguration? Wanted)
        {

            // Another port or another host is another server: the one there is goes first.
            if (loginTimeServer is NTSServer running &&
                (Wanted is null ||
                 Wanted.NTPPortInEffect  != loginTimeServerAs!.NTPPortInEffect ||
                 Wanted.NTPHost          != loginTimeServerAs.NTPHost          ||
                 Wanted.PlainNTPInEffect != loginTimeServerAs.PlainNTPInEffect))
            {

                await StopTheTimeServerOfSSHLogins(running);

                if (Wanted is null)
                    Log.Notice("The SSH logins no longer get their time from this " + Kind.Name + ".", "ssh", "nts");

            }

            if (Wanted is null || loginTimeServer is not null)
                return null;

            if (Wanted.WhyNotServable() is String notServable)
            {
                Log.Warning($"The SSH logins do not get their time from this {Kind.Name}: {notServable}", "ssh", "nts");
                return notServable;
            }

            var port = Wanted.NTPPortInEffect;

            OwnerOnly.Directory(Path.GetDirectoryName(NTSMasterKeysPath)!, problem => Log.Warning(problem, "ssh", "nts", "security"));

            var server = new NTSServer(
                             NTSPort:             port,
                             // Told only where the stations have to be told: on another port than
                             // 123, the host with it. Otherwise they ask the host they signed in at.
                             ExternalURLs:        Wanted.NTPHost is String host
                                                      ? [ URL.Parse($"udp://{(host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host)}:{port}") ]
                                                      : null,
                             DNSClient:           dnsClient,
                             ListenIPAddress:     listenAddress,
                             MasterKeysFilePath:  NTSMasterKeysPath,
                             TimeProvider:        TimeProvider,
                             NTSKEOverTLS:        false,
                             PlainNTP:            Wanted.PlainNTPInEffect
                         );

            try
            {
                await server.Start();
            }
            catch (SocketException problem)
            {

                await server.ShutdownAsync();

                var said = new PortUnavailableException(port, problem, NodePort.TimeServer).Message +
                           ". The SSH logins do not get their time from this " + Kind.Name + " (ssh.nts).";

                Log.Error(said, "ssh", "nts");

                return said;

            }

            try
            {
                ServeNTSKEOverSSH(server);
            }
            catch (ArgumentException)
            {

                await server.ShutdownAsync();

                // A kind that answers NTS-KE over SSH itself - a time server - has it already.
                var said = $"The SSH logins do not get their time from this {Kind.Name} (ssh.nts): it serves {NTSKE_SSH.SubsystemName} itself.";
                Log.Warning(said, "ssh", "nts");
                return said;

            }

            loginTimeServer    = server;
            loginTimeServerAs  = Wanted;

            Log.Notice($"The SSH logins of this {Kind.Name} get their time from it: NTS-KE over their SSH connection ({NTSKE_SSH.SubsystemName}), " +
                       $"NTP with NTS on UDP port {port}{(Wanted.NTPHost is String told ? $" of {told}" : "")}" +
                       $"{(Wanted.PlainNTPInEffect ? ", and plain NTP" : ", and no plain NTP")}, the time of this machine's clock. " +
                       $"A login group gives it with the channel {NTSKE_SSH.SubsystemName}.",
                       "ssh", "nts");

            loginTimeServerClock      = null;
            DescribeTheTimeServerOfSSHLogins();

            // Whatever no check says: that the last one grows old.
            loginTimeServerDescriber  = TimeProvider.CreateTimer(_ => DescribeTheTimeServerOfSSHLogins(),
                                                                 null,
                                                                 TimeServerDescribedEvery,
                                                                 TimeServerDescribedEvery);

            return null;

        }

        #endregion

        #region (private) StopTheTimeServerOfSSHLogins(Server)

        private async Task StopTheTimeServerOfSSHLogins(NTSServer Server)
        {

            loginTimeServer    = null;
            loginTimeServerAs  = null;

            loginTimeServerDescriber?.Dispose();
            loginTimeServerDescriber  = null;
            loginTimeServerClock      = null;

            StopServingNTSKEOverSSH();

            await Server.ShutdownAsync();

        }

        #endregion

        #region (private) StopSSHNamesAndTime()

        /// <summary>
        /// Let go of the port of the time server, and stop serving names and time: as the node stops.
        /// The file is not touched, and the next start serves them again.
        /// </summary>
        private async Task StopSSHNamesAndTime()
        {

            await namesAndTimeLock.WaitAsync();

            try
            {

                if (loginNameServer is not null)
                {
                    loginNameServer = null;
                    RemoveSSHSubsystem(HermodDNSServer.SSHSubsystemName);
                }

                if (loginTimeServer is NTSServer running)
                    await StopTheTimeServerOfSSHLogins(running);

            }
            finally
            {
                namesAndTimeLock.Release();
            }

        }

        #endregion

        #region (private) DescribeTheTimeServerOfSSHLogins()

        /// <summary>
        /// How often the time server of the SSH logins is described anew without a check: the
        /// last check grows old, and its clock may drift since.
        /// </summary>
        public static readonly TimeSpan TimeServerDescribedEvery = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tell the time server of the SSH logins what its clock is worth now - see
        /// <see cref="TimeServerClock"/> - and write down when that changes between synchronised
        /// and not.
        /// </summary>
        private void DescribeTheTimeServerOfSSHLogins()
        {

            if (loginTimeServer is not NTSServer server)
                return;

            try
            {

                var clock   = TimeServerClock.Of(NTSEnabled,
                                                 legalTimeUpstream,
                                                 LegalTime.LastCheck,
                                                 LegalTime.LastCheckOffset,
                                                 LegalTimeTolerance,
                                                 LegalTimeMaxAge,
                                                 TimeProvider.GetUtcNow(),
                                                 server.ClockResolution);

                var before  = loginTimeServerClock;

                if (clock is null)
                    server.Redescribe();

                else
                {

                    server.Redescribe(clock.Stratum,
                                      clock.Reference,
                                      clock.RootDelay,
                                      clock.RootDispersion,
                                      clock.LeapIndicator);

                    if (clock.IsSynchronised && LegalTime.LastCheck is DateTimeOffset checkedAt)
                        server.ClockLastSynchronized = checkedAt;

                }

                loginTimeServerClock = clock;

                if (ReferenceEquals(before, clock) ||
                    (before?.IsSynchronised ?? true) == (clock?.IsSynchronised ?? true) &&
                    before?.Why                      == clock?.Why                      &&
                    before?.Upstream?.Hostname       == clock?.Upstream?.Hostname)
                {
                    return;
                }

                if (clock is null)
                    Log.Notice($"The time server of the SSH logins hands out the clock of this {Kind.Name} as an uncalibrated local clock (stratum 1, LOCL): it is not checked against NTS.",
                               "ssh", "nts", "clock");

                else if (clock.IsSynchronised)
                    Log.Notice($"The time server of the SSH logins hands out the clock of this {Kind.Name} at stratum {clock.Stratum}, from {clock.Upstream!.Hostname}, as the check of its clock found it.",
                               "ssh", "nts", "clock");

                else
                    Log.Warning($"The time server of the SSH logins says that the clock of this {Kind.Name} is not synchronised, and no station takes its time: " +
                                clock.Why switch {
                                    "stale"  => $"its last check is older than {LegalTimeMaxAge.TotalSeconds:F0} s.",
                                    "offBy"  => $"its last check found it {SignedSeconds(LegalTime.LastCheckOffset ?? TimeSpan.Zero)} off, more than {LegalTimeTolerance.TotalSeconds:0.###} s.",
                                    _        => "it has not been checked yet."
                                },
                                "ssh", "nts", "clock");

            }
            catch (Exception e)
            {
                Log.Warning($"The time server of the SSH logins could not be described anew: {e.Message}", "ssh", "nts", "clock");
            }

        }

        #endregion

        #region (private) RememberTheLegalUpstream(Verdict, MaxDeviation)

        /// <summary>
        /// A check of the legal group produced a time: the server it rests on is what the time
        /// server of the SSH logins names as its reference from now on.
        /// </summary>
        private void RememberTheLegalUpstream(org.GraphDefined.Vanaheimr.Norn.TimeSync.TimeSyncVerdict  Verdict,
                                              TimeSpan                                                MaxDeviation)
        {

            legalTimeUpstream = TimeServerUpstream.Of(Verdict, MaxDeviation);

            DescribeTheTimeServerOfSSHLogins();

        }

        #endregion

        #region (private) SSHNamesAndTimeJSON()

        /// <summary>
        /// Names and time of the SSH logins as the SSH page shows them: what the file says, and
        /// what is served.
        /// </summary>
        private (JObject DNS, JObject NTS) SSHNamesAndTimeJSON()
        {

            var timeServer = loginTimeServer;
            var clock      = TimeServerOfSSHLoginsClock;
            var nts        = sshFile?.NTS;

            return (
                       new JObject(
                           new JProperty("enabled",     sshFile?.DNS?.Enabled == true),
                           new JProperty("served",      loginNameServer is not null),
                           new JProperty("subsystem",   HermodDNSServer.SSHSubsystemName),
                           new JProperty("upstream",    DNSClient.ToString())
                       ),
                       new JObject(
                           new JProperty("enabled",     nts?.Enabled == true),
                           new JProperty("served",      timeServer is not null),
                           new JProperty("subsystem",   NTSKE_SSH.SubsystemName),
                           new JProperty("ntpPort",     (timeServer?.UDPPort ?? nts?.NTPPortInEffect ?? SSHTimeServiceConfiguration.DefaultNTPPort).ToUInt16()),
                           new JProperty("ntpHost",     nts?.NTPHost),
                           new JProperty("plainNTP",    timeServer?.PlainNTP ?? nts?.PlainNTPInEffect ?? false),
                           new JProperty("masterKeys",  NTSMasterKeysPath),
                           new JProperty("clock",       timeServer is null
                                                            ? null
                                                            : new JObject(
                                                                  new JProperty("stratum",       timeServer.Stratum),
                                                                  new JProperty("reference",     clock?.Upstream?.Hostname ?? (clock is null ? "LOCL" : null)),
                                                                  new JProperty("synchronised",  clock?.IsSynchronised ?? true),
                                                                  new JProperty("checked",       clock is not null),
                                                                  new JProperty("why",           clock?.Why)
                                                              ))
                       )
                   );

        }

        #endregion

    }

}
