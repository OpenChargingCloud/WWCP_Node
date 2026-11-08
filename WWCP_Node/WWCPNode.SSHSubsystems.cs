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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a kind of node adds to its SSH server: subsystems besides the command line and SFTP - OCPP or
    /// WWCP messages - and logins besides its accounts, e.g. a local controller's charging stations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One SSH server for all of it, on the node's SSH port: a station signs in under its own name with
    /// its own key and gets the subsystems it may use and nothing else - no command line, no command, no
    /// SFTP, no terminal, no forwarding. An account gets a subsystem only with the permission the kind
    /// asked for it.
    /// </para>
    /// <para>
    /// A session of a subsystem is asked, as one at the command line or of SFTP is, whether it may go on:
    /// before it is served, every few seconds while it lasts, and at once when the access rules change or
    /// a kind asks (<see cref="RecheckSSHSessions"/>). One that may not is ended - its handler's token
    /// fires and its channel is closed - and the log says why.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// The subsystems the kind serves, by name.
        /// </summary>
        private readonly ConcurrentDictionary<String, SSHSubsystem>  sshSubsystems               = new (StringComparer.Ordinal);

        /// <summary>
        /// Who the kind lets sign in besides the accounts.
        /// </summary>
        private          ISSHSignIns[]                               sshSignIns                  = [];
        private readonly Lock                                        sshSignInsLock              = new ();

        /// <summary>
        /// As whom each connection signed in, from the door on: an account (null), or one of the kind's
        /// logins - so that a name that becomes another's later does not change what the session is.
        /// </summary>
        private readonly ConcurrentDictionary<String, SSHSignedIn>   sshSignedIn                 = new ();

        /// <summary>
        /// Each open subsystem session's check of whether it may go on, which ends it where it may not,
        /// by session.
        /// </summary>
        private readonly ConcurrentDictionary<String, Func<String?>>  subsystemSessionRechecks   = new ();

        /// <summary>
        /// When each name that is an account and a kind's login as well was last warned about.
        /// </summary>
        private readonly ConcurrentDictionary<String, DateTimeOffset>  sshClashesWarned          = new (StringComparer.Ordinal);

        private          Int64                                       lastSubsystemSession;

        /// <summary>
        /// As whom a connection signed in: one of the kind's logins, or (null) an account.
        /// </summary>
        private sealed record SSHSignedIn(ISSHSignIns? SignIns);

        #endregion

        #region Properties

        /// <summary>
        /// The subsystems the kind serves on the SSH server, by name.
        /// </summary>
        public IReadOnlyList<SSHSubsystem>  SSHSubsystems
            => [.. sshSubsystems.Values.OrderBy(subsystem => subsystem.Name, StringComparer.Ordinal)];

        /// <summary>
        /// Who the kind lets sign in over SSH besides the accounts.
        /// </summary>
        public IReadOnlyList<ISSHSignIns>   SSHSignIns
            => Volatile.Read(ref sshSignIns);

        #endregion


        #region AddSSHSubsystem(Subsystem)

        /// <summary>
        /// Serve the given subsystem on the SSH server - from now on, for the next session that asks for
        /// it: before the node starts or while it runs, without the SSH server starting anew.
        /// </summary>
        /// <param name="Subsystem">The subsystem.</param>
        /// <exception cref="ArgumentException">Where its name is none, is "sftp", or is served already.</exception>
        public void AddSSHSubsystem(SSHSubsystem Subsystem)
        {

            if (!SSHSubsystem.IsName(Subsystem.Name))
                throw new ArgumentException($"'{Subsystem.Name}' can not name an SSH subsystem here: printable ASCII without spaces, at most {SSHSubsystem.MaxNameLength} characters, and not 'sftp'.",
                                            nameof(Subsystem));

            if (String.IsNullOrWhiteSpace(Subsystem.Label))
                throw new ArgumentException($"The SSH subsystem '{Subsystem.Name}' needs a label for the log and the SSH page.", nameof(Subsystem));

            if (!sshSubsystems.TryAdd(Subsystem.Name, Subsystem))
                throw new ArgumentException($"There is an SSH subsystem '{Subsystem.Name}' already.", nameof(Subsystem));

            if (started && SSHEnabled)
                Log.Info($"{Subsystem.Label} is served over SSH, as the subsystem '{Subsystem.Name}'.", "ssh", "subsystem");

        }

        #endregion

        #region RemoveSSHSubsystem(Name)

        /// <summary>
        /// Serve the given subsystem no more: refused to the next session that asks for it, and the
        /// sessions of it open now ended. Whether it was served.
        /// </summary>
        /// <param name="Name">The subsystem's name.</param>
        public Boolean RemoveSSHSubsystem(String Name)
        {

            if (!sshSubsystems.TryRemove(Name, out var removed))
                return false;

            var ended = RecheckSubsystemSessions();

            if (started && SSHEnabled)
                Log.Info($"{removed.Label} is no longer served over SSH" + (ended > 0 ? $": {ended} session(s) ended." : "."), "ssh", "subsystem");

            return true;

        }

        #endregion

        #region AddSSHSignIns(SignIns)

        /// <summary>
        /// Let the given logins sign in over SSH besides the accounts - confined to the subsystems they
        /// say, see <see cref="ISSHSignIns"/>.
        /// </summary>
        /// <param name="SignIns">The logins.</param>
        /// <exception cref="ArgumentException">Where their kind is no name the access rules can write, is "account" or "group", or is there already.</exception>
        public void AddSSHSignIns(ISSHSignIns SignIns)
        {

            var kind = SignIns.PrincipalKind;

            if (!IsPrincipalKind(kind))
                throw new ArgumentException($"'{kind}' can not be what logins over SSH are: a lower-case letter, then lower-case letters, digits, '-' or '_', at most 32 characters - and not 'account' or 'group'.",
                                            nameof(SignIns));

            lock (sshSignInsLock)
            {

                if (sshSignIns.Any(signIns => signIns.PrincipalKind == kind))
                    throw new ArgumentException($"There are SSH logins of the kind '{kind}' already.", nameof(SignIns));

                Volatile.Write(ref sshSignIns, [.. sshSignIns, SignIns]);

            }

        }

        #endregion

        #region (internal static) IsPrincipalKind(Kind)

        internal static Boolean IsPrincipalKind(String? Kind)

            => Kind is not null &&
               Kind.Length is > 0 and <= 32 &&
               Kind[0] is >= 'a' and <= 'z' &&
               Kind.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_') &&
               Kind is not SSHPrincipal.Account and not "group" and not "unknown";

        #endregion

        #region SSHLoginOf(Username)

        /// <summary>
        /// Which of the kind's logins the given name is - null where it is an account or nothing - or why
        /// it is let in as nothing: a name that is an account and a login of the kind as well, or a login
        /// of two kinds, is let in as neither.
        /// </summary>
        /// <param name="Username">The login name, as the client sent it.</param>
        public (ISSHSignIns? SignIns, String? Clash) SSHLoginOf(String Username)
        {

            var knowers   = new List<ISSHSignIns>();

            foreach (var signIns in SSHSignIns)
            {
                try
                {
                    if (signIns.Knows(Username))
                        knowers.Add(signIns);
                }
                catch (Exception problem)
                {
                    // What can not be told is not let in as either.
                    return (null, $"whether '{Username}' is a {signIns.PrincipalKind} of this {Kind.Name} could not be told: {problem.Message}");
                }
            }

            var isAccount = User_Id.TryParse(Username) is User_Id userId &&
                            ExtAPI.TryGetUser(userId, out var user) && user is not null;

            if (knowers.Count + (isAccount ? 1 : 0) > 1)
            {

                var what = knowers.Select(signIns => $"a {signIns.PrincipalKind}").ToList();

                if (isAccount)
                    what.Insert(0, "an account");

                return (null, $"'{Username}' is {String.Join(" and ", what)} of this {Kind.Name}, and is let in over SSH as neither until one of them is renamed");

            }

            return (knowers.FirstOrDefault(), null);

        }

        #endregion

        #region (internal) WarnOfSSHClash(Clash)

        /// <summary>
        /// Say in the log, at most once a minute for each name, that a name is let in as neither.
        /// </summary>
        internal void WarnOfSSHClash(String  Username,
                                     String  Clash)
        {

            var now = TimeProvider.GetUtcNow();

            if (sshClashesWarned.TryGetValue(Username, out var warned) && now - warned < TimeSpan.FromMinutes(1))
                return;

            sshClashesWarned[Username] = now;

            Log.Warning($"{Clash[..1].ToUpperInvariant()}{Clash[1..]}.", "ssh", "auth", "security");

        }

        #endregion

        #region (private) WarnOfSSHClashesAtTheStart()

        /// <summary>
        /// At the start: every account whose name a kind's login has as well.
        /// </summary>
        private void WarnOfSSHClashesAtTheStart()
        {

            if (SSHSignIns.Count == 0)
                return;

            foreach (var user in ExtAPI.Users)
                if (SSHLoginOf(user.Id.ToString()).Clash is String clash)
                    WarnOfSSHClash(user.Id.ToString(), clash);

        }

        #endregion

        #region (internal) SSHSignInsOf(Session)

        /// <summary>
        /// Which of the kind's logins the given session signed in as - null for an account: as the door
        /// saw it, and where the door did not see it (a session made up to ask the rules), as the name is
        /// now.
        /// </summary>
        internal ISSHSignIns? SSHSignInsOf(SshSessionInfo Session)

            => sshSignedIn.TryGetValue(Session.ConnectionId, out var signedIn)
                   ? signedIn.SignIns
                   : SSHLoginOf(Session.Username).SignIns;

        #endregion

        #region (private) RememberSSHSignIn(Session) / ForgetSSHSignIn(ConnectionId)

        /// <summary>
        /// Remember as whom the given session signed in - asked at the door, before anything is served.
        /// Why it may not come in, where the name is let in as nothing.
        /// </summary>
        private String? RememberSSHSignIn(SshSessionInfo Session)
        {

            var (signIns, clash) = SSHLoginOf(Session.Username);

            if (clash is not null)
                return clash;

            sshSignedIn[Session.ConnectionId] = new SSHSignedIn(signIns);

            return null;

        }

        private void ForgetSSHSignIn(String? ConnectionId)
        {
            if (ConnectionId is not null)
                sshSignedIn.TryRemove(ConnectionId, out _);
        }

        #endregion

        #region (internal static) SSHConfinementOf(SignIns, Username)

        /// <summary>
        /// What a login of a kind is always confined to: the subsystems it may use, and of those never
        /// SFTP; no terminal, no forwarding.
        /// </summary>
        internal static SshSessionRestrictions SSHConfinementOf(ISSHSignIns?  SignIns,
                                                                String        Username)
        {

            IReadOnlySet<String> subsystems;

            try
            {
                subsystems = SignIns is not null
                                 ? new HashSet<String>(SignIns.SubsystemsFor(Username).Where(name => name != "sftp"), StringComparer.Ordinal)
                                 : new HashSet<String>(StringComparer.Ordinal);
            }
            catch (Exception)
            {
                subsystems = new HashSet<String>(StringComparer.Ordinal);
            }

            return new SshSessionRestrictions(AllowPty:             false,
                                              AllowPortForwarding:  false,
                                              PermittedSubsystems:  subsystems);

        }

        #endregion

        #region SSHPrincipalFor(Session)

        /// <summary>
        /// Who a session is, as the access rules and the log see it: an account with its roles, or one of
        /// the kind's logins with its groups - for a subsystem's handler that serves them apart.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        public SSHPrincipal SSHPrincipalFor(SshSessionInfo Session)

            => SSHPrincipalOf(Session);

        #endregion

        #region RecheckSSHSessions()

        /// <summary>
        /// Ask every open session - at the command line, of SFTP and of a subsystem - at once whether it
        /// may go on, rather than within the next few seconds: what is ended, by how many. For a kind
        /// that took a login's key out or switched a login off.
        /// </summary>
        public Int32 RecheckSSHSessions()
        {

            var ended = 0;

            foreach (var recheck in sshSessionRechecks.Values.Concat(sftpSessionRechecks.Values).Concat(subsystemSessionRechecks.Values).ToArray())
                if (recheck() is not null)
                    ended++;

            return ended;

        }

        #endregion

        #region (private) RecheckSubsystemSessions()

        private Int32 RecheckSubsystemSessions()
        {

            var ended = 0;

            foreach (var recheck in subsystemSessionRechecks.Values.ToArray())
                if (recheck() is not null)
                    ended++;

            return ended;

        }

        #endregion


        #region (private) SubsystemFor(Session, Name, CancellationToken)

        /// <summary>
        /// What a session that asks for a subsystem gets: the kind's handler for it, watched - or nothing,
        /// where nobody serves it, which the audit then says; or a refusal that says why.
        /// </summary>
        private ValueTask<SshSubsystemHandler?> SubsystemFor(SshSessionInfo     Session,
                                                             String             Name,
                                                             CancellationToken  CancellationToken)
        {

            if (!sshSubsystems.TryGetValue(Name, out var subsystem))
                return ValueTask.FromResult<SshSubsystemHandler?>(null);

            if (WhySubsystemSessionMayNotGoOn(Session, subsystem) is String why)
                throw new InvalidOperationException(why);

            return ValueTask.FromResult<SshSubsystemHandler?>((context, token) => ServeSubsystemAsync(subsystem, context, token));

        }

        #endregion

        #region (private) WhySubsystemSessionMayNotGoOn(Session, Subsystem)

        /// <summary>
        /// Why the given session may not have the given subsystem - asked before it is served and while it
        /// lasts - or null where it may.
        /// </summary>
        private String? WhySubsystemSessionMayNotGoOn(SshSessionInfo  Session,
                                                      SSHSubsystem    Subsystem)
        {

            try
            {

                if (!sshSubsystems.TryGetValue(Subsystem.Name, out var current) || !ReferenceEquals(current, Subsystem))
                    return $"{Subsystem.Label} is no longer served on this {Kind.Name}";

                if (sshAuthenticator is not NodeSSHAuthenticator authenticator)
                    return $"the SSH server of this {Kind.Name} is not running";

                if (authenticator.WhyNoLongerIn(Session) is String notIn)
                    return notIn;

                if (SSHSignInsOf(Session) is ISSHSignIns signIns)
                {
                    // Asked at the door already (PermittedSubsystems), and asked again here: a login
                    // that may no longer use it ends its session.
                    if (!signIns.SubsystemsFor(Session.Username).Contains(Subsystem.Name))
                        return $"the {signIns.PrincipalKind} '{Session.Username}' may not use {Subsystem.Label}";
                }

                else
                {

                    if (User_Id.TryParse(Session.Username) is not User_Id userId ||
                        !ExtAPI.TryGetUser(userId, out var account) || account is null)
                        return $"there is no account '{Session.Username}' on this {Kind.Name} any more";

                    if (Subsystem.ForAccounts is not Permission needed)
                        return $"{Subsystem.Label} is served to no account of this {Kind.Name}";

                    if (!IsAllowed(account, [ needed ]))
                        return $"'{account.Id}' may not use {Subsystem.Label}: that takes {needed}";

                }

                // The access rules: who may have it, from where and to where.
                return SSHAccessRefusal(Session, $"subsystem:{Subsystem.Name}");

            }
            catch (Exception problem)
            {
                // What can not be asked is not a pass.
                return $"whether '{Session.Username}' may use {Subsystem.Label} could not be asked: {problem.Message}";
            }

        }

        #endregion

        #region (private) ServeSubsystemAsync(Subsystem, Context, CancellationToken)

        /// <summary>
        /// Serve one session of a subsystem with the kind's handler - shown among the sessions, asked
        /// every few seconds whether it may go on, and ended where not: its handler's token fires and its
        /// channel is closed, whatever the handler does with the token.
        /// </summary>
        private async ValueTask ServeSubsystemAsync(SSHSubsystem         Subsystem,
                                                    SshSubsystemContext  Context,
                                                    CancellationToken    CancellationToken)
        {

            var session    = Context.Session;
            var id         = $"{session.ConnectionId}/{Subsystem.Name}-{Interlocked.Increment(ref lastSubsystemSession)}";
            var since      = TimeProvider.GetUtcNow();
            var from       = session.Peer?.ToString() ?? "somewhere";
            var principal  = SSHPrincipalOf(session);
            var who        = principal.Kind == SSHPrincipal.Account
                                 ? $"'{principal.Name}'"
                                 : $"the {principal.Kind} '{principal.Name}'";

            using var asked     = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            String?   signedOut = null;

            // Ended where it may no longer go on: the handler's token, and its channel, whatever the
            // handler makes of the token.
            String? Recheck()
            {

                if (Volatile.Read(ref signedOut) is String already)
                    return already;

                if (WhySubsystemSessionMayNotGoOn(session, Subsystem) is not String why)
                    return null;

                if (Interlocked.CompareExchange(ref signedOut, why, null) is null)
                {

                    try
                    {
                        asked.Cancel();
                    }
                    catch (ObjectDisposedException)
                    { }

                    _ = CloseQuietly(Context.Channel);

                }

                return Volatile.Read(ref signedOut);

            }

            sshSessions[id]               = new SSHSession(id, session.Username, from, session.PublicKeyFingerprint, since,
                                                           SSHSession.Subsystem, principal.Kind, Subsystem.Name, Subsystem.Label);
            subsystemSessionRechecks[id]  = Recheck;

            Log.Info($"{who} opened {Subsystem.Label} over SSH from {from}.", "ssh", "subsystem");

            var watch = TimeProvider.CreateTimer(_ => Recheck(), null, SSHSessionRecheckEvery, SSHSessionRecheckEvery);

            try
            {
                await Subsystem.Handler(Context, asked.Token);
            }
            catch (Exception) when (asked.IsCancellationRequested || Context.Closed.IsCancellationRequested)
            {
                // Ended from here, or by the client, in the middle of something.
            }
            catch (Exception problem)
            {
                Log.Warning($"{Subsystem.Label} over SSH from {from}, for {who}, ended in an error: {problem.Message}", "ssh", "subsystem");
            }
            finally
            {

                await watch.DisposeAsync();

                subsystemSessionRechecks.TryRemove(id, out _);
                sshSessions.             TryRemove(id, out _);

                var lasted = Lasted(TimeProvider.GetUtcNow() - since);

                if (Volatile.Read(ref signedOut) is String why)
                    Log.Notice($"{who[..1].ToUpperInvariant()}{who[1..]} was signed out of {Subsystem.Label} over SSH from {from} after {lasted}: {why}.",
                               "ssh", "subsystem", "security");

                else
                    Log.Info($"{who[..1].ToUpperInvariant()}{who[1..]} left {Subsystem.Label} over SSH after {lasted}" +
                             (Context.Stopping.IsCancellationRequested ? $", as the {Kind.Name} stopped." : "."),
                             "ssh", "subsystem");

            }

        }

        #endregion

        #region (private static) CloseQuietly(Channel)

        private static async Task CloseQuietly(SshMuxChannel Channel)
        {
            try
            {
                await Channel.CloseAsync(CancellationToken.None);
            }
            catch (Exception)
            { }
        }

        #endregion

    }

}
