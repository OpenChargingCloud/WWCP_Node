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

using System.Runtime.CompilerServices;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// How many connections each kind that signs in over SSH may have open at once - the accounts, and
    /// each kind of login a kind of node lets in besides, its stations - counted apart, so that stations
    /// filling the server leave room for an account, and the other way round.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A connection is counted once it has signed in, asked at the door (see AuthorizeSSHSession), and
    /// until it closes - however it closes: the server says so for every connection that ends. One that
    /// would be one too many of its kind is refused at the door, and the log says so at most once a
    /// minute for each kind, with how many it did not say.
    /// </para>
    /// <para>
    /// The SSH server itself lets in what every kind may have together, and the connections that have
    /// not signed in yet besides - so that no kind takes another's place before it is known who signed
    /// in. It takes that number when it starts: a change of the limits is in effect at once for each
    /// kind, and for the server as a whole once it starts again.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        private readonly Object                                            sshAdmittedLock    = new ();

        /// <summary>
        /// The kind of every connection let in, by its id.
        /// </summary>
        private readonly Dictionary<String, String>                        sshAdmitted        = new (StringComparer.Ordinal);

        /// <summary>
        /// How many connections of each kind are let in.
        /// </summary>
        private readonly Dictionary<String, Int32>                         sshAdmittedByKind  = new (StringComparer.Ordinal);

        /// <summary>
        /// When it was said last that a kind is full, and how many were refused since without a word.
        /// </summary>
        private readonly Dictionary<String, SSHFullKindSaid>               sshFullKindsSaid   = new (StringComparer.Ordinal);

        /// <summary>
        /// What each SSH server this node started lets in.
        /// </summary>
        private readonly ConditionalWeakTable<SshServer, SshServerLimits>  sshServersLimits   = new ();

        private sealed record SSHFullKindSaid(DateTimeOffset  At,
                                              Int32           Unsaid);

        #endregion


        #region SSHKindsSigningIn

        /// <summary>
        /// The kinds that sign in over SSH: "account", and the logins this kind of node lets in besides
        /// ("station"), see <see cref="AddSSHSignIns"/>.
        /// </summary>
        public IReadOnlyList<String> SSHKindsSigningIn

            => [ SSHPrincipal.Account, .. SSHSignIns.Select(signIns => signIns.PrincipalKind) ];

        #endregion

        #region SSHMaxConnectionsOf(Kind)

        /// <summary>
        /// How many connections the given kind may have open at once: what the "ssh" section says, or
        /// <see cref="SSHConfiguration.DefaultMaxConnectionsOfAccounts"/> for the accounts and
        /// <see cref="SSHConfiguration.DefaultMaxConnectionsOfLogins"/> for any other kind.
        /// </summary>
        /// <param name="Kind">"account", or a kind of login: "station".</param>
        public Int32 SSHMaxConnectionsOf(String Kind)

            => SSHMaxConnectionsOf(Kind, sshFile);

        private static Int32 SSHMaxConnectionsOf(String             Kind,
                                                 SSHConfiguration?  File)

            => File?.MaxConnections is { } configured && configured.TryGetValue(Kind, out var max)
                   ? max
                   : Kind == SSHPrincipal.Account
                         ? SSHConfiguration.DefaultMaxConnectionsOfAccounts
                         : SSHConfiguration.DefaultMaxConnectionsOfLogins;

        #endregion

        #region SSHConnectionsOf(Kind)

        /// <summary>
        /// How many connections of the given kind are open now, signed in.
        /// </summary>
        /// <param name="Kind">"account", or a kind of login: "station".</param>
        public Int32 SSHConnectionsOf(String Kind)
        {
            lock (sshAdmittedLock)
                return sshAdmittedByKind.GetValueOrDefault(Kind);
        }

        #endregion


        #region (private) SSHMaxConnectionsInAll(File)

        /// <summary>
        /// What an SSH server of this node lets in at once, with the given "ssh" section: what every kind
        /// may have together, and the connections that have not signed in yet besides.
        /// </summary>
        private Int32 SSHMaxConnectionsInAll(SSHConfiguration? File)

            => SSHKindsSigningIn.Sum(kind => SSHMaxConnectionsOf(kind, File)) +
               new SshServerLimits().MaxUnauthenticated;

        #endregion

        #region (private) SSHServerLimits(File)

        /// <summary>
        /// What an SSH server of this node allows, with the given "ssh" section: the server's defaults,
        /// and this node's own - a sign-in within half a minute, four sessions on a connection, a client
        /// asked every minute whether it is still there, and as many connections at once as every kind
        /// may have together and those not signed in yet.
        /// </summary>
        private SshServerLimits SSHServerLimits(SSHConfiguration? File)

            => new () {
                   LoginGraceTime       = SSHLoginGraceTime,
                   MaxSessions          = 4,
                   MaxConnections       = SSHMaxConnectionsInAll(File),
                   ClientAliveInterval  = TimeSpan.FromSeconds(60),
                   ClientAliveCountMax  = 3
               };

        #endregion

        #region (private) SSHServerLimitsInEffect()

        /// <summary>
        /// What the SSH server that runs allows - or, where none runs, what one would.
        /// </summary>
        private SshServerLimits SSHServerLimitsInEffect()

            => sshServer is SshServer running && sshServersLimits.TryGetValue(running, out var limits)
                   ? limits
                   : SSHServerLimits(sshFile);

        #endregion

        #region (private) SSHServerTakesFewer()

        /// <summary>
        /// Where the SSH server that runs lets fewer in at once than every kind may have together now:
        /// that, as a sentence - or null.
        /// </summary>
        private String? SSHServerTakesFewer()
        {

            if (sshServer is null)
                return null;

            var running  = SSHServerLimitsInEffect().MaxConnections;
            var needed   = SSHMaxConnectionsInAll(sshFile);

            return running < needed
                       ? $"The SSH server lets {running} connection(s) in at once until it starts again, {needed} after - " +
                         $"what every kind may have together, and {new SshServerLimits().MaxUnauthenticated} not signed in yet. " +
                         "Until then, one kind may fill what another may have."
                       : null;

        }

        #endregion

        #region (private) SSHMaxConnectionsSaid()

        /// <summary>
        /// How many connections each kind may have open at once, as a sentence says it: "20 account
        /// connection(s) and 100 station connection(s)".
        /// </summary>
        private String SSHMaxConnectionsSaid()
        {

            var each = SSHKindsSigningIn.Select(kind => $"{SSHMaxConnectionsOf(kind)} {kind} connection(s)").ToList();

            return each.Count == 1
                       ? each[0]
                       : $"{String.Join(", ", each.Take(each.Count - 1))} and {each[^1]}";

        }

        #endregion

        #region (private) SSHMaxConnectionsJSON()

        /// <summary>
        /// Each kind that signs in, with how many connections it may have open at once and how many it has.
        /// </summary>
        private JObject SSHMaxConnectionsJSON()
        {

            var json = new JObject();

            foreach (var kind in SSHKindsSigningIn)
                json.Add(kind, new JObject(
                                   new JProperty("maxConnections",  SSHMaxConnectionsOf(kind)),
                                   new JProperty("connections",     SSHConnectionsOf(kind))
                               ));

            return json;

        }

        #endregion


        #region (private static) MergedMaxConnections(Saved, Sent)

        /// <summary>
        /// The limits saved, with those sent over them - as the file merges them: a kind that was not
        /// sent keeps what it had.
        /// </summary>
        private static IReadOnlyDictionary<String, Int32>? MergedMaxConnections(IReadOnlyDictionary<String, Int32>?  Saved,
                                                                                IReadOnlyDictionary<String, Int32>?  Sent)
        {

            if (Sent is null)
                return Saved;

            var merged = new Dictionary<String, Int32>(Saved ?? new Dictionary<String, Int32>(), StringComparer.Ordinal);

            foreach (var (kind, max) in Sent)
                merged[kind] = max;

            return merged;

        }

        #endregion

        #region (private) RememberSSHServerLimits(Server, Limits)

        private void RememberSSHServerLimits(SshServer        Server,
                                             SshServerLimits  Limits)

            => sshServersLimits.AddOrUpdate(Server, Limits);

        #endregion

        #region (private) AdmitSSHConnection(Session, out Kind) / ReleaseSSHConnection(ConnectionId)

        /// <summary>
        /// Count the given session's connection in as one of its kind - or say why not: its kind has as
        /// many open as it may.
        /// </summary>
        private String? AdmitSSHConnection(SshSessionInfo  Session,
                                           out String      Kind)
        {

            Kind = SSHSignInsOf(Session)?.PrincipalKind ?? SSHPrincipal.Account;

            var max = SSHMaxConnectionsOf(Kind);

            lock (sshAdmittedLock)
            {

                if (sshAdmitted.ContainsKey(Session.ConnectionId))
                    return null;

                var open = sshAdmittedByKind.GetValueOrDefault(Kind);

                if (open >= max)
                    return open == max
                               ? $"{open} {Kind} connection(s) are open, as many as ssh.maxConnections lets in"
                               : $"{open} {Kind} connection(s) are open, more than ssh.maxConnections lets in ({max})";

                sshAdmitted[Session.ConnectionId]  = Kind;
                sshAdmittedByKind[Kind]            = open + 1;

                return null;

            }

        }

        /// <summary>
        /// The given connection is closed: counted out of its kind, where it was counted in.
        /// </summary>
        private void ReleaseSSHConnection(String? ConnectionId)
        {

            if (ConnectionId is null)
                return;

            lock (sshAdmittedLock)
            {

                if (!sshAdmitted.Remove(ConnectionId, out var kind))
                    return;

                var left = sshAdmittedByKind.GetValueOrDefault(kind) - 1;

                if (left > 0)
                    sshAdmittedByKind[kind] = left;
                else
                    sshAdmittedByKind.Remove(kind);

            }

        }

        #endregion

        #region (private) SayFullSSHKind(Kind, Session, Refusal)

        /// <summary>
        /// Say in the log that a kind is full and the given session was refused - at most once a minute
        /// for each kind, and then with how many were refused since without a word: stations knocking
        /// again and again at a full server write a line a minute, not a line each.
        /// </summary>
        private void SayFullSSHKind(String          Kind,
                                    SshSessionInfo  Session,
                                    String          Refusal)
        {

            var now     = TimeProvider.GetUtcNow();
            var unsaid  = 0;

            lock (sshAdmittedLock)
            {

                if (sshFullKindsSaid.TryGetValue(Kind, out var said))
                {

                    if (now - said.At < TimeSpan.FromMinutes(1))
                    {
                        sshFullKindsSaid[Kind] = said with { Unsaid = said.Unsaid + 1 };
                        return;
                    }

                    unsaid = said.Unsaid;

                }

                sshFullKindsSaid[Kind] = new SSHFullKindSaid(now, 0);

            }

            Log.Warning($"'{Session.Username}' signed in over SSH from {Session.Peer?.ToString() ?? "somewhere"}, and was refused: {Refusal}" +
                        (unsaid > 0 ? $" - and {unsaid} more were refused since that was said last." : "."),
                        "ssh", "auth", "security");

        }

        #endregion

    }

}
