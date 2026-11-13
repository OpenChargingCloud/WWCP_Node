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
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What the last attempt to ask a name server over SSH came to: SSHStatus
    /// of DNSServerController in the OCPP Device Model (white paper "DNS over
    /// SSH", section 7.1), in its words.
    /// </summary>
    public enum NameServerSSHStatus
    {

        /// <summary>
        /// Its host key was believed - or used although nothing vouches for
        /// it, where its entry records or accepts that - the node was let in,
        /// and the subsystem is served.
        /// </summary>
        Accepted,

        /// <summary>
        /// It showed a host key that neither a pin nor a CA vouches for.
        /// </summary>
        PinMismatch,

        /// <summary>
        /// It showed a host certificate of one of its CAs that is not valid
        /// now, or not for the address it was asked under.
        /// </summary>
        Untrusted,

        /// <summary>
        /// It does not signal strict KEX, or offers only algorithms the node
        /// must not use.
        /// </summary>
        WeakAlgorithms,

        /// <summary>
        /// It did not take the node's key.
        /// </summary>
        AuthenticationFailed,

        /// <summary>
        /// It let the node in, and refused the subsystem.
        /// </summary>
        SubsystemRefused,

        /// <summary>
        /// It is to share the connection to an SSH peer, and its address is no
        /// SSH peer of the node.
        /// </summary>
        NoSSHPeer

    }


    /// <summary>
    /// Which news an attempt to ask a name server over SSH is: what a CSMS is
    /// told without asking, in the security events of section 7.4 of the white
    /// paper "DNS over SSH".
    /// </summary>
    public enum NameServerSSHNews
    {

        /// <summary>
        /// It showed a host key nothing vouches for, or an invalid host
        /// certificate, and was not used: InvalidNameServerHostKey.
        /// </summary>
        HostKeyRefused,

        /// <summary>
        /// It showed a host key nothing vouches for and was used all the same,
        /// as its entry says: InvalidNameServerHostKey as well.
        /// </summary>
        HostKeyTolerated,

        /// <summary>
        /// It was believed with another host key than before:
        /// NameServerHostKeyChanged.
        /// </summary>
        HostKeyChanged,

        /// <summary>
        /// It did not take the node's key: NameServerAuthenticationFailed.
        /// </summary>
        AuthenticationFailed,

        /// <summary>
        /// It does not signal strict KEX: InvalidSSHAlgorithms.
        /// </summary>
        WeakAlgorithms

    }


    /// <summary>
    /// What the last attempt to ask a name server over SSH came to.
    /// </summary>
    /// <param name="At">When.</param>
    /// <param name="Status">What it came to.</param>
    /// <param name="HostKey">The SHA-256 fingerprint of the host key it showed at that handshake, "SHA256:...", or null where it showed none.</param>
    /// <param name="Matched">Whether that key is one it is held to - or, on a shared connection, one the SSH peer is held to.</param>
    /// <param name="Why">What it was believed by, or why it was not used.</param>
    /// <param name="Previously">The host key it was believed with before, where this one is another.</param>
    public sealed record NameServerSSHState(DateTimeOffset       At,
                                            NameServerSSHStatus  Status,
                                            String?              HostKey,
                                            Boolean              Matched,
                                            String               Why,
                                            String?              Previously   = null)
    {

        /// <summary>
        /// Whether it is the same verdict as another one: what is said once,
        /// and not again at every attempt.
        /// </summary>
        public Boolean SameVerdictAs(NameServerSSHState? Other)

            => Other is not null             &&
               Status  == Other.Status       &&
               HostKey == Other.HostKey      &&
               Matched == Other.Matched;

        /// <summary>
        /// As the DNS page and the OCPP Device Model read it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("at",        At.ToString("o")),
                   new JProperty("status",    Status.ToString()),
                   new JProperty("hostKey",   HostKey),
                   new JProperty("matched",   Matched),
                   new JProperty("accepted",  Status == NameServerSSHStatus.Accepted),
                   new JProperty("why",       Why)
               );

    }


    /// <summary>
    /// Name servers asked over SSH - the subsystem "dns@open.charging.cloud" of
    /// the white paper "DNS over SSH" - instead of UDP, TCP, TLS or HTTPS: the
    /// transport SSH of DNSServerController in the OCPP Device Model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Such a server has an SSH connection of its own: the node signs in with
    /// a key it has for name servers alone, made at its first need and kept
    /// beside its SSH host key - so that it can be withdrawn at a name server
    /// without anything else being touched, and no name server holds a key
    /// that opens anything else (decision 2 of the paper). Under its own name,
    /// unless the entry names another login (decision 5). And the server is
    /// held to its host key, by the rule of a time server whose key exchange
    /// goes over SSH - see <see cref="NTSServerSSH.Believes(Byte[], String, DateTimeOffset, out String, out String, out SSHHostKeyVerdict)"/>.
    /// </para>
    /// <para>
    /// Or it shares the SSH connection the node keeps to the SSH peer its
    /// address is, where its entry says "connection": "shared": then nothing
    /// is its own - neither login, key nor host key - and where the address is
    /// no SSH peer, it is not asked (see <see cref="SSHPeers"/>).
    /// </para>
    /// <para>
    /// Either way the connection is handed to Hermod's DNS client, which opens
    /// its channel on it; the node dials it. That is what lets the node say
    /// what an attempt came to. Hermod's client knows as much, in
    /// DNSSSHClient.LastConnectionError, but a DNSClient keeps the clients of
    /// its servers to itself - so the node goes by what it sees: its own
    /// verdict on the host key, the exception of its own dial, and whether the
    /// subsystem is granted on the connection it hands out, which it asks
    /// once per connection, on a channel it closes again at once.
    /// </para>
    /// <para>
    /// A server over SSH is asked over SSH or not at all: there is no other
    /// transport it falls back to.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What the file of the key this node signs in with at its name servers
        /// over SSH is called, beside its SSH host key.
        /// </summary>
        public const String  DNSSSHClientKeyFileName  = "dns_client_ed25519_key";

        /// <summary>
        /// How long the SSH connection to a name server may take to be had.
        /// </summary>
        public static readonly TimeSpan  NameServerSSHConnectTimeout  = TimeSpan.FromSeconds(10);

        private readonly Object                                                       dnsSSHClientKeyLock  = new ();
        private          ISshHostKey?                                                 dnsSSHClientKey;
        private          String?                                                      dnsSSHClientKeyProblem;

        /// <summary>
        /// How each configured name server asked over SSH is reached, and what
        /// its host key is held to.
        /// </summary>
        private          IReadOnlyDictionary<DNSServerConfig, NTSServerSSH>           dnsSSH               = new Dictionary<DNSServerConfig, NTSServerSSH>();

        private readonly ConcurrentDictionary<DNSServerConfig, NameServerSSHState>    dnsSSHStates         = new ();
        private readonly ConcurrentDictionary<DNSServerConfig, SshSharedConnection>   dnsSSHConnections    = new ();

        /// <summary>
        /// The host key each server showed at the handshake that is going on,
        /// or went last, and what it came to - for what is said of that
        /// handshake after the key was judged.
        /// </summary>
        private readonly ConcurrentDictionary<DNSServerConfig, (String Shown, Boolean Matched, String Why)>  dnsSSHShown  = new ();

        /// <summary>
        /// The certified key of the host certificate each server was refused
        /// with last - see <see cref="JudgeNameServerHostKey"/>.
        /// </summary>
        private readonly ConcurrentDictionary<DNSServerConfig, String>                dnsSSHCertificatesRefused  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Where the key this node signs in with at its name servers over SSH
        /// is kept: beside its SSH host key.
        /// </summary>
        public String  DNSSSHClientKeyPath
            => Beside(ConfigFile.Path, Path.Combine(DefaultSSHDirectory, DNSSSHClientKeyFileName));

        /// <summary>
        /// The public key this node signs in with at its name servers over
        /// SSH, as a line of an authorized_keys file - made now where there is
        /// none yet; null where it can be neither read nor made, which the log
        /// says why.
        /// </summary>
        /// <remarks>
        /// SSHClientPublicKey of section 7.1 of the white paper "DNS over SSH",
        /// and SSHClientController.ClientPublicKey[DNS] of its section 7.3: a
        /// CSMS reads it before it gives the node a name server over SSH, and
        /// enters it at that server.
        /// </remarks>
        public virtual String? DNSSSHClientPublicKey

            => DNSSSHClientKey is ISshHostKey key
                   ? SshPublicKey.FromHostKey(key, $"{Kind.Tag}-dns@{Environment.MachineName}").ToAuthorizedKeyLine()
                   : null;

        /// <summary>
        /// The key this node signs in with at its name servers over SSH: read
        /// from its file, or made and written there at the first need; null
        /// where neither can be done. A kind that keeps its keys elsewhere - a
        /// charging station with a key of the purpose DNS - signs in with that
        /// one.
        /// </summary>
        protected virtual ISshHostKey? DNSSSHClientKey
        {
            get
            {

                lock (dnsSSHClientKeyLock)
                {

                    if (dnsSSHClientKey is not null)
                        return dnsSSHClientKey;

                    var path = DNSSSHClientKeyPath;

                    try
                    {

                        // A private key: whoever can read it can sign in as this node.
                        OwnerOnly.Directory(Path.GetDirectoryName(path)!, problem => Log.Warning(problem, Kind.Tag, "dns", "ssh", "security"));

                        if (File.Exists(path))
                            dnsSSHClientKey = SshKeyGenerator.LoadPrivateKey(File.ReadAllText(path)).Key;

                        else
                        {

                            var key = SshHostKey.GenerateEd25519();

                            SshKeyGenerator.WriteKeyPairAsync(key, path, Comment: $"{Kind.Tag}-dns@{Environment.MachineName}").GetAwaiter().GetResult();

                            Log.Notice($"A key was made for this {Kind.Name} to sign in with at its name servers over SSH: " +
                                       $"{key.AlgorithmNames[0]} {SshFingerprint.Sha256(key.PublicKeyBlob)}, kept in '{path}'.",
                                       Kind.Tag, "dns", "ssh", "security");

                            dnsSSHClientKey = key;

                        }

                        dnsSSHClientKeyProblem = null;

                    }
                    catch (Exception problem)
                    {

                        var said = $"The key this {Kind.Name} signs in with at its name servers over SSH could not be had from '{path}': {problem.Message}";

                        if (said != dnsSSHClientKeyProblem)
                            Log.Error(said, Kind.Tag, "dns", "ssh", "security");

                        dnsSSHClientKeyProblem = said;

                    }

                    return dnsSSHClientKey;

                }

            }
        }

        /// <summary>
        /// The user name this node signs in under at a name server over SSH
        /// whose entry names none: what it calls itself, as at its SSH peers -
        /// which views, limits and logs per node need (decision 5 of the white
        /// paper "DNS over SSH").
        /// </summary>
        protected virtual String DefaultNameServerSSHUser
            => DefaultSSHPeerUser;

        /// <summary>
        /// The hosts that become SSH peers of this node once something dials
        /// them, beside those that are peers already: none for a node, whose
        /// peers are those of its configuration from the moment it reads it. A
        /// kind that makes a host a peer by dialling it - a charging station,
        /// for a connection of OCPP over SSH - names them here, so that a name
        /// server can be given such a connection to share before it was made.
        /// </summary>
        protected virtual IEnumerable<String> SSHPeerHostsToBe
            => [];

        /// <summary>
        /// The hosts a name server may share an SSH connection with: the SSH
        /// peers of this node, and those to be - see <see cref="SSHPeerHostsToBe"/>.
        /// </summary>
        public IReadOnlyList<String> NameServerSSHPeerHosts

            => [.. SSHPeers.Select  (peer => peer.Host.Trimmed).
                            Concat  (SSHPeerHostsToBe.Select(host => host.Trim().TrimEnd('.'))).
                            Where   (host => host.Length > 0).
                            Distinct(StringComparer.OrdinalIgnoreCase).
                            OrderBy (host => host, StringComparer.OrdinalIgnoreCase)];

        #endregion

        #region Events

        /// <summary>
        /// An attempt to ask a name server over SSH is news: the server, what
        /// the attempt came to, and which news it is. Told once per change of
        /// the verdict, and not again at every attempt.
        /// </summary>
        /// <remarks>
        /// Of a server with a connection of its own alone: what the host key of
        /// a shared connection came to is news of the SSH peer it is the
        /// connection of. Told from inside the attempt, so a listener that
        /// takes long holds up a query; what only asks - a dry run of a
        /// configuration - tells nothing.
        /// </remarks>
        public event Action<DNSServerConfig, NameServerSSHState, NameServerSSHNews>?  OnNameServerSSHNews;

        #endregion


        #region NameServerSSHOf(Server) / NameServerSSHStateOf(Server) / NameServerSSHClientPublicKeyOf(Server)

        /// <summary>
        /// How the given name server is asked over SSH and what its host key is
        /// held to, or null where it is not asked over SSH.
        /// </summary>
        public NTSServerSSH? NameServerSSHOf(DNSServerConfig Server)

            => dnsSSH.GetValueOrDefault(Server);

        /// <summary>
        /// What the last attempt to ask the given name server over SSH came to,
        /// or null before the first one.
        /// </summary>
        public NameServerSSHState? NameServerSSHStateOf(DNSServerConfig Server)

            => dnsSSHStates.TryGetValue(Server, out var state)
                   ? state
                   : null;

        /// <summary>
        /// The public key the node signs in with at the given name server over
        /// SSH, as a line of an authorized_keys file: its key for name servers,
        /// or - on a shared connection - the key it signs in with at that SSH
        /// peer, for which no key of its own is made. Null where there is none.
        /// </summary>
        public String? NameServerSSHClientPublicKeyOf(DNSServerConfig Server)

            => NameServerSSHOf(Server) switch {
                   null                => null,
                   { IsShared: true }  => SSHPeerHostOf(Server) is DomainName host
                                              ? SSHPeerTo(host)?.PublicKey?.Invoke()
                                              : null,
                   _                   => DNSSSHClientPublicKey
               };

        #endregion

        #region (private static) SSHHostOf(Server) / SSHPeerHostOf(Server) / FingerprintOf(HostKeyBlob)

        /// <summary>
        /// What a name server over SSH is dialled by, and what a host
        /// certificate of its has to name: its address, or its name.
        /// </summary>
        private static String SSHHostOf(DNSServerConfig Server)

            => Server.IPAddress?.ToString() ?? Server.DomainName?.Trimmed ?? "";

        /// <summary>
        /// The host an SSH peer would be known by, were the given name server
        /// one: SSH peers are told apart by their host, which may be an address.
        /// </summary>
        private static DomainName? SSHPeerHostOf(DNSServerConfig Server)

            => Server.DomainName
                   ?? (DomainName.TryParse(SSHHostOf(Server), out var host, out _)
                           ? host
                           : null);

        /// <summary>
        /// The SHA-256 fingerprint of the key a server showed: of the
        /// certified key, where it showed a host certificate - as
        /// <see cref="NTSServerSSH.Believes(Byte[], String, DateTimeOffset, out String, out String)"/> says it.
        /// </summary>
        private static String FingerprintOf(Byte[] HostKeyBlob)

            => SshFingerprint.Sha256(SshCertificate.TryParse(HostKeyBlob, out var certificate) && certificate is not null
                                         ? certificate.SubjectPublicKey
                                         : HostKeyBlob);

        #endregion

        #region (private) WithSSH(Servers) / WithSSH(Server)

        /// <summary>
        /// The given name servers as the DNS client is given them: each one
        /// asked over SSH with the connection it is asked on, which the node
        /// hands out - one of the server's own, or the one it shares with an
        /// SSH peer.
        /// </summary>
        /// <remarks>
        /// The same server to the client, whatever it is held to: a server is
        /// told apart by its transport, its address and its port. What it is
        /// held to is looked up when a connection is asked for, so that a
        /// change of it needs no other list of servers - only the connection
        /// closed, see <see cref="ApplyNameServersOverSSH"/>.
        /// </remarks>
        private IReadOnlyList<DNSServerConfig> WithSSH(IEnumerable<DNSServerConfig> Servers)

            => [.. Servers.Select(WithSSH)];

        private DNSServerConfig WithSSH(DNSServerConfig Server)
        {

            // Not over SSH - or made by whoever made this node, with a
            // connection of its own making.
            if (Server.Transport != DNSTransport.SSH || Server.SSH is not null)
                return Server;

            Func<CancellationToken, ValueTask<SshClient>> connection = cancellationToken => NameServerSSHConnection(Server, cancellationToken);

            return Server.IPAddress is IIPAddress address
                       ? DNSServerConfig.OverSSH(address,            connection, Server.Port, Server.QueryTimeout)
                       : DNSServerConfig.OverSSH(Server.DomainName!, connection, Server.Port, Server.QueryTimeout);

        }

        #endregion

        #region (private) ApplyNameServersOverSSH(Now)

        /// <summary>
        /// Put into effect how the name servers over SSH are reached and what
        /// their host keys are held to. A server whose way changed lets go of
        /// its connection, and of what its last attempt came to: a host key is
        /// only looked at when a connection is made, and a server held to
        /// another key from now on must not go on being asked over a connection
        /// that was believed by the old one (T21 of the white paper).
        /// </summary>
        /// <param name="Now">What the list of servers says now; null for nothing.</param>
        /// <returns>What changed, as the log line says it.</returns>
        private IReadOnlyList<String> ApplyNameServersOverSSH(IReadOnlyDictionary<DNSServerConfig, NTSServerSSH>? Now)
        {

            var was      = dnsSSH;
            var said     = Now ?? new Dictionary<DNSServerConfig, NTSServerSSH>();
            var now      = new Dictionary<DNSServerConfig, NTSServerSSH>();
            var changed  = new List<DNSServerConfig>();
            var changes  = new List<String>();

            foreach (var server in was.Keys.Union(said.Keys).ToArray())
            {

                var before = was. TryGetValue(server, out var wasSSH)  ? wasSSH. ToJSON().ToString(Newtonsoft.Json.Formatting.None) : null;
                var after  = said.TryGetValue(server, out var saidSSH) ? saidSSH.ToJSON().ToString(Newtonsoft.Json.Formatting.None) : null;

                // The entry it had, where a save says the same again: an
                // attempt that is on its way was begun by that one, and is
                // still the attempt of what is in effect.
                if (before == after)
                    now[server] = wasSSH!;

                else
                {

                    changed.Add(server);

                    if (saidSSH is not null)
                        now[server] = saidSSH;

                }

            }

            dnsSSH = now;

            foreach (var server in changed)
            {

                var nowSSH = now.GetValueOrDefault(server);

                LetGoOfNameServerSSH(server);

                if (nowSSH is not null)
                    changes.Add($"{NameOf(server)} {NameServerSSHText(server, nowSSH)}");

            }

            return changes;

        }

        /// <summary>
        /// How a name server is asked over SSH, as a sentence says it: "on the
        /// shared SSH connection to 10.10.0.1", or "signed in as cs001, held
        /// to SHA256:...".
        /// </summary>
        /// <remarks>
        /// The login an entry does not name is not looked up here: this is
        /// said while a node is made, when a kind that signs in under a name
        /// of its own - a charging station - does not know that name yet.
        /// </remarks>
        private static String NameServerSSHText(DNSServerConfig  Server,
                                                NTSServerSSH     SSH)

            => SSH.IsShared
                   ? $"asked on the shared SSH connection to {SSHHostOf(Server)}"
                   : $"signed in {(SSH.User is not null ? $"as {SSH.User}" : "under its own name")}, held to {String.Join(", ", SSH.Pins.Concat(SSH.CAs.Select(ca => $"the CA {ca}")))}" +
                     (SSH.OnMismatch != PinMismatch.Refuse
                          ? $", a mismatch {(SSH.OnMismatch == PinMismatch.Record ? "recorded" : "accepted")}"
                          : "");

        #endregion

        #region (private) LetGoOfNameServerSSH(Server) / CloseNameServerSSHConnections()

        /// <summary>
        /// Close the connection to the given name server over SSH - the one of
        /// its own; a shared one is the peer's, and only the channel on it goes
        /// - and forget what its last attempt came to.
        /// </summary>
        private void LetGoOfNameServerSSH(DNSServerConfig Server)
        {

            // The channel, and with it what Hermod's client holds of the connection.
            dnsClient.CloseConnection(Server);

            dnsSSHStates.             TryRemove(Server, out _);
            dnsSSHShown.              TryRemove(Server, out _);
            dnsSSHCertificatesRefused.TryRemove(Server, out _);

            if (dnsSSHConnections.TryRemove(Server, out var connection))
                _ = Task.Run(async () => {
                        try   { await connection.DisposeAsync(); }
                        catch { }
                    });

        }

        /// <summary>
        /// Close the connections to the name servers over SSH: the node stops.
        /// </summary>
        private async Task CloseNameServerSSHConnections()
        {

            foreach (var server in dnsSSHConnections.Keys.ToArray())
                if (dnsSSHConnections.TryRemove(server, out var connection))
                {
                    try   { await connection.DisposeAsync(); }
                    catch { }
                }

        }

        #endregion

        #region (private) NameServerSSHConnection(Server, CancellationToken)

        /// <summary>
        /// The SSH connection the given name server is asked on, for Hermod's
        /// DNS client to open its channel on: the one of its own that lasts, or
        /// a new one; or the one the node shares with the SSH peer its address
        /// is. And what the attempt came to is kept, and said where it is news.
        /// </summary>
        /// <remarks>
        /// Asked for by the client at its first query, and again once the
        /// connection it was handed has ended - and at every query for as long
        /// as this throws. Whether the server grants the subsystem on the
        /// connection is asked here, on a channel that is closed again at once:
        /// the client would learn it at its own channel, and keep it to itself.
        /// </remarks>
        private async ValueTask<SshClient> NameServerSSHConnection(DNSServerConfig    Server,
                                                                   CancellationToken  CancellationToken)
        {

            if (NameServerSSHOf(Server) is not NTSServerSSH entry)
                throw new InvalidOperationException($"The name server {NameOf(Server)} is not asked over SSH any more.");

            SshClient ssh;

            if (entry.IsShared)
            {

                if (SSHPeerHostOf(Server) is not DomainName host || SSHPeerTo(host) is null)
                {

                    var why = $"{SSHHostOf(Server)} is no SSH peer of this {Kind.Name}: there is no connection to share";

                    NameServerSSHCameTo(Server, entry, NameServerSSHStatus.NoSSHPeer, null, false, why);

                    throw new InvalidOperationException(why + ".");

                }

                try
                {
                    ssh = await SharedSSHConnectionTo(host, DNSServer.SSHSubsystemName, CancellationToken).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    NameServerSSHFailed(Server, entry, e);
                    throw;
                }

                // Believed by what the peer is held to, not judged again.
                dnsSSHShown[Server] = (FingerprintOf(ssh.ServerHostKey), true, "its host key is the one the shared connection is held to");

            }

            else
            {

                var connection = dnsSSHConnections.GetOrAdd(Server,
                                                            server => new SshSharedConnection(cancellationToken => ConnectToNameServerOverSSH(server, cancellationToken)));

                try
                {
                    ssh = await connection.GetAsync(CancellationToken).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    NameServerSSHFailed(Server, entry, e);
                    throw;
                }

            }

            // Let in. Whether names are served there is the last thing to know.
            try
            {

                var channel = await ssh.OpenSubsystemAsync(DNSServer.SSHSubsystemName, CancellationToken).ConfigureAwait(false);

                try   { await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false); }
                catch { }

            }
            catch (Exception e)
            {
                NameServerSSHFailed(Server, entry, e);
                throw;
            }

            var shown = dnsSSHShown.TryGetValue(Server, out var last)
                            ? last
                            : (Shown: FingerprintOf(ssh.ServerHostKey), Matched: true, Why: "its host key was believed");

            NameServerSSHCameTo(Server, entry, NameServerSSHStatus.Accepted, shown.Shown, shown.Matched, shown.Why);

            return ssh;

        }

        #endregion

        #region (private) ConnectToNameServerOverSSH(Server, CancellationToken)

        /// <summary>
        /// An SSH connection of its own to the given name server: its host key
        /// judged, and this node signed in with its key for name servers -
        /// with that key and nothing else, so no password is ever sent - to a
        /// server that signals strict KEX.
        /// </summary>
        private async ValueTask<SshClient> ConnectToNameServerOverSSH(DNSServerConfig    Server,
                                                                      CancellationToken  CancellationToken)
        {

            if (NameServerSSHOf(Server) is not NTSServerSSH entry || entry.IsShared)
                throw new InvalidOperationException($"The name server {NameOf(Server)} has no SSH connection of its own any more.");

            var key = DNSSSHClientKey
                          ?? throw new InvalidOperationException(dnsSSHClientKeyProblem ?? $"This {Kind.Name} has no key to sign in with at its name servers.");

            return await SshClient.ConnectAsync(
                             SSHHostOf(Server),
                             Server.Port.ToUInt16(),
                             new SshClientOptions {
                                 Username          = entry.User ?? DefaultNameServerSSHUser,
                                 DNSClient         = dnsClient,
                                 Credentials       = [ key ],
                                 VerifyHostKey     = blob => JudgeNameServerHostKey(Server, entry, blob),
                                 RequireStrictKex  = true,
                                 ConnectTimeout    = NameServerSSHConnectTimeout
                             },
                             CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion

        #region (private) JudgeNameServerHostKey(Server, SSH, HostKeyBlob)

        /// <summary>
        /// Whether the connection to a name server goes on with the host key it
        /// showed: one it is held to, or a mismatch its entry records or
        /// accepts.
        /// </summary>
        /// <remarks>
        /// A key that is refused is what the attempt came to, and said here. A
        /// key the connection goes on with is kept for what is said of the
        /// attempt when it is over - and, where it is one the server is held
        /// to, remembered as what the server was believed with, so that
        /// another one next time is noticed (Secure DNS paper, section 2.3).
        /// <para>
        /// A host certificate that is refused is asked about once more by
        /// Hermod, as the key it certifies alone - as OpenSSH retries "with
        /// plain key". That key was looked for among the pins when its
        /// certificate was judged, so the answer is the same, and the verdict
        /// stays the one of the certificate: Untrusted for one that is not
        /// valid, where the second question alone would make it PinMismatch.
        /// </para>
        /// </remarks>
        private Boolean JudgeNameServerHostKey(DNSServerConfig  Server,
                                               NTSServerSSH     SSH,
                                               Byte[]           HostKeyBlob)
        {

            var certified = SshCertificate.TryParse(HostKeyBlob, out var certificate) && certificate is not null;

            // The key of the certificate that was just refused, on its own.
            if (dnsSSHCertificatesRefused.TryRemove(Server, out var refused) && !certified && refused == SshFingerprint.Sha256(HostKeyBlob))
                return false;

            var now       = TimeProvider.GetUtcNow();
            var matched   = SSH.Believes(HostKeyBlob, SSHHostOf(Server), now, out var shown, out var why, out var verdict);
            var accepted  = matched || SSH.OnMismatch != PinMismatch.Refuse;

            dnsSSHShown[Server] = (shown, matched, why);

            if (!accepted && certified)
                dnsSSHCertificatesRefused[Server] = shown;

            if (!accepted)
                NameServerSSHCameTo(Server,
                                    SSH,
                                    verdict == SSHHostKeyVerdict.InvalidCertificate
                                        ? NameServerSSHStatus.Untrusted
                                        : NameServerSSHStatus.PinMismatch,
                                    shown,
                                    false,
                                    why);

            return accepted;

        }

        #endregion

        #region (private) NameServerSSHFailed(Server, SSH, Problem)

        /// <summary>
        /// What an attempt that threw came to, by what it threw: a host key
        /// that was refused - said already when it was judged, where the node
        /// judged it - no strict KEX, a key that was not taken, a subsystem
        /// that was refused. Anything else - a server that is not there, a
        /// connection that broke - is none of the outcomes there are words for,
        /// and leaves what was known of the server as it was.
        /// </summary>
        private void NameServerSSHFailed(DNSServerConfig  Server,
                                         NTSServerSSH     SSH,
                                         Exception        Problem)
        {

            var shown = dnsSSHShown.TryGetValue(Server, out var last)
                            ? last.Shown
                            : null;

            switch (Problem)
            {

                // Its own connection: judged, and said, in JudgeNameServerHostKey.
                // A shared one: the peer's verdict, which is all there is to say.
                case SshHostKeyRejectedException rejected when SSH.IsShared:
                    NameServerSSHCameTo(Server, SSH, NameServerSSHStatus.PinMismatch, FingerprintOf(rejected.HostKey), false,
                                        "the host key the SSH peer showed is none the shared connection is held to");
                    break;

                case SshStrictKexRequiredException:
                    NameServerSSHCameTo(Server, SSH, NameServerSSHStatus.WeakAlgorithms, shown, false,
                                        "it does not signal strict KEX, which is required against Terrapin (CVE-2023-48795)");
                    break;

                case SshAuthenticationException:
                    NameServerSSHCameTo(Server, SSH, NameServerSSHStatus.AuthenticationFailed, shown, last.Matched,
                                        SSH.IsShared
                                            ? $"the SSH peer did not let this {Kind.Name} in: {Problem.Message}"
                                            : $"it did not take the key of this {Kind.Name} for the login '{SSH.User ?? DefaultNameServerSSHUser}': {Problem.Message}");
                    break;

                case SshSubsystemRefusedException:
                    NameServerSSHCameTo(Server, SSH, NameServerSSHStatus.SubsystemRefused, shown, last.Matched,
                                        $"it refused the subsystem '{DNSServer.SSHSubsystemName}' to this login");
                    break;

            }

        }

        #endregion

        #region (private) NameServerSSHCameTo(Server, SSH, Status, HostKey, Matched, Why)

        /// <summary>
        /// Keep what an attempt to ask a name server over SSH came to, and say
        /// it where it is another verdict than the one before: in the log, and
        /// to whatever listens.
        /// </summary>
        /// <remarks>
        /// A server that does not answer is asked again at every query, and
        /// would say the same thing every time. A mismatch that is recorded
        /// goes into the metrological log as well, as a certificate's would.
        /// </remarks>
        private void NameServerSSHCameTo(DNSServerConfig      Server,
                                         NTSServerSSH         SSH,
                                         NameServerSSHStatus  Status,
                                         String?              HostKey,
                                         Boolean              Matched,
                                         String               Why)
        {

            var now       = TimeProvider.GetUtcNow();
            var before    = NameServerSSHStateOf(Server);
            var name      = NameOf(Server);

            // What it was believed with before, between starts as well: only a
            // key that is one it is held to is remembered, as only a
            // certificate that was believed is.
            String? previously = null;

            if (Status == NameServerSSHStatus.Accepted && Matched && HostKey is not null)
            {

                var known = KnownServers.Observe(CertificateUsages.DNS, name, HostKey, null, now);

                if (known is not null && !String.Equals(known.Certificate, HostKey, StringComparison.Ordinal))
                    previously = known.Certificate;

            }

            var state     = new NameServerSSHState(now, Status, HostKey, Matched, Why, previously);

            dnsSSHStates[Server] = state;

            // Still asked over SSH, and by this entry: a change of the
            // configuration that came in between let go of it already.
            if (!ReferenceEquals(NameServerSSHOf(Server), SSH))
                dnsSSHStates.TryRemove(new KeyValuePair<DNSServerConfig, NameServerSSHState>(Server, state));

            if (previously is not null)
            {

                Log.Notice($"DNS: the name server {name} is believed with the SSH host key {HostKey} now, and was with {previously} before.",
                           Kind.Tag, "dns", "ssh", "security");

                if (!SSH.IsShared)
                    TellNameServerSSHNews(Server, state, NameServerSSHNews.HostKeyChanged);

            }

            if (state.SameVerdictAs(before))
                return;

            switch (Status)
            {

                case NameServerSSHStatus.Accepted when !Matched:

                    var used = $"DNS: the name server {name} showed the SSH host key {HostKey}, but {Why}: " +
                               (SSH.OnMismatch == PinMismatch.Record
                                    ? "used, and recorded."
                                    : "used, as its entry says.");

                    if (SSH.OnMismatch == PinMismatch.Record)
                        Log.Metrological(LogLevel.Warning, used, Kind.Tag, "dns", "ssh", "security");
                    else
                        Log.Warning(used, Kind.Tag, "dns", "ssh", "security");

                    TellNameServerSSHNews(Server, state, NameServerSSHNews.HostKeyTolerated);

                    break;

                case NameServerSSHStatus.Accepted:

                    if (before is not null && before.Status != NameServerSSHStatus.Accepted)
                        Log.Notice($"DNS: the name server {name} is asked over SSH again: {Why}.", Kind.Tag, "dns", "ssh", "security");

                    break;

                case NameServerSSHStatus.PinMismatch:
                case NameServerSSHStatus.Untrusted:

                    Log.Warning($"DNS: the name server {name} showed the SSH host key {HostKey}, but {Why}: refused, and it is not asked.",
                                Kind.Tag, "dns", "ssh", "security");

                    if (!SSH.IsShared)
                        TellNameServerSSHNews(Server, state, NameServerSSHNews.HostKeyRefused);

                    break;

                case NameServerSSHStatus.WeakAlgorithms:

                    Log.Warning($"DNS: the name server {name} is not asked over SSH: {Why}.", Kind.Tag, "dns", "ssh", "security");

                    if (!SSH.IsShared)
                        TellNameServerSSHNews(Server, state, NameServerSSHNews.WeakAlgorithms);

                    break;

                case NameServerSSHStatus.AuthenticationFailed:

                    Log.Warning($"DNS: the name server {name} is not asked over SSH: {Why}.", Kind.Tag, "dns", "ssh", "security");

                    if (!SSH.IsShared)
                        TellNameServerSSHNews(Server, state, NameServerSSHNews.AuthenticationFailed);

                    break;

                default:

                    Log.Warning($"DNS: the name server {name} is not asked over SSH: {Why}.", Kind.Tag, "dns", "ssh");

                    break;

            }

        }

        private void TellNameServerSSHNews(DNSServerConfig     Server,
                                           NameServerSSHState  State,
                                           NameServerSSHNews   News)

            => Tell(OnNameServerSSHNews, listener => listener(Server, State, News), $"the name server {NameOf(Server)} was asked over SSH ({News})", CertificateUsages.DNS);

        #endregion

        #region (private) ForADryRun(Server, SSH)

        /// <summary>
        /// A name server over SSH as a dry run of a configuration asks it - see
        /// <see cref="ResolveWithAsync"/>: by what the configuration that is
        /// not in effect holds it to, on a connection of the dry run's own that
        /// goes with it, and with nothing about it news: no line in the log,
        /// nothing kept as what its last attempt came to or as what it was
        /// believed with. A shared connection is the node's, and stays.
        /// </summary>
        /// <param name="Server">The server.</param>
        /// <param name="SSH">How the configuration asks it over SSH.</param>
        private DNSServerConfig ForADryRun(DNSServerConfig  Server,
                                           NTSServerSSH     SSH)
        {

            if (SSH.IsShared)
            {

                Func<CancellationToken, ValueTask<SshClient>> shared = cancellationToken => SSHPeerHostOf(Server) is DomainName host
                                                                                                ? SharedSSHConnectionTo(host, DNSServer.SSHSubsystemName, cancellationToken)
                                                                                                : throw new InvalidOperationException($"{SSHHostOf(Server)} is no SSH peer of this {Kind.Name}.");

                return Server.IPAddress is IIPAddress peer
                           ? DNSServerConfig.OverSSH(peer,               shared, Server.Port, Server.QueryTimeout)
                           : DNSServerConfig.OverSSH(Server.DomainName!, shared, Server.Port, Server.QueryTimeout);

            }

            var options = new SshClientOptions {
                              Username          = SSH.User ?? DefaultNameServerSSHUser,
                              DNSClient         = dnsClient,
                              Credentials       = DNSSSHClientKey is ISshHostKey key ? [ key ] : [],
                              VerifyHostKey     = blob => SSH.Believes(blob, SSHHostOf(Server), TimeProvider.GetUtcNow(), out _, out _) ||
                                                          SSH.OnMismatch != PinMismatch.Refuse,
                              RequireStrictKex  = true,
                              ConnectTimeout    = NameServerSSHConnectTimeout
                          };

            return Server.IPAddress is IIPAddress address
                       ? DNSServerConfig.OverSSH(address,            options, Server.Port, Server.QueryTimeout)
                       : DNSServerConfig.OverSSH(Server.DomainName!, options, Server.Port, Server.QueryTimeout);

        }

        #endregion

    }

}
