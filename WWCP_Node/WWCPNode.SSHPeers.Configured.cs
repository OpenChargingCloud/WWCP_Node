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
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The SSH peers the configuration file names under "ssh.peers": hosts the
    /// node keeps one SSH connection to without anything of OCPP - for the time
    /// and the names of a node that speaks OCPP over a WebSocket, or none at
    /// all. SSHPeerController in the OCPP Device Model.
    /// </summary>
    /// <remarks>
    /// The node signs in at them with a key of its own, made at its first need
    /// and kept beside its SSH host key - unless its kind has a key it is known
    /// by already, as a charging station has - and believes them by the host
    /// keys and CAs their entries hold them to.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What the file of the key this node signs in with at its SSH peers is
        /// called, beside its SSH host key.
        /// </summary>
        public const String  SSHPeerClientKeyFileName  = "peer_client_ed25519_key";

        /// <summary>
        /// How long the SSH connection to a peer may take to be had.
        /// </summary>
        public static readonly TimeSpan  SSHPeerConnectTimeout  = TimeSpan.FromSeconds(10);

        private readonly Object                                                    configuredSSHPeersLock  = new ();
        private readonly Dictionary<String, (SSHPeerConfiguration Entry, SSHPeer Peer)>  configuredSSHPeers  = new (StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<String, TimeServerHostKeyJudgement>  sshPeerJudgements       = new (StringComparer.OrdinalIgnoreCase);

        private readonly Object       sshPeerClientKeyLock  = new ();
        private          ISshHostKey? sshPeerClientKey;
        private          String?      sshPeerClientKeyProblem;

        #endregion

        #region Properties

        /// <summary>
        /// The SSH peers the configuration file names, as it names them and in
        /// its order - also one that is not used, because its host is a peer
        /// by a connection the node dials already.
        /// </summary>
        public IReadOnlyList<SSHPeerConfiguration> ConfiguredSSHPeers
            => sshFile?.Peers ?? [];

        /// <summary>
        /// Where the key this node signs in with at its SSH peers is kept: beside
        /// its SSH host key.
        /// </summary>
        public String  SSHPeerClientKeyPath
            => Beside(ConfigFile.Path, Path.Combine(DefaultSSHDirectory, SSHPeerClientKeyFileName));

        /// <summary>
        /// The user name this node signs in under at an SSH peer whose entry
        /// names none.
        /// </summary>
        protected virtual String DefaultSSHPeerUser
            => Kind.Tag;

        /// <summary>
        /// The key this node signs in with at its SSH peers: its own, read from
        /// its file or made and written there at the first need; null where
        /// neither can be done. A kind that is known by a key already - a
        /// charging station - signs in with that one.
        /// </summary>
        protected virtual ISshHostKey? SSHPeerClientKey
        {
            get
            {

                lock (sshPeerClientKeyLock)
                {

                    if (sshPeerClientKey is not null)
                        return sshPeerClientKey;

                    var path = SSHPeerClientKeyPath;

                    try
                    {

                        // A private key: whoever can read it can sign in as this node.
                        OwnerOnly.Directory(Path.GetDirectoryName(path)!, problem => Log.Warning(problem, Kind.Tag, "ssh", "peers", "security"));

                        if (File.Exists(path))
                            sshPeerClientKey = SshKeyGenerator.LoadPrivateKey(File.ReadAllText(path)).Key;

                        else
                        {

                            var key = SshHostKey.GenerateEd25519();

                            SshKeyGenerator.WriteKeyPairAsync(key, path, Comment: $"{Kind.Tag}@{Environment.MachineName}").GetAwaiter().GetResult();

                            Log.Notice($"A key was made for this {Kind.Name} to sign in with at its SSH peers: " +
                                       $"{key.AlgorithmNames[0]} {SshFingerprint.Sha256(key.PublicKeyBlob)}, kept in '{path}'.",
                                       Kind.Tag, "ssh", "peers", "security");

                            sshPeerClientKey = key;

                        }

                        sshPeerClientKeyProblem = null;

                    }
                    catch (Exception problem)
                    {

                        var said = $"The key this {Kind.Name} signs in with at its SSH peers could not be had from '{path}': {problem.Message}";

                        if (said != sshPeerClientKeyProblem)
                            Log.Error(said, Kind.Tag, "ssh", "peers", "security");

                        sshPeerClientKeyProblem = said;

                    }

                    return sshPeerClientKey;

                }

            }
        }

        /// <summary>
        /// The public key this node signs in with at its SSH peers, as a line of
        /// an authorized_keys file - made now where there is none yet; null
        /// where it can be neither read nor made.
        /// </summary>
        public virtual String? SSHPeerClientPublicKey

            => SSHPeerClientKey is ISshHostKey key
                   ? SshPublicKey.FromHostKey(key, $"{Kind.Tag}@{Environment.MachineName}").ToAuthorizedKeyLine()
                   : null;

        #endregion


        #region Events

        /// <summary>
        /// The SSH peers of the configuration changed: one was added, changed
        /// or taken out. Told once the node let go of its configuration, so
        /// that what is read then is what was saved.
        /// </summary>
        public event Action? OnSSHPeersChanged;

        #endregion

        #region SSHPeerHostKeyJudgementOf(Id)

        /// <summary>
        /// What the host key the given configured SSH peer showed last came to,
        /// or null where it showed none yet.
        /// </summary>
        public TimeServerHostKeyJudgement? SSHPeerHostKeyJudgementOf(String Id)

            => sshPeerJudgements.TryGetValue(Id, out var judgement)
                   ? judgement
                   : null;

        #endregion

        #region (private) ApplyConfiguredSSHPeers(Peers)

        /// <summary>
        /// Make the SSH peers of the node what the configuration says: one that
        /// is new becomes a peer, with a connection that is dialled when
        /// something first needs it; one that changed or is named no more is a
        /// peer no longer, and its connection is closed - for everything that
        /// shared it, which has the next one made by what the entry says now.
        /// </summary>
        /// <returns>Whether a peer was added, changed or taken out.</returns>
        private Boolean ApplyConfiguredSSHPeers(IReadOnlyList<SSHPeerConfiguration>? Peers)
        {

            var gone     = new List<SSHPeer>();
            var changed  = false;

            lock (configuredSSHPeersLock)
            {

                var said = (Peers ?? []).ToDictionary(peer => peer.Id, StringComparer.OrdinalIgnoreCase);

                foreach (var (name, configured) in configuredSSHPeers.ToArray())
                {

                    if (said.TryGetValue(name, out var now) &&
                        now.ToJSON().ToString(Newtonsoft.Json.Formatting.None) == configured.Entry.ToJSON().ToString(Newtonsoft.Json.Formatting.None))
                    {
                        continue;
                    }

                    changed = true;
                    configuredSSHPeers.Remove(name);
                    sshPeerJudgements.TryRemove(name, out _);
                    RemoveSSHPeer(configured.Peer);
                    gone.Add(configured.Peer);

                }

                foreach (var entry in said.Values)
                {

                    if (configuredSSHPeers.ContainsKey(entry.Id))
                        continue;

                    // Somebody else's peer already: a charging station's, for an
                    // "ssh://" connection of OCPP it dials there.
                    if (SSHPeerTo(entry.Address) is not null)
                    {
                        Log.Warning($"The SSH peer '{entry.Id}' of the configuration is not used: {entry.Address.Trimmed} is an SSH peer of this {Kind.Name} already, " +
                                    "by a connection it dials there.",
                                    Kind.Tag, "ssh", "peers");
                        continue;
                    }

                    var peer = new SSHPeer(
                                   entry.Address,
                                   entry.Port,
                                   new SshSharedConnection(cancellationToken => ConnectToSSHPeer(entry, cancellationToken)),
                                   PublicKey: () => SSHPeerClientPublicKey
                               );

                    AddSSHPeer(peer);

                    changed = true;
                    configuredSSHPeers[entry.Id] = (entry, peer);

                }

            }

            foreach (var peer in gone)
                _ = Task.Run(async () => {
                        try   { await peer.Connection.DisposeAsync(); }
                        catch { }
                    });

            return changed;

        }

        #endregion

        #region (private) CloseConfiguredSSHPeers()

        /// <summary>
        /// Close the connections to the configured SSH peers: the node stops.
        /// </summary>
        private async Task CloseConfiguredSSHPeers()
        {

            SSHPeer[] peers;

            lock (configuredSSHPeersLock)
            {

                peers = [.. configuredSSHPeers.Values.Select(configured => configured.Peer)];

                configuredSSHPeers.Clear();

            }

            foreach (var peer in peers)
            {

                RemoveSSHPeer(peer);

                try   { await peer.Connection.DisposeAsync(); }
                catch { }

            }

        }

        #endregion

        #region (private) ConnectToSSHPeer(Entry, CancellationToken)

        /// <summary>
        /// An SSH connection to the given configured peer: its host key judged,
        /// and this node signed in with its key.
        /// </summary>
        private async ValueTask<SshClient> ConnectToSSHPeer(SSHPeerConfiguration  Entry,
                                                            CancellationToken     CancellationToken)
        {

            var key = SSHPeerClientKey
                          ?? throw new InvalidOperationException(sshPeerClientKeyProblem ?? $"This {Kind.Name} has no key to sign in with at its SSH peers.");

            return await SshClient.ConnectAsync(
                             Entry.Address.Trimmed,
                             Entry.Port,
                             new SshClientOptions {
                                 Username          = Entry.User ?? DefaultSSHPeerUser,
                                 DNSClient         = dnsClient,
                                 Credentials       = [ key ],
                                 VerifyHostKey     = blob => JudgeSSHPeerHostKey(Entry, blob),
                                 RequireStrictKex  = true,
                                 ConnectTimeout    = SSHPeerConnectTimeout
                             },
                             CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion

        #region (private) JudgeSSHPeerHostKey(Entry, HostKeyBlob)

        /// <summary>
        /// Whether the connection to a configured SSH peer goes on with the host
        /// key it showed: one it is held to, or a mismatch its entry records or
        /// accepts. A mismatch is said once, when it is new.
        /// </summary>
        private Boolean JudgeSSHPeerHostKey(SSHPeerConfiguration  Entry,
                                            Byte[]                HostKeyBlob)
        {

            var matched   = Entry.Trust.Believes(HostKeyBlob, Entry.Address.Trimmed, TimeProvider.GetUtcNow(), out var shown, out var why);
            var accepted  = matched || Entry.Trust.OnMismatch != PinMismatch.Refuse;
            var judgement = new TimeServerHostKeyJudgement(TimeProvider.GetUtcNow(), shown, matched, accepted, why);

            var before    = SSHPeerHostKeyJudgementOf(Entry.Id);

            sshPeerJudgements[Entry.Id] = judgement;

            if (!matched && (before is null || before.Matched || before.Shown != shown))
            {

                var said = $"The SSH peer '{Entry.Id}' ({Entry.Address.Trimmed}) showed the SSH host key {shown}, but {why}: " +
                           (Entry.Trust.OnMismatch switch {
                                PinMismatch.Record  => "used, and recorded.",
                                PinMismatch.Accept  => "used, as its entry says.",
                                _                   => "refused."
                            });

                if (Entry.Trust.OnMismatch == PinMismatch.Record)
                    Log.Metrological(LogLevel.Warning, said, Kind.Tag, "ssh", "peers", "security");
                else
                    Log.Warning(said, Kind.Tag, "ssh", "peers", "security");

            }

            return accepted;

        }

        #endregion

        #region SSHPeersJSON()

        /// <summary>
        /// The configured SSH peers with what is known of each: its entry, the
        /// key the node signs in with, whether its connection lasts, and what
        /// the host key it showed last came to.
        /// </summary>
        public JArray SSHPeersJSON()
        {

            lock (configuredSSHPeersLock)
                return new JArray(
                           configuredSSHPeers.Values.Select(configured => {

                               var json = configured.Entry.ToJSON();

                               json["connected"]         = configured.Peer.Connection.Current is not null;
                               json["port"]              = configured.Entry.Port;
                               json["hostKeyJudgement"]  = SSHPeerHostKeyJudgementOf(configured.Entry.Id)?.ToJSON();

                               return json;

                           })
                       );

        }

        #endregion

    }

}
