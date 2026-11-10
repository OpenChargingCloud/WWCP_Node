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
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a host key a time server showed over SSH came to: the key it showed,
    /// whether it was one the server is held to, and whether it was taken.
    /// </summary>
    /// <param name="At">When it was shown.</param>
    /// <param name="Shown">The SHA-256 fingerprint of the key, "SHA256:...".</param>
    /// <param name="Matched">Whether it is a pinned key, or certified by one of the server's CAs.</param>
    /// <param name="Accepted">Whether the connection went on: matched, or a mismatch to be recorded or accepted.</param>
    /// <param name="Why">What it was believed by, or why not.</param>
    public sealed record TimeServerHostKeyJudgement(DateTimeOffset  At,
                                                    String          Shown,
                                                    Boolean         Matched,
                                                    Boolean         Accepted,
                                                    String          Why)
    {

        /// <summary>
        /// As the NTS page and the OCPP Device Model read it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("at",        At.ToString("o")),
                   new JProperty("hostKey",   Shown),
                   new JProperty("matched",   Matched),
                   new JProperty("accepted",  Accepted),
                   new JProperty("why",       Why)
               );

    }


    /// <summary>
    /// Time servers whose key exchange goes over SSH - the subsystem
    /// "ntske/1@open.charging.cloud" of the white paper "NTS Key Establishment
    /// over SSH" - instead of TLS: NTSv4SSH in the OCPP Device Model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By the rule of every other setting of a time server: the first entry
    /// naming a host across every group decides, and the key exchanges of a host
    /// are one, whichever group asks it.
    /// </para>
    /// <para>
    /// The node signs in with a key of its own, made at its first need and kept
    /// beside its SSH host key - never the host key itself, which is what its
    /// own SSH server is known by. Whoever runs the time server enters the
    /// public half into its authorized_keys, or has it certified by an SSH CA:
    /// a CSMS reads it as SSHClientPublicKey.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What the file of the key this node signs in with at the SSH servers
        /// of its time servers is called, beside its SSH host key.
        /// </summary>
        public const String  NTSKEClientKeyFileName  = "ntske_client_ed25519_key";

        /// <summary>
        /// How long the SSH connection of a key exchange may take to be had.
        /// </summary>
        public static readonly TimeSpan  TimeServerSSHConnectTimeout  = TimeSpan.FromSeconds(10);

        private readonly Object                                                      ntskeClientKeyLock    = new ();
        private          ISshHostKey?                                                ntskeClientKey;
        private          String?                                                     ntskeClientKeyProblem;
        private readonly ConcurrentDictionary<DomainName, TimeServerHostKeyJudgement> hostKeyJudgements     = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Where the key this node signs in with at its time servers' SSH servers
        /// is kept: beside its SSH host key.
        /// </summary>
        public String  NTSKEClientKeyPath
            => Beside(ConfigFile.Path, Path.Combine(DefaultSSHDirectory, NTSKEClientKeyFileName));

        /// <summary>
        /// The public key this node signs in with at the SSH servers of its time
        /// servers, as a line of an authorized_keys file - made now where there
        /// is none yet; null where it can be neither read nor made, which the
        /// log says why.
        /// </summary>
        /// <remarks>
        /// SSHClientPublicKey of section 7 of the white paper "NTS Key
        /// Establishment over SSH": a CSMS reads it before it switches a server
        /// to NTSv4SSH, and enters it at that server.
        /// </remarks>
        public String? NTSKEClientPublicKey

            => NTSKEClientKey is ISshHostKey key
                   ? SshPublicKey.FromHostKey(key, $"{Kind.Tag}-ntske@{Environment.MachineName}").ToAuthorizedKeyLine()
                   : null;

        /// <summary>
        /// The key this node signs in with at the SSH servers of its time
        /// servers: read from its file, or made and written there at the first
        /// need; null where neither can be done.
        /// </summary>
        private ISshHostKey? NTSKEClientKey
        {
            get
            {

                lock (ntskeClientKeyLock)
                {

                    if (ntskeClientKey is not null)
                        return ntskeClientKey;

                    var path = NTSKEClientKeyPath;

                    try
                    {

                        // A private key: whoever can read it can sign in as this node.
                        OwnerOnly.Directory(Path.GetDirectoryName(path)!, problem => Log.Warning(problem, Kind.Tag, "nts", "ssh", "security"));

                        if (File.Exists(path))
                            ntskeClientKey = SshKeyGenerator.LoadPrivateKey(File.ReadAllText(path)).Key;

                        else
                        {

                            var key = SshHostKey.GenerateEd25519();

                            SshKeyGenerator.WriteKeyPairAsync(key, path, Comment: $"{Kind.Tag}-ntske@{Environment.MachineName}").GetAwaiter().GetResult();

                            Log.Metrological(LogLevel.Notice,
                                             $"A key was made for this {Kind.Name} to sign in with at the SSH servers of its time servers: " +
                                             $"{key.AlgorithmNames[0]} {SshFingerprint.Sha256(key.PublicKeyBlob)}, kept in '{path}'.",
                                             Kind.Tag, "nts", "ssh", "security");

                            ntskeClientKey = key;

                        }

                        ntskeClientKeyProblem = null;

                    }
                    catch (Exception problem)
                    {

                        var said = $"The key this {Kind.Name} signs in with at the SSH servers of its time servers could not be had from '{path}': {problem.Message}";

                        if (said != ntskeClientKeyProblem)
                            Log.Error(said, Kind.Tag, "nts", "ssh", "security");

                        ntskeClientKeyProblem = said;

                    }

                    return ntskeClientKey;

                }

            }
        }

        #endregion


        #region TimeServersOverSSH() / SSHOf(Hostname)

        /// <summary>
        /// The time servers whose key exchange goes over SSH, each as the first
        /// entry naming it across every group says.
        /// </summary>
        private Dictionary<DomainName, NTSServerSSH> TimeServersOverSSH()
        {

            var overSSH = new Dictionary<DomainName, NTSServerSSH>();
            var named   = new HashSet<DomainName>();

            foreach (var server in ntsGroups.SelectMany(group => group.Settings?.Servers ?? []))
            {

                // The first entry decides, also where it says TLS.
                if (!named.Add(server.Hostname))
                    continue;

                if (server.SSH is NTSServerSSH ssh)
                    overSSH[server.Hostname] = ssh;

            }

            return overSSH;

        }

        /// <summary>
        /// How the key exchange with the given time server goes over SSH, or null
        /// where it goes over TLS.
        /// </summary>
        public NTSServerSSH? SSHOf(DomainName Hostname)

            => TimeServersOverSSH().TryGetValue(Hostname, out var ssh)
                   ? ssh
                   : null;

        #endregion

        #region HostKeyJudgementOf(Hostname)

        /// <summary>
        /// What the host key the given time server showed last came to, or null
        /// where it showed none yet.
        /// </summary>
        public TimeServerHostKeyJudgement? HostKeyJudgementOf(DomainName Hostname)

            => hostKeyJudgements.TryGetValue(Hostname, out var judgement)
                   ? judgement
                   : null;

        #endregion

        #region (private) PutSSH()

        /// <summary>
        /// Give each time server whose key exchange goes over SSH the connection
        /// it is made on, on the servers of every group; and every other one
        /// none.
        /// </summary>
        private void PutSSH()
        {

            var overSSH = TimeServersOverSSH();

            foreach (var source in ntsGroups.SelectMany(group => group.Sources.Sources))
            {

                var hostname = source.Hostname;

                source.ConnectOverSSH = overSSH.TryGetValue(hostname, out var ssh)
                                            ? cancellationToken => ConnectToTimeServerOverSSH(hostname, ssh, cancellationToken)
                                            : null;

            }

        }

        #endregion

        #region (private) SSHChanges(Was)

        /// <summary>
        /// What changed about how the time servers' key exchanges go over SSH
        /// since the given state, as the log line says it - and each server
        /// whose way changed lets go of its key exchange and of what its host
        /// key came to.
        /// </summary>
        /// <param name="Was">The servers over SSH before, by <see cref="TimeServersOverSSH"/>.</param>
        private IEnumerable<String> SSHChanges(Dictionary<DomainName, NTSServerSSH> Was)
        {

            var now      = TimeServersOverSSH();
            var changes  = new List<String>();

            foreach (var server in Was.Keys.Union(now.Keys).ToArray())
            {

                var before = Was.TryGetValue(server, out var wasSSH) ? wasSSH.ToJSON().ToString(Newtonsoft.Json.Formatting.None) : null;
                var after  = now.TryGetValue(server, out var nowSSH) ? nowSSH.ToJSON().ToString(Newtonsoft.Json.Formatting.None) : null;

                if (before == after)
                    continue;

                timeEngine.ForgetKeyExchange(server);
                hostKeyJudgements.TryRemove(server, out _);

                changes.Add(nowSSH is not null
                                ? $"{server.Trimmed}'s key exchange over {nowSSH.TextFor(server.Trimmed)}"
                                : $"{server.Trimmed}'s key exchange over TLS");

            }

            return changes;

        }

        #endregion

        #region (private) ConnectToTimeServerOverSSH(Hostname, SSH, CancellationToken)

        /// <summary>
        /// An SSH connection to the given time server for a key exchange: its
        /// host key judged, and this node signed in with its own key.
        /// </summary>
        private async ValueTask<SshClient> ConnectToTimeServerOverSSH(DomainName         Hostname,
                                                                      NTSServerSSH       SSH,
                                                                      CancellationToken  CancellationToken)
        {

            var key = NTSKEClientKey
                          ?? throw new InvalidOperationException(ntskeClientKeyProblem ?? $"This {Kind.Name} has no key to sign in with.");

            return await SshClient.ConnectAsync(
                             Hostname.Trimmed,
                             SSH.PortOrDefault,
                             new SshClientOptions {
                                 Username        = SSH.UserOrDefault,
                                 DNSClient       = dnsClient,
                                 Credentials     = [ key ],
                                 VerifyHostKey   = blob => JudgeTimeServerHostKey(Hostname, SSH, blob),
                                 ConnectTimeout  = TimeServerSSHConnectTimeout
                             },
                             CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion

        #region (private) JudgeTimeServerHostKey(Hostname, SSH, HostKeyBlob)

        /// <summary>
        /// Whether the connection to a time server goes on with the host key it
        /// showed: one it is held to, or a mismatch its entry records or accepts.
        /// </summary>
        /// <remarks>
        /// A mismatch is said once, when it is new - a key exchange that is
        /// refused is tried again at every round, and the log would say the same
        /// thing every time. Recorded, it goes into the metrological log as well,
        /// as a certificate's would.
        /// </remarks>
        private Boolean JudgeTimeServerHostKey(DomainName    Hostname,
                                               NTSServerSSH  SSH,
                                               Byte[]        HostKeyBlob)
        {

            var matched   = SSH.Believes(HostKeyBlob, Hostname.Trimmed, TimeProvider.GetUtcNow(), out var shown, out var why);
            var accepted  = matched || SSH.OnMismatch != PinMismatch.Refuse;
            var judgement = new TimeServerHostKeyJudgement(TimeProvider.GetUtcNow(), shown, matched, accepted, why);

            var before    = HostKeyJudgementOf(Hostname);

            hostKeyJudgements[Hostname] = judgement;

            if (!matched && (before is null || before.Matched || before.Shown != shown))
            {

                var said = $"The time server {Hostname.Trimmed} showed the SSH host key {shown} at its key exchange over SSH, but {why}: " +
                           (SSH.OnMismatch switch {
                                PinMismatch.Record  => "used, and recorded.",
                                PinMismatch.Accept  => "used, as its entry says.",
                                _                   => "refused."
                            });

                if (SSH.OnMismatch == PinMismatch.Record)
                    Log.Metrological(LogLevel.Warning, said, Kind.Tag, "nts", "ssh", "security");
                else
                    Log.Warning(said, Kind.Tag, "nts", "ssh", "security");

            }

            return accepted;

        }

        #endregion

    }

}
