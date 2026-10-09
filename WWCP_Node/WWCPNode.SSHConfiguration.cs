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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a change of the SSH server's settings came to: done, or refused
    /// and why - where the configuration file could not be written, or the
    /// port asked for is taken - and what is worth saying beside it.
    /// </summary>
    /// <param name="IsChanged">Whether the change was saved and made.</param>
    /// <param name="Error">Why nothing was changed.</param>
    /// <param name="NotSaved">Whether the configuration file could not be read or written: nothing about the change was wrong.</param>
    /// <param name="PortTaken">Whether the port asked for is taken: the server goes on where it was.</param>
    /// <param name="Notice">What is worth saying of a change made: a switch on the command line that wins over what was saved.</param>
    public sealed record SSHConfigurationChange(Boolean  IsChanged,
                                                String?  Error      = null,
                                                Boolean  NotSaved   = false,
                                                Boolean  PortTaken  = false,
                                                String?  Notice     = null);


    /// <summary>
    /// The SSH server as its page shows it, and its settings changed from
    /// there.
    /// </summary>
    public partial class WWCPNode
    {

        #region SSHConfigurationJSON(Host = null)

        /// <summary>
        /// The SSH server as its page shows it: whether it runs, where, and
        /// whether passwords open it - and what the file and the command line
        /// say of that; what it allows; its host key, as a client compares it
        /// and as a known_hosts file takes it; what it offers to encrypt with;
        /// who is connected, and with which keys every account may sign in.
        /// </summary>
        /// <param name="Host">The name the node was reached by, for the known_hosts line; the address it listens on where none is given.</param>
        public JObject SSHConfigurationJSON(String? Host = null)
        {

            var hostKey  = SSHHostKeyAsKept();
            var limits   = SSHServerLimits();

            return new JObject(

                       new JProperty("enabled",        SSHEnabled),
                       new JProperty("port",           SSHPort?.ToUInt16()),
                       new JProperty("passwords",      SSHPasswords),
                       new JProperty("listenAddress",  listenAddress.ToString()),
                       new JProperty("url",            SSHURL),
                       new JProperty("defaultPort",    SSHSettings.DefaultPortFor(sshWebInterfacePort)?.ToUInt16()),
                       new JProperty("file",           ConfigFile.Path),

                       // What the file says, and what a switch said, which wins
                       // over it: --no-ssh, or a port given with --ssh-port.
                       new JProperty("configured",     sshFile?.ToJSON() ?? new JObject()),
                       new JProperty("commandLine",    new JObject(
                                                           sshSettings?.Enabled is Boolean on ? [ new JProperty("enabled", on) ]                  : Array.Empty<JProperty>(),
                                                           sshSettings?.Port    is IPPort  at ? [ new JProperty("port",    at.ToUInt16()) ]       : Array.Empty<JProperty>()
                                                       )),

                       new JProperty("limits",         new JObject(
                                                           new JProperty("loginGraceTime",                (Int32) limits.LoginGraceTime.TotalSeconds),
                                                           new JProperty("maxAuthTries",                  limits.MaxAuthTries),
                                                           new JProperty("maxSessions",                   limits.MaxSessions),
                                                           new JProperty("maxConnections",                limits.MaxConnections),
                                                           new JProperty("maxUnauthenticated",            limits.MaxUnauthenticated),
                                                           new JProperty("maxUnauthenticatedPerAddress",  limits.MaxUnauthenticatedPerAddress),
                                                           new JProperty("clientAliveInterval",           limits.ClientAliveInterval is TimeSpan every ? (Int32?) every.TotalSeconds : null),
                                                           new JProperty("clientAliveCountMax",           limits.ClientAliveCountMax)
                                                       )),

                       new JProperty("hostKeys",       new JArray(
                                                           hostKey is null ? [] : new[] { HostKeyJSON(hostKey.Value.Key, hostKey.Value.Comment, Host) }
                                                       )),

                       // What the server offers, in the order it prefers them: the
                       // server's own lists, which no node changes, and the one
                       // host key there is.
                       new JProperty("algorithms",     new JObject(
                                                           new JProperty("keyExchange",  new JArray(KexInitMessage.DefaultKeyExchanges)),
                                                           new JProperty("hostKey",      new JArray(hostKey?.Key.AlgorithmNames ?? [])),
                                                           new JProperty("cipher",       new JArray(KexInitMessage.DefaultCiphers)),
                                                           new JProperty("mac",          new JArray(KexInitMessage.DefaultMacs)),
                                                           new JProperty("compression",  new JArray("none"))
                                                       )),

                       new JProperty("connections",    SSHConnections),
                       new JProperty("sessions",       new JArray(
                                                           CommandLineSessions.Select(session => new JObject(
                                                               new JProperty("id",       session.Id),
                                                               new JProperty("account",  session.Account),
                                                               new JProperty("from",     session.From),
                                                               new JProperty("key",      session.Key),
                                                               new JProperty("since",    session.Since.ToString("o"))
                                                           ))
                                                       )),

                       // Every account, with the keys it may sign in with - public
                       // halves alone, which say nothing a client does not show
                       // every server it connects to.
                       new JProperty("accounts",       new JArray(
                                                           ExtAPI.Users.
                                                               OrderBy(user => user.Id.ToString(), StringComparer.Ordinal).
                                                               Select (user => new JObject(
                                                                   new JProperty("account",  user.Id.ToString()),
                                                                   new JProperty("keys",     new JArray(
                                                                       ExtAPI.GetSSHKeys(user.Id).Select(key => new JObject(
                                                                           new JProperty("fingerprint",  key.Fingerprint),
                                                                           new JProperty("algorithm",    key.Key.PublicKey.Algorithm),
                                                                           new JProperty("comment",      key.Key.PublicKey.Comment),
                                                                           new JProperty("label",        key.Label),
                                                                           new JProperty("created",      key.Created.ToString("o")),
                                                                           new JProperty("createdBy",    key.CreatedBy),
                                                                           new JProperty("isDisabled",   key.IsDisabled)
                                                                       ))
                                                                   ))
                                                               ))
                                                       ))

                   );

        }

        #endregion

        #region (private) SSHHostKeyAsKept()

        /// <summary>
        /// The host key in its file, with its comment - or null where there is
        /// none yet, or it cannot be read. Read, never made: a page looked at
        /// before SSH ever ran makes no identity for this node.
        /// </summary>
        private (ISshHostKey Key, String Comment)? SSHHostKeyAsKept()
        {

            try
            {

                if (!File.Exists(SSHHostKeyPath))
                    return null;

                var loaded = SshKeyGenerator.LoadPrivateKey(File.ReadAllText(SSHHostKeyPath));

                return (loaded.Key, loaded.Comment);

            }
            catch (Exception)
            {
                return null;
            }

        }

        #endregion

        #region (private) HostKeyJSON(Key, Comment, Host)

        /// <summary>
        /// A host key as a client compares it - its type and SHA-256 fingerprint
        /// - and as an authorized_keys and a known_hosts file take it.
        /// </summary>
        private JObject HostKeyJSON(ISshHostKey  Key,
                                    String       Comment,
                                    String?      Host)
        {

            var publicKey  = SshPublicKey.FromHostKey(Key, Comment).ToAuthorizedKeyLine();
            var typeAndKey = String.Join(' ', publicKey.Split(' ', 3).Take(2));
            var host       = Host is { Length: > 0 } ? Host : listenAddress.ToString();
            var name       = SSHPort is IPPort port && port.ToUInt16() != 22
                                 ? $"[{host.Trim('[', ']')}]:{port}"
                                 : host;

            return new JObject(
                       new JProperty("algorithm",    Key.AlgorithmNames[0]),
                       new JProperty("fingerprint",  SshFingerprint.Sha256(Key.PublicKeyBlob)),
                       new JProperty("publicKey",    publicKey),
                       new JProperty("file",         SSHHostKeyPath),
                       new JProperty("knownHosts",   $"{name} {typeAndKey}")
                   );

        }

        #endregion

        #region TryUpdateSSHConfiguration(JSON)

        /// <summary>
        /// Change whether the SSH server runs, on which port, and whether
        /// passwords open it: saved in the "ssh" section of the configuration
        /// file, and made at once.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A new port is bound before anything else changes: where it is
        /// taken, nothing is saved and the server goes on where it was. Moved,
        /// switched off or told otherwise of passwords, the server that ran
        /// says goodbye to its sessions and stops - a session typed at over SSH
        /// ends, which the page says before it is sent.
        /// </para>
        /// <para>
        /// A switch on the command line wins over the file, as it does at a
        /// start: what was sent is saved all the same, for the next start
        /// without that switch, and that is said.
        /// </para>
        /// </remarks>
        /// <param name="JSON">What the page sent, in the shape of the "ssh" section.</param>
        public async Task<SSHConfigurationChange> TryUpdateSSHConfiguration(JObject JSON)
        {

            if (!SSHConfiguration.TryParse(JSON, out var sent, out var error))
                return new SSHConfigurationChange(false, error);

            await reconfigureLock.WaitAsync();

            try
            {

                var file   = new SSHConfiguration(sent.Enabled   ?? sshFile?.Enabled,
                                                  sent.Port      ?? sshFile?.Port,
                                                  sent.Passwords ?? sshFile?.Passwords);

                var after  = EffectiveSSH(sshSettings, file, sshWebInterfacePort);

                if (after.Enabled && after.Port is null)
                    return new SSHConfigurationChange(false, $"The web interface's port {sshWebInterfacePort} plus {SSHSettings.DefaultPortOffset} is no port: give the SSH server one.");

                var restart  = (SSHEnabled, SSHPort, SSHPasswords) != after;
                var rebind   = restart && after.Enabled && SSHEnabled && sshServer is not null && after.Port == SSHPort;
                var started  = default(SshServer);

                // Bound first, so that a port that is taken costs nothing.
                if (restart && after.Enabled && !rebind)
                {
                    try
                    {
                        started = await StartedSSHServer(after.Port!.Value, after.Passwords);
                    }
                    catch (PortUnavailableException)
                    {
                        return new SSHConfigurationChange(false,
                                                          $"Port {after.Port} is taken on this machine. " +
                                                          (SSHEnabled && SSHPort is IPPort was
                                                               ? $"The SSH server goes on on port {was}, and nothing was saved."
                                                               : "Nothing was saved."),
                                                          PortTaken: true);
                    }
                }

                if (!ConfigFile.TryMergeSection(SSHConfiguration.SectionName, file.ToJSON(), out error))
                {

                    if (started is not null)
                        await started.DisposeAsync();

                    return new SSHConfigurationChange(false, error, NotSaved: true);

                }

                sshFile = file;

                if (restart)
                {

                    var running = Interlocked.Exchange(ref sshServer, null);

                    if (running is not null)
                        await running.DisposeAsync();

                    (SSHEnabled, SSHPort, SSHPasswords) = after;

                    // On the port it had, it is bound once the old one let go.
                    if (rebind)
                    {
                        try
                        {
                            started = await StartedSSHServer(after.Port!.Value, after.Passwords);
                        }
                        catch (PortUnavailableException problem)
                        {

                            SSHEnabled = false;

                            Log.Error($"The SSH server could not start again on port {after.Port}: {problem.Message}", "ssh");

                            return new SSHConfigurationChange(true, Notice: $"Saved, but the SSH server could not start again on port {after.Port}: {problem.Message}");

                        }
                    }

                    sshServer = started;

                    Log.Notice(SSHEnabled
                                   ? $"The command line is served over SSH on {SSHURL} from now on{(SSHPasswords ? ", and passwords open it as well" : ", with keys alone")}."
                                   : "The command line is no longer served over SSH.",
                               "ssh");

                }

                return new SSHConfigurationChange(true, Notice: CommandLineWins(sent));

            }
            finally
            {
                reconfigureLock.Release();
            }

        }

        #endregion

        #region (private) CommandLineWins(Sent)

        /// <summary>
        /// What a switch on the command line keeps of what was sent from taking
        /// effect, as a sentence - or null where nothing.
        /// </summary>
        private String? CommandLineWins(SSHConfiguration Sent)
        {

            var said = new List<String>();

            if (sshSettings?.Enabled is Boolean on && Sent.Enabled is Boolean wanted && wanted != on)
                said.Add(on ? "the command line gave the SSH server a port, so it runs" : "the command line said --no-ssh, so it stays off");

            if (sshSettings?.Port is IPPort port && Sent.Port is IPPort asked && asked != port)
                said.Add($"the command line said --ssh-port {port}, so it stays there");

            return said.Count == 0
                       ? null
                       : $"Saved for the next start without that switch - {String.Join("; ", said)}.";

        }

        #endregion

    }

}
