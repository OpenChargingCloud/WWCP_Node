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
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The node's command line over SSH: what somebody signed in with PuTTY or
    /// ssh gets, and nothing else - no shell of the machine, no files, no
    /// tunnels.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Hermod's SSH server, on the address the web interface listens on - the
    /// loopback unless --any says every address - and on a port of its own,
    /// twenty thousand above the web interface's unless something says
    /// otherwise: the vehicle's is 22347.
    /// </para>
    /// <para>
    /// Whoever signs in is an account of the node, under its name, with one of
    /// its keys - kept with the account in the HTTPExt API, where the sshKeys
    /// command and the routes below /ext add and remove them - and may do there
    /// what its roles let it do on the web interface. A node none of whose
    /// accounts has a key yet listens, and lets nobody in. Files of keys below
    /// the accounts, where they were kept before, are taken over once - see
    /// <see cref="AuthorizedKeysStore"/>.
    /// </para>
    /// <para>
    /// The node presents itself with a host key of its own, made at the first
    /// start that serves SSH and kept beside the configuration file: what PuTTY
    /// shows the first time it connects, and what the banner says to compare
    /// it with. Losing it is not repaired by making another one quietly: a
    /// node with a new key is, to every client that knew the old one, a
    /// machine pretending to be this node.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// Where the host key is kept, beside the configuration file.
        /// </summary>
        public const String  DefaultSSHDirectory     = "ssh";

        /// <summary>
        /// What the host key's file is called.
        /// </summary>
        public const String  SSHHostKeyFileName      = "ssh_host_ed25519_key";

        /// <summary>
        /// How long somebody has to sign in once connected.
        /// </summary>
        public static readonly TimeSpan  SSHLoginGraceTime  = TimeSpan.FromSeconds(30);

        private          SshServer?    sshServer;
        private readonly IIPAddress    listenAddress;
        private readonly SSHSettings?  sshSettings;

        /// <summary>
        /// The fingerprint of the key each connection authenticated with, by
        /// connection, until the sign-in is said - the audit events name one
        /// and then the other.
        /// </summary>
        private readonly ConcurrentDictionary<String, String>  sshSignInKeys  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Whether the command line is served over SSH.
        /// </summary>
        public Boolean              SSHEnabled              { get; private set; }

        /// <summary>
        /// The port the SSH server listens on, where it does.
        /// </summary>
        public IPPort?              SSHPort                 { get; private set; }

        /// <summary>
        /// Whether an account's password opens it as well as its keys.
        /// </summary>
        public Boolean              SSHPasswords            { get; private set; }

        /// <summary>
        /// Where the host key is kept: beside the configuration file.
        /// </summary>
        public String               SSHHostKeyPath
            => Beside(ConfigFile.Path, Path.Combine(DefaultSSHDirectory, SSHHostKeyFileName));

        /// <summary>
        /// The host key's type and SHA-256 fingerprint - "ssh-ed25519
        /// SHA256:..." - as PuTTY shows them the first time; null until the SSH
        /// server has started.
        /// </summary>
        public String?              SSHHostKey              { get; private set; }

        /// <summary>
        /// Where the files of keys were, one per account, before the keys were
        /// kept with the accounts: taken over once, and renamed, at a start.
        /// </summary>
        public String               SSHKeyFilesPath
            => Path.Combine(AccountsPath, AuthorizedKeysStore.DefaultDirectoryName);

        /// <summary>
        /// The SSH key made up for the first account at a first start, its
        /// private key to be shown once, as the password is - or null: when
        /// accounts were there already, when SSH is off, and when the command
        /// line brought a key for that account, which is the way recommended
        /// for a first start.
        /// </summary>
        /// <remarks>
        /// Set by <see cref="Start"/>, as <see cref="GeneratedPassword"/> is.
        /// </remarks>
        public GeneratedSSHKey?     GeneratedSSHKey         { get; private set; }

        /// <summary>
        /// Where the SSH server is reached, "ssh://127.0.0.1:22347"; null where
        /// there is none.
        /// </summary>
        public String?              SSHURL
            => SSHEnabled && SSHPort is IPPort port
                   ? $"ssh://{(listenAddress.IsIPv6 && !listenAddress.IsIPv4 ? $"[{listenAddress}]" : listenAddress.ToString())}:{port}"
                   : null;

        /// <summary>
        /// How many SSH connections are open now.
        /// </summary>
        public Int32                SSHConnections
            => sshServer?.ConnectionCount ?? 0;

        #endregion


        #region (private) ResolveSSH(Settings, File, WebInterfacePort)

        /// <summary>
        /// Whether, where and how the command line is served over SSH: a switch,
        /// then the file, then the program's default - see <see cref="SSHSettings"/>.
        /// </summary>
        private void ResolveSSH(SSHSettings?       Settings,
                                SSHConfiguration?  File,
                                IPPort             WebInterfacePort)
        {

            SSHEnabled    = Settings?.Enabled ?? File?.Enabled ?? Settings?.OnByDefault == true;
            SSHPort       = Settings?.Port    ?? File?.Port    ?? SSHSettings.DefaultPortFor(WebInterfacePort);
            SSHPasswords  = File?.Passwords   ?? false;

            if (SSHEnabled && SSHPort is null)
            {

                SSHEnabled = false;

                Log.Warning($"The command line is not served over SSH: the web interface's port {WebInterfacePort} plus {SSHSettings.DefaultPortOffset} " +
                             "is no port. Give the SSH server one with --ssh-port, or the configuration file's ssh.port.",
                            "ssh");

            }

        }

        #endregion

        #region (private) AuthorizeSSHKeys(Authorize)

        /// <summary>
        /// Let in over SSH whom the program named, with the keys in the files it
        /// named - kept with the account, with the command line as who let them
        /// in - and stop the start where an account is not this node's, or a
        /// file holds no key, rather than start with somebody locked out who was
        /// meant to be let in.
        /// </summary>
        private async Task AuthorizeSSHKeys(IReadOnlyList<(String Account, String File)>? Authorize)
        {

            foreach (var (account, file) in Authorize ?? [])
            {

                if (User_Id.TryParse(account) is not User_Id userId || !ExtAPI.TryGetUser(userId, out var user) || user is null)
                    throw new InvalidOperationException(
                              $"--authorize-ssh-key: this {Kind.Name} has no account '{account}'. Its accounts are " +
                              $"{String.Join(", ", ExtAPI.Users.Select(user => user.Id.ToString()).Order(StringComparer.Ordinal))}."
                          );

                if (!AuthorizedKeysStore.TryReadFile(file, out var text, out var refused) ||
                    !AuthorizedKeysStore.TryRead(text, out var lines, out refused))
                    throw new InvalidOperationException($"--authorize-ssh-key: {refused}");

                foreach (var line in lines)
                {

                    var added = await ExtAPI.AddSSHKey(user,
                                                       line,
                                                       Label:      $"--authorize-ssh-key {Path.GetFileName(file)}",
                                                       CreatedBy:  "the command line");

                    switch (added.Outcome)
                    {

                        case AddSSHKeyOutcome.Added:
                            Log.Notice($"The command line let '{account}' in over SSH with the key {added.SSHKey!.Fingerprint}.", "ssh", "auth", "security");
                            break;

                        case AddSSHKeyOutcome.AlreadyThere:
                            Log.Info($"'{account}' had the key {added.SSHKey!.Fingerprint} in '{file}' already.", "ssh", "auth");
                            break;

                        default:
                            throw new InvalidOperationException($"--authorize-ssh-key: '{file}': {added.Reason}");

                    }

                }

            }

        }

        #endregion

        #region (private) GiveTheFirstAccountAKey()

        /// <summary>
        /// At a first start with SSH on, and no key the command line brought for
        /// the first account: an Ed25519 key pair made up for it, its public key
        /// let in, its private key kept in memory for the banner to show once.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Without it nobody could sign in over SSH after a first start: SSH
        /// takes keys, passwords only where the configuration file says so, and
        /// the account the start made up has no key. Its password is shown once
        /// on the console, and this key is shown there too: whoever reads that
        /// console has the password already.
        /// </para>
        /// <para>
        /// The way recommended for a first start is still to bring one's own
        /// key - --authorize-ssh-key root=&lt;file.pub&gt; - so that the private key
        /// never leaves the machine it was made on and no console ever shows
        /// it. Where the command line did, no key is made up here; nor where the
        /// account had a key already - taken over from an earlier file of keys.
        /// </para>
        /// </remarks>
        private async Task GiveTheFirstAccountAKey()
        {

            if (GeneratedPassword is null || !SSHEnabled ||
                !ExtAPI.TryGetUser(User_Id.Parse(DefaultAdminUser), out var admin) || admin is null ||
                ExtAPI.GetSSHKeys(admin.Id).Count > 0)
                return;

            var key      = SshKeyGenerator.Generate("ssh-ed25519");
            var comment  = $"{DefaultAdminUser}@{Kind.Tag}-first-start";

            var added    = await ExtAPI.AddSSHKey(admin,
                                                  SshPublicKey.FromHostKey(key, comment).ToAuthorizedKeyLine(),
                                                  Label:      "made up at the first start",
                                                  CreatedBy:  "the first start");

            if (!added.IsAdded)
                throw new InvalidOperationException($"The SSH key made up for '{DefaultAdminUser}' at the first start could not be let in: {added.Reason ?? added.Outcome.ToString()}");

            GeneratedSSHKey = new GeneratedSSHKey(DefaultAdminUser, added.SSHKey!.Fingerprint, OpenSshPrivateKey.Format(key, comment));

            Log.Notice($"No SSH key was given for '{DefaultAdminUser}', so one was made up at the first start and let in: {added.SSHKey.Fingerprint}. " +
                        "Its private key is shown once, on the console, and kept nowhere.",
                       "ssh", "auth", "security");

        }

        #endregion

        #region AccountsWithSSHKeys()

        /// <summary>
        /// The accounts that have at least one SSH key, by name.
        /// </summary>
        public IReadOnlyList<String> AccountsWithSSHKeys()

            => [.. ExtAPI.Users.
                       Where (user => ExtAPI.GetSSHKeys(user.Id).Count > 0).
                       Select(user => user.Id.ToString()).
                       Order (StringComparer.Ordinal)];

        #endregion

        #region AuthorizeSSHKey(Account, Line, CreatedBy = null)

        /// <summary>
        /// Let the given account in over SSH with the key of the given
        /// authorized_keys line - kept with the account, as the sshKeys command
        /// and --authorize-ssh-key keep it.
        /// </summary>
        /// <param name="Account">The account, by name.</param>
        /// <param name="Line">One line, as an authorized_keys file holds it.</param>
        /// <param name="CreatedBy">Who lets the key in, as the database of the accounts writes it down.</param>
        public Task<AddSSHKeyResult> AuthorizeSSHKey(String   Account,
                                                     String   Line,
                                                     String?  CreatedBy = null)

            => User_Id.TryParse(Account) is User_Id userId && ExtAPI.TryGetUser(userId, out var user) && user is not null
                   ? ExtAPI.AddSSHKey(user, Line, CreatedBy: CreatedBy)
                   : Task.FromResult(new AddSSHKeyResult(AddSSHKeyOutcome.UnknownUser, null, $"This {Kind.Name} has no account '{Account}'."));

        #endregion

        #region (private) TakeOverSSHKeyFiles()

        /// <summary>
        /// The files of keys below the accounts, where the keys were kept before
        /// they were kept with their account: each line of each is added to its
        /// account - with "the take-over of ssh/&lt;account&gt;" as who
        /// let it in - a line that cannot be held to is said in the log, and the
        /// file is renamed to &lt;account&gt;.imported, after which it is never
        /// read again.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Once: a file renamed is not taken over again, and a key there already
        /// is not added twice - a start that stopped half way through a file
        /// takes the rest of it over at the next.
        /// </para>
        /// <para>
        /// A file of a name that is no account of this node is renamed too, with
        /// a warning: it let nobody in before, and it lets nobody in now.
        /// </para>
        /// </remarks>
        private async Task TakeOverSSHKeyFiles()
        {

            if (!Directory.Exists(SSHKeyFilesPath))
                return;

            foreach (var file in Directory.EnumerateFiles(SSHKeyFilesPath).Order(StringComparer.Ordinal).ToArray())
            {

                var account = Path.GetFileName(file);

                if (!AuthorizedKeysStore.IsAccountName(account) ||
                    account.EndsWith(AuthorizedKeysStore.ImportedSuffix, StringComparison.Ordinal))
                    continue;

                var from = $"{AuthorizedKeysStore.DefaultDirectoryName}/{account}";

                if (User_Id.TryParse(account) is not User_Id userId || !ExtAPI.TryGetUser(userId, out var user) || user is null)
                {

                    Log.Warning($"The file of SSH keys '{from}' names no account of this {Kind.Name}: it let nobody in, and is put aside as {account}{AuthorizedKeysStore.ImportedSuffix}.",
                                "ssh", "auth");

                }

                else
                {

                    String text;

                    try
                    {
                        text = File.ReadAllText(file);
                    }
                    catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
                    {
                        Log.Warning($"The file of SSH keys '{from}' could not be read, and is left where it is: {problem.Message}", "ssh", "auth");
                        continue;
                    }

                    var number = 0;

                    foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
                    {

                        number++;

                        var line = raw.Trim();

                        if (line.Length == 0 || line.StartsWith('#'))
                            continue;

                        var added = await ExtAPI.AddSSHKey(user,
                                                           line,
                                                           CreatedBy: $"the take-over of {from}");

                        switch (added.Outcome)
                        {

                            case AddSSHKeyOutcome.Added:
                                Log.Notice($"'{account}' keeps the SSH key {added.SSHKey!.Fingerprint} from '{from}', line {number}, with its account now.",
                                           "ssh", "auth", "security");
                                break;

                            case AddSSHKeyOutcome.AlreadyThere:
                                break;

                            default:
                                Log.Warning($"Line {number} of '{from}' is not taken over, and lets nobody in: {added.Reason}",
                                            "ssh", "auth", "security");
                                break;

                        }

                    }

                }

                try
                {

                    // Beside one put aside before, with the time in front of the
                    // suffix - which is what keeps it from being read again.
                    var aside = file + AuthorizedKeysStore.ImportedSuffix;

                    if (File.Exists(aside))
                        aside = $"{file}.{TimeProvider.GetUtcNow():yyyyMMddHHmmssfff}{AuthorizedKeysStore.ImportedSuffix}";

                    File.Move(file, aside);

                }
                catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
                {
                    Log.Warning($"'{from}' could not be put aside, and will be taken over again at the next start - which adds no key twice: {problem.Message}",
                                "ssh", "auth");
                }

            }

        }

        #endregion

        #region (private) StartSSH()

        /// <summary>
        /// Start the SSH server, with the host key of this node - made now if
        /// there is none yet.
        /// </summary>
        private async Task StartSSH()
        {

            if (!SSHEnabled || SSHPort is not IPPort port)
                return;

            var hostKey = await LoadOrCreateSSHHostKey();

            SSHHostKey  = $"{hostKey.AlgorithmNames[0]} {SshFingerprint.Sha256(hostKey.PublicKeyBlob)}";

            var server  = new SshServer(new SshServerOptions {
                              HostKeys             = [ hostKey ],
                              Authenticator        = new NodeSSHAuthenticator(this, SSHPasswords),
                              ShellHandler         = ServeShellAsync,
                              AuditSink            = new DelegateAuditSink(Audited),
                              ShutdownGracePeriod  = TimeSpan.FromSeconds(3),
                              Limits               = new SshServerLimits {
                                                         LoginGraceTime       = SSHLoginGraceTime,
                                                         MaxSessions          = 4,
                                                         ClientAliveInterval  = TimeSpan.FromSeconds(60),
                                                         ClientAliveCountMax  = 3
                                                     }
                          });

            try
            {
                await server.StartAsync(new IPSocket(listenAddress, port));
            }
            catch (SocketException problem)
            {
                await server.DisposeAsync();
                throw new PortUnavailableException(port, problem, NodePort.SSH);
            }

            sshServer = server;

            var accounts = AccountsWithSSHKeys();

            Log.Notice($"The command line is served over SSH on {SSHURL}, host key {SSHHostKey}; " +
                       (accounts.Count == 0
                            ? $"no account has a key yet, so nobody can sign in."
                            : $"{accounts.Count} account(s) can sign in with a key: {String.Join(", ", accounts)}.") +
                       (SSHPasswords ? " Passwords open it as well." : ""),
                       "ssh");

        }

        #endregion

        #region (private) StopSSH()

        /// <summary>
        /// Stop the SSH server: every session is told and given a moment to say
        /// goodbye, then its connection ends.
        /// </summary>
        private async Task StopSSH()
        {

            var server = Interlocked.Exchange(ref sshServer, null);

            if (server is not null)
                await server.DisposeAsync();

        }

        #endregion

        #region (private) LoadOrCreateSSHHostKey()

        /// <summary>
        /// The host key of this node: read where it is, made where there is none.
        /// </summary>
        /// <remarks>
        /// One that is there and cannot be read stops the start, as a
        /// configuration file that cannot be read does. Making a new one
        /// instead would be a new identity, which every client that knew the
        /// old one rightly takes for an impostor.
        /// </remarks>
        private async Task<ISshHostKey> LoadOrCreateSSHHostKey()
        {

            var path = SSHHostKeyPath;

            if (File.Exists(path))
            {
                try
                {
                    return SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(path)).Key;
                }
                catch (Exception problem)
                {
                    throw new InvalidOperationException(
                              $"The SSH host key in '{path}' could not be read: {problem.Message} " +
                              $"Repair it, or remove it for a new one - which every client that knows this {Kind.Name} will take for another machine.",
                              problem
                          );
                }
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            var key = SshHostKey.GenerateEd25519();

            await SshKeyGenerator.WriteKeyPairAsync(key, path, Comment: $"{Kind.Tag}@{Environment.MachineName}");

            Log.Metrological(LogLevel.Notice,
                             $"A host key was made for this {Kind.Name}'s SSH server: {key.AlgorithmNames[0]} {SshFingerprint.Sha256(key.PublicKeyBlob)}, " +
                             $"kept in '{path}'.",
                             Kind.Tag, "ssh", "security");

            return key;

        }

        #endregion

        #region CommandLines

        /// <summary>
        /// Makes the command line a session over SSH gets: the kind's own, with
        /// its own commands, where the program says so; the node's otherwise.
        /// </summary>
        /// <remarks>
        /// The program's to say, because the command line of a kind is the
        /// program's vocabulary and not the library's: the vehicle's
        /// "discover" is in EVCLI, not in EV. Set before the node starts.
        /// </remarks>
        public Func<ICLITerminal, CLICaller, NodeCLI>?  CommandLines  { get; set; }

        #endregion

        #region CommandLineSessions

        /// <summary>
        /// One session over SSH: who, from where, with which key, since when.
        /// </summary>
        /// <param name="Id">The session's id - its connection's.</param>
        /// <param name="Account">The account.</param>
        /// <param name="From">Where from.</param>
        /// <param name="Key">The fingerprint of the key it signed in with, if one.</param>
        /// <param name="Since">When the session began.</param>
        public sealed record CommandLineSession(String          Id,
                                                String          Account,
                                                String          From,
                                                String?         Key,
                                                DateTimeOffset  Since);

        private readonly ConcurrentDictionary<String, CommandLineSession>  commandLineSessions = new ();

        /// <summary>
        /// The command line's sessions over SSH, open now, the oldest first.
        /// </summary>
        public IReadOnlyList<CommandLineSession>  CommandLineSessions
            => [.. commandLineSessions.Values.OrderBy(session => session.Since)];

        #endregion

        #region MayReadTheLog(User)

        /// <summary>
        /// Whether the given account may read this node's log - as its Logs page
        /// and its event stream ask it.
        /// </summary>
        public Boolean MayReadTheLog(IUser User)

            => JSONAPI?.MayReadTheLogFor(User) ?? true;

        #endregion

        #region (protected virtual) ServeShellAsync(Context, CancellationToken)

        /// <summary>
        /// What somebody signed in over SSH gets: this node's command line, on
        /// their terminal, as the account they signed in as - until they leave,
        /// close their window, or the node stops.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The command line is the console's: the same commands, Tab, the history,
        /// the log above the line being typed. What differs is what ends it -
        /// 'quit', 'exit' and Ctrl+D leave the session and the node keeps running -
        /// and who is asking: an account, whose roles say what it may do, and
        /// whom the log names.
        /// </para>
        /// <para>
        /// Without a terminal there is nothing to type at: a session asked for
        /// without one - ssh -T, or a program feeding it from a pipe - is told
        /// so and ends.
        /// </para>
        /// <para>
        /// A node that stops says so on every session while its channel is still
        /// open, and then ends it.
        /// </para>
        /// </remarks>
        /// <param name="Context">The session.</param>
        /// <param name="CancellationToken">Fires when the session is over, or the node is stopping.</param>
        protected virtual async ValueTask<Int32> ServeShellAsync(SshShellContext    Context,
                                                                 CancellationToken  CancellationToken)
        {

            var session = Context.Session;

            if (User_Id.TryParse(session.Username) is not User_Id userId ||
                !ExtAPI.TryGetUser(userId, out var account) ||
                account is null)
            {
                await Context.WriteAsync($"There is no account '{session.Username}' on this {Kind.Name} any more.\r\n", CancellationToken);
                return 1;
            }

            if (Context.Size is not SshWindowSize size)
            {
                await Context.WriteAsync($"This is the command line of the {Kind.Name}, and it wants a terminal to be typed at: " +
                                          "connect with ssh -t, or with PuTTY.\r\n",
                                         CancellationToken);
                return 1;
            }

            var since     = TimeProvider.GetUtcNow();
            var from      = session.Peer?.ToString() ?? "somewhere";
            var caller    = new CLICaller(account, session);

            await using var terminal = new VT100Terminal((bytes, ct) => Context.WriteAsync(bytes, ct),
                                                         Width:         Columns(size),
                                                         TimeProvider:  TimeProvider);

            Context.WindowChanged += changed => terminal.Width = Columns(changed);
            Context.Signalled     += signal  => { if (signal is "INT" or "TERM") terminal.Interrupt(); };

            using var cli = (CommandLines ?? ((t, c) => new NodeCLI(this, t, c)))(terminal, caller);

            // The log from where the console shows it, where the account may read it.
            cli.SessionLog = MayReadTheLog(account)
                                 ? new SessionLog(Log, cli, consoleLog?.MinimumLevel ?? LogLevel.Info, () => MayReadTheLog(account))
                                 : null;

            commandLineSessions[session.ConnectionId] = new CommandLineSession(session.ConnectionId,
                                                                               account.Id.ToString(),
                                                                               from,
                                                                               session.PublicKeyFingerprint,
                                                                               since);

            var reading = terminal.ReadFromAsync(Context.Input, CancellationToken);

            try
            {

                terminal.WriteLine($"{Kind.CapitalisedName} v{Version}: signed in as '{account.Id}' from {from}.");
                terminal.WriteLine($"Type 'help' for what can be typed here; 'quit' or Ctrl+D leaves, and the {Kind.Name} keeps running.");
                terminal.WriteLine();

                await cli.Run(CancellationToken);

                if (Context.Stopping.IsCancellationRequested && !Context.Closed.IsCancellationRequested)
                {
                    terminal.WriteLine();
                    terminal.WriteLine($"The {Kind.Name} is shutting down.");
                }

                if (!Context.Closed.IsCancellationRequested)
                    await terminal.FlushAsync().WaitAsync(TimeSpan.FromSeconds(2));

            }
            catch (Exception) when (Context.Closed.IsCancellationRequested || CancellationToken.IsCancellationRequested)
            {
                // The window was closed in the middle of something.
            }
            catch (IOException)
            {
                // The far end stopped taking what it was sent.
            }
            catch (TimeoutException)
            {
                // The goodbye did not get through in time; the session ends regardless.
            }
            finally
            {

                if (cli.SessionLog is SessionLog sessionLog)
                    await sessionLog.DisposeAsync();

                commandLineSessions.TryRemove(session.ConnectionId, out _);

                var lasted = TimeProvider.GetUtcNow() - since;

                Log.Info($"'{account.Id}' left the command line over SSH after {Lasted(lasted)}" +
                         (Context.Stopping.IsCancellationRequested ? $", as the {Kind.Name} stopped." : "."),
                         "ssh", "cli");

            }

            _ = reading.ContinueWith(task => _ = task.Exception, TaskContinuationOptions.OnlyOnFaulted);

            return 0;

        }

        #endregion

        #region (private static) Columns(Size)

        /// <summary>
        /// How wide the terminal is: what the client said - and 80 where it said
        /// 0, which OpenSSH does when its own output is not a terminal, and which
        /// would leave the line being typed one column to be shown in.
        /// </summary>
        private static Int32 Columns(SshWindowSize Size)

            => Size.Columns == 0
                   ? 80
                   : (Int32) Math.Min(Size.Columns, 1000);

        #endregion

        #region (private static) Lasted(Duration)

        /// <summary>
        /// How long something lasted, as somebody says it: "12 s", "4 min", "3 h 5 min".
        /// </summary>
        private static String Lasted(TimeSpan Duration)

            => Duration.TotalSeconds < 60   ? $"{Math.Max(0, (Int32) Duration.TotalSeconds)} s"
             : Duration.TotalMinutes < 60   ? $"{(Int32) Duration.TotalMinutes} min"
             :                                $"{(Int32) Duration.TotalHours} h {Duration.Minutes} min";

        #endregion
        #region (private) Audited(Event)

        /// <summary>
        /// What the SSH server says happened, in the node's log: who signed in
        /// and from where with which key, who could not, which limit was
        /// reached, what was refused - and the rest for the debug log.
        /// </summary>
        private void Audited(SshAuditEvent Event)
        {

            var from = Event.PeerEndpoint is not null ? $" from {Event.PeerEndpoint}" : "";

            switch (Event)
            {

                case AuthMethodSucceededEvent succeeded:
                    if (succeeded.Identity is not null && Event.ConnectionId is not null)
                        sshSignInKeys[Event.ConnectionId] = succeeded.Identity;
                    break;

                case AuthenticationSucceededEvent signedIn:
                    sshSignInKeys.TryRemove(Event.ConnectionId ?? "", out var key);
                    Log.Notice($"'{signedIn.Username}' signed in over SSH{from}" +
                               (key is not null ? $" with the key {key}." : $" with {String.Join(" and ", signedIn.Methods)}."),
                               "ssh", "auth", "security");
                    break;

                case AuthMethodFailedEvent failed:
                    Log.Info($"Somebody{from} could not sign in over SSH as '{failed.Username}' with {failed.Method}" +
                             (failed.Identity is not null ? $" ({failed.Identity})." : "."),
                             "ssh", "auth", "security");
                    break;

                case AuthenticationFailedEvent gaveUp:
                    Log.Warning(gaveUp.FailedAttempts > 0
                                    ? $"Somebody{from} failed to sign in over SSH as '{gaveUp.Username}' {gaveUp.FailedAttempts} time(s), and was disconnected."
                                    : $"'{gaveUp.Username}' signed in over SSH{from}, with a credential that may not be used from there, and was disconnected.",
                                "ssh", "auth", "security");
                    break;

                case LimitExceededEvent limit:
                    Log.Warning($"The SSH server refused{from}: {limit.Limit} - {limit.Detail}.", "ssh", "security");
                    break;

                case PolicyDeniedEvent denied:
                    Log.Info($"Refused over SSH{from}: {denied.PolicyType}{(denied.Target.Length > 0 ? $" '{denied.Target}'" : "")} - only the command line is served.",
                             "ssh", "security");
                    break;

                case DisconnectedEvent { Code: (UInt32) DisconnectReason.ProtocolError } broken:
                    Log.Info($"An SSH connection{from} ended in a protocol error: {broken.Description}", "ssh");
                    break;

                case ConnectionClosedEvent:
                    sshSignInKeys.TryRemove(Event.ConnectionId ?? "", out _);
                    Log.Debug($"An SSH connection{from} ended.", "ssh");
                    break;

                case KexCompletedEvent kex:
                    Log.Debug($"An SSH connection{from}: {kex.KeyExchange}, {kex.Cipher}{(kex.PostQuantum ? ", post-quantum" : "")}.", "ssh");
                    break;

                case VersionExchangedEvent version:
                    Log.Debug($"An SSH client{from}: {version.RemoteVersion}.", "ssh");
                    break;

                default:
                    Log.Debug($"SSH{from}: {Event.EventType}.", "ssh");
                    break;

            }

        }

        #endregion

    }

}
