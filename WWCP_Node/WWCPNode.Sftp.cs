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
using System.Globalization;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The node's files over SFTP, on its SSH server: its areas - the log files
    /// for every node, and whatever its kind adds - each read and written as
    /// the role model says, and nothing else of the machine.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off unless the configuration file's "ssh" section says "sftp": true, or
    /// the SSH server page did: after an update a node does nothing it did not
    /// do before. Switched on or off, it takes effect for the next session
    /// without the SSH server starting anew; switched off, the sessions open
    /// end.
    /// </para>
    /// <para>
    /// A session is the account's, as a session at the command line is: let
    /// in as there, asked again every few seconds and before every operation
    /// whether what let it in still does, and ended where not. The log says
    /// who opened it from where, every file put up, removed or downloaded,
    /// and in one line what the session came to.
    /// </para>
    /// <para>
    /// A back end that connects to this node over SSH - its CSMS, written down as a
    /// connection the other end makes under the login it signs in with - has
    /// SFTP as well, and sees nothing of the areas: a tree of its own, its own
    /// files and the node's log files to read (see BackEndSftpFileSystem).
    /// Its files lie in a directory of its login beside the configuration
    /// file, and stay there until it or the node takes them away.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// What the folder of the log files is called over SFTP.
        /// </summary>
        public const String  SftpLogsArea              = "logs";

        /// <summary>
        /// What the folder of the metrological log is called over SFTP.
        /// </summary>
        public const String  SftpMetrologicalLogArea   = "logs/metrological";

        /// <summary>
        /// The directory beside the configuration file the files of the back
        /// ends that connect to this node over SSH lie in, one directory a login.
        /// </summary>
        public const String  SftpBackEndsDirectory     = "sftp";

        /// <summary>
        /// The areas the kind added, before the start.
        /// </summary>
        private readonly List<SftpArea>                              kindsSftpAreas       = [];

        /// <summary>
        /// The areas from the start on: the node's, then the kind's.
        /// </summary>
        private          IReadOnlyList<SftpArea>                     sftpAreasInEffect    = [];

        /// <summary>
        /// Each open SFTP session's check of whether it may go on, which ends it
        /// where it may not, by session.
        /// </summary>
        private readonly ConcurrentDictionary<String, Func<String?>>  sftpSessionRechecks  = new ();

        private          Int64                                       lastSftpSession;

        #endregion

        #region Properties

        /// <summary>
        /// Whether the node's files are served over SFTP: where its SSH server
        /// runs and the configuration file says "sftp": true - or says nothing,
        /// and the program serves them by default (SSHSettings.SftpByDefault).
        /// </summary>
        public Boolean                  SFTPEnabled
            => SSHEnabled && (sshFile?.Sftp ?? sshSettings?.SftpByDefault == true);

        /// <summary>
        /// The areas of the SFTP tree: the node's - its log files, and its
        /// metrological log, where it keeps them - and those its kind added.
        /// </summary>
        public IReadOnlyList<SftpArea>  SftpAreas
            => started
                   ? sftpAreasInEffect
                   : [.. NodeSftpAreas(), .. kindsSftpAreas];

        #endregion


        #region AddSftpArea(Area)

        /// <summary>
        /// Add an area of the kind's to the SFTP tree - before the node starts.
        /// </summary>
        /// <param name="Area">The area.</param>
        public void AddSftpArea(SftpArea Area)
        {

            if (started)
                throw new InvalidOperationException($"The SFTP area '/{Area.Path}' comes too late: the areas are added before the {Kind.Name} starts.");

            if (SftpAreas.Any(area => area.Path == Area.Path))
                throw new ArgumentException($"There is an SFTP area '/{Area.Path}' already.", nameof(Area));

            kindsSftpAreas.Add(Area);

        }

        #endregion

        #region (private) NodeSftpAreas()

        /// <summary>
        /// The areas every node has: its log files, one a day, and its
        /// metrological log's - the day files and the public key, never the
        /// private one beside them. Read with what reading the log needs, and
        /// written by nobody: the logs are evidence.
        /// </summary>
        private IEnumerable<SftpArea> NodeSftpAreas()
        {

            var reading = JSONAPI?.ReadingTheLogNeeds;

            if (fileLog is FileLog files)
                yield return new SftpArea(SftpLogsArea,
                                          files.Directory,
                                          name => IsDayFile(name, files.FilePrefix, ".log"),
                                          Read: reading) {
                                 Tags = [ "log" ]
                             };

            if (MetrologicalLog is SignedLog signed)
                yield return new SftpArea(SftpMetrologicalLogArea,
                                          signed.Path,
                                          name => name == LogSigner.PublicKeyFileName ||
                                                  IsDayFile(name, signed.FilePrefix, ".jsonl"),
                                          Read: reading) {
                                 Tags = [ "log" ]
                             };

        }

        #endregion

        #region (private static) IsDayFile(Name, Prefix, Extension)

        /// <summary>
        /// Whether the given name is a day's file of a log: the prefix, a dash,
        /// a date and the extension - and nothing else.
        /// </summary>
        private static Boolean IsDayFile(String  Name,
                                         String  Prefix,
                                         String  Extension)

            => Name.Length == Prefix.Length + "-yyyy-MM-dd".Length + Extension.Length &&
               Name.StartsWith(Prefix + "-", StringComparison.Ordinal) &&
               Name.EndsWith  (Extension,    StringComparison.Ordinal) &&
               DateOnly.TryParseExact(Name.AsSpan(Prefix.Length + 1, "yyyy-MM-dd".Length), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

        #endregion

        #region SftpDirectoryOf(Login) / BackEndThatConnectsOverSSH(Login) / (internal) GetsSftp(Login)

        /// <summary>
        /// The directory of the files of the back end that comes under the
        /// given login over SSH - beside the configuration file, below
        /// <see cref="SftpBackEndsDirectory"/>, its name the login with every
        /// character but letters, digits, '-' and '_' written as its number.
        /// </summary>
        /// <param name="Login">The login the back end signs in to SSH with.</param>
        public String SftpDirectoryOf(User_Id Login)

            => Beside(ConfigFile.Path,
                      Path.Combine(SftpBackEndsDirectory,
                                   String.Concat(Login.ToString().Select(c => Char.IsAsciiLetterOrDigit(c) || c is '-' or '_'
                                                                       ? c.ToString()
                                                                       : $"%{(Int32) c:X4}"))));

        /// <summary>
        /// The connection the other end makes over SSH, switched on, that comes
        /// under the given login - a back end that connects to this node, its CSMS -
        /// or null.
        /// </summary>
        /// <param name="Login">The login a session signed in to SSH with.</param>
        public ConnectionEntry? BackEndThatConnectsOverSSH(User_Id Login)

            => Connections?.Connections.FirstOrDefault(entry => entry.Inbound     &&
                                                                entry.AutoConnect &&
                                                                entry.IsSSH       &&
                                                                User_Id.TryParse(entry.InboundName) == Login);

        /// <summary>
        /// Whether a login of the kind's has SFTP: SFTP is served, and it is
        /// the login of a back end that connects to this node over SSH.
        /// </summary>
        internal Boolean GetsSftp(User_Id Login)
        {
            try
            {
                return SFTPEnabled && BackEndThatConnectsOverSSH(Login) is not null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion

        #region (private) PrepareSftpAreas()

        /// <summary>
        /// The areas from the start on - and what an upload that never finished
        /// left in an area that is written, taken away.
        /// </summary>
        private void PrepareSftpAreas()
        {

            sftpAreasInEffect = [.. NodeSftpAreas(), .. kindsSftpAreas];

            foreach (var area in sftpAreasInEffect.Where(area => area.IsWritable && Directory.Exists(area.Directory)))
            {
                foreach (var left in Directory.EnumerateFiles(area.Directory, SftpArea.UploadPrefix + "*"))
                {
                    try
                    {
                        File.Delete(left);
                        Log.Info($"An upload over SFTP to /{area.Path} that never finished was taken away: '{Path.GetFileName(left)}'.", "ssh", "sftp");
                    }
                    catch (Exception problem) when (problem is IOException or UnauthorizedAccessException)
                    {
                        Log.Warning($"An upload over SFTP to /{area.Path} that never finished could not be taken away: '{left}': {problem.Message}", "ssh", "sftp");
                    }
                }
            }

        }

        #endregion

        #region (private) SftpSessionFor(Session, CancellationToken)

        /// <summary>
        /// What a session that asks for SFTP gets: its account's view of the
        /// areas - or nothing, where SFTP is switched off, which the audit then
        /// says; or a refusal that says why, where the account may not go on.
        /// </summary>
        private ValueTask<SftpSessionOptions?> SftpSessionFor(SshSessionInfo     Session,
                                                              CancellationToken  CancellationToken)
        {

            if (!SFTPEnabled)
                return ValueTask.FromResult<SftpSessionOptions?>(null);

            // A login of the kind's, and no account: a back end that connects to
            // this node over SSH, with a tree of its own - or nobody.
            if (SSHSignInsOf(Session) is not null)
                return ValueTask.FromResult<SftpSessionOptions?>(BackEndSftpSessionFor(Session));

            if (!ExtAPI.TryGetUser(Session.Username, out var found) ||
                found is not IUser account)
            {
                throw new InvalidOperationException($"there is no account '{Session.Username}' on this {Kind.Name} any more");
            }

            if (sshAuthenticator?.WhyNoLongerIn(Session) is String notIn)
                throw new InvalidOperationException(notIn);

            // The access rules: who may have SFTP, from where and to where.
            if (SSHAccessRefusal(Session, "sftp") is String refused)
                throw new InvalidOperationException(refused);

            var id         = $"{Session.ConnectionId}/sftp-{Interlocked.Increment(ref lastSftpSession)}";
            var since      = TimeProvider.GetUtcNow();
            var from       = Session.Peer?.ToString() ?? "somewhere";
            var ends       = new CancellationTokenSource();
            String? signedOut = null;

            // Ended where what let it in no longer does, or SFTP was switched off.
            String? Recheck()
            {

                if (Volatile.Read(ref signedOut) is String already)
                    return already;

                var why = SFTPEnabled
                              ? WhySSHSessionMayNotGoOn(Session, "sftp")
                              : $"SFTP was switched off on this {Kind.Name}";

                if (why is null)
                    return null;

                if (Interlocked.CompareExchange(ref signedOut, why, null) is null)
                {
                    try
                    {
                        ends.Cancel();
                    }
                    catch (ObjectDisposedException)
                    { }
                }

                return Volatile.Read(ref signedOut);

            }

            var watch      = TimeProvider.CreateTimer(_ => Recheck(), null, SSHSessionRecheckEvery, SSHSessionRecheckEvery);

            sshSessions[id]          = new SSHSession(id, account.Id, from, Session.PublicKeyFingerprint, since, SSHSession.SFTP);
            sftpSessionRechecks[id]  = Recheck;

            Log.Info($"'{account.Id}' opened SFTP over SSH from {from}.", "ssh", "sftp");

            var files      = new NodeSftpFileSystem(sftpAreasInEffect,
                                                    account,
                                                    from,
                                                    Kind.Name,
                                                    permission => IsAllowed(account, [ permission ]),
                                                    Recheck,
                                                    Log,
                                                    Ended: session => {

                                                        watch.Dispose();

                                                        sftpSessionRechecks.TryRemove(id, out _);
                                                        sshSessions.        TryRemove(id, out _);

                                                        ends.Dispose();

                                                        var lasted  = Lasted(TimeProvider.GetUtcNow() - since);
                                                        var moved   = (session.FilesUp   > 0 ? $"{session.FilesUp} file(s) up ({NodeSftpFileSystem.SizeOf(session.BytesUp)})"       : "nothing up") + ", " +
                                                                      (session.FilesDown > 0 ? $"{session.FilesDown} file(s) down ({NodeSftpFileSystem.SizeOf(session.BytesDown)})" : "nothing down");

                                                        if (Volatile.Read(ref signedOut) is String why)
                                                            Log.Notice($"'{account.Id}' was signed out of SFTP over SSH from {from} after {lasted}: {why}. {moved[..1].ToUpperInvariant()}{moved[1..]}.",
                                                                       "ssh", "sftp", "security");

                                                        else
                                                            Log.Info($"'{account.Id}' left SFTP after {lasted}: {moved}.",
                                                                     "ssh", "sftp");

                                                    });

            return ValueTask.FromResult<SftpSessionOptions?>(new SftpSessionOptions(files) {
                                                                 Ends = ends.Token
                                                             });

        }

        #endregion

        #region (private) BackEndSftpSessionFor(Session)

        /// <summary>
        /// What a back end that connects to this node over SSH gets that asks for
        /// SFTP: its own files and the node's log files to read - or a refusal
        /// that says why, where it is no such back end or may not go on.
        /// </summary>
        private SftpSessionOptions BackEndSftpSessionFor(SshSessionInfo Session)
        {

            //var login = WebSocketLogins.LoginOf(Session.Username);
            var login = Session.Username;

            if (sshAuthenticator?.WhyNoLongerIn(Session) is String notIn)
                throw new InvalidOperationException(notIn);

            if (BackEndThatConnectsOverSSH(login) is not ConnectionEntry backEnd)
                throw new InvalidOperationException($"'{login}' is no back end that connects to this {Kind.Name} over SSH - of the logins only those have SFTP");

            if (SSHAccessRefusal(Session, "sftp") is String refused)
                throw new InvalidOperationException(refused);

            var id         = $"{Session.ConnectionId}/sftp-{Interlocked.Increment(ref lastSftpSession)}";
            var since      = TimeProvider.GetUtcNow();
            var from       = Session.Peer?.ToString() ?? "somewhere";
            var ends       = new CancellationTokenSource();
            String? signedOut = null;

            // Ended where what let it in no longer does, it is no back end
            // that connects any more, or SFTP was switched off.
            String? Recheck()
            {

                if (Volatile.Read(ref signedOut) is String already)
                    return already;

                var why = !SFTPEnabled
                              ? $"SFTP was switched off on this {Kind.Name}"
                              : WhySSHSessionMayNotGoOn(Session, "sftp") ??
                                (BackEndThatConnectsOverSSH(login) is null
                                     ? $"'{login}' is no back end that connects to this {Kind.Name} over SSH any more"
                                     : null);

                if (why is null)
                    return null;

                if (Interlocked.CompareExchange(ref signedOut, why, null) is null)
                {
                    try
                    {
                        ends.Cancel();
                    }
                    catch (ObjectDisposedException)
                    { }
                }

                return Volatile.Read(ref signedOut);

            }

            var watch      = TimeProvider.CreateTimer(_ => Recheck(), null, SSHSessionRecheckEvery, SSHSessionRecheckEvery);

            sshSessions[id]          = new SSHSession(id, login, from, Session.PublicKeyFingerprint, since, SSHSession.SFTP);
            sftpSessionRechecks[id]  = Recheck;

            // Its own, and nobody else's.
            OwnerOnly.Directory(Beside(ConfigFile.Path, SftpBackEndsDirectory), problem => Log.Warning(problem, Kind.Tag, "ssh", "sftp", "security"));

            var directory  = SftpDirectoryOf(login);
            var logs       = fileLog as FileLog;

            Log.Info($"The back end '{login}' of the connection '{backEnd.Id}' opened SFTP over SSH from {from}: its own files in '{directory}'" +
                     (logs is not null ? ", and the log files to read." : "."),
                     "ssh", "sftp");

            BackEndSftpFileSystem? files = null;

            files = new BackEndSftpFileSystem(directory,
                                              logs?.Directory,
                                              name => logs is not null && IsDayFile(name, logs.FilePrefix, ".log"),
                                              Said:  what => Log.Info($"The back end '{login}' {what} over SFTP.", "ssh", "sftp"),
                                              Ended: () => {

                                                  watch.Dispose();

                                                  sftpSessionRechecks.TryRemove(id, out _);
                                                  sshSessions.        TryRemove(id, out _);

                                                  ends.Dispose();

                                                  var lasted  = Lasted(TimeProvider.GetUtcNow() - since);
                                                  var moved   = $"{files?.FilesUp ?? 0} file(s) up, {files?.FilesDown ?? 0} file(s) down";

                                                  if (Volatile.Read(ref signedOut) is String why)
                                                      Log.Notice($"The back end '{login}' was signed out of SFTP over SSH from {from} after {lasted}: {why}. {moved[..1].ToUpperInvariant()}{moved[1..]}.",
                                                                 "ssh", "sftp", "security");

                                                  else
                                                      Log.Info($"The back end '{login}' left SFTP after {lasted}: {moved}.",
                                                               "ssh", "sftp");

                                              });

            return new SftpSessionOptions(files) {
                       Ends = ends.Token
                   };

        }

        #endregion

        #region (private) EndSftpSessions()

        /// <summary>
        /// Ask every open SFTP session again whether it may go on - and so end
        /// them all, once SFTP is switched off. How many there were.
        /// </summary>
        private Int32 EndSftpSessions()
        {

            var ended = 0;

            foreach (var recheck in sftpSessionRechecks.Values)
                if (recheck() is not null)
                    ended++;

            return ended;

        }

        #endregion

    }

}
