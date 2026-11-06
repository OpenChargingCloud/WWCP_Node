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

            if (User_Id.TryParse(Session.Username) is not User_Id userId ||
                !ExtAPI.TryGetUser(userId, out var found) ||
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

            sshSessions[id]          = new SSHSession(id, account.Id.ToString(), from, Session.PublicKeyFingerprint, since, SSHSession.SFTP);
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
