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

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// One group of time servers of a node: its servers and the rules for
    /// believing them, the client its detailed test starts from, the timer
    /// that checks the clock against it, and what the last check found.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What a node used to hold once, in fields of its own, because it had
    /// one group - the "legal" one. The white paper names more than one: a
    /// "legal" group for billing, asked rarely and held to a quorum, and a
    /// "local" group for load balancing, asked often. Gathered here so that a
    /// group can be made, switched off and taken away whole: whatever runs for
    /// it is its own, and ends with it.
    /// </para>
    /// <para>
    /// What a group does - asking its servers, judging their certificates,
    /// writing into the log and the file - is the node's, which holds the
    /// log, the file, the name resolution and the measuring engine every
    /// group shares. The group holds what is different between groups.
    /// </para>
    /// </remarks>
    public sealed class NTSGroup : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// The group billing and certificate validity hang off, by the name
        /// the white paper gives it.
        /// </summary>
        public const String  LegalId  = "legal";

        /// <summary>
        /// The clock that makes this node check its own against this group,
        /// while the group is switched on and the node is running.
        /// </summary>
        private ITimer?  timer;

        /// <summary>
        /// What ends the checks running against this group, when it is taken
        /// away in the middle of one.
        /// </summary>
        private readonly CancellationTokenSource  stopping  = new ();

        /// <summary>
        /// The checks running against this group, and what is waited on for
        /// the last of them to end once it is taken away.
        /// </summary>
        private readonly Lock                     gate      = new ();
        private          Int32                    running;
        private          TaskCompletionSource?    lastEnded;
        private          Boolean                  disposed;

        #endregion

        #region Properties

        /// <summary>
        /// What this group is for, e.g. "legal" or "local".
        /// </summary>
        public String           Id                  { get; }

        /// <summary>
        /// Whether this is the group legal time rests on.
        /// </summary>
        public Boolean          IsLegal
            => Id == LegalId;

        /// <summary>
        /// Whether this group is asked at all.
        /// </summary>
        public Boolean          Enabled             { get; internal set; } = true;

        /// <summary>
        /// Every time server of this group, and the rules for believing them.
        /// </summary>
        /// <remarks>
        /// Beside the single client rather than instead of it, because the two
        /// answer different questions. The group answers "what is the time",
        /// which several servers should agree on before a clock moves. The
        /// client answers "what is that one server doing", which is what the
        /// detailed test on the page asks and which a group would only blur.
        /// </remarks>
        public TimeSourceGroup  Sources             { get; internal set; }

        /// <summary>
        /// The client the detailed test of a server starts from - none for a
        /// group that names no server yet. The legal group always has one.
        /// </summary>
        public NTSClient?       Client              { get; internal set; }

        /// <summary>
        /// What the file said about this group, kept because the parts of it
        /// that are not the servers - how often to check, and what the
        /// operator claims about them - are read long afterwards.
        /// </summary>
        internal NTSConfiguration?  Settings        { get; set; }

        /// <summary>
        /// How many of the servers this group was told must answer: by the
        /// last section that named "minServers", or the default of two.
        /// </summary>
        /// <remarks>
        /// Kept apart from the group's own quorum, which cannot be more than the
        /// servers it has switched on. A lone hostname holds a group to one, and
        /// if that one were all that was remembered, a list of four arriving
        /// afterwards would be held to one as well - where the same file, read
        /// at the next start, holds it to two.
        /// </remarks>
        internal Byte           Quorum              { get; set; } = NTSConfiguration.DefaultMinServers;

        /// <summary>
        /// What this group is called on a page, by language - "*" for every
        /// language - or null, for "&lt;id&gt; time".
        /// </summary>
        public IReadOnlyDictionary<String, String>?  DisplayName
            => Settings?.DisplayName;

        /// <summary>
        /// How often the clock is checked against this group.
        /// </summary>
        public TimeSpan         CheckEvery
            => Settings?.CheckEvery ?? NTSConfiguration.DefaultCheckEvery;

        /// <summary>
        /// Who stands behind this group's time, as the operator says - null
        /// when nobody claims anything.
        /// </summary>
        public String?          Authority
            => Settings?.LegalTimeAuthority;

        /// <summary>
        /// How far the clock may be from this group's time and still count.
        /// </summary>
        public TimeSpan         Tolerance
            => Settings?.LegalTimeTolerance ?? NTSConfiguration.DefaultLegalTolerance;

        /// <summary>
        /// How old the last check against this group may be and still count.
        /// </summary>
        public TimeSpan         MaxAge
            => Settings?.LegalTimeMaxAge ?? NTSConfiguration.DefaultLegalMaxAge;

        /// <summary>
        /// Whether the clock is being checked against this group on a timer.
        /// </summary>
        public Boolean          IsChecking
            => timer is not null;

        /// <summary>
        /// Whether this group was taken away: nothing runs for it any more, and
        /// nothing new is begun.
        /// </summary>
        public Boolean          IsDisposed
        {
            get
            {
                lock (gate)
                    return disposed;
            }
        }

        /// <summary>
        /// How many checks are running against this group at the moment.
        /// </summary>
        public Int32            Running
        {
            get
            {
                lock (gate)
                    return running;
            }
        }

        /// <summary>
        /// Cancelled when this group is taken away: whatever asks its servers
        /// asks with this, beside its own.
        /// </summary>
        internal CancellationToken  Stopping
            => stopping.Token;

        #endregion

        #region Properties: what the last check found

        // Separate properties rather than one object because they are written
        // from one place and read from another, and the alternative - digging
        // them back out of the JSON of the last check - would make a page or a
        // screen depend on the shape of a diagnostic.
        //
        // The server is a host name only where there is one of them. A group
        // of four is counted instead, in numbers, because a screen puts this
        // behind "checked against" in whichever language it is showing, and a
        // phrase assembled here would arrive in the wrong one.

        /// <summary>
        /// When the clock was last checked against this group successfully.
        /// </summary>
        public DateTimeOffset?  LastCheck           { get; private set; }

        /// <summary>
        /// How far off the clock was then.
        /// </summary>
        public TimeSpan?        LastCheckOffset     { get; private set; }

        /// <summary>
        /// The one server it was checked against, where there was one.
        /// </summary>
        public String?          LastCheckServer     { get; private set; }

        /// <summary>
        /// How many servers were asked then.
        /// </summary>
        public Int32?           LastCheckAsked      { get; private set; }

        /// <summary>
        /// How many of them answered.
        /// </summary>
        public Int32?           LastCheckAnswered   { get; private set; }

        /// <summary>
        /// How the last synchronisation went, as the web interface reads it,
        /// or null while none has been asked for.
        /// </summary>
        public JObject?         LastSync            { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A group of time servers of a node.
        /// </summary>
        /// <param name="Id">What the group is for, e.g. "legal" or "local".</param>
        /// <param name="Sources">Its servers, and the rules for believing them.</param>
        /// <param name="Client">The client the detailed test of a server starts from, if it names one.</param>
        public NTSGroup(String           Id,
                        TimeSourceGroup  Sources,
                        NTSClient?       Client)
        {

            this.Id       = Id;
            this.Sources  = Sources;
            this.Client   = Client;

        }

        #endregion


        #region (internal) Checked(At, Offset, Asked, Answered, Server)

        /// <summary>
        /// Remember a check of the clock against this group that produced a time.
        /// </summary>
        internal void Checked(DateTimeOffset  At,
                              TimeSpan?       Offset,
                              Int32           Asked,
                              Int32           Answered,
                              String?         Server)
        {
            LastCheck          = At;
            LastCheckOffset    = Offset;
            LastCheckAsked     = Asked;
            LastCheckAnswered  = Answered;
            LastCheckServer    = Server;
        }

        #endregion

        #region (internal) Synced(Result)

        /// <summary>
        /// Remember how the last synchronisation went, whichever way it went.
        /// </summary>
        internal JObject Synced(JObject Result)
        {
            LastSync = Result;
            return Result;
        }

        #endregion

        #region (internal) ForgetChecks()

        /// <summary>
        /// Forget what the last checks found: they were against servers this
        /// group no longer asks.
        /// </summary>
        internal void ForgetChecks()
        {
            LastSync           = null;
            LastCheck          = null;
            LastCheckOffset    = null;
            LastCheckServer    = null;
            LastCheckAsked     = null;
            LastCheckAnswered  = null;
        }

        #endregion

        #region (internal) StartChecking(TimeProvider, Check, FirstIn)

        /// <summary>
        /// Check the clock against this group every <see cref="CheckEvery"/>,
        /// from <paramref name="FirstIn"/> on - instead of whatever timer it
        /// had before.
        /// </summary>
        /// <param name="TimeProvider">The clock of the node, which the timer runs on.</param>
        /// <param name="Check">What checking the clock against this group is.</param>
        /// <param name="FirstIn">How long until the first check.</param>
        internal void StartChecking(TimeProvider          TimeProvider,
                                    Func<NTSGroup, Task>  Check,
                                    TimeSpan              FirstIn)
        {

            StopChecking();

            // A group taken away is checked against no more, whoever asks.
            if (IsDisposed)
                return;

            timer = TimeProvider.CreateTimer(
                        _ => _ = Check(this),
                        null,
                        FirstIn,
                        CheckEvery
                    );

        }

        #endregion

        #region (internal) StopChecking()

        /// <summary>
        /// Check the clock against this group no more.
        /// </summary>
        internal void StopChecking()
        {
            timer?.Dispose();
            timer = null;
        }

        #endregion

        #region (internal) TryBegin() / End()

        /// <summary>
        /// Count a check as running against this group - or say that the group
        /// was taken away, and nothing is to be begun for it.
        /// </summary>
        /// <remarks>
        /// Every TryBegin that says yes is followed by one End, whichever way
        /// the check goes.
        /// </remarks>
        internal Boolean TryBegin()
        {
            lock (gate)
            {

                if (disposed)
                    return false;

                running++;
                return true;

            }
        }

        /// <summary>
        /// A check against this group has ended.
        /// </summary>
        internal void End()
        {
            lock (gate)
            {

                running--;

                if (running == 0)
                    lastEnded?.TrySetResult();

            }
        }

        #endregion

        #region DisposeAsync()

        /// <summary>
        /// End whatever runs for this group: its timer, and every check running
        /// against it - cancelled, and waited for until it has ended.
        /// </summary>
        /// <remarks>
        /// <para>
        /// In that order. The timer first, so that no check begins while the
        /// others are being ended; and waited for, because a check that ends
        /// after its group was taken away would write what it found into a
        /// group nobody has, and its log line about a group that is gone.
        /// </para>
        /// <para>
        /// The token source is cancelled and not disposed of: a check that is
        /// still on its way out reads its token, and a disposed source throws at
        /// that instead of saying it was cancelled. Without a timeout of its
        /// own it holds nothing that needs letting go of.
        /// </para>
        /// </remarks>
        public async ValueTask DisposeAsync()
        {

            Task? waitFor = null;

            lock (gate)
            {

                if (disposed)
                    return;

                disposed = true;

                if (running > 0)
                {
                    lastEnded  = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    waitFor    = lastEnded.Task;
                }

            }

            var ending = timer;
            timer      = null;

            if (ending is not null)
                await ending.DisposeAsync();

            stopping.Cancel();

            if (waitFor is not null)
                await waitFor;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// The group by its name, as a log line names it.
        /// </summary>
        public override String ToString()

            => Id;

        #endregion

    }

}
