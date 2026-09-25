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

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Logging
{

    /// <summary>
    /// Everything that happens inside this node, in one place: the
    /// last few thousand entries in memory, and every new one handed on at once
    /// to whoever is listening - the console, and the Server-Sent Events stream
    /// the web interface hangs on.
    /// </summary>
    /// <remarks>
    /// One log rather than one per protocol, because the question somebody
    /// actually has in front of a node is "what happened just now",
    /// and the answer is an SDP response next to the HTTP request that caused
    /// it next to the ISO 15118 session it is about. What keeps that readable
    /// is the tags: every entry says what it is about, and the web interface
    /// filters on them.
    ///
    /// The entries are numbered, and the number only ever grows. A browser
    /// loads a snapshot, which says how far it reaches, and then applies
    /// everything from the stream that is newer - so a reconnect that replays
    /// a few cached events costs bytes and nothing else.
    /// </remarks>
    public sealed class EventLog
    {

        #region Data

        /// <summary>
        /// How many entries are kept in memory by default: enough that a
        /// browser opening the page sees what led up to now.
        /// </summary>
        public const Int32 DefaultCapacity = 2_000;

        private readonly Queue<LogEntry>   entries = new();
        private readonly SortedSet<String> tags    = new(StringComparer.Ordinal);
        private readonly Lock              padlock = new();

        private readonly IEventLogStore?   store;
        private readonly IEventLogStore?   metrologicalStore;

        /// <summary>
        /// Whether the store, or the metrological store, threw the last time
        /// it was handed an entry - so that one that keeps throwing is
        /// complained about once, and again only after it has worked in between.
        /// </summary>
        private Boolean storeFailing;
        private Boolean metrologicalStoreFailing;

        private UInt64 lastId;

        #endregion

        #region Properties

        /// <summary>
        /// How many entries are kept in memory.
        /// </summary>
        public Int32         Capacity      { get; }

        /// <summary>
        /// Where the timestamp of an entry comes from.
        /// </summary>
        /// <remarks>
        /// Handed in rather than reached for: a log whose times come from
        /// somewhere else than the rest of the node is a log that cannot be
        /// held against anything - and a test that cannot move the clock can
        /// only ever watch the log say "now".
        /// </remarks>
        public TimeProvider  TimeProvider  { get; }

        /// <summary>
        /// What puts a complaint of this log about itself on the console as one
        /// piece - see <see cref="Complain"/>. By default it just writes it.
        /// </summary>
        /// <remarks>
        /// Settable for the reason the console log's WriteBlock is: once a
        /// command line is being typed on the same console, whatever is written
        /// there has to go around that line, and only whoever draws the line
        /// knows how. The node puts the same block here as on its console
        /// log, so that a complaint lands neither in the middle of an entry nor
        /// past a command somebody is typing.
        /// </remarks>
        public Action<Action>  ComplaintBlock  { get; set; } = write => write();

        /// <summary>
        /// Where every entry of this log is kept beyond the process, or null
        /// when they are kept in memory only.
        /// </summary>
        public IEventLogStore?  Store
            => store;

        /// <summary>
        /// Where the metrological entries of this log are kept, or null when
        /// there is no metrological log - see <see cref="Metrological(LogLevel, String, String[])"/>.
        /// </summary>
        public IEventLogStore?  MetrologicalStore
            => metrologicalStore;

        /// <summary>
        /// The number of the newest entry; 0 when nothing has been logged yet.
        /// </summary>
        public UInt64  LastId
        {
            get
            {
                lock (padlock)
                    return lastId;
            }
        }

        /// <summary>
        /// How many entries are in memory right now.
        /// </summary>
        public Int32   Count
        {
            get
            {
                lock (padlock)
                    return entries.Count;
            }
        }

        /// <summary>
        /// Every tag that has been seen since the start, so that the web
        /// interface can offer them instead of asking somebody to guess.
        /// </summary>
        public IEnumerable<String> KnownTags
        {
            get
            {
                lock (padlock)
                    return [.. tags];
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Sent for every new entry, while the caller of <see cref="Log"/>
        /// waits - so a listener has to be quick and must not throw. One that
        /// does throw is caught here and complained about: a broken listener
        /// must not swallow the event that was being logged.
        /// </summary>
        public event Action<LogEntry>? OnLogged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create an event log keeping the given number of entries.
        /// </summary>
        /// <param name="Capacity">How many entries are kept in memory.</param>
        /// <param name="TimeProvider">Where the timestamp of an entry comes from; the system clock by default.</param>
        /// <param name="Store">Where every entry is kept beyond the process, or null to keep them in memory only.</param>
        /// <param name="MetrologicalStore">Where the metrological entries are kept, or null for no metrological log.</param>
        public EventLog(Int32            Capacity            = DefaultCapacity,
                        TimeProvider?    TimeProvider        = null,
                        IEventLogStore?  Store               = null,
                        IEventLogStore?  MetrologicalStore   = null)
        {

            if (Capacity < 1)
                throw new ArgumentOutOfRangeException(nameof(Capacity), "An event log must be able to keep at least one entry!");

            if (Store is not null && ReferenceEquals(Store, MetrologicalStore))
                throw new ArgumentException("One store cannot keep every entry and the metrological ones as well: it would be handed every metrological entry twice.", nameof(MetrologicalStore));

            this.Capacity           = Capacity;
            this.TimeProvider       = TimeProvider ?? System.TimeProvider.System;
            this.store              = Store;
            this.metrologicalStore  = MetrologicalStore;

            #region What was written down before this start

            var everything    = store?.            Load(Capacity);
            var metrological  = metrologicalStore?.Load(Capacity);

            // The entries of the store that has all of them, where there is
            // one, and those of the metrological log where it is the only one -
            // so that a node with nothing but a metrological log still opens its
            // page on what mattered before the restart, rather than on nothing.
            foreach (var entry in (everything ?? metrological)?.Entries ?? [])
            {

                entries.Enqueue(entry);

                foreach (var tag in entry.Tags)
                    tags.Add(tag);

            }

            while (entries.Count > Capacity)
                entries.Dequeue();

            // Where the numbering carries on from: the higher of the two, since
            // both were numbered by this log and a number either of them holds
            // must not be handed out again. A log that began again at 1 would
            // hand a browser entries it had already seen - and worse, two
            // different events would share a number in a file. What no store
            // kept is not known: the numbers of the ordinary entries written
            // after the last metrological one are handed out again, as every
            // number was before there were stores, and a store of every entry
            // is what prevents that.
            lastId = Math.Max(everything?.LastId ?? 0, metrological?.LastId ?? 0);

            #endregion

        }

        #endregion


        #region Log(Level, Message, params Tags)

        /// <summary>
        /// Write one entry.
        /// </summary>
        /// <param name="Level">How much attention it wants.</param>
        /// <param name="Message">One line, as somebody would read it.</param>
        /// <param name="Tags">What it is about: "ocpp", "15118", "http", ...</param>
        public LogEntry Log(LogLevel         Level,
                            String           Message,
                            params String[]  Tags)

            => Log(Level, Message, null, Tags);

        #endregion

        #region Log(Level, Message, Data, params Tags)

        /// <summary>
        /// Write one entry with the whole of what it is about attached.
        /// </summary>
        /// <param name="Level">How much attention it wants.</param>
        /// <param name="Message">One line, as somebody would read it.</param>
        /// <param name="Data">Whatever else belongs to it, or null.</param>
        /// <param name="Tags">What it is about: "ocpp", "15118", "http", ...</param>
        public LogEntry Log(LogLevel         Level,
                            String           Message,
                            JObject?         Data,
                            params String[]  Tags)

            => Write(Level, Message, Data, false, Tags);

        #endregion

        #region Metrological(Level, Message, params Tags)

        /// <summary>
        /// Write one entry that belongs in the metrological log: into this log
        /// like any other, and into the metrological log beside it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Said entry by entry, by whoever writes it, and not decided by a tag
        /// or a level: what is metrologically relevant is a question about what
        /// happened rather than about how loudly it was described. A clock found
        /// to be 800 ms off is; the request for the page that shows it is not,
        /// whatever level either of them was logged at.
        /// </para>
        /// <para>
        /// Numbered in this log's own sequence, so that one event carries one
        /// number in both, and the metrological log is the part of this one
        /// that matters for what the node measures and how far its record of it
        /// can be believed. Without a metrological log it is an ordinary entry,
        /// marked for the page as one that would have gone there.
        /// </para>
        /// </remarks>
        /// <param name="Level">How much attention it wants.</param>
        /// <param name="Message">One line, as somebody would read it.</param>
        /// <param name="Tags">What it is about: "nts", "certificates", ...</param>
        public LogEntry Metrological(LogLevel         Level,
                                     String           Message,
                                     params String[]  Tags)

            => Write(Level, Message, null, true, Tags);

        #endregion

        #region Metrological(Level, Message, Data, params Tags)

        /// <summary>
        /// Write one entry that belongs in the metrological log, with the whole
        /// of what it is about attached - see <see cref="Metrological(LogLevel, String, String[])"/>.
        /// </summary>
        /// <param name="Level">How much attention it wants.</param>
        /// <param name="Message">One line, as somebody would read it.</param>
        /// <param name="Data">Whatever else belongs to it, or null.</param>
        /// <param name="Tags">What it is about: "nts", "certificates", ...</param>
        public LogEntry Metrological(LogLevel         Level,
                                     String           Message,
                                     JObject?         Data,
                                     params String[]  Tags)

            => Write(Level, Message, Data, true, Tags);

        #endregion

        #region (private) Write(Level, Message, Data, Metrological, Tags)

        private LogEntry Write(LogLevel  Level,
                               String    Message,
                               JObject?  Data,
                               Boolean   Metrological,
                               String[]  Tags)
        {

            var entry     = default(LogEntry);
            var failures  = default(List<String>);

            lock (padlock)
            {

                entry = new LogEntry(
                            ++lastId,
                            TimeProvider.GetUtcNow(),
                            Level,
                            Normalize(Tags),
                            Message?.Trim() ?? "",
                            Data,
                            Metrological
                        );

                entries.Enqueue(entry);

                while (entries.Count > Capacity)
                    entries.Dequeue();

                foreach (var tag in entry.Tags)
                    tags.Add(tag);

                // Inside the lock, and that is the point: a store has to end up
                // in the order of the numbers, or reading it back would put the
                // entries in an order nothing ever happened in - and a store
                // whose every line points back at the one before it would point
                // at the wrong one.
                Keep(store,                   entry, "store",              ref storeFailing,              ref failures);

                if (Metrological)
                    Keep(metrologicalStore,   entry, "metrological store", ref metrologicalStoreFailing,  ref failures);

            }

            // Outside the lock, like the listeners below - see Complain.
            foreach (var failure in failures ?? [])
                Complain(failure);

            // Outside the lock: a listener writing to the console or handing
            // the entry to a browser must not hold up whoever is logging - and
            // certainly must not be able to deadlock them.
            var handler = OnLogged;

            if (handler is not null)
            {
                foreach (var listener in handler.GetInvocationList().Cast<Action<LogEntry>>())
                {
                    try
                    {
                        listener(entry);
                    }
                    catch (Exception e)
                    {
                        // Beside the log and not through it - see Complain.
                        Complain($"An event log listener failed: {e.Message}");
                    }
                }
            }

            return entry;

        }

        #endregion

        #region (private static) Keep(Store, Entry, Name, ref Failing, ref Failures)

        /// <summary>
        /// Hand one entry to a store, and remember - rather than throw - what
        /// went wrong.
        /// </summary>
        /// <remarks>
        /// A store is asked not to throw, and one that does must not take the
        /// entry down with it, nor whoever was logging. Said once while it keeps
        /// failing, as a log file that cannot be written is: a store broken for
        /// an hour must not bury the console under one line per entry.
        /// </remarks>
        private static void Keep(IEventLogStore?    Store,
                                 LogEntry           Entry,
                                 String             Name,
                                 ref Boolean        Failing,
                                 ref List<String>?  Failures)
        {

            if (Store is null)
                return;

            try
            {
                Store.Append(Entry);
                Failing = false;
            }
            catch (Exception e)
            {

                if (!Failing)
                    (Failures ??= []).Add($"The event log's {Name} failed, and is tried again with every entry: {e.Message}");

                Failing = true;

            }

        }

        #endregion

        #region Debug/Info/Notice/Warning/Error/Critical(Message, params Tags)

        /// <summary>The detail one only wants while looking for something.</summary>
        public LogEntry Debug   (String Message, params String[] Tags) => Log(LogLevel.Debug,    Message, Tags);

        /// <summary>What happened, in the ordinary course of things.</summary>
        public LogEntry Info    (String Message, params String[] Tags) => Log(LogLevel.Info,     Message, Tags);

        /// <summary>Ordinary, but worth finding again later.</summary>
        public LogEntry Notice  (String Message, params String[] Tags) => Log(LogLevel.Notice,   Message, Tags);

        /// <summary>Something is not as it should be, but the node carries on.</summary>
        public LogEntry Warning (String Message, params String[] Tags) => Log(LogLevel.Warning,  Message, Tags);

        /// <summary>Something did not work.</summary>
        public LogEntry Error   (String Message, params String[] Tags) => Log(LogLevel.Error,    Message, Tags);

        /// <summary>Something did not work and will not start working by itself.</summary>
        public LogEntry Critical(String Message, params String[] Tags) => Log(LogLevel.Critical, Message, Tags);

        #endregion

        #region Exception(Exception, Message, params Tags)

        /// <summary>
        /// Write an error with the exception behind it attached.
        /// </summary>
        public LogEntry Exception(Exception        Exception,
                                  String           Message,
                                  params String[]  Tags)

            => Log(
                   LogLevel.Error,
                   $"{Message}: {Exception.Message}",
                   new JObject(
                       new JProperty("exception",   Exception.GetType().FullName),
                       new JProperty("message",     Exception.Message),
                       new JProperty("stackTrace",  Exception.StackTrace)
                   ),
                   Tags
               );

        #endregion

        #region Complain(Complaint)

        /// <summary>
        /// Say on stderr what is wrong with this log itself: a listener that
        /// failed, a file that cannot be written.
        /// </summary>
        /// <remarks>
        /// On stderr and not through the log, because a complaint about the log
        /// that went through the log would come back to whatever failed and fail
        /// again - a fine way to spend an afternoon in a loop. And through the
        /// <see cref="ComplaintBlock"/>, because the console may have a command
        /// line on it that somebody is typing.
        ///
        /// Never with an exception, since a complaint is made where something
        /// has gone wrong already - and often what went wrong is the console: a
        /// listener fails because the command line could not draw itself, and
        /// then the block fails as well. The complaint is written without it
        /// rather than not at all, and not a second time when the block got as
        /// far as writing it. One that cannot be written anywhere is dropped;
        /// there is nobody left to tell.
        /// </remarks>
        /// <param name="Complaint">One line, as somebody would read it.</param>
        public void Complain(String Complaint)
        {

            var written = false;

            try
            {
                ComplaintBlock(() => {
                    Console.Error.WriteLine(Complaint);
                    written = true;
                });
            }
            catch
            {

                if (!written)
                {
                    try
                    {
                        Console.Error.WriteLine(Complaint);
                    }
                    catch
                    { }
                }

            }

        }

        #endregion


        #region Recent(Limit, After = null, Tag = null)

        /// <summary>
        /// The newest entries, oldest first - what a browser loads before it
        /// starts following the stream.
        /// </summary>
        /// <param name="Limit">At most this many entries.</param>
        /// <param name="After">Only entries newer than this number.</param>
        /// <param name="Tag">Only entries carrying this tag or level.</param>
        public IEnumerable<LogEntry> Recent(Int32    Limit,
                                            UInt64?  After   = null,
                                            String?  Tag     = null)
        {

            if (Limit < 1)
                return [];

            LogEntry[] snapshot;

            lock (padlock)
                snapshot = [.. entries];

            var matching = snapshot.AsEnumerable();

            if (After.HasValue)
                matching = matching.Where(entry => entry.Id > After.Value);

            if (!String.IsNullOrWhiteSpace(Tag))
                matching = matching.Where(entry => entry.Matches(Tag));

            // Counted from the end, because the interesting end of a log is the
            // new one; the order within the page stays oldest first, which is
            // how a log reads and how the browser appends it.
            return [.. matching.TakeLast(Limit)];

        }

        #endregion


        #region (private static) Normalize(Tags)

        /// <summary>
        /// Tags as they are stored: lower case, trimmed, without empties and
        /// without repeats, in the order they were given.
        /// </summary>
        private static IReadOnlyList<String> Normalize(String[] Tags)
        {

            if (Tags.Length == 0)
                return [];

            var normalized = new List<String>(Tags.Length);

            foreach (var tag in Tags)
            {

                if (String.IsNullOrWhiteSpace(tag))
                    continue;

                var lower = tag.Trim().ToLowerInvariant();

                if (!normalized.Contains(lower))
                    normalized.Add(lower);

            }

            return normalized;

        }

        #endregion

    }

}
