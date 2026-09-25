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

namespace cloud.charging.open.protocols.WWCP.Node.Logging
{

    /// <summary>
    /// Where an event log is kept beyond the process: read back once, when the
    /// log is made, and handed each new entry in the order of its number.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Beside the listeners of the log rather than one of them. A listener is
    /// called outside the log's lock, and so in whatever order the threads
    /// logging at the same moment happen to get there. A file that has to end
    /// up in the order of the numbers - one whose every line points back at the
    /// line before it - is handed each entry inside the lock, where its number
    /// was given.
    /// </para>
    /// <para>
    /// And read back, which no listener is: the numbers carry on after a
    /// restart from the highest one written before it. A browser follows the
    /// log by number, and would take the first entries of a new process for
    /// ones it had already seen; and a file of numbered lines would have two
    /// different lines under one number.
    /// </para>
    /// <para>
    /// What a node writes by day for somebody to read, <see cref="FileLog"/>,
    /// is a listener and not one of these: it is written to be read by a
    /// person, and never read back.
    /// </para>
    /// </remarks>
    public interface IEventLogStore
    {

        /// <summary>
        /// The newest entries that were kept before this start, oldest first,
        /// and the highest number any entry kept here carries.
        /// </summary>
        /// <remarks>
        /// Called once, while the log is being made. A store that cannot read
        /// what it holds says so its own way and answers with what it could
        /// read, down to nothing at all: a node whose old log is unreadable
        /// still has a new one to write.
        /// </remarks>
        /// <param name="Limit">How many entries the log keeps in memory, and so the most worth returning.</param>
        (IReadOnlyList<LogEntry> Entries, UInt64 LastId) Load(Int32 Limit);

        /// <summary>
        /// Keep one new entry.
        /// </summary>
        /// <remarks>
        /// Called inside the log's lock, so it has to be quick, and it must not
        /// log: an entry written from here would be written in the middle of
        /// writing another. A store that cannot write says so its own way
        /// rather than by throwing; one that throws anyway is caught, and
        /// complained about once the lock is let go.
        /// </remarks>
        /// <param name="Entry">The entry, numbered.</param>
        void Append(LogEntry Entry);

    }

}
