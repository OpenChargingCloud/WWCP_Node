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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// How often one address may sign in wrong within a minute before it is
    /// told to wait: one brake of a node for the logins of its kind, at every
    /// door they come through - the station port, over a WebSocket, and the
    /// SSH server - so that a door is no faster way to guess.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An account is not braked here: its password is rationed with the
    /// sign-in of the web interface, over SSH as well.
    /// </para>
    /// <para>
    /// A sign-in that is no guess - a client certificate, an SSH key - is
    /// neither counted nor held back: what is brought there cannot be guessed
    /// at.
    /// </para>
    /// <para>
    /// Kept small: what is older than a minute says nothing any more, and is
    /// forgotten once the brake knows of many addresses.
    /// </para>
    /// </remarks>
    /// <param name="TimeProvider">The clock the minute is read from.</param>
    public sealed class SignInBrake(TimeProvider TimeProvider)
    {

        #region Data

        /// <summary>
        /// How many wrong sign-ins of one address are let through within a
        /// minute, where nothing says otherwise.
        /// </summary>
        public const    UInt32  DefaultMaxFailedPerMinute  = 5;

        /// <summary>
        /// How many addresses are remembered before what is older than a
        /// minute is forgotten.
        /// </summary>
        private const   Int32   ForgetAbove                = 4096;

        private static readonly TimeSpan  Minute  = TimeSpan.FromMinutes(1);

        private readonly ConcurrentDictionary<String, Queue<DateTimeOffset>>  failed  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// How many wrong sign-ins of one address are let through within a
        /// minute; null, or 0, for no brake at all.
        /// </summary>
        public UInt32?  MaxFailedPerMinute    { get; set; } = DefaultMaxFailedPerMinute;

        /// <summary>
        /// Whether the brake holds anything back at all.
        /// </summary>
        public Boolean  IsOn
            => MaxFailedPerMinute is > 0;

        #endregion


        #region IsHeldBack(Address)

        /// <summary>
        /// Whether the given address signed in wrong as often within the last
        /// minute as it may; never where the brake is off.
        /// </summary>
        /// <param name="Address">The address of the client, as text.</param>
        public Boolean IsHeldBack(String? Address)
        {

            if (MaxFailedPerMinute is not UInt32 max || max == 0 ||
                Address is null ||
                !failed.TryGetValue(Address, out var guesses))
            {
                return false;
            }

            var since = TimeProvider.GetUtcNow() - Minute;

            lock (guesses)
            {

                while (guesses.Count > 0 && guesses.Peek() < since)
                    guesses.Dequeue();

                return guesses.Count >= max;

            }

        }

        #endregion

        #region CountFailed(Address)

        /// <summary>
        /// One more wrong sign-in of the given address; nothing where the brake
        /// is off.
        /// </summary>
        /// <param name="Address">The address of the client, as text.</param>
        public void CountFailed(String? Address)
        {

            if (MaxFailedPerMinute is not UInt32 max || max == 0 || Address is null)
                return;

            var now    = TimeProvider.GetUtcNow();
            var since  = now - Minute;

            if (failed.Count > ForgetAbove)
            {
                foreach (var (address, old) in failed.ToArray())
                {
                    lock (old)
                    {
                        if (old.Count == 0 || old.Last() < since)
                            failed.TryRemove(KeyValuePair.Create(address, old));
                    }
                }
            }

            var guesses = failed.GetOrAdd(Address, _ => new Queue<DateTimeOffset>());

            lock (guesses)
            {

                while (guesses.Count > 0 && guesses.Peek() < since)
                    guesses.Dequeue();

                // No more kept than are counted.
                if (guesses.Count < max)
                    guesses.Enqueue(now);

            }

        }

        #endregion

    }

}
