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

using System.Net.Sockets;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The time server of the legal group's check that the time of this node rests on: the one
    /// its clock was found to agree with, as it described itself in its answer (RFC 5905 § 7.3).
    /// </summary>
    /// <param name="Hostname">Its name.</param>
    /// <param name="Address">The address it was asked at, where known.</param>
    /// <param name="Stratum">Its stratum.</param>
    /// <param name="RootDelay">Its round trip to its reference.</param>
    /// <param name="RootDispersion">Its largest error relative to its reference.</param>
    /// <param name="RoundTrip">The round trip from this node to it.</param>
    /// <param name="LeapIndicator">Its leap indicator.</param>
    public sealed record TimeServerUpstream(String                     Hostname,
                                            System.Net.IPAddress?      Address,
                                            Byte                       Stratum,
                                            TimeSpan                   RootDelay,
                                            TimeSpan                   RootDispersion,
                                            TimeSpan                   RoundTrip,
                                            Byte                       LeapIndicator)
    {

        #region (static) Of(Verdict, MaxDeviation)

        /// <summary>
        /// The server of a usable round that the time it found rests on best: among those that
        /// could be trusted and agree with the time of the round - within the group's
        /// MaxDeviation of it - the one of the lowest stratum, and of these the one closest to
        /// its reference (RFC 5905 § 11.3's root distance). Null where there is none.
        /// </summary>
        /// <param name="Verdict">What a round of the legal group concluded.</param>
        /// <param name="MaxDeviation">How far apart the group's servers may be and still agree.</param>
        public static TimeServerUpstream? Of(TimeSyncVerdict  Verdict,
                                             TimeSpan         MaxDeviation)
        {

            if (!Verdict.IsUsable || Verdict.Offset is not TimeSpan offset)
                return null;

            var best = Verdict.Results.
                           Where  (TimeSyncVerdict.CanBeTrusted).
                           Select (result => (result.ServerHostname, NTP: result.NTP!)).
                           Where  (result => result.NTP.Stratum is > 0 and < 16 &&
                                             (result.NTP.Offset - offset).Duration() < MaxDeviation).
                           OrderBy(result => result.NTP.Stratum).
                           ThenBy (result => result.NTP.RootDelaySeconds / 2 +
                                             result.NTP.RootDispersionSeconds +
                                             result.NTP.RoundTripDelay.TotalSeconds / 2).
                           FirstOrDefault();

            return best.NTP is null
                       ? null
                       : new TimeServerUpstream(
                             best.ServerHostname.ToString().TrimEnd('.'),
                             best.NTP.RemoteAddress?.ToDotNet(),
                             best.NTP.Stratum,
                             TimeSpan.FromSeconds(Math.Max(0, best.NTP.RootDelaySeconds)),
                             TimeSpan.FromSeconds(Math.Max(0, best.NTP.RootDispersionSeconds)),
                             best.NTP.RoundTripDelay < TimeSpan.Zero ? TimeSpan.Zero : best.NTP.RoundTripDelay,
                             best.NTP.LeapIndicator
                         );

        }

        #endregion

    }


    /// <summary>
    /// What the time server of the SSH logins says about its clock (RFC 5905 § 7.3), from the
    /// check of this node's clock against its legal group: the clock is the system clock of this
    /// machine, which the check does not set, so what it is worth is what the last check found.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Synchronised</b> where the last check is no older than the legal time's MaxAge and found
    /// the clock within its Tolerance: one stratum below the server it rests on, that server as
    /// the reference - its address, or the first four octets of the MD5 of an IPv6 address - its
    /// root delay with the round trip to it, and its root dispersion with the offset found and
    /// what the clock may have drifted since (15 µs a second, RFC 5905's PHI). A leap second it
    /// announces is announced on.
    /// </para>
    /// <para>
    /// <b>Not synchronised</b> - leap indicator 3, stratum 16, which no client takes the time
    /// from - where the clock is checked and the check says nothing good: none yet, none for
    /// longer than MaxAge, or one that found the clock further off than the Tolerance. A station
    /// then keeps its own time rather than take one this node cannot vouch for.
    /// </para>
    /// <para>
    /// Where the clock is not checked at all - NTS switched off - there is nothing to say but
    /// what Norn says by default: stratum 1 and "LOCL", an uncalibrated local clock, which is
    /// what it then is.
    /// </para>
    /// </remarks>
    /// <param name="Stratum">The stratum it reports.</param>
    /// <param name="Reference">The reference identifier it reports.</param>
    /// <param name="RootDelay">The root delay it reports.</param>
    /// <param name="RootDispersion">The root dispersion it reports.</param>
    /// <param name="LeapIndicator">The leap indicator it reports.</param>
    /// <param name="Upstream">The server it rests on, where there is one.</param>
    /// <param name="Why">Why it is not synchronised - "neverChecked", "stale" or "offBy" - or null where it is.</param>
    public sealed record TimeServerClock(Byte                 Stratum,
                                         ReferenceIdentifier  Reference,
                                         TimeSpan             RootDelay,
                                         TimeSpan             RootDispersion,
                                         Byte                 LeapIndicator,
                                         TimeServerUpstream?  Upstream,
                                         String?              Why)
    {

        #region Data

        /// <summary>
        /// The stratum of a clock that is not synchronised, RFC 5905 § 7.3.
        /// </summary>
        public const           Byte      Unsynchronised  = 16;

        /// <summary>
        /// The largest stratum a synchronised server reports.
        /// </summary>
        public const           Byte      MaxStratum      = 15;

        /// <summary>
        /// The leap indicator of a clock that is not synchronised.
        /// </summary>
        public const           Byte      Alarm           = 3;

        /// <summary>
        /// How fast an undisciplined clock may drift, RFC 5905 § 7.2: 15 ppm.
        /// </summary>
        public static readonly Double    PHI             = 15e-6;

        #endregion

        #region Properties

        /// <summary>
        /// Whether a client may take its time from it.
        /// </summary>
        public Boolean IsSynchronised
            => LeapIndicator != Alarm;

        #endregion


        #region (static) Of(Checked, Upstream, CheckedAt, Offset, Tolerance, MaxAge, Now, Resolution)

        /// <summary>
        /// What the time server says about its clock now, or null where the clock is not checked
        /// and the server says what it says by default.
        /// </summary>
        /// <param name="Checked">Whether this node's clock is checked against its legal group.</param>
        /// <param name="Upstream">The server the last good check rests on.</param>
        /// <param name="CheckedAt">When the clock was last checked successfully.</param>
        /// <param name="Offset">How far off it was found then.</param>
        /// <param name="Tolerance">How far off it may be and still count.</param>
        /// <param name="MaxAge">How old the check may be and still count.</param>
        /// <param name="Now">The time now.</param>
        /// <param name="Resolution">How finely the clock advances.</param>
        public static TimeServerClock? Of(Boolean              Checked,
                                          TimeServerUpstream?  Upstream,
                                          DateTimeOffset?      CheckedAt,
                                          TimeSpan?            Offset,
                                          TimeSpan             Tolerance,
                                          TimeSpan             MaxAge,
                                          DateTimeOffset       Now,
                                          TimeSpan             Resolution)
        {

            if (!Checked)
                return null;

            if (Upstream is null || CheckedAt is not DateTimeOffset checkedAt || Offset is not TimeSpan offset)
                return NotSynchronised(Upstream, "neverChecked");

            var age = Now - checkedAt;

            if (age < TimeSpan.Zero)
                age = TimeSpan.Zero;

            if (age > MaxAge)
                return NotSynchronised(Upstream, "stale");

            if (offset.Duration() > Tolerance)
                return NotSynchronised(Upstream, "offBy");

            return new TimeServerClock(
                       (Byte) Math.Min(Upstream.Stratum + 1, MaxStratum),
                       ReferenceOf(Upstream),
                       Upstream.RootDelay + Upstream.RoundTrip,
                       Upstream.RootDispersion + offset.Duration() + Resolution + TimeSpan.FromSeconds(PHI * age.TotalSeconds),
                       Upstream.LeapIndicator is 1 or 2 ? Upstream.LeapIndicator : (Byte) 0,
                       Upstream,
                       null
                   );

        }

        #endregion

        #region (private static) NotSynchronised(Upstream, Why)

        private static TimeServerClock NotSynchronised(TimeServerUpstream?  Upstream,
                                                       String               Why)

            => new (Unsynchronised,
                    Upstream is not null ? ReferenceOf(Upstream) : ReferenceIdentifier.From("INIT"),
                    TimeSpan.Zero,
                    TimeSpan.Zero,
                    Alarm,
                    Upstream,
                    Why);

        #endregion

        #region (static) ReferenceOf(Upstream)

        /// <summary>
        /// The reference identifier of a server one stratum above, RFC 5905 § 7.3: its IPv4
        /// address, or the first four octets of the MD5 hash of its IPv6 address - a client
        /// sees from it that it would be asking itself in a loop. Where its address is not known,
        /// its name, hashed as an IPv6 address would be.
        /// </summary>
        public static ReferenceIdentifier ReferenceOf(TimeServerUpstream Upstream)
        {

            var address = Upstream.Address;

            if (address is not null && address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            if (address?.AddressFamily == AddressFamily.InterNetwork)
                return ReferenceIdentifier.From(address.GetAddressBytes());

            var hash = MD5.HashData(address?.GetAddressBytes() ?? System.Text.Encoding.UTF8.GetBytes(Upstream.Hostname));

            return ReferenceIdentifier.From(hash[0], hash[1], hash[2], hash[3]);

        }

        #endregion

    }

}
