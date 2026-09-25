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

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What time this node thinks it is, and what that is worth.
    /// </summary>
    /// <remarks>
    /// Two different questions, and a node has to keep them apart.
    /// The time it shows is its own system clock. Whether that clock is any
    /// good is a separate matter, answered by asking a server that knows - and
    /// **this node does not set its clock from the answer**. It measures the
    /// difference and reports it.
    ///
    /// That is deliberate. Stepping the clock of a machine that is metering
    /// energy and writing signed records is not something a background task
    /// does by surprise; a jump backwards would put two readings out of order
    /// and there would be nothing in the record to say why. Measuring is the
    /// part that can be done safely and is the part that tells somebody whether
    /// there is a problem.
    ///
    /// **"Legal time" is never guessed.** Nothing here can tell from a hostname
    /// whether a server disseminates a country's legal time - that is a fact
    /// about an institution, not about DNS. So the operator says so, in
    /// <c>nts.legalTimeAuthority</c>, and this node then only repeats that
    /// claim while it can stand behind it: the claim exists, the clock was
    /// actually checked against that server, the check is recent, and the
    /// difference it found was small. Any one of those missing and the display
    /// says the time is unverified instead - which is a true statement about a
    /// node that has not checked, and the whole point of not printing the
    /// word "legal" over it.
    /// </remarks>
    public partial class WWCPNode : IAsyncDisposable
    {

        #region Properties

        /// <summary>
        /// How often this node checks its clock.
        /// </summary>
        public TimeSpan        TimeCheckEvery
            => ntsSettings?.CheckEvery ?? NTSConfiguration.DefaultCheckEvery;

        /// <summary>
        /// Who the operator says stands behind the time of the configured
        /// server, or null when nobody has said.
        /// </summary>
        public String?         LegalTimeAuthority
            => ntsSettings?.LegalTimeAuthority;

        /// <summary>
        /// How far this node's clock may be off and still count.
        /// </summary>
        public TimeSpan        LegalTimeTolerance
            => ntsSettings?.LegalTimeTolerance ?? NTSConfiguration.DefaultLegalTolerance;

        /// <summary>
        /// How old the last check may be and still count.
        /// </summary>
        public TimeSpan        LegalTimeMaxAge
            => ntsSettings?.LegalTimeMaxAge ?? NTSConfiguration.DefaultLegalMaxAge;

        /// <summary>
        /// Whether this node's clock has been checked against its time servers
        /// - and found a time - since it last started asking them.
        /// </summary>
        /// <remarks>
        /// What a signed reading needs to know, and less than
        /// <see cref="ClockJSON"/>'s "legal": a record says how far its
        /// timestamp can be trusted with one letter, and the honest letter is
        /// "S" only when something outside this node has confirmed the time.
        /// Claiming a synchronised clock it does not have would be lying about
        /// the one field of a record that cannot be checked afterwards. Taken
        /// back when the servers are replaced by another one: what the last
        /// check found belongs to servers this node no longer asks. The
        /// Modbus/TLS energy meter had this before it was a node.
        /// </remarks>
        public Boolean         ClockIsSynchronised
            => lastTimeCheck.HasValue;

        #endregion


        #region (private) StartCheckingTheClock()

        /// <summary>
        /// Begin checking this node's clock against its time server.
        /// </summary>
        /// <remarks>
        /// Through the node's own <see cref="TimeProvider"/> rather than a
        /// bare timer, so that a test which moves the clock moves this too.
        ///
        /// The first check is one minute in rather than at once: everything
        /// else is still coming up, the network may not be there yet, and a
        /// display that says "unverified" for a minute after a start is telling
        /// the truth.
        /// </remarks>
        private void StartCheckingTheClock()
        {

            timeCheckTimer?.Dispose();
            timeCheckTimer = null;

            if (!NTSEnabled)
            {
                Log.Metrological(LogLevel.Info, $"The clock of this {Kind.Name} is not being checked: NTS is switched off.", "nts", "clock");
                return;
            }

            timeCheckTimer = TimeProvider.CreateTimer(
                                 _ => _ = CheckTheClockAsync(),
                                 null,
                                 TimeSpan.FromMinutes(1),
                                 TimeCheckEvery
                             );

            // Named rather than counted, because this is written once at a
            // start and somebody reading it is checking that the file took
            // effect. "4 time servers" would not tell them which four.
            //
            // The group and not ntsClient.Hostname, which is what this line
            // used to say: the check below has asked the whole group since
            // groups arrived, so naming one server described neither what was
            // asked nor what had to answer - and did it in the one line
            // somebody reads to find out.
            var asking = CheckedAgainst();

            Log.Metrological(
                LogLevel.Info,
                $"The clock of this {Kind.Name} will be checked against {String.Join(", ", asking)} every {TimeCheckEvery.TotalMinutes:F0} minute(s)" +
                (asking.Length > 1 ? $", at least {timeSources.MinServers} of which must answer" : "") +
                (LegalTimeAuthority is not null ? $", which the operator says is {LegalTimeAuthority}." : "."),
                "nts", "clock"
            );

        }

        #endregion

        #region (private) CheckTheClockAsync()

        /// <summary>
        /// One check, quietly.
        /// </summary>
        /// <remarks>
        /// The same exchange the "Sync now" button does, so there is one way of
        /// asking and one place that records the answer. A failed check is a
        /// warning and not an exception: a time server that cannot be reached
        /// for ten minutes is a thing that happens, and the display already
        /// says the time is unverified when the last check has gone stale.
        /// </remarks>
        private async Task CheckTheClockAsync()
        {

            try
            {

                var result = await SyncTimeAsync();

                if (result.Value<Boolean>("ok") != true)
                    Log.Warning(
                        $"The clock of this {Kind.Name} could not be checked: {result.Value<String>("error") ?? "no answer"}.",
                        "nts", "clock"
                    );

            }
            catch (Exception e)
            {
                Log.Warning($"The clock of this {Kind.Name} could not be checked: {e.Message}", "nts", "clock");
            }

        }

        #endregion

        #region (private) CheckedAgainst()

        /// <summary>
        /// The time servers the clock check asks: those switched on, in the
        /// order their bands are asked in.
        /// </summary>
        /// <remarks>
        /// Trimmed, because both places this goes are read by somebody: a
        /// sentence in the log, and the clock's JSON for a screen. The root dot
        /// belongs on a name going back into a file, not in the middle of
        /// prose, where it reads as a typing mistake.
        /// </remarks>
        private String[] CheckedAgainst()

            => [.. timeSources.Bands().SelectMany(band => band).Select(source => source.Hostname.Trimmed)];

        #endregion

        #region ClockJSON()

        /// <summary>
        /// What time it is here, and what that is worth, for the display.
        /// </summary>
        /// <remarks>
        /// Everything a screen needs to say something true, and nothing it
        /// would have to interpret: the time, whether it has been checked,
        /// against whom, how long ago, by how much it was out, and whether all
        /// of that adds up to legal time. The one word the display must not
        /// invent is "legal", so it is decided here and sent as a fact.
        /// </remarks>
        public JObject ClockJSON()
        {

            var now       = TimeProvider.GetUtcNow();
            var asking    = timeSources.Bands().SelectMany(band => band).ToArray();
            var checkedAt = lastTimeCheck;
            var offset    = lastTimeCheckOffset;
            var age       = checkedAt.HasValue ? now - checkedAt.Value : (TimeSpan?) null;

            var fresh     = age.HasValue && age.Value <= LegalTimeMaxAge;
            var close     = offset.HasValue && offset.Value.Duration() <= LegalTimeTolerance;

            // Every one of these has to hold. Each is a different way of not
            // knowing, and none of them is repaired by the others.
            var legal     = LegalTimeAuthority is not null &&
                            NTSEnabled                     &&
                            fresh                          &&
                            close;

            return new JObject(

                       new JProperty("now",             now.ToString("o")),

                       // Said out loud: the number above is this node's own
                       // clock, and the check below did not set it.
                       new JProperty("source",          "system"),

                       // Against whom: the group the check asks, as the log line
                       // at the start names it, and how many of it have to
                       // answer - nobody while NTS is switched off. This used to
                       // be "server", with the host of the single client that is
                       // only there for a server's detailed test - one name for
                       // a check that has asked the whole group since there were
                       // groups. "server" is the one server of a group of one
                       // now, which is what a screen shows beside the time; a
                       // group of more is counted, by the last check, in
                       // numbers a screen can put into its own language.
                       new JProperty("nts",             new JObject(
                           new JProperty("enabled",       NTSEnabled),
                           new JProperty("group",         NTSEnabled ? timeSources.Name : null),
                           new JProperty("server",        NTSEnabled && asking.Length == 1
                                                              ? asking[0].Hostname.Trimmed
                                                              : null),
                           new JProperty("servers",       NTSEnabled ? new JArray(CheckedAgainst()) : null),
                           new JProperty("minServers",    NTSEnabled ? timeSources.MinServers : null),
                           new JProperty("lastServer",    lastTimeCheckServer),
                           new JProperty("asked",         lastTimeCheckAsked),
                           new JProperty("answered",      lastTimeCheckAnswered),
                           new JProperty("checkedAt",     checkedAt?.ToString("o")),
                           new JProperty("ageSeconds",    age.HasValue ? Math.Round(age.Value.TotalSeconds, 1) : null),
                           new JProperty("offset_ms",     offset.HasValue ? Math.Round(offset.Value.TotalMilliseconds, 1) : null),
                           new JProperty("everySeconds",  Math.Round(TimeCheckEvery.TotalSeconds, 0))
                       )),

                       new JProperty("legal",           legal),
                       new JProperty("authority",       LegalTimeAuthority),

                       // Why not, when not - so that a screen can say something
                       // more useful than "no" and somebody looking at it knows
                       // what to go and fix.
                       new JProperty("why",             legal
                                                            ? null
                                                            : LegalTimeAuthority is null ? "notClaimed"
                                                            : !NTSEnabled                ? "ntsOff"
                                                            : !checkedAt.HasValue        ? "neverChecked"
                                                            : !fresh                     ? "stale"
                                                            : !close                     ? "offBy"
                                                            : "unknown"),

                       new JProperty("toleranceSeconds",  Math.Round(LegalTimeTolerance.TotalSeconds, 3)),
                       new JProperty("maxAgeSeconds",     Math.Round(LegalTimeMaxAge.   TotalSeconds, 0))

                   );

        }

        #endregion

    }

}
