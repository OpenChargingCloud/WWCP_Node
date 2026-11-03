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

using System.Globalization;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The offsets of this node's clock that are reported: one of at least
    /// the legal group's "offsetReportingThresholdSeconds" is written into the
    /// metrological log as security critical, and told to whatever listens -
    /// a charging station tells its CSMS, as the security event
    /// SettingSystemTime.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The white paper's threshold (Secure Time Synchronization, section 2.2)
    /// is for a correction of the clock, and for the offset measured where the
    /// clock is only verified - which is what this node does: it does not set
    /// its clock, see WWCPNode.Clock.cs. Every check of the legal group is
    /// written down with its offset already; what the threshold adds is the
    /// entry that says an offset is one to act on.
    /// </para>
    /// <para>
    /// Said when it is reached, and when a check is back below it, not at
    /// every check in between: an offset the clock keeps is the same offset,
    /// until the operating system sets the clock.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Events

        /// <summary>
        /// A check found this node's clock at least the legal group's
        /// <see cref="NTSGroup.OffsetReportingThreshold"/> off, where the check
        /// before it did not: the group, and the offset the check found.
        /// </summary>
        public event Action<NTSGroup, TimeSpan>? OnNTSOffsetReached;

        #endregion


        #region (private) ReportTheOffset(Group, Offset)

        /// <summary>
        /// A check of a group produced a time this far off the clock: written
        /// down and told where it reaches the threshold, written down where it
        /// is back below it.
        /// </summary>
        /// <param name="Group">The group of time servers.</param>
        /// <param name="Offset">How far off the check found the clock.</param>
        private void ReportTheOffset(NTSGroup   Group,
                                     TimeSpan?  Offset)
        {

            if (Group.ReconsiderTheOffset(Offset) is not { } reached ||
                Group.OffsetReportingThreshold    is not { } threshold)
            {
                return;
            }

            var offset = Offset!.Value;

            if (!reached)
            {
                LogTime(Group,
                        LogLevel.Notice,
                        $"NTS: the clock of this {Kind.Name} is within {Seconds(threshold)} of the time of group '{Group.Id}' again: {SignedSeconds(offset)}.",
                        "nts", "clock", "offset");
                return;
            }

            LogTime(Group,
                    LogLevel.Critical,
                    $"NTS: the clock of this {Kind.Name} is {SignedSeconds(offset)} off the time of group '{Group.Id}', " +
                    $"at least the {Seconds(threshold)} of '{NTSConfiguration.OffsetReportingThresholdKey}'.",
                    "nts", "clock", "offset", "security");

            if (OnNTSOffsetReached is not { } listeners)
                return;

            foreach (var listener in listeners.GetInvocationList().Cast<Action<NTSGroup, TimeSpan>>())
            {
                try
                {
                    listener(Group, offset);
                }
                catch (Exception e)
                {
                    Log.Warning($"Something told that the clock is {SignedSeconds(offset)} off the time of NTS group '{Group.Id}' failed: {e.Message}", "nts", "offset");
                }
            }

        }

        #endregion

        #region (internal static) SignedSeconds(Offset), Seconds(Threshold)

        /// <summary>
        /// An offset as a log line and a security event say it, the same under
        /// every culture: "+6.123 s", "-0.004 s".
        /// </summary>
        internal static String SignedSeconds(TimeSpan Offset)

            => $"{Offset.TotalSeconds.ToString("+0.000;-0.000;0.000", CultureInfo.InvariantCulture)} s";

        /// <summary>
        /// A threshold as they say it: "5 s".
        /// </summary>
        internal static String Seconds(TimeSpan Threshold)

            => $"{Threshold.TotalSeconds.ToString("0", CultureInfo.InvariantCulture)} s";

        #endregion

    }

}
