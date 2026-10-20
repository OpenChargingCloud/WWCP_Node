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

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The checks of a group of time servers that produce no time, counted:
    /// written down once there are "errorLogging" of them in a row, limiting
    /// what rests on the group once there are "maxErrors", and written down
    /// again once a check produces a time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The white paper's two numbers, for every group. Each failed check is
    /// written down as well, as it was before - into the metrological log for
    /// the legal group. What the numbers add is the run: one entry where a
    /// server being away for a check or two has become a clock that cannot be
    /// checked, and one where it can be again.
    /// </para>
    /// <para>
    /// What "limited" takes away is not this node's to decide: a dynamic
    /// tariff, by the white paper, for the legal group, and load management
    /// for the local one. It is said, by <see cref="NTSGroup.IsLimited"/> and
    /// <see cref="OnNTSGroupLimited"/>, to whatever rests on the group.
    /// </para>
    /// <para>
    /// A run that ends without a check producing a time - the servers were
    /// changed, or the group was switched off - is not a recovery and is not
    /// written down as one: the count starts again from none, and the log
    /// says why.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region Events

        /// <summary>
        /// A group of time servers began or stopped limiting what rests on its
        /// time: true where <see cref="NTSGroup.MaxErrors"/> checks in a row
        /// produced no time, false where that run has ended.
        /// </summary>
        public event Action<NTSGroup, Boolean>? OnNTSGroupLimited;

        #endregion


        #region (private) CountTheFailure(Group)

        /// <summary>
        /// A check of a group produced no time.
        /// </summary>
        /// <param name="Group">The group of time servers.</param>
        private void CountTheFailure(NTSGroup Group)
        {

            var (inARow, write, limit) = Group.CountFailure();

            if (write)
                LogTime(Group,
                        LogLevel.Warning,
                        $"NTS: group '{Group.Id}' has produced no time {Checks(inARow)} in a row ('errorLogging' is {Group.ErrorLogging}).",
                        "nts", "clock", "errors");

            if (limit)
            {

                LogTime(Group,
                        LogLevel.Error,
                        $"NTS: group '{Group.Id}' has produced no time {Checks(inARow)} in a row ('maxErrors' is {Group.MaxErrors}): " +
                         "what rests on its time is limited until it produces one again.",
                        "nts", "clock", "errors");

                Limited(Group, true);

            }

        }

        #endregion

        #region (private) CountTheSuccess(Group)

        /// <summary>
        /// A check of a group produced a time: whatever run of failures there
        /// was has ended, and is written down as ended where it was written
        /// down as begun.
        /// </summary>
        /// <param name="Group">The group of time servers.</param>
        private void CountTheSuccess(NTSGroup Group)
        {

            var (inARow, wasWritten, wasLimited) = Group.CountAgain();

            if (wasWritten || wasLimited)
                LogTime(Group,
                        LogLevel.Notice,
                        $"NTS: group '{Group.Id}' produced a time again after {Checks(inARow)} in a row that produced none" +
                        (wasLimited ? "; what rests on its time is no longer limited." : "."),
                        "nts", "clock", "errors");

            if (wasLimited)
                Limited(Group, false);

        }

        #endregion

        #region (private) CountAgain(Group, Reason)

        /// <summary>
        /// Start counting the failed checks of a group from none, for a reason
        /// that is not a check producing a time.
        /// </summary>
        /// <param name="Group">The group of time servers.</param>
        /// <param name="Reason">Why, as the end of a sentence: "its time servers changed".</param>
        private void CountAgain(NTSGroup  Group,
                                String    Reason)
        {

            var (inARow, wasWritten, wasLimited) = Group.CountAgain();

            if (wasWritten || wasLimited)
                LogTime(Group,
                        LogLevel.Notice,
                        $"NTS: the checks of group '{Group.Id}' that produced no time are counted from none again, after {inARow} in a row: {Reason}." +
                        (wasLimited ? " What rests on its time is no longer limited." : ""),
                        "nts", "clock", "errors");

            if (wasLimited)
                Limited(Group, false);

        }

        #endregion

        #region (private) ReconsiderTheLimit(Group)

        /// <summary>
        /// Whether a group's run of failures limits what rests on it, after
        /// its "maxErrors" changed.
        /// </summary>
        /// <param name="Group">The group of time servers.</param>
        private void ReconsiderTheLimit(NTSGroup Group)
        {

            var limited = Group.ReconsiderLimit();

            if (limited is null)
                return;

            var inARow = Group.ErrorsInARow;

            LogTime(Group,
                    limited.Value ? LogLevel.Error : LogLevel.Notice,
                    limited.Value
                        ? $"NTS: group '{Group.Id}' has produced no time {Checks(inARow)} in a row ('maxErrors' is now {Group.MaxErrors}): " +
                           "what rests on its time is limited until it produces one again."
                        : $"NTS: what rests on the time of group '{Group.Id}' is no longer limited: 'maxErrors' is now {Group.MaxErrors}, " +
                          $"more than the {Checks(inARow)} in a row that produced no time.",
                    "nts", "clock", "errors");

            Limited(Group, limited.Value);

        }

        #endregion

        #region (private static) Checks(Count)

        /// <summary>
        /// "1 check", "2 checks": a "maxErrors" or an "errorLogging" of one is
        /// reached by one.
        /// </summary>
        private static String Checks(Int32 Count)

            => Count == 1 ? "1 check" : $"{Count} checks";

        #endregion

        #region (private) Limited(Group, Limited)

        /// <summary>
        /// Tell whatever rests on a group that it began or stopped being
        /// limited - each listener on its own, so that one throwing neither
        /// keeps the others from hearing it nor fails the check.
        /// </summary>
        private void Limited(NTSGroup  Group,
                             Boolean   Limited)
        {

            if (OnNTSGroupLimited is not { } listeners)
                return;

            foreach (var listener in listeners.GetInvocationList().Cast<Action<NTSGroup, Boolean>>())
            {
                try
                {
                    listener(Group, Limited);
                }
                catch (Exception e)
                {
                    Log.Warning($"Something told that NTS group '{Group.Id}' is {(Limited ? "" : "no longer ")}limited failed: {e.Message}", "nts", "errors");
                }
            }

        }

        #endregion

    }

}
