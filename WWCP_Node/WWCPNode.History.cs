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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What an account typed at the command line is its own, kept in a file
    /// of its own below the accounts (see NodeCLI.HistoryPathOf), and goes
    /// with it: an account deleted takes its history along, and an account
    /// made never starts with a history somebody else left under its name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Left there, the history of a deleted account was the history of the
    /// next one made under the same name: Up brought back what somebody else
    /// typed. Hermod takes the account's password, keys, sessions and
    /// memberships along for the same reason; the history is the node's,
    /// and so is taking it.
    /// </para>
    /// <para>
    /// Taken where the accounts say they changed, so that it is the same
    /// whoever deleted the account - the web interface, a kind of node of its
    /// own, a program. An account made takes away whatever is left: a node
    /// before this one left the files of the accounts it deleted.
    /// </para>
    /// <para>
    /// A session of the account deleted may still type a line before it is
    /// ended, and write the file again - see ServeShellAsync, which takes it
    /// once more as the session ends.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region (private) AnAccountWasAdded / AnAccountWasDeleted

        private Task AnAccountWasAdded(DateTimeOffset     Timestamp,
                                       IUser              User,
                                       EventTracking_Id?  EventTrackingId   = null,
                                       User_Id?           CurrentUserId     = null)
        {
            ForgetTheHistoryOf(User.Id, "made");
            return Task.CompletedTask;
        }

        private Task AnAccountWasDeleted(DateTimeOffset     Timestamp,
                                         IUser              User,
                                         EventTracking_Id?  EventTrackingId   = null,
                                         User_Id?           CurrentUserId     = null)
        {
            ForgetTheHistoryOf(User.Id, "deleted");
            return Task.CompletedTask;
        }

        #endregion

        #region (private) ForgetTheHistoryOf(Account, Because)

        /// <summary>
        /// Take away the history file of the given account, where there is one.
        /// </summary>
        /// <param name="Account">The account.</param>
        /// <param name="Because">What was done to the account, for the log: "made", "deleted".</param>
        private void ForgetTheHistoryOf(User_Id  Account,
                                        String   Because)
        {

            var path = NodeCLI.HistoryPathOf(this, Account);

            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                    Log.Info($"The command line history of '{Account}' was taken away: the account was {Because}.", "cli", "accounts");
                }
            }
            catch (Exception e)
            {
                Log.Warning($"The command line history of '{Account}' could not be taken away, though the account was {Because}: {e.Message}", "cli", "accounts", "security");
            }

        }

        #endregion

    }

}
