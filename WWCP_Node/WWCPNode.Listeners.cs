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

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// How a node tells what listens to its events: the groups of time
    /// servers, the name resolution, what it made of a server's certificate.
    /// </summary>
    public partial class WWCPNode
    {

        #region (private) Tell(Listeners, Call, What, Service)

        /// <summary>
        /// Tell each listener on its own, so that one throwing neither keeps
        /// the others from hearing it nor fails what was done.
        /// </summary>
        /// <param name="Listeners">The event's listeners, or null for none.</param>
        /// <param name="Call">How one of them is told.</param>
        /// <param name="What">What happened, for the log line when a listener fails: "NTS group 'local' changed".</param>
        /// <param name="Service">What it is about, the first tag of that log line: "nts", "dns".</param>
        private void Tell<TListener>(TListener?         Listeners,
                                     Action<TListener>  Call,
                                     String             What,
                                     String             Service)

            where TListener : Delegate

        {

            if (Listeners is null)
                return;

            foreach (var listener in Listeners.GetInvocationList().Cast<TListener>())
            {
                try
                {
                    Call(listener);
                }
                catch (Exception e)
                {
                    Log.Warning($"Something told that {What} failed: {e.Message}", Service, "errors");
                }
            }

        }

        #endregion

    }

}
