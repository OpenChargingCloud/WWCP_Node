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
    /// How much a log entry wants somebody's attention.
    /// </summary>
    /// <remarks>
    /// One of these is always the first tag of an entry, so that the web
    /// interface can filter by "critical" the same way it filters by "ocpp".
    /// </remarks>
    public enum LogLevel
    {

        /// <summary>
        /// The detail one only wants while looking for something.
        /// </summary>
        Debug,

        /// <summary>
        /// What happened, in the ordinary course of things.
        /// </summary>
        Info,

        /// <summary>
        /// Ordinary, but worth finding again later: a start, a sign-in.
        /// </summary>
        Notice,

        /// <summary>
        /// Something is not as it should be, but the node carries on.
        /// </summary>
        Warning,

        /// <summary>
        /// Something did not work.
        /// </summary>
        Error,

        /// <summary>
        /// Something did not work and will not start working by itself.
        /// </summary>
        Critical

    }

}
