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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Connections
{

    /// <summary>
    /// How many of the charging stations a node serves one of its peers gets:
    /// counted by their logins, those switched off left out.
    /// </summary>
    /// <param name="First">The stations whose forwarding target names the peer first.</param>
    /// <param name="InReserve">The stations whose forwarding target names it after another peer.</param>
    /// <param name="WithoutTarget">The stations that name no target and so belong to the back end in charge, where the peer is it; otherwise none.</param>
    /// <param name="Now">The stations whose messages go to the peer now: those of a target whose first connected peer it is, and those without one while it is the back end in charge and connected.</param>
    public sealed record PeerStations(Int32  First,
                                      Int32  InReserve,
                                      Int32  WithoutTarget,
                                      Int32  Now)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("first",          First),
                   new JProperty("inReserve",      InReserve),
                   new JProperty("withoutTarget",  WithoutTarget),
                   new JProperty("now",            Now)
               );

    }

}
