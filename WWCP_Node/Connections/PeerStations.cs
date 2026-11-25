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
    /// <param name="At">The stations connected to the node whose messages go to the peer now, by their names - where a node knows it, and any are; null otherwise. Where a peer turned a station away, or a station is on its way back to a peer, this is where it is, not where its target says.</param>
    /// <param name="HeldBack">How many messages of its stations the node holds back for the peer, to be sent in the order they came while it is connected.</param>
    /// <param name="HeldBackSince">When the oldest of them came, where any are held back.</param>
    /// <param name="Sessions">How many charging sessions that have not ended belong to the peer: those that began at it.</param>
    public sealed record PeerStations(Int32                   First,
                                      Int32                   InReserve,
                                      Int32                   WithoutTarget,
                                      Int32                   Now,
                                      IReadOnlyList<String>?  At             = null,
                                      Int32                   HeldBack       = 0,
                                      DateTimeOffset?         HeldBackSince  = null,
                                      Int32                   Sessions       = 0)
    {

        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("first",          First),
                           new JProperty("inReserve",      InReserve),
                           new JProperty("withoutTarget",  WithoutTarget),
                           new JProperty("now",            Now),
                           new JProperty("heldBack",       HeldBack),
                           new JProperty("sessions",       Sessions)
                       );

            if (At is not null)
                json.Add(new JProperty("at",             new JArray(At)));

            if (HeldBackSince is DateTimeOffset since)
                json.Add(new JProperty("heldBackSince",  since.ToString("o")));

            return json;

        }

        /// <summary>
        /// Equal where the counts are, and the same stations are at the peer, in
        /// the same order.
        /// </summary>
        public Boolean Equals(PeerStations? Other)

            => Other is not null                       &&
               First          == Other.First           &&
               InReserve      == Other.InReserve       &&
               WithoutTarget  == Other.WithoutTarget   &&
               Now            == Other.Now             &&
               HeldBack       == Other.HeldBack        &&
               HeldBackSince  == Other.HeldBackSince   &&
               Sessions       == Other.Sessions        &&
               (At ?? []).SequenceEqual(Other.At ?? []);

        public override Int32 GetHashCode()

            => HashCode.Combine(First, InReserve, WithoutTarget, Now, HeldBack, HeldBackSince, Sessions, (At ?? []).Count);

    }

}
