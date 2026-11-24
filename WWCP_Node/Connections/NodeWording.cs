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

namespace cloud.charging.open.protocols.WWCP.Node.Connections
{

    /// <summary>
    /// What the node that connects is called in what its connections say - in
    /// their warnings, in the log, in the refusals of their stores: "this
    /// station cannot ...", "this local controller cannot ...".
    /// </summary>
    /// <remarks>
    /// One word for the process, set by a kind of node when it is first
    /// used - and only what is said where no node is to ask: a store made
    /// on its own, as a command of the command line makes one. A node says
    /// its own word, <see cref="WWCPNode.NodeNoun"/>, and gives it to the
    /// stores it makes, so that a test which runs a station and a gateway in
    /// one process hears each of them call itself what it is. Nothing but
    /// texts reads it.
    /// </remarks>
    public static class NodeWording
    {

        /// <summary>
        /// The node in a word: "station", "local controller"; "node" where
        /// nobody said.
        /// </summary>
        public static String Noun        { get; set; } = "node";

        /// <summary>
        /// The node by its full name, where a text gives it: "charging
        /// station", "local controller"; "node" where nobody said.
        /// </summary>
        public static String LongNoun    { get; set; } = "node";

        /// <summary>
        /// Say what this process is.
        /// </summary>
        /// <param name="Noun">The node in a word.</param>
        /// <param name="LongNoun">The node by its full name; the word where there is none.</param>
        public static void Is(String Noun, String? LongNoun = null)
        {
            NodeWording.Noun      = Noun;
            NodeWording.LongNoun  = LongNoun ?? Noun;
        }

        /// <summary>
        /// More than one of what the given noun names: "charging stations",
        /// "registration authorities", "CPOs".
        /// </summary>
        /// <param name="Noun">A noun in the singular.</param>
        public static String Plural(String Noun)

            => Noun.Length > 1 &&
               Noun.EndsWith('y') &&
               !"aeiou".Contains(Noun[^2])
                   ? $"{Noun[..^1]}ies"
                   : Noun.EndsWith('s') || Noun.EndsWith('x') || Noun.EndsWith("ch") || Noun.EndsWith("sh")
                         ? $"{Noun}es"
                         : $"{Noun}s";

    }

}
