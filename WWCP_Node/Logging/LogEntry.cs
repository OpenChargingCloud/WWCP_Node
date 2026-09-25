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

namespace cloud.charging.open.protocols.WWCP.Node.Logging
{

    /// <summary>
    /// One thing that happened inside this node: when, how loudly,
    /// what it was about, and what it was.
    /// </summary>
    /// <param name="Id">A number that only ever grows, so a browser can tell what it has already seen.</param>
    /// <param name="Timestamp">When it happened.</param>
    /// <param name="Level">How much attention it wants.</param>
    /// <param name="Tags">What it is about: "15118", "sdp", "http", ... - lower case, without the level.</param>
    /// <param name="Message">One line, as somebody would read it.</param>
    /// <param name="Data">Whatever else belongs to it, or null.</param>
    /// <param name="Metrological">Whether it belongs in the metrological log as well - see <see cref="EventLog.Metrological(LogLevel, String, String[])"/>.</param>
    public sealed record LogEntry(UInt64                 Id,
                                  DateTimeOffset         Timestamp,
                                  LogLevel               Level,
                                  IReadOnlyList<String>  Tags,
                                  String                 Message,
                                  JObject?               Data           = null,
                                  Boolean                Metrological   = false)
    {

        #region Properties

        /// <summary>
        /// The level as it is written in JSON and shown in the browser: "info",
        /// "critical", ...
        /// </summary>
        public String  LevelName
            => Level.ToString().ToLowerInvariant();

        #endregion


        #region Matches(Tag)

        /// <summary>
        /// Whether this entry carries the given tag - the level counting as one
        /// of them, which is how "critical" and "ocpp" can be typed into the
        /// same filter box.
        /// </summary>
        public Boolean Matches(String Tag)
        {

            var tag = Tag.Trim().ToLowerInvariant();

            if (tag.Length == 0)
                return true;

            if (LevelName == tag)
                return true;

            foreach (var own in Tags)
            {
                if (own == tag)
                    return true;
            }

            return false;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The entry as the browser reads it.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("id",         Id),
                           new JProperty("timestamp",  Timestamp.ToString("o")),
                           new JProperty("level",      LevelName),
                           new JProperty("tags",       new JArray(Tags)),
                           new JProperty("message",    Message)
                       );

            if (Data is not null)
                json.Add("data", Data);

            // Only where it is so: an entry that is not metrological reads
            // exactly as every entry did before there was a metrological log -
            // to a browser, and in every file an entry is written to.
            if (Metrological)
                json.Add("metrological", true);

            return json;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// The entry as it is written to the console.
        /// </summary>
        public override String ToString()

            => String.Concat(
                   Timestamp.ToLocalTime().ToString("HH:mm:ss.fff"),
                   " [", LevelName, Tags.Count > 0 ? " " + String.Join(" ", Tags) : "", "] ",
                   Message
               );

        #endregion

    }

}
