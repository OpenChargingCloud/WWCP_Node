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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// "ssh.dns": whether the logins of a kind of node - a local controller's charging stations - may
    /// resolve names over their SSH connection (DNS-over-SSH, the subsystem "dns@open.charging.cloud"),
    /// which this node passes on to its own name servers.
    /// </summary>
    /// <remarks>
    /// The node answers no name itself: what a station asks is asked of the name servers of the
    /// "dns" section, over whatever they are reached by, and what they answer goes back. Which
    /// station may ask at all is its login group's, as ever: "dns@open.charging.cloud" among its
    /// SSH channels.
    /// </remarks>
    /// <param name="Enabled">Whether it is served; no where absent.</param>
    public sealed record SSHNameServiceConfiguration(Boolean? Enabled = null)
    {

        #region Data

        /// <summary>
        /// The key of this part of the "ssh" section.
        /// </summary>
        public const String Key   = "dns";

        /// <summary>
        /// Where this part stands in the configuration file.
        /// </summary>
        public const String Path  = $"{SSHConfiguration.SectionName}.{Key}";

        #endregion

        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// "ssh.dns", or the one sentence that says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JToken                                                JSON,
                                       [NotNullWhen(true)]  out SSHNameServiceConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?                       Error)
        {

            Configuration = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object: {{ \"enabled\": true }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadBoolean(json, "enabled", Path, out var enabled, out Error))
                return false;

            Configuration = new SSHNameServiceConfiguration(enabled);
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// This part as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Enabled is not null)
                json.Add("enabled", Enabled.Value);

            return json;

        }

        #endregion

        #region (static) Merged(File, Sent)

        /// <summary>
        /// What was sent, where it says something, over what the file has.
        /// </summary>
        public static SSHNameServiceConfiguration? Merged(SSHNameServiceConfiguration?  File,
                                                          SSHNameServiceConfiguration?  Sent)

            => Sent is null
                   ? File
                   : new SSHNameServiceConfiguration(Sent.Enabled ?? File?.Enabled);

        #endregion

    }


    /// <summary>
    /// "ssh.nts": whether the logins of a kind of node - a local controller's charging stations - get
    /// their time from it: NTS key establishment over their SSH connection (the subsystem
    /// "ntske/1@open.charging.cloud"), and NTP with NTS on a UDP port of this node.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The time is the node's system clock. The node has a time server of its own for it, with
    /// master keys of its own beside the SSH host key, and no key exchange over TLS: the cookies
    /// come over SSH alone, under the key the station signed in with.
    /// </para>
    /// <para>
    /// A station asks for the time at the host it signed in at, on port 123. Where the time server
    /// listens on another port, the key exchange has to tell it the host as well: RFC 8915 has no
    /// record for a port alone.
    /// </para>
    /// </remarks>
    /// <param name="Enabled">Whether it is served; no where absent.</param>
    /// <param name="NTPPort">The UDP port of NTP and NTS; 123 where absent.</param>
    /// <param name="NTPHost">The name or address the key exchange tells the stations to ask for the time at; none where absent, and the host they signed in at is asked.</param>
    public sealed record SSHTimeServiceConfiguration(Boolean?  Enabled   = null,
                                                     IPPort?   NTPPort   = null,
                                                     String?   NTPHost   = null)
    {

        #region Data

        /// <summary>
        /// The key of this part of the "ssh" section.
        /// </summary>
        public const String  Key             = "nts";

        /// <summary>
        /// Where this part stands in the configuration file.
        /// </summary>
        public const String  Path            = $"{SSHConfiguration.SectionName}.{Key}";

        /// <summary>
        /// The longest a host name may be, RFC 1035 § 2.3.4.
        /// </summary>
        public const Int32   MaxHostLength   = 253;

        /// <summary>
        /// The port of NTP, RFC 5905, where nothing says otherwise.
        /// </summary>
        public static readonly IPPort DefaultNTPPort = IPPort.NTP;

        #endregion

        #region Properties

        /// <summary>
        /// The UDP port of NTP and NTS in effect.
        /// </summary>
        public IPPort  NTPPortInEffect
            => NTPPort ?? DefaultNTPPort;

        #endregion

        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// "ssh.nts", or the one sentence that says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JToken                                                JSON,
                                       [NotNullWhen(true)]  out SSHTimeServiceConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?                       Error)
        {

            Configuration = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object: {{ \"enabled\": true, \"ntpPort\": 123 }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadBoolean(json, "enabled",  Path,                out var enabled,  out Error) ||
                !ConfigurationReader.TryReadPort   (json, "ntpPort",  Path,                out var ntpPort,  out Error) ||
                !ConfigurationReader.TryReadString (json, "ntpHost",  Path, MaxHostLength, out var ntpHost,  out Error))
                return false;

            if (ntpHost is not null &&
                (ntpHost.Any(c => c is <= ' ' or '/' or '@' or '?' or '#') ||
                 !URL.TryParse($"udp://{(ntpHost.Contains(':') && !ntpHost.StartsWith('[') ? $"[{ntpHost}]" : ntpHost)}:{(ntpPort ?? DefaultNTPPort)}", out _)))
            {
                Error = $"'{Path}.ntpHost' must be a host name or an address, without port or path: '{ntpHost}' is none.";
                return false;
            }

            Configuration = new SSHTimeServiceConfiguration(enabled, ntpPort, ntpHost);
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// This part as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Enabled is not null)  json.Add("enabled",  Enabled.Value);
            if (NTPPort is not null)  json.Add("ntpPort",  NTPPort.Value.ToUInt16());
            if (NTPHost is not null)  json.Add("ntpHost",  NTPHost);

            return json;

        }

        #endregion

        #region (static) Merged(File, Sent)

        /// <summary>
        /// What was sent, where it says something, over what the file has. A host sent as an empty
        /// string takes the host away.
        /// </summary>
        public static SSHTimeServiceConfiguration? Merged(SSHTimeServiceConfiguration?  File,
                                                          SSHTimeServiceConfiguration?  Sent,
                                                          Boolean                       HostCleared)

            => Sent is null && !HostCleared
                   ? File
                   : new SSHTimeServiceConfiguration(Sent?.Enabled ?? File?.Enabled,
                                                     Sent?.NTPPort ?? File?.NTPPort,
                                                     HostCleared ? null : Sent?.NTPHost ?? File?.NTPHost);

        #endregion

        #region (static) HostClearedIn(JSON)

        /// <summary>
        /// Whether the given "ssh" section, as it was sent, takes the host away: "ntpHost" given, and
        /// blank or null.
        /// </summary>
        public static Boolean HostClearedIn(JObject SSHSection)

            => SSHSection.TryGetValue(Key, out var nts)         &&
               nts is JObject json                              &&
               json.TryGetValue("ntpHost", out var host)        &&
               (host.Type == JTokenType.Null ||
                (host.Type == JTokenType.String && String.IsNullOrWhiteSpace(host.Value<String>())));

        #endregion

        #region WhyNotServable()

        /// <summary>
        /// Why this cannot be served as it says, or null where it can: on another port than 123,
        /// a station has to be told the host as well.
        /// </summary>
        public String? WhyNotServable()

            => Enabled == true && NTPPortInEffect != DefaultNTPPort && NTPHost is null
                   ? $"'{Path}.ntpPort' is {NTPPortInEffect}, and a station asks on port {DefaultNTPPort} where it is told no host: give '{Path}.ntpHost' as well."
                   : null;

        #endregion

    }

}
