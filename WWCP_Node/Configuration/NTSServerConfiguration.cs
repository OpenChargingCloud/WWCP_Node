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
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// One time server of this node, as the configuration file names it.
    /// </summary>
    /// <param name="Hostname">Where the server is.</param>
    /// <param name="Priority">Which servers are asked first: lower is earlier, and servers sharing a value are asked together.</param>
    /// <param name="NTSKEPort">The key exchange port, when it is not the usual one.</param>
    /// <param name="NTPPort">The time port, when it is not the usual one.</param>
    /// <param name="Enabled">Whether to ask it at all.</param>
    /// <param name="Pins">What it is held to beside what every server is held to - see <see cref="ServerPins"/> - or null for nothing.</param>
    public sealed record NTSServerConfiguration(DomainName   Hostname,
                                                Byte         Priority   = 0,
                                                IPPort?      NTSKEPort  = null,
                                                IPPort?      NTPPort    = null,
                                                Boolean      Enabled    = true,
                                                ServerPins?  Pins       = null)
    {

        #region Properties

        /// <summary>
        /// Whether this server is held to a certificate or to a root, beside
        /// what every server is held to.
        /// </summary>
        /// <remarks>
        /// Beside it, and never instead of it: a server held to a fingerprint
        /// still has to show a certificate issued for its name, whose chain ends
        /// at a root this node trusts - the machine's, or one of its own TLS
        /// roots. A pin narrows what is believed, and cannot widen it. A server
        /// with a certificate that signed itself is believed by importing that
        /// certificate as a TLS root, which is saying the same thing on purpose.
        /// </remarks>
        public Boolean  IsPinned
            => Pins?.IsPinned == true;

        /// <summary>
        /// What this server is held to, as a sentence names it, or null when it
        /// is held to nothing beyond the usual.
        /// </summary>
        public String?  PinsText
            => Pins?.Text;

        /// <summary>
        /// The first certificate it is held to, or null: what a server was held
        /// to before it could be held to several.
        /// </summary>
        public String?  CertificateFingerprint
            => Pins?.Certificates.FirstOrDefault();

        /// <summary>
        /// The first root it is held to, or null: what a server was held to
        /// before it could be held to several.
        /// </summary>
        public String?  RootFingerprint
            => Pins?.Roots.FirstOrDefault();

        /// <summary>
        /// What a key exchange comes to whose certificate is not one it is held to.
        /// </summary>
        public PinMismatch  OnMismatch
            => Pins?.OnMismatch ?? PinMismatch.Refuse;

        #endregion

        #region ToEndpoint()

        /// <summary>
        /// This entry as the time library wants it.
        /// </summary>
        public NTSServerEndpoint ToEndpoint()

            => new (Hostname,
                    NTSKEPort,
                    NTPPort,
                    Enabled,
                    Priority);

        #endregion

        #region (static) TryParse(JSON, Index, out Configuration, out Error)

        /// <summary>
        /// Read one server of the "nts.servers" list.
        /// </summary>
        /// <param name="Index">Its place in the list, so that a complaint can say which one is wrong.</param>
        public static Boolean TryParse(JToken                                       JSON,
                                       Int32                                        Index,
                                       [NotNullWhen(true)]  out NTSServerConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?                  Error)
        {

            Configuration  = null;
            Error          = null;
            var where      = $"'nts.servers[{Index}]'";

            // A bare string is the common case written the short way:
            //   "servers": [ "ptbtime1.ptb.de", "ptbtime2.ptb.de" ]
            // which is four equivalent servers in one band, and the thing most
            // people want. The object form is for saying more than the name.
            if (JSON.Type == JTokenType.String)
            {

                if (!DomainName.TryParse(JSON.Value<String>() ?? "", out var onlyName, out var nameProblem))
                {
                    Error = $"{where}: {nameProblem}";
                    return false;
                }

                Configuration = new NTSServerConfiguration(onlyName);
                return true;

            }

            if (JSON is not JObject json)
            {
                Error = $"{where} must be a host name or an object!";
                return false;
            }

            if (!ConfigurationReader.TryReadString (json, "hostname",               where, 253, out var hostname,        out Error) ||
                !ConfigurationReader.TryReadByte   (json, "priority",               where,      out var priority,        out Error) ||
                !ConfigurationReader.TryReadPort   (json, "ntsKEPort",              where,      out var ntsKEPort,       out Error) ||
                !ConfigurationReader.TryReadPort   (json, "ntpPort",                where,      out var ntpPort,         out Error) ||
                !ConfigurationReader.TryReadBoolean(json, "enabled",                where,      out var enabled,         out Error))
            {
                return false;
            }

            // What it is held to, beside the usual - the same for a time server
            // as for a name server.
            if (!ServerPins.TryParse(json, $"nts.servers[{Index}]", out var pins, out Error))
                return false;

            if (hostname is null)
            {
                Error = $"{where} names no host!";
                return false;
            }

            if (!DomainName.TryParse(hostname, out var domainName, out var problem))
            {
                Error = $"{where}.hostname: {problem}";
                return false;
            }

            Configuration = new NTSServerConfiguration(
                                domainName,
                                priority ?? 0,
                                ntsKEPort,
                                ntpPort,
                                enabled ?? true,
                                pins
                            );

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// This entry as it is written back.
        /// </summary>
        /// <remarks>
        /// A bare host name where nothing else was said, so that a file written
        /// by this node reads the way somebody would have written it.
        /// </remarks>
        public JToken ToJSON()
        {

            if (Priority == 0 && NTSKEPort is null && NTPPort is null && Enabled && Pins?.SaysAnything != true)
                return Hostname.ToString();

            var json = new JObject(
                           new JProperty("hostname", Hostname.ToString())
                       );

            if (Priority != 0)          json.Add("priority",  Priority);
            if (NTSKEPort.HasValue)     json.Add("ntsKEPort", NTSKEPort.Value.ToUInt16());
            if (NTPPort.  HasValue)     json.Add("ntpPort",   NTPPort.  Value.ToUInt16());
            if (!Enabled)               json.Add("enabled",   false);

            Pins?.WriteInto(json);

            return json;

        }

        #endregion


        #region (override) ToString()

        public override String ToString()

            => $"{Hostname}{(Priority != 0 ? $" (priority {Priority})" : "")}{(Enabled ? "" : " - switched off")}{(Pins?.SaysAnything == true ? $" - held to {Pins}" : "")}";

        #endregion

    }

}
