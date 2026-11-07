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
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;
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
    /// <param name="Id">What names it across every group of the node, whatever its host name becomes - or null where the file gives it none; see <see cref="IdsOf"/>.</param>
    /// <param name="AEAD">The one AEAD algorithm its key exchange offers, or null for every one in <see cref="AEADAlgorithmsOffered"/>, the server choosing.</param>
    /// <param name="MinRefresh">The shortest time after a key exchange before the next one, or null for <see cref="DefaultMinRefresh"/>; see <see cref="RefreshOf"/>.</param>
    /// <param name="MaxRefresh">The longest time after a key exchange before the next one, or null for <see cref="DefaultMaxRefresh"/>; see <see cref="RefreshOf"/>.</param>
    /// <param name="DelayAsymmetry">A correction added to every offset measured with it, for a known stable asymmetry of the delays, or null for none.</param>
    /// <param name="DelayVarAsymmetry">Where a hold-up of its delays is, from -0.5 (on the way there) to +0.5 (on the way back), or null for half each.</param>
    /// <param name="NTSKEHostname">The key exchange server its keys and cookies come from, where it is another than the server itself, or null.</param>
    public sealed record NTSServerConfiguration(DomainName       Hostname,
                                                Byte             Priority           = 0,
                                                IPPort?          NTSKEPort          = null,
                                                IPPort?          NTPPort            = null,
                                                Boolean          Enabled            = true,
                                                ServerPins?      Pins               = null,
                                                String?          Id                 = null,
                                                AEADAlgorithms?  AEAD               = null,
                                                TimeSpan?        MinRefresh         = null,
                                                TimeSpan?        MaxRefresh         = null,
                                                TimeSpan?        DelayAsymmetry     = null,
                                                Double?          DelayVarAsymmetry  = null,
                                                DomainName?      NTSKEHostname      = null)
    {

        #region Data

        /// <summary>
        /// The longest a server's id may be: what OCPP allows for the instance
        /// of a component, which a server's id is to a CSMS.
        /// </summary>
        public const Int32 MaxIdLength = 50;

        private static readonly Regex serverId = new ("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant);

        /// <summary>
        /// The shortest time an entry may set between two key exchanges with a
        /// server: a minute, as the Secure Time Synchronization white paper says.
        /// </summary>
        public const UInt32 MinRefreshSeconds = 60;

        /// <summary>
        /// The longest time an entry may set between two key exchanges with a
        /// server: sixty days, what the paper once gave OCPP 1.6 as its longest.
        /// </summary>
        public const UInt32 MaxRefreshSeconds = 60 * 86400;

        /// <summary>
        /// The shortest time after a key exchange with a server before the next
        /// one, where its entry says nothing: twelve hours, as the paper says.
        /// </summary>
        public static readonly TimeSpan DefaultMinRefresh = TimeSpan.FromHours(12);

        /// <summary>
        /// The longest time after a key exchange with a server before the next
        /// one, where its entry says nothing: a day, as the paper says.
        /// </summary>
        /// <remarks>
        /// A key exchange is the only moment a server's certificate is seen, and
        /// cookies alone would go on for much longer: a new one at least once a
        /// day keeps a replaced certificate from going unnoticed for longer than
        /// that, and keeps the load of TLS handshakes on public time servers low.
        /// It used to be half an hour, the time library's own interval.
        /// </remarks>
        public static readonly TimeSpan DefaultMaxRefresh = TimeSpan.FromHours(24);

        /// <summary>
        /// The largest correction, either way, an entry may add to the offsets
        /// measured with its server: a second, far beyond what a path is ever
        /// asymmetric by, and short of what would hide a clock that is wrong.
        /// </summary>
        public const Double MaxDelayAsymmetryMs = 1000;

        /// <summary>
        /// How far a hold-up of the delays may be put on one way: all of it, on
        /// the way there (-0.5) or back (+0.5).
        /// </summary>
        public const Double MaxDelayVarAsymmetry = 0.5;

        #endregion

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
        /// <remarks>
        /// With the one AEAD algorithm this entry offers, where it names one.
        /// The node offers what a server is held to by name across all its
        /// groups, and puts that on every endpoint after this - see
        /// WWCPNode.TimeServerAEAD.cs.
        /// </remarks>
        public NTSServerEndpoint ToEndpoint()

            => new (Hostname,
                    NTSKEPort,
                    NTPPort,
                    Enabled,
                    Priority,
                    OfferedAEADAlgorithms:  AEAD is { } aead ? [ aead ] : null,
                    MinRefresh:             RefreshOf(this).Min,
                    MaxRefresh:             RefreshOf(this).Max,
                    DelayAsymmetry:         DelayAsymmetry,
                    DelayVarAsymmetry:      DelayVarAsymmetry,
                    NTSKEHost:              NTSKEHostname);

        #endregion

        #region (static) RefreshOf(Entry) / RefreshOf(MinRefresh, MaxRefresh) / SetsRefresh(Entry)

        /// <summary>
        /// When the next key exchange with the server of the given entry is due:
        /// at a random time between Min and Max after the last one.
        /// </summary>
        /// <remarks>
        /// What the entry sets, and the defaults for what it does not. An entry
        /// setting a shortest time beyond the default longest one has that as
        /// its longest too, and one setting a longest time below the default
        /// shortest one has that as its shortest: never a longest below the
        /// shortest.
        /// </remarks>
        /// <param name="Entry">The entry, or null for one that says nothing.</param>
        public static (TimeSpan Min, TimeSpan Max) RefreshOf(NTSServerConfiguration? Entry)

            => RefreshOf(Entry?.MinRefresh, Entry?.MaxRefresh);

        /// <summary>
        /// When the next key exchange is due, for an entry that sets the given
        /// times: at a random time between Min and Max after the last one.
        /// </summary>
        /// <param name="MinRefresh">The shortest time the entry sets, or null.</param>
        /// <param name="MaxRefresh">The longest time the entry sets, or null.</param>
        public static (TimeSpan Min, TimeSpan Max) RefreshOf(TimeSpan?  MinRefresh,
                                                             TimeSpan?  MaxRefresh)
        {

            var min = MinRefresh ?? (MaxRefresh is { } maxOnly && maxOnly < DefaultMinRefresh ? maxOnly : DefaultMinRefresh);
            var max = MaxRefresh ?? (min > DefaultMaxRefresh ? min : DefaultMaxRefresh);

            return (min, max);

        }

        /// <summary>
        /// Whether the given entry sets when its server's key exchange is made
        /// again, or leaves it to the defaults.
        /// </summary>
        public static Boolean SetsRefresh(NTSServerConfiguration Entry)

            => Entry.MinRefresh.HasValue || Entry.MaxRefresh.HasValue;

        #endregion

        #region (static) SetsCorrection(Entry) / CorrectionText(DelayAsymmetry, DelayVarAsymmetry)

        /// <summary>
        /// Whether the given entry corrects the offsets measured with its server.
        /// </summary>
        public static Boolean SetsCorrection(NTSServerConfiguration Entry)

            => Entry.DelayAsymmetry.HasValue || Entry.DelayVarAsymmetry.HasValue;

        /// <summary>
        /// How the offsets measured with a server are corrected, as a sentence
        /// says it: "by -0.05 ms", "for an asymmetry of -0.5", "by 1 ms and for an
        /// asymmetry of 0.25", or "not" where nothing is set.
        /// </summary>
        public static String CorrectionText(TimeSpan?  DelayAsymmetry,
                                            Double?    DelayVarAsymmetry)
        {

            static String Number(Double Value) => Value.ToString("0.######", System.Globalization.CultureInfo.InvariantCulture);

            var by   = DelayAsymmetry    is { } shift     ? $"by {Number(shift.TotalMilliseconds)} ms"       : null;
            var asym = DelayVarAsymmetry is { } asymmetry ? $"for an asymmetry of {Number(asymmetry)}"       : null;

            return by is not null && asym is not null
                       ? $"{by} and {asym}"
                       : by ?? asym ?? "not";

        }

        #endregion

        #region (static) AEADAlgorithmsOffered / AEADNameOf(Algorithm) / TryParseAEAD(Text, out Algorithm)

        /// <summary>
        /// The AEAD algorithms a time server's key exchange is offered where
        /// its entry names none, in the order the server is asked to choose
        /// from - and the ones an entry may name.
        /// </summary>
        /// <remarks>
        /// The time library's: what it can perform and has seen work with
        /// another implementation. An algorithm it can perform but never ran
        /// against anybody else's server is not offered, so it cannot be named
        /// either.
        /// </remarks>
        public static IReadOnlyList<AEADAlgorithms> AEADAlgorithmsOffered
            => NTSAEAD.Supported;

        /// <summary>
        /// An AEAD algorithm as the file, the page and OCPP name it:
        /// "AES-SIV-CMAC-256", "AES-128-GCM-SIV".
        /// </summary>
        public static String AEADNameOf(AEADAlgorithms Algorithm)

            => Algorithm.AsText().Replace('_', '-');

        /// <summary>
        /// The AEAD algorithm of that name, where it is one an entry may name.
        /// </summary>
        /// <remarks>
        /// Whatever its case, as the names are written in capitals and read by
        /// people.
        /// </remarks>
        public static Boolean TryParseAEAD(String              Text,
                                           out AEADAlgorithms  Algorithm)
        {

            foreach (var offered in AEADAlgorithmsOffered)
            {
                if (String.Equals(AEADNameOf(offered), Text.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    Algorithm = offered;
                    return true;
                }
            }

            Algorithm = default;
            return false;

        }

        #endregion

        #region (static) IsServerId(Text)

        /// <summary>
        /// Whether a text can be the id of a server: lower-case letters, digits
        /// and hyphens, beginning with a letter - the way a group is named - and
        /// at most <see cref="MaxIdLength"/> of them.
        /// </summary>
        /// <remarks>
        /// Longer than a group's name may be, so that the id given to a server
        /// of a group with the longest name, "&lt;group&gt;-&lt;n&gt;", can be
        /// written into the file as it is.
        /// </remarks>
        public static Boolean IsServerId(String? Text)

            => Text is not null &&
               Text.Length <= MaxIdLength &&
               serverId.IsMatch(Text);

        #endregion

        #region (static) IdsOf(Group, Given)

        /// <summary>
        /// The id of every server of a group, by its place in the list: the one
        /// the file gives it, or else "&lt;group&gt;-&lt;n&gt;" for the n-th
        /// server - the next number not taken where a server of the group has
        /// that one already.
        /// </summary>
        /// <remarks>
        /// <para>
        /// An id the file does not give is as stable as the server's place in
        /// the list, and no more: take the first server away and the second is
        /// "&lt;group&gt;-1" from then on. That is why whatever names a server
        /// to somebody else - a page saving the list, a bridge to OCPP - writes
        /// the ids it was shown back into the file, where they stay.
        /// </para>
        /// <para>
        /// Not the host name, which names the server to the network and not to
        /// people: a new host name for the same place would be a new server to
        /// a CSMS, and one of 253 characters would not fit an OCPP instance.
        /// </para>
        /// </remarks>
        /// <param name="Group">The group's name.</param>
        /// <param name="Given">The id the file gives each server, by its place in the list, or null where it gives none.</param>
        public static IReadOnlyList<String> IdsOf(String                 Group,
                                                  IEnumerable<String?>  Given)
        {

            var given  = Given.ToArray();
            var taken  = new HashSet<String>(given.OfType<String>(), StringComparer.Ordinal);
            var ids    = new String[given.Length];

            for (var index = 0; index < given.Length; index++)
            {

                if (given[index] is String id)
                {
                    ids[index] = id;
                    continue;
                }

                var n = index + 1;

                while (!taken.Add($"{Group}-{n}"))
                    n++;

                ids[index] = $"{Group}-{n}";

            }

            return ids;

        }

        #endregion

        #region (static) TryParse(JSON, Index, out Configuration, out Error, Section = "nts")

        /// <summary>
        /// Read one server of the "servers" list of an NTS group.
        /// </summary>
        /// <param name="Index">Its place in the list, so that a complaint can say which one is wrong.</param>
        /// <param name="Section">Where the list is in the file: "nts.groups.local".</param>
        public static Boolean TryParse(JToken                                       JSON,
                                       Int32                                        Index,
                                       [NotNullWhen(true)]  out NTSServerConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?                  Error,
                                       String                                       Section = NTSConfiguration.SectionName)
        {

            Configuration  = null;
            Error          = null;
            var where      = $"'{Section}.servers[{Index}]'";

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

            if (!ConfigurationReader.TryReadString (json, "id",                     $"{Section}.servers[{Index}]", MaxIdLength, out var id, out Error) ||
                !ConfigurationReader.TryReadString (json, "hostname",               where, 253, out var hostname,        out Error) ||
                !ConfigurationReader.TryReadByte   (json, "priority",               where,      out var priority,        out Error) ||
                !ConfigurationReader.TryReadPort   (json, "ntsKEPort",              where,      out var ntsKEPort,       out Error) ||
                !ConfigurationReader.TryReadPort   (json, "ntpPort",                where,      out var ntpPort,         out Error) ||
                !ConfigurationReader.TryReadBoolean(json, "enabled",                where,      out var enabled,         out Error))
            {
                return false;
            }

            if (id is not null && !IsServerId(id))
            {
                Error = $"'{Section}.servers[{Index}].id': '{id}' cannot be the id of a server, which is lower-case letters, digits and hyphens, beginning with a letter, and at most {MaxIdLength} of them.";
                return false;
            }

            // The one AEAD algorithm to offer, where the entry names one; left
            // out, the server chooses from all of them.
            if (!ConfigurationReader.TryReadString(json, "aead", $"{Section}.servers[{Index}]", 32, out var aeadName, out Error))
                return false;

            AEADAlgorithms? aead = null;

            if (aeadName is not null)
            {

                if (!TryParseAEAD(aeadName, out var named))
                {
                    Error = $"'{Section}.servers[{Index}].aead': '{aeadName}' is not an AEAD algorithm this node offers, which are " +
                            $"{String.Join(" and ", AEADAlgorithmsOffered.Select(AEADNameOf))}.";
                    return false;
                }

                aead = named;

            }

            // When its key exchange is made again: at a random time between the
            // two, after the last one.
            if (!ConfigurationReader.TryReadSeconds(json, "minRefreshSeconds", $"{Section}.servers[{Index}]", MinRefreshSeconds, MaxRefreshSeconds, out var minRefresh, out Error) ||
                !ConfigurationReader.TryReadSeconds(json, "maxRefreshSeconds", $"{Section}.servers[{Index}]", MinRefreshSeconds, MaxRefreshSeconds, out var maxRefresh, out Error))
            {
                return false;
            }

            if (minRefresh.HasValue && maxRefresh.HasValue && maxRefresh.Value < minRefresh.Value)
            {
                Error = $"'{Section}.servers[{Index}].maxRefreshSeconds' ({maxRefresh.Value.TotalSeconds}) must not be shorter than its minRefreshSeconds ({minRefresh.Value.TotalSeconds}).";
                return false;
            }

            // What is known about the path to it: a correction of every offset
            // measured, and where a hold-up of the delays is.
            if (!ConfigurationReader.TryReadNumber(json, "delayAsymmetryMs",  $"{Section}.servers[{Index}]", -MaxDelayAsymmetryMs,  MaxDelayAsymmetryMs,  out var delayAsymmetry,    out Error) ||
                !ConfigurationReader.TryReadNumber(json, "delayVarAsymmetry", $"{Section}.servers[{Index}]", -MaxDelayVarAsymmetry, MaxDelayVarAsymmetry, out var delayVarAsymmetry, out Error))
            {
                return false;
            }

            // The key exchange server its keys and cookies come from, where it
            // is another than the server itself.
            if (!ConfigurationReader.TryReadString(json, "ntsKEHostname", $"{Section}.servers[{Index}]", 253, out var ntsKEHostname, out Error))
                return false;

            DomainName? keyExchange = null;

            if (ntsKEHostname is not null && ntsKEHostname.Trim().Length > 0)
            {

                if (!DomainName.TryParse(ntsKEHostname.Trim(), out var parsed, out var keyExchangeProblem))
                {
                    Error = $"'{Section}.servers[{Index}].ntsKEHostname': {keyExchangeProblem}";
                    return false;
                }

                keyExchange = parsed;

            }

            // What it is held to, beside the usual - the same for a time server
            // as for a name server.
            if (!ServerPins.TryParse(json, $"{Section}.servers[{Index}]", out var pins, out Error))
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
                                pins,
                                id,
                                aead,
                                minRefresh,
                                maxRefresh,
                                // Zero corrects nothing, and is written as nothing.
                                delayAsymmetry    is Double shift     && shift     != 0 ? TimeSpan.FromMilliseconds(shift) : null,
                                delayVarAsymmetry is Double asymmetry && asymmetry != 0 ? asymmetry                        : null,
                                // The server itself named as its key exchange server is
                                // no other one.
                                keyExchange is not null && !keyExchange.Equals(domainName) ? keyExchange : null
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

            if (Id is null && Priority == 0 && NTSKEPort is null && NTPPort is null && Enabled && AEAD is null && !SetsRefresh(this) && !SetsCorrection(this) && NTSKEHostname is null && Pins?.SaysAnything != true)
                return Hostname.ToString();

            var json = new JObject();

            if (Id is not null)         json.Add("id",        Id);

            json.Add("hostname", Hostname.ToString());

            if (Priority != 0)          json.Add("priority",  Priority);
            if (NTSKEPort.HasValue)     json.Add("ntsKEPort", NTSKEPort.Value.ToUInt16());
            if (NTPPort.  HasValue)     json.Add("ntpPort",   NTPPort.  Value.ToUInt16());
            if (!Enabled)               json.Add("enabled",   false);
            if (AEAD.HasValue)          json.Add("aead",      AEADNameOf(AEAD.Value));
            if (MinRefresh.HasValue)    json.Add("minRefreshSeconds", MinRefresh.Value.TotalSeconds);
            if (MaxRefresh.HasValue)    json.Add("maxRefreshSeconds", MaxRefresh.Value.TotalSeconds);
            if (DelayAsymmetry.HasValue)    json.Add("delayAsymmetryMs",  DelayAsymmetry.Value.TotalMilliseconds);
            if (DelayVarAsymmetry.HasValue) json.Add("delayVarAsymmetry", DelayVarAsymmetry.Value);
            if (NTSKEHostname is not null)  json.Add("ntsKEHostname",     NTSKEHostname.ToString());

            Pins?.WriteInto(json);

            return json;

        }

        #endregion


        #region (static) RefreshText(Refresh)

        /// <summary>
        /// When a key exchange is made again, as a sentence says it: "12 to 24
        /// hours", "90 minutes".
        /// </summary>
        public static String RefreshText((TimeSpan Min, TimeSpan Max) Refresh)
        {

            static String In(TimeSpan Time, Double Unit)

                => (Time.TotalSeconds / Unit).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);

            var (min, max)    = Refresh;
            var (unit, name)  = min.TotalSeconds % 3600 == 0 && max.TotalSeconds % 3600 == 0 ? (3600.0, "hours")
                              : min.TotalSeconds %   60 == 0 && max.TotalSeconds %   60 == 0 ? (  60.0, "minutes")
                              :                                                                (   1.0, "seconds");

            return min == max
                       ? $"{In(max, unit)} {name}"
                       : $"{In(min, unit)} to {In(max, unit)} {name}";

        }

        #endregion


        #region (override) ToString()

        public override String ToString()

            => $"{Hostname}{(Priority != 0 ? $" (priority {Priority})" : "")}{(Enabled ? "" : " - switched off")}{(AEAD is { } aead ? $" - offered {AEADNameOf(aead)} alone" : "")}{(SetsRefresh(this) ? $" - key exchange again after {RefreshText(RefreshOf(this))}" : "")}{(SetsCorrection(this) ? $" - offsets corrected {CorrectionText(DelayAsymmetry, DelayVarAsymmetry)}" : "")}{(NTSKEHostname is not null ? $" - keys from {NTSKEHostname.Trimmed}" : "")}{(Pins?.SaysAnything == true ? $" - held to {Pins}" : "")}";

        #endregion

    }

}
