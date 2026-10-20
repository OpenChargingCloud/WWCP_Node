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

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// Groups of time servers made and taken away while the node runs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A group is made switched off, because it has nothing to ask yet, and is
    /// switched on once it has - by the same save that changes any group. It is
    /// taken away only while it is switched off, so that nothing stops checking
    /// the clock as a side effect of tidying up: switching a group off is the
    /// decision, taking it away is the tidying.
    /// </para>
    /// <para>
    /// Taking a group away ends everything that runs for it - its timer, the
    /// checks running against it, its client, the key exchanges of servers no
    /// other group asks - and takes it out of the file. The legal group too: a
    /// country without legal time for charging stations has no use for one,
    /// and a node without it says its time is not legal time, which is true.
    /// </para>
    /// </remarks>
    public partial class WWCPNode : IAsyncDisposable
    {

        #region NTSGroupOf(Id)

        /// <summary>
        /// The group of time servers of the given name, or null where this node
        /// has none.
        /// </summary>
        /// <param name="Id">The group's name, e.g. "legal" or "local".</param>
        public NTSGroup? NTSGroupOf(String Id)

            => ntsGroups.FirstOrDefault(group => group.Id == Id);

        #endregion

        #region NTSGroupsJSON()

        /// <summary>
        /// Every group of time servers of this node, as a page lists them in
        /// its tabs - and the names it may suggest for one more.
        /// </summary>
        /// <remarks>
        /// The name a page shows is the page's to choose, by its language,
        /// from the display name; a group without one is "&lt;id&gt; time".
        /// </remarks>
        public JObject NTSGroupsJSON()
        {

            var groups = ntsGroups;

            return new JObject(
                       new JProperty("groups",     new JArray(groups.Select(NTSGroupJSON))),
                       new JProperty("suggested",  new JArray(NTSSection.SuggestedIds.Where(id => groups.All(group => group.Id != id)))),
                       new JProperty("limits",     new JObject(
                           new JProperty("maxIdLength",           NTSSection.MaxIdLength),
                           new JProperty("maxDisplayNameLength",  NTSConfiguration.MaxDisplayNameLength)
                       )),
                       new JProperty("file",       ConfigFile.Path)
                   );

        }

        #endregion

        #region NTSGroupJSON(Group)

        /// <summary>
        /// One group in a few words: what it is called, whether it is asked,
        /// whom, and what the last check found.
        /// </summary>
        public JObject NTSGroupJSON(NTSGroup Group)
        {

            var checkedAt = Group.LastCheck;
            var age       = checkedAt.HasValue ? TimeProvider.GetUtcNow() - checkedAt.Value : (TimeSpan?) null;

            return new JObject(
                       new JProperty("id",            Group.Id),
                       new JProperty("displayName",   Group.DisplayName is { } name ? NTSConfiguration.DisplayNameJSON(name) : null),
                       new JProperty("legal",         Group.IsLegal),
                       new JProperty("enabled",       Group.Enabled),
                       new JProperty("checking",      Group.IsChecking),
                       new JProperty("servers",       new JArray(CheckedAgainst(Group))),
                       new JProperty("minServers",    Group.Sources.MinServers),
                       new JProperty("everySeconds",  Math.Round(Group.CheckEvery.TotalSeconds, 0)),
                       new JProperty("checkedAt",     checkedAt?.ToString("o")),
                       new JProperty("ageSeconds",    age.HasValue ? Math.Round(age.Value.TotalSeconds, 1) : null),
                       new JProperty("offset_ms",     Group.LastCheckOffset.HasValue ? Math.Round(Group.LastCheckOffset.Value.TotalMilliseconds, 1) : null),
                       new JProperty("asked",         Group.LastCheckAsked),
                       new JProperty("answered",      Group.LastCheckAnswered),
                       new JProperty("errorsInARow",  Group.ErrorsInARow),
                       new JProperty("errorLogging",  Group.ErrorLogging),
                       new JProperty("maxErrors",     Group.MaxErrors),
                       new JProperty("limited",       Group.IsLimited)
                   );

        }

        #endregion

        #region TryAddNTSGroup(Id, DisplayName, out Group, out Error, out NotSaved)

        /// <summary>
        /// Make a group of time servers, switched off and naming no server, and
        /// write it into the configuration file.
        /// </summary>
        /// <remarks>
        /// The legal group as well, where this node has none: then it is the
        /// PTB's four again, switched off like any group made here, and legal
        /// time rests on it once it is switched on.
        /// </remarks>
        /// <param name="Id">The group's name: lower-case letters, digits and hyphens, beginning with a letter.</param>
        /// <param name="DisplayName">What a page calls it, by language - "*" for every language - or nothing, for "&lt;id&gt; time".</param>
        /// <param name="Group">The group made.</param>
        /// <param name="Error">Why none was made.</param>
        /// <param name="NotSaved">True where the configuration file could not be read or written: nothing about the group was wrong, and nothing was made.</param>
        public Boolean TryAddNTSGroup(String                                Id,
                                      IReadOnlyDictionary<String, String>?  DisplayName,
                                      [NotNullWhen(true)]  out NTSGroup?    Group,
                                      [NotNullWhen(false)] out String?      Error,
                                      out Boolean                           NotSaved)
        {

            Group     = null;
            NotSaved  = false;

            if (!NTSSection.IsGroupId(Id))
            {
                Error = $"'{Id}' cannot be the name of a group, which is lower-case letters, digits and hyphens, beginning with a letter, and at most {NTSSection.MaxIdLength} of them.";
                return false;
            }

            reconfigureLock.Wait();

            try
            {

                if (NTSGroupOf(Id) is not null)
                {
                    Error = $"This {Kind.Name} has an NTS group '{Id}' already.";
                    return false;
                }

                var configuration  = new NTSConfiguration(Enabled:      false,
                                                          DisplayName:  DisplayName);

                if (!TryWriteNTSGroup(Id, configuration, out Error, out NotSaved))
                    return false;

                // The legal group this node keeps for not having one, which is
                // switched off already and has the PTB's four.
                var group          = Id == NTSGroup.LegalId
                                         ? LegalTime
                                         : NewNTSGroup(Id, configuration);

                group.Enabled      = false;
                group.Settings     = configuration;

                ntsGroups          = [ .. ntsGroups, group ];

                LogTime(group, LogLevel.Notice, $"NTS group '{Id}' added, switched off.", "nts", "config");

                Group = group;
                return true;

            }
            finally
            {
                reconfigureLock.Release();
            }

        }

        #endregion

        #region TryRemoveNTSGroupAsync(Id)

        /// <summary>
        /// Take a group of time servers away, while it is switched off: end
        /// everything that runs for it, and take it out of the configuration
        /// file.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Out of the file and out of the list first, under the reconfiguration
        /// lock, so that from then on nothing finds the group to begin anything
        /// with. Then its timer and the checks still running against it - a
        /// "Sync now" somebody pressed before switching it off, or the last
        /// check the timer began - are cancelled and waited for, outside the
        /// lock: a check on its way out may be learning a server's pin, which
        /// takes the lock.
        /// </para>
        /// <para>
        /// The key exchange of each of its servers is forgotten, and what was
        /// made of its certificate, where no other group asks that server; what
        /// it was last believed with is kept, which is history and not state.
        /// </para>
        /// <para>
        /// The legal group taken away is replaced by one switched off and
        /// listed nowhere, the PTB's four: <see cref="LegalTime"/> is never
        /// null, and what asks about legal time is told it is switched off.
        /// </para>
        /// </remarks>
        /// <param name="Id">The group's name.</param>
        /// <returns>Whether it was taken away; why not; and whether that was the file's doing rather than the request's.</returns>
        public async Task<(Boolean Removed, String? Error, Boolean NotSaved)> TryRemoveNTSGroupAsync(String Id)
        {

            NTSGroup? group;

            await reconfigureLock.WaitAsync();

            try
            {

                group = NTSGroupOf(Id);

                if (group is null)
                    return (false, $"This {Kind.Name} has no NTS group '{Id}'.", false);

                if (group.Enabled)
                    return (false, $"NTS group '{Id}' is switched on: switch it off before removing it.", false);

                if (!TryWriteNTSSection(section => NTSSection.WithoutGroup(section, Id), out var error, out var notSaved))
                    return (false, error, notSaved);

                ntsGroups = [ .. ntsGroups.Where(other => other != group) ];

                if (group.IsLegal)
                    LegalTime = NewLegalTime();

            }
            finally
            {
                reconfigureLock.Release();
            }

            await group.DisposeAsync();

            var stillAsked = ntsGroups.SelectMany(other => other.Sources.Sources).Select(source => source.Hostname).ToHashSet();

            foreach (var source in group.Sources.Sources.Where(source => !stillAsked.Contains(source.Hostname)))
            {
                timeEngine.ForgetKeyExchange(source.Hostname);
                judgements.TryRemove((CertificateUsages.NTS, source.Hostname.Trimmed.ToLowerInvariant()), out _);
            }

            // Its client, with the cookies of a key exchange nobody will spend.
            // The node's NTSClient is the client of the legal group that took
            // this one's place, where this was the legal one.
            group.Client = null;

            LogTime(group,
                    LogLevel.Notice,
                    group.IsLegal
                        ? $"NTS group '{Id}' removed: this {Kind.Name} has no legal time from now on."
                        : $"NTS group '{Id}' removed.",
                    "nts", "config");

            return (true, null, false);

        }

        #endregion

        #region (private) NewLegalTime()

        /// <summary>
        /// A legal group for a node that has none: the PTB's four, switched off,
        /// with a client for the first of them.
        /// </summary>
        private NTSGroup NewLegalTime()
        {

            var hostname  = DomainName.Parse(NTSConfiguration.DefaultHostname);

            var legal     = new NTSGroup(
                                NTSGroup.LegalId,
                                NTSConfiguration.DefaultGroup(),
                                new NTSClient(
                                    hostname,
                                    RemoteCertificateValidator:  TimeServerValidator(hostname),
                                    Timeout:                     DefaultNTSTimeout,
                                    DNSClient:                   dnsClient,
                                    TimeProvider:                TimeProvider
                                )
                            ) {
                                Enabled = false
                            };

            AttachValidators(legal.Sources);

            return legal;

        }

        #endregion

    }

}
