/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.KeyPins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Connections
{

    /// <summary>
    /// Trust on first use by asking (mDNS-Concept.md, B.4): the key the server
    /// of a connection showed is written down and waits for an admin, who
    /// confirms it - and it is pinned - or turns it down - and the connection
    /// is not made until somebody saves it again.
    /// </summary>
    public sealed partial class ConnectionStore
    {

        #region TryAwaitHostKey(Id, URL, HostKey, out Error)

        /// <summary>
        /// Write down the host key the server of an ssh:// connection that trusts
        /// on first use by asking showed: it waits for an admin from now on - in
        /// place of the one that waited before, where it is another one (Q7).
        /// </summary>
        /// <param name="Id">The connection.</param>
        /// <param name="URL">Where it went when its server showed the key.</param>
        /// <param name="HostKey">The SHA-256 fingerprint of the host key.</param>
        /// <param name="Error">Why it was not written down - nothing where it was not to be.</param>
        /// <returns>Whether it was written down.</returns>
        public Boolean TryAwaitHostKey(String       Id,
                                       URL          URL,
                                       String       HostKey,
                                       out String?  Error)
        {

            Error = null;

            lock (updateLock)
            {

                if (!connections.TryGetValue(Id, out var entry)                                ||
                    entry.URL != URL                                                           ||
                    entry.URL.Scheme != URIScheme.ssh                                          ||
                    entry.EffectiveSshTrustOnFirstUse != SshTrustOnFirstUse.Ask                ||
                    entry.SshHostKey is not null                                               ||
                    entry.SshAwaitingHostKey == HostKey)
                {
                    return false;
                }

                var before       = entry.SshAwaitingHostKey;
                var beforeSince  = entry.SshAwaitingSince;

                entry.SshAwaitingHostKey  = HostKey;
                entry.SshAwaitingSince    = TimeProvider.GetUtcNow();

                if (!TrySaveConnections(out Error))
                {
                    entry.SshAwaitingHostKey  = before;
                    entry.SshAwaitingSince    = beforeSince;
                    return false;
                }

                Notice(LogLevel.Warning,
                       $"'{entry.Description.FirstText()}' was shown the host key {HostKey} by its server" +
                       (before is not null ? $", in place of {before}, which waited before" : "") +
                        ". It waits for an admin to confirm it; nothing goes over the connection until then.");

                return true;

            }

        }

        #endregion

        #region TryAwaitServerKeyPin(Id, URL, Pin, out Error)

        /// <summary>
        /// Write down the key pin of the key the server of a wss:// connection
        /// that trusts on first use by asking showed: it waits for an admin from
        /// now on - in place of the one that waited before, where it is another
        /// one (Q7).
        /// </summary>
        /// <param name="Id">The connection.</param>
        /// <param name="URL">Where it went when its server showed the key.</param>
        /// <param name="Pin">The key pin of the key.</param>
        /// <param name="NotWritten">Why it was not written down - nothing where it was not to be.</param>
        /// <returns>Whether it was written down.</returns>
        public Boolean TryAwaitServerKeyPin(String       Id,
                                            URL          URL,
                                            KeyPin       Pin,
                                            out String?  NotWritten)
        {

            NotWritten = null;

            lock (updateLock)
            {

                if (!connections.TryGetValue(Id, out var entry)                               ||
                    entry.URL != URL                                                          ||
                    entry.EffectiveTrustOnFirstUse != KeyTrustOnFirstUse.Ask                   ||
                    entry.ServerKeyPins.Count > 0                                             ||
                    Pin.Equals(entry.ServerKeyPinAwaiting))
                {
                    return false;
                }

                var before       = entry.ServerKeyPinAwaiting;
                var beforeSince  = entry.ServerKeyPinAwaitingSince;

                entry.ServerKeyPinAwaiting       = Pin;
                entry.ServerKeyPinAwaitingSince  = TimeProvider.GetUtcNow();

                if (!TrySaveConnections(out NotWritten))
                {
                    entry.ServerKeyPinAwaiting       = before;
                    entry.ServerKeyPinAwaitingSince  = beforeSince;
                    return false;
                }

                Notice(LogLevel.Warning,
                       $"'{entry.Description.FirstText()}' was shown a key whose key pin is {Pin} by its server" +
                       (before is not null ? $", in place of {before}, which waited before" : "") +
                        ". It waits for an admin to confirm it; nothing goes over the connection until then.");

                return true;

            }

        }

        #endregion

        #region TryConfirmKey(Id, ConfirmedBy, Expected, out Confirmed, out Error)

        /// <summary>
        /// An admin confirms the key that waits for it - or one learned on first
        /// use and still on probation: it is pinned from now on, with who
        /// confirmed it and when (Q6), and the connection is made again with it.
        /// </summary>
        /// <param name="Id">The connection.</param>
        /// <param name="ConfirmedBy">Who confirmed it: the account.</param>
        /// <param name="Expected">The fingerprint or key pin that was shown to whoever confirms it; another one waiting now is not confirmed. Null for whichever waits.</param>
        /// <param name="Confirmed">The fingerprint or key pin confirmed.</param>
        /// <param name="Error">Why nothing was confirmed.</param>
        public Boolean TryConfirmKey(String?                           Id,
                                     String                            ConfirmedBy,
                                     String?                           Expected,
                                     out String?                       Confirmed,
                                     [NotNullWhen(false)] out String?  Error)
        {

            Confirmed = null;

            lock (updateLock)
            {

                if (Id is null || !connections.TryGetValue(Id, out var entry))
                {
                    Error = $"There is no connection '{Id}' here.";
                    return false;
                }

                var was = entry.Copy();

                if (entry.IsSSH)
                {

                    var key = entry.SshAwaitingHostKey ?? entry.SshLearnedHostKey;

                    if (key is null)
                    {
                        Error = $"No host key of '{entry.Description.FirstText()}' waits to be confirmed.";
                        return false;
                    }

                    if (Expected is not null && !String.Equals(Expected.Trim(), key, StringComparison.Ordinal))
                    {
                        Error = $"The host key that waits now is {key}, not {Expected.Trim()}: look at it again before you confirm it.";
                        return false;
                    }

                    entry.SshHostKey          = key;
                    entry.SshAwaitingHostKey  = null;
                    entry.SshAwaitingSince    = null;
                    entry.SshLearnedHostKey   = null;
                    entry.SshLearnedAt        = null;
                    Confirmed                 = key;

                }

                else
                {

                    var pin = entry.ServerKeyPinAwaiting ?? entry.ServerKeyPinLearned;

                    if (pin is null)
                    {
                        Error = $"No key pin of '{entry.Description.FirstText()}' waits to be confirmed.";
                        return false;
                    }

                    if (Expected is not null && !(KeyPin.TryParse(Expected, out var expected) && expected.Equals(pin)))
                    {
                        Error = $"The key pin that waits now is {pin}, not {Expected.Trim()}: look at it again before you confirm it.";
                        return false;
                    }

                    entry.ServerKeyPins              = [ pin ];
                    entry.ServerKeyPinsConfirmed     = true;
                    entry.ServerKeyPinAwaiting       = null;
                    entry.ServerKeyPinAwaitingSince  = null;
                    entry.ServerKeyPinLearned        = null;
                    entry.ServerKeyPinLearnedAt      = null;
                    Confirmed                        = pin.ToString();

                }

                entry.KeyConfirmedBy  = ConfirmedBy;
                entry.KeyConfirmedAt  = TimeProvider.GetUtcNow();
                entry.KeyRejected     = null;
                entry.KeyRejectedBy   = null;
                entry.KeyRejectedAt   = null;

                var revisionWas = BumpConnectionRevision(entry.Id);

                if (!TrySaveConnections(out Error))
                {
                    connections[entry.Id]          = was;
                    connectionRevisions[entry.Id]  = revisionWas;
                    return false;
                }

                Notice(LogLevel.Notice,
                       $"'{was.Description.FirstText()}': {ConfirmedBy} confirmed the {(was.IsSSH ? "host key" : "key pin")} {Confirmed}, which is pinned " +
                        "from now on; the connection is made again with it.");

                Error = null;
                return true;

            }

        }

        #endregion

        #region TryRejectKey(Id, RejectedBy, out Rejected, out Error)

        /// <summary>
        /// An admin turns down the key that waits for it - or one learned on
        /// first use and still on probation: it is forgotten, and the connection
        /// is not made until somebody saves it again or confirms a key.
        /// </summary>
        /// <param name="Id">The connection.</param>
        /// <param name="RejectedBy">Who turned it down: the account.</param>
        /// <param name="Rejected">The fingerprint or key pin turned down.</param>
        /// <param name="Error">Why nothing was turned down.</param>
        public Boolean TryRejectKey(String?                           Id,
                                    String                            RejectedBy,
                                    out String?                       Rejected,
                                    [NotNullWhen(false)] out String?  Error)
        {

            Rejected = null;

            lock (updateLock)
            {

                if (Id is null || !connections.TryGetValue(Id, out var entry))
                {
                    Error = $"There is no connection '{Id}' here.";
                    return false;
                }

                var was = entry.Copy();

                Rejected = entry.SshAwaitingHostKey ?? entry.SshLearnedHostKey ?? (entry.ServerKeyPinAwaiting ?? entry.ServerKeyPinLearned)?.ToString();

                if (Rejected is null)
                {
                    Error = $"No key of '{entry.Description.FirstText()}' waits to be confirmed or turned down.";
                    return false;
                }

                entry.SshAwaitingHostKey         = null;
                entry.SshAwaitingSince           = null;
                entry.SshLearnedHostKey          = null;
                entry.SshLearnedAt               = null;
                entry.ServerKeyPinAwaiting       = null;
                entry.ServerKeyPinAwaitingSince  = null;
                entry.ServerKeyPinLearned        = null;
                entry.ServerKeyPinLearnedAt      = null;
                entry.KeyRejected                = Rejected;
                entry.KeyRejectedBy              = RejectedBy;
                entry.KeyRejectedAt              = TimeProvider.GetUtcNow();

                var revisionWas = BumpConnectionRevision(entry.Id);

                if (!TrySaveConnections(out Error))
                {
                    connections[entry.Id]          = was;
                    connectionRevisions[entry.Id]  = revisionWas;
                    return false;
                }

                Notice(LogLevel.Warning,
                       $"'{was.Description.FirstText()}': {RejectedBy} turned down the {(was.IsSSH ? "host key" : "key pin")} {Rejected}. The connection " +
                        "is not made until somebody saves it again or confirms a key.");

                Error = null;
                return true;

            }

        }

        #endregion

    }

}
