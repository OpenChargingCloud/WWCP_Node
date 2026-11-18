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

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// What every listener of a node shows, one <see cref="ListenerCertificate"/>
    /// each, and the clock that notices when what they show changes by itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A listener shows another certificate without anybody touching the
    /// store: one put in ahead of time becomes valid, one runs out. The
    /// choice itself is made again at every handshake and needs nobody to
    /// notice - but somebody has to say it in the log, and a listener that
    /// does not ask at every handshake - an HTTP/3 listener, whose certificate
    /// is handed over once when it starts - has to be told. So the store is
    /// looked at by the node's clock every <see cref="CheckEvery"/>, and right
    /// after every change of it: an identity that became valid or ran out is
    /// said, and a listener that shows another certificate than before raises
    /// <see cref="OnShownChanged"/>.
    /// </para>
    /// <para>
    /// By the node's clock, and only by it: a test moves it, and a node whose
    /// clock is wrong is wrong about this the way it is about everything else,
    /// which its log will say elsewhere.
    /// </para>
    /// </remarks>
    public sealed class ListenerCertificates : IDisposable
    {

        #region Data

        /// <summary>
        /// How often the store is looked at by default: every half minute,
        /// which says a change within half a minute of it and costs a look into
        /// a list of a handful.
        /// </summary>
        /// <remarks>
        /// Not a minute, which is how long the clock check of an NTS group
        /// waits first: a node's timers are told apart by how long they wait,
        /// by the tests that count them.
        /// </remarks>
        public static readonly TimeSpan DefaultCheckEvery = TimeSpan.FromSeconds(30);

        private readonly CertificateStore                                    store;
        private readonly TimeProvider                                        clock;
        private readonly EventLog                                            log;

        private readonly Lock                                                checkLock        = new ();
        private readonly Dictionary<CertificateUsage, ListenerCertificate>  listeners        = [];
        private readonly HashSet<CertificateUsage>                           keepServingLast  = [];
        private          Dictionary<String, String>                          validity         = [];
        private readonly Dictionary<CertificateUsage, String?>               shown            = [];
        private          ITimer?                                             timer;

        #endregion

        #region Properties

        /// <summary>
        /// How often the store is looked at.
        /// </summary>
        public TimeSpan CheckEvery { get; }

        /// <summary>
        /// Every listener that goes on showing the last certificate it showed
        /// where nothing is valid.
        /// </summary>
        public IReadOnlyList<CertificateUsage> KeepServingLastOn
        {
            get
            {
                lock (checkLock)
                    return [.. keepServingLast.OrderBy(listener => listener.ToString(), StringComparer.Ordinal)];
            }
        }

        /// <summary>
        /// Every listener asked for so far, by name.
        /// </summary>
        public IReadOnlyList<CertificateUsage> Listeners
        {
            get
            {
                lock (checkLock)
                    return [.. listeners.Keys.OrderBy(listener => listener.ToString(), StringComparer.Ordinal)];
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// A listener shows another certificate than before - or none, or one
        /// after none: the listener, what it showed, and what it shows now.
        /// </summary>
        /// <remarks>
        /// Raised outside every lock, after the store changed or the clock
        /// moved a certificate in or out of its validity, for what does not
        /// ask at every handshake - an HTTP/3 listener restarted with the new
        /// one. A handler that throws is caught and complained about.
        /// </remarks>
        public event Action<CertificateUsage, CertificateEntry?, CertificateEntry?>? OnShownChanged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// What every listener of a node shows, out of its store.
        /// </summary>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Clock">The node's clock, which the store is looked at by.</param>
        /// <param name="Log">Where a change is said.</param>
        /// <param name="CheckEvery">How often the store is looked at; <see cref="DefaultCheckEvery"/> by default.</param>
        public ListenerCertificates(CertificateStore  Store,
                                    TimeProvider      Clock,
                                    EventLog          Log,
                                    TimeSpan?         CheckEvery   = null)
        {

            this.store       = Store;
            this.clock       = Clock;
            this.log         = Log;
            this.CheckEvery  = CheckEvery ?? DefaultCheckEvery;

            lock (checkLock)
                validity = ValidityNow();

            store.OnChanged += Check;

        }

        #endregion


        #region For(Listener, ShownOn = null)

        /// <summary>
        /// The certificate a listener shows - the same one for every caller,
        /// made at the first.
        /// </summary>
        /// <param name="Listener">The listener, e.g. "web" or "ocpp".</param>
        /// <param name="ShownOn">What the listener is called in a sentence, where it is made now.</param>
        public ListenerCertificate For(CertificateUsage  Listener,
                                       String?           ShownOn = null)
        {

            ListenerCertificate? made;

            lock (checkLock)
            {

                if (listeners.TryGetValue(Listener, out var known))
                    return known;

                made = new ListenerCertificate(store, Listener, log, ShownOn, keepServingLast.Contains(Listener));

                listeners[Listener] = made;

            }

            // What it shows from the start is not a change.
            var entry = made.Entry;

            lock (checkLock)
                shown[Listener] = entry?.Id;

            return made;

        }

        #endregion

        #region KeepServingLast(Listener)

        /// <summary>
        /// Have a listener go on showing the last certificate it showed where
        /// nothing is valid, rather than nothing - see <see cref="ListenerCertificate"/>.
        /// </summary>
        /// <param name="Listener">The listener, e.g. "ocpp".</param>
        public void KeepServingLast(CertificateUsage Listener)
        {
            lock (checkLock)
            {

                keepServingLast.Add(Listener);

                if (listeners.TryGetValue(Listener, out var known))
                    known.KeepsServingLast = true;

            }
        }

        #endregion

        #region StartChecking() / StopChecking()

        /// <summary>
        /// Look at the store every <see cref="CheckEvery"/> from now on.
        /// </summary>
        public void StartChecking()
        {
            lock (checkLock)
                timer ??= clock.CreateTimer(_ => Check(), null, CheckEvery, CheckEvery);
        }

        /// <summary>
        /// Look at the store no more by the clock; a change of the store is
        /// still looked at.
        /// </summary>
        public void StopChecking()
        {

            ITimer? stopped;

            lock (checkLock)
            {
                stopped = timer;
                timer   = null;
            }

            stopped?.Dispose();

        }

        #endregion

        #region Check()

        /// <summary>
        /// Look at the store now: say every TLS server identity that became
        /// valid or ran out since the last look, and tell whoever follows of
        /// every listener that shows another certificate than before.
        /// </summary>
        public void Check()
        {

            var changes = new List<(CertificateUsage Listener, CertificateEntry? Before, CertificateEntry? After)>();

            lock (checkLock)
            {

                #region What became valid, and what ran out

                var now = ValidityNow();

                foreach (var (id, state) in now)
                {

                    if (!validity.TryGetValue(id, out var was) || was == state)
                        continue;

                    var entry = store.Get(id, CertificateKind.TLSServerIdentity);

                    if (entry is null)
                        continue;

                    if (state == "valid")
                        log.Metrological(LogLevel.Notice,
                                         $"Certificates: the TLS server identity '{entry.Label}' ({entry.Id}) is valid from now on, until {entry.NotAfter.UtcDateTime:yyyy-MM-dd HH:mm} UTC.",
                                         "certificates", "tls", "security");

                    else if (state == "expired")
                        log.Metrological(LogLevel.Warning,
                                         $"Certificates: the TLS server identity '{entry.Label}' ({entry.Id}) ran out on {entry.NotAfter.UtcDateTime:yyyy-MM-dd HH:mm} UTC.",
                                         "certificates", "tls", "security");

                }

                validity = now;

                #endregion

                #region What every listener shows now

                foreach (var (listener, certificate) in listeners)
                {

                    var after   = certificate.Choose();
                    var before  = shown.GetValueOrDefault(listener);

                    if (before == after?.Entry.Id)
                        continue;

                    shown[listener] = after?.Entry.Id;

                    var was = before is not null ? store.Get(before, CertificateKind.TLSServerIdentity) : null;

                    changes.Add((listener, was, after?.Entry));

                    if (after is null)
                        log.Metrological(LogLevel.Error,
                                         $"Certificates: the listener '{listener}' has no certificate to show any more.",
                                         "certificates", "tls", "security");

                    else
                        log.Metrological(after.IsKeptOn ? LogLevel.Warning : LogLevel.Notice,
                                         $"Certificates: the listener '{listener}' shows '{after.Entry.Label}' ({after.Entry.Id}) from now on" +
                                         (after.IsCarrier ? ", the carrier of its server key" : "") +
                                         (after.IsKeptOn  ? ", although it is not valid: nothing else is, and this listener keeps serving the last" : "") +
                                         (before is not null ? $", in place of '{was?.Label ?? before}'." : "."),
                                         "certificates", "tls", "security");

                }

                #endregion

            }

            foreach (var (listener, before, after) in changes)
            {
                try
                {
                    OnShownChanged?.Invoke(listener, before, after);
                }
                catch (Exception e)
                {
                    log.Warning($"Certificates: whoever follows what the listener '{listener}' shows failed - {e.Message}", "certificates");
                }
            }

        }

        #endregion

        #region Dispose()

        /// <summary>
        /// Stop looking, and let go of every certificate read.
        /// </summary>
        public void Dispose()
        {

            StopChecking();

            store.OnChanged -= Check;

            List<ListenerCertificate> all;

            lock (checkLock)
            {
                all = [.. listeners.Values];
                listeners.Clear();
            }

            foreach (var certificate in all)
                certificate.Dispose();

        }

        #endregion


        #region (private) ValidityNow()

        /// <summary>
        /// Every TLS server identity that is switched on, and whether it is
        /// "pending", "valid" or "expired" by the store's clock now.
        /// </summary>
        private Dictionary<String, String> ValidityNow()
        {

            var now = store.Clock.GetUtcNow();

            return store.ByKind(CertificateKind.TLSServerIdentity).
                         Where           (entry => entry.IsActive).
                         DistinctBy      (entry => entry.Id).
                         ToDictionary    (entry => entry.Id,
                                          entry => entry.IsNotYetValidAt(now) ? "pending"
                                                       : entry.IsExpiredAt(now) ? "expired"
                                                       : "valid");

        }

        #endregion

    }

}
