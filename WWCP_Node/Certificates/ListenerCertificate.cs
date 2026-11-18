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

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// What a listener shows, as it was chosen: the identity of the store,
    /// its certificate as a TLS server takes it, and why it is that one.
    /// </summary>
    /// <param name="Entry">The identity of the store.</param>
    /// <param name="Chain">Its certificate with its key, and its intermediates.</param>
    /// <param name="IsCarrier">Whether it is the carrier of the listener's current server key, shown where no certificate issued for the key is valid.</param>
    /// <param name="IsKeptOn">Whether nothing is valid and it is shown all the same - the last shown, or the one that lasted longest - by a listener that keeps serving the last.</param>
    public sealed record ShownCertificate(CertificateEntry        Entry,
                                          ServerCertificateChain  Chain,
                                          Boolean                 IsCarrier,
                                          Boolean                 IsKeptOn)
    {

        /// <summary>
        /// What the key is shown in, as the JSON API says it: "carrier" or
        /// "certificate".
        /// </summary>
        public String PresentedAs
            => IsCarrier ? "carrier" : "certificate";

    }


    /// <summary>
    /// The certificate one listener of a node shows at every handshake, out
    /// of the node's certificate store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The choice.</b> Where the listener has a current server key - see
    /// <see cref="CertificateStore.TryCreateServerKey(String, String?, Boolean, out ServerKey?, out String?)"/> -
    /// the newest certificate issued for that key that is switched on and
    /// valid now, and the key's carrier where there is none: a client that
    /// pinned the key gets the key either way, and one that checks chains gets
    /// a chain whenever there is one. Where it has none, the TLS server
    /// identities told the listener, or told no listener, that are switched on
    /// and valid now, the one whose validity began last - as the web interface
    /// has always chosen, so that a certificate put in before the old one runs
    /// out takes over on the day it becomes valid, without anybody being there.
    /// </para>
    /// <para>
    /// <b>Asked at every handshake, loaded once.</b> Which one is a look into a
    /// list of a handful, by the store's clock. Its file is read once and the
    /// certificate kept until the store changes - on Windows a certificate is
    /// read into a key store of the user's, and doing that at every handshake
    /// would leave one more there at each. The certificates read before a
    /// change are let go of at the change after it rather than at once, so
    /// that a handshake that took one just before the change is not left
    /// holding a certificate whose key is gone.
    /// </para>
    /// <para>
    /// <b>Keeping on serving the last</b> is for a listener whose clients are
    /// better served by an expired certificate than by none - a charging
    /// station, which cannot reach anybody to be given a new one if its CSMS
    /// connection is refused: with nothing valid, such a listener shows the
    /// certificate it showed last, or on a fresh start the one that lasted
    /// longest, and is never left with nothing while the store holds anything
    /// it could show. A web interface is not such a listener: a browser that is
    /// refused says why, and somebody can do something about it.
    /// </para>
    /// </remarks>
    public sealed class ListenerCertificate : IDisposable
    {

        #region Data

        private readonly CertificateStore                              store;
        private readonly EventLog                                      log;
        private readonly String                                        shownOn;

        private readonly Lock                                          cacheLock  = new ();
        private readonly Dictionary<String, ServerCertificateChain?>   loaded     = [];
        private          List<ServerCertificateChain>                  retired    = [];
        private          String?                                       lastShown;
        private          Boolean                                       disposed;

        #endregion

        #region Properties

        /// <summary>
        /// The listener whose certificate this is, e.g. "web" or "ocpp".
        /// </summary>
        public CertificateUsage  Listener            { get; }

        /// <summary>
        /// Whether this listener goes on showing the last certificate it showed
        /// where nothing is valid, rather than nothing - see the remarks on
        /// this class.
        /// </summary>
        public Boolean           KeepsServingLast    { get; internal set; }

        /// <summary>
        /// The identities of the store the listener could show now, the one it
        /// shows first - without the one kept on where none of them can be.
        /// </summary>
        public IReadOnlyList<CertificateEntry> Candidates
        {
            get
            {

                var now = store.Clock.GetUtcNow();

                if (store.GetCurrentAndNextKey(Listener, out _) is ServerKey key)
                {

                    var carrier = store.CarrierOf(key);

                    return [.. store.IssuedFor(key).
                                     Where            (entry => entry.IsUsableAt(now)).
                                     OrderByDescending(entry => entry.NotBefore).
                                     ThenByDescending (entry => entry.NotAfter).
                                     ThenByDescending (entry => entry.Id, StringComparer.Ordinal),
                            .. carrier is null ? Array.Empty<CertificateEntry>() : new[] { carrier }];

                }

                return [.. store.UsableFor(CertificateKind.TLSServerIdentity, Listener).
                                 OrderByDescending(entry => entry.NotBefore).
                                 ThenByDescending (entry => entry.NotAfter).
                                 ThenByDescending (entry => entry.Id, StringComparer.Ordinal)];

            }
        }

        /// <summary>
        /// What the listener shows now, with its intermediates, or null while
        /// there is nothing to show.
        /// </summary>
        public ServerCertificateChain? Current
            => Choose()?.Chain;

        /// <summary>
        /// The identity of the store the listener shows now, or null.
        /// </summary>
        public CertificateEntry? Entry
            => Choose()?.Entry;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The certificate one listener of a node shows.
        /// </summary>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Listener">The listener, e.g. "web" or "ocpp".</param>
        /// <param name="Log">Where a certificate that cannot be read is said.</param>
        /// <param name="ShownOn">What the listener is called in a sentence, e.g. "the web interface"; "the listener '...'" by default.</param>
        /// <param name="KeepServingLast">Whether it goes on showing the last certificate it showed where nothing is valid.</param>
        public ListenerCertificate(CertificateStore  Store,
                                   CertificateUsage  Listener,
                                   EventLog          Log,
                                   String?           ShownOn           = null,
                                   Boolean           KeepServingLast   = false)
        {

            this.store             = Store;
            this.log               = Log;
            this.Listener          = Listener;
            this.shownOn           = ShownOn ?? $"the listener '{Listener}'";
            this.KeepsServingLast  = KeepServingLast;

            store.OnChanged       += Forget;

        }

        #endregion


        #region Choose()

        /// <summary>
        /// What the listener shows now, and why that one - or null where there
        /// is nothing it could show.
        /// </summary>
        public ShownCertificate? Choose()
        {

            var key = store.GetCurrentAndNextKey(Listener, out _);

            foreach (var entry in Candidates)
            {
                if (Load(entry) is ServerCertificateChain chain)
                {
                    Remember(entry);
                    return new ShownCertificate(entry, chain, entry.Id == key?.CarrierId, IsKeptOn: false);
                }
            }

            if (!KeepsServingLast)
                return null;

            // Nothing valid. What was shown last goes on being shown where it
            // is still here and switched on; a fresh start in this state takes
            // the one that lasted longest. Never a certificate of a server key
            // that is not current, which its clients may not have pinned.
            String? last;

            lock (cacheLock)
                last = lastShown;

            var keptOn = (last is not null ? store.Get(last, CertificateKind.TLSServerIdentity) : null) is CertificateEntry before &&
                         before.IsActive && before.IsFor(Listener) && store.ServerKeyOf(before) is null
                             ? before
                             : null;

            foreach (var entry in (keptOn is not null ? new[] { keptOn } : Array.Empty<CertificateEntry>()).
                                  Concat(store.ByKind(CertificateKind.TLSServerIdentity).
                                               Where            (entry => entry.IsActive         &&
                                                                          entry.HasPrivateKey    &&
                                                                          entry.IsFor(Listener)  &&
                                                                          store.ServerKeyOf(entry) is null).
                                               OrderByDescending(entry => entry.NotAfter).
                                               ThenByDescending (entry => entry.Id, StringComparer.Ordinal)))
            {
                if (Load(entry) is ServerCertificateChain chain)
                {
                    Remember(entry);
                    return new ShownCertificate(entry, chain, IsCarrier: false, IsKeptOn: true);
                }
            }

            return null;

        }

        #endregion

        #region Dispose()

        /// <summary>
        /// Let go of every certificate read, and of the store.
        /// </summary>
        public void Dispose()
        {

            store.OnChanged -= Forget;

            lock (cacheLock)
            {

                disposed = true;

                foreach (var chain in retired.Concat(loaded.Values.OfType<ServerCertificateChain>()))
                    Release(chain);

                retired.Clear();
                loaded. Clear();

            }

        }

        #endregion


        #region (private) Load(Entry) / Remember(Entry) / Forget()

        /// <summary>
        /// The identity of an entry as a TLS server takes it, or null where it
        /// cannot be read - read once until the store changes.
        /// </summary>
        private ServerCertificateChain? Load(CertificateEntry Entry)
        {

            lock (cacheLock)
                if (loaded.TryGetValue(Entry.Thumbprint, out var known))
                    return known;

            ServerCertificateChain? chain = null;

            try
            {
                var path  = store.FullPath(Entry);
                chain     = ServerCertificateChain.FromPkcs12(File.ReadAllBytes(path), null, path);
            }
            catch (Exception e)
            {
                log.Warning($"The TLS server identity '{Entry.Label}' cannot be shown on {shownOn}: {e.Message}", "tls", "security");
            }

            lock (cacheLock)
            {

                // Read twice at once: the first one read is the one kept.
                if (loaded.TryGetValue(Entry.Thumbprint, out var meanwhile))
                {
                    if (chain is not null)
                        Release(chain);
                    return meanwhile;
                }

                if (disposed)
                {
                    if (chain is not null)
                        Release(chain);
                    return null;
                }

                loaded[Entry.Thumbprint] = chain;

            }

            return chain;

        }

        private void Remember(CertificateEntry Entry)
        {
            lock (cacheLock)
                lastShown = Entry.Id;
        }

        /// <summary>
        /// The store changed: what was read is read again when it is asked for,
        /// and what was read before the change before is let go of now.
        /// </summary>
        private void Forget()
        {
            lock (cacheLock)
            {

                foreach (var chain in retired)
                    Release(chain);

                retired = [.. loaded.Values.OfType<ServerCertificateChain>()];
                loaded.Clear();

            }
        }

        private static void Release(ServerCertificateChain Chain)
        {

            Chain.Certificate.Dispose();

            foreach (var intermediate in Chain.Intermediates)
                intermediate.Dispose();

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Entry is CertificateEntry entry
                   ? $"{shownOn}: '{entry.Label}' ({entry.Id})"
                   : $"{shownOn}: nothing";

        #endregion

    }

}
