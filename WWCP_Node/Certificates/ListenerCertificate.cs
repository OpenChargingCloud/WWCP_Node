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

using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

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
    /// certificate kept for as long as it is in the store - on Windows a
    /// certificate is read into a key store of the user's, and doing that at
    /// every handshake would leave one more there at each. A server may keep
    /// what it was handed, as one that builds a TLS context per certificate
    /// does, and is not left holding a certificate whose key is gone: a change
    /// of the store - another certificate taken in, a usage told, a server key
    /// switched - lets go of nothing that is still in it. A certificate taken
    /// out of the store is let go of at the change after the one that took it
    /// out rather than at once, so that a handshake that took it just before
    /// is not cut off; everything is let go of when this is disposed of.
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
    /// <para>
    /// <b>Only what this machine can present.</b> A certificate that can be
    /// read is not yet one a handshake can be made with: Windows' TLS stack,
    /// for one, has the curve P-521 switched off unless somebody switched it
    /// on, and reads such an identity without a word. Every certificate is
    /// asked <see cref="KeyAlgorithm.CanBePresented"/> once, as it is first
    /// read; one that cannot be presented is said once in the log and passed
    /// over as one that cannot be read is - also by a listener that keeps
    /// serving the last, which would otherwise keep on showing what no client
    /// gets through.
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
        private readonly Dictionary<String, Boolean>                   presentable = [];
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
        /// Whether this machine can present a certificate with its key over
        /// TLS, by the identification of its key algorithm - Hermod's
        /// <see cref="KeyAlgorithm.CanBePresented"/>, which finds out by trying;
        /// a test's own answer in its place.
        /// </summary>
        internal Func<String, X509Certificate2, Boolean> CanBePresented { get; set; } = KeyAlgorithm.CanBePresented;

        /// <summary>
        /// The identities of the store the listener could show now, the one it
        /// shows first - without the one kept on where none of them can be, and
        /// without those found to be ones this machine cannot present.
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
                                     Where            (entry => entry.IsUsableAt(now) && !IsKnownUnpresentable(entry)).
                                     OrderByDescending(entry => entry.NotBefore).
                                     ThenByDescending (entry => entry.NotAfter).
                                     ThenByDescending (entry => entry.Id, StringComparer.Ordinal),
                            .. carrier is null || IsKnownUnpresentable(carrier) ? Array.Empty<CertificateEntry>() : new[] { carrier }];

                }

                return [.. store.UsableFor(CertificateKind.TLSServerIdentity, Listener).
                                 Where            (entry => !IsKnownUnpresentable(entry)).
                                 OrderByDescending(entry => entry.NotBefore).
                                 ThenByDescending (entry => entry.NotAfter).
                                 ThenByDescending (entry => entry.Id, StringComparer.Ordinal)];

            }
        }

        /// <summary>
        /// What the listener shows now, with its intermediates, or null while
        /// there is nothing to show. A caller may hold on to it for as long as
        /// its certificate is in the store - see the remarks on this class.
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
        /// is nothing it could show. The chain in it is this listener's to let
        /// go of: a caller may hold on to it for as long as its certificate is
        /// in the store, and until this is disposed of.
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


        #region (static) AlgorithmIdOf(Leaf, Key = null)

        /// <summary>
        /// What Hermod calls the kind of key a certificate carries - see
        /// <see cref="KeyAlgorithm.All"/> - for asking whether it can be
        /// presented: the server key's own where it is one's, else read off
        /// the certificate; the identification of the key's algorithm where
        /// Hermod has no name for it, and "unknown" where there is none.
        /// </summary>
        /// <param name="Leaf">The certificate.</param>
        /// <param name="Key">The server key it shows, if any.</param>
        internal static String AlgorithmIdOf(X509Certificate2  Leaf,
                                             ServerKey?        Key   = null)
        {

            if (KeyAlgorithm.Find(Key?.Algorithm) is KeyAlgorithm known)
                return known.Id;

            using (var ecdsa = Leaf.GetECDsaPublicKey())
            {
                if (ecdsa is not null)
                {

                    var curve = ecdsa.ExportParameters(false).Curve.Oid;

                    return curve?.Value switch {
                               "1.2.840.10045.3.1.7"  => "ecdsa-p256",
                               "1.3.132.0.34"         => "ecdsa-p384",
                               "1.3.132.0.35"         => "ecdsa-p521",
                               _                      => $"ecdsa-{curve?.Value ?? curve?.FriendlyName ?? ecdsa.KeySize.ToString()}"
                           };

                }
            }

            using (var rsa = Leaf.GetRSAPublicKey())
            {
                if (rsa is not null)
                    return $"rsa-{rsa.KeySize}";
            }

            return Leaf.PublicKey.Oid.Value switch {
                       "1.3.101.112"  => "ed25519",
                       "1.3.101.113"  => "ed448",
                       String oid     => oid,
                       null           => "unknown"
                   };

        }

        #endregion

        #region (private) Load(Entry) / IsKnownUnpresentable(Entry) / Remember(Entry) / Forget()

        /// <summary>
        /// The identity of an entry as a TLS server takes it, or null where it
        /// cannot be read or this machine cannot present it - read once until
        /// the store changes, and asked whether it can be presented once.
        /// </summary>
        private ServerCertificateChain? Load(CertificateEntry Entry)
        {

            lock (cacheLock)
            {

                if (loaded.TryGetValue(Entry.Thumbprint, out var known))
                    return known;

                if (presentable.TryGetValue(Entry.Thumbprint, out var canBe) && !canBe)
                    return null;

            }

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

            if (chain is not null && !IsPresentable(Entry, chain))
            {
                Release(chain);
                chain = null;
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

        /// <summary>
        /// Whether this machine can present a certificate it read - asked once
        /// per certificate, and said once in the log where it cannot.
        /// </summary>
        private Boolean IsPresentable(CertificateEntry        Entry,
                                      ServerCertificateChain  Chain)
        {

            lock (cacheLock)
                if (presentable.TryGetValue(Entry.Thumbprint, out var before))
                    return before;

            String algorithm;

            try
            {
                algorithm = AlgorithmIdOf(Chain.Certificate, store.ServerKeyOf(Entry));
            }
            catch (Exception)
            {
                algorithm = Chain.Certificate.PublicKey.Oid.Value ?? "unknown";
            }

            Boolean canBe;

            try
            {
                canBe = CanBePresented(algorithm, Chain.Certificate);
            }
            catch (Exception)
            {
                canBe = false;
            }

            lock (cacheLock)
            {

                // Asked twice at once: the first answer is the one kept, and said.
                if (presentable.TryAdd(Entry.Thumbprint, canBe) && !canBe)
                    log.Warning($"The TLS server identity '{Entry.Label}' cannot be shown on {shownOn}: its {Entry.KeyAlgorithm} key cannot be " +
                                $"presented over TLS by this machine ('{algorithm}'), every handshake would fail - it is passed over.",
                                "tls", "security");

                return presentable[Entry.Thumbprint];

            }

        }

        /// <summary>
        /// Whether an entry was found to be one this machine cannot present -
        /// kept when the store changes, since the answer is the machine's and
        /// not the store's.
        /// </summary>
        private Boolean IsKnownUnpresentable(CertificateEntry Entry)
        {
            lock (cacheLock)
                return presentable.TryGetValue(Entry.Thumbprint, out var canBe) && !canBe;
        }

        private void Remember(CertificateEntry Entry)
        {
            lock (cacheLock)
                lastShown = Entry.Id;
        }

        /// <summary>
        /// The store changed: what was read and is still in the store is kept,
        /// whatever else changed about it; what was taken out is let go of at
        /// the next change, and what could not be read is tried again.
        /// </summary>
        private void Forget()
        {

            // Called with the store's lock released, so the store may be asked.
            var inTheStore = store.Entries.Select(entry => entry.Thumbprint).ToHashSet(StringComparer.OrdinalIgnoreCase);

            lock (cacheLock)
            {

                if (disposed)
                    return;

                foreach (var chain in retired)
                    Release(chain);

                retired = [];

                foreach (var (thumbprint, chain) in loaded.ToArray())
                {
                    if (chain is null)
                        loaded.Remove(thumbprint);

                    else if (!inTheStore.Contains(thumbprint))
                    {
                        retired.Add(chain);
                        loaded.Remove(thumbprint);
                    }
                }

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
