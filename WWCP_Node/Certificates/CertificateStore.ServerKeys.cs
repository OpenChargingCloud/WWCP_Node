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
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// The server keys of this node's listeners: keys made here that the
    /// clients of a listener may pin, each presented in a self-signed carrier
    /// certificate made from it, one of them current and perhaps one announced
    /// as the next.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A key pin vouches for a key, and not for a certificate.</b> A client
    /// that pinned a key checks the key it is shown and nothing else, so the
    /// key can be shown before any certificate authority has issued anything
    /// for it - in a carrier certificate that claims as little as it can - and
    /// goes on being shown in it after a certificate issued for it has run out.
    /// So the carrier is kept beside whatever is issued later, and both are TLS
    /// server identities of this store, told the listener, like any other: put
    /// in through <see cref="Import(Byte[], CertificateKind, String?, String?, IEnumerable{String}?, out CertificateEntry?, out String?, out Boolean)"/>,
    /// written as the store writes every identity, owner-only.
    /// </para>
    /// <para>
    /// <b>The rest is the index's.</b> Which listener a key is for, whether it
    /// is the current or the next one and since when, and which identity is its
    /// carrier are what no certificate says about itself, so they are kept in
    /// <c>index.json</c> under "serverKeys", keyed by key pin, beside the
    /// labels and switches: one file written whole and moved over, so that a
    /// key made, or a switch, is in the index together with what it needs, or
    /// not at all - never a switch whose key is in another file that was not
    /// written. A lost index costs as little as it can: a carrier says in its
    /// own subject which key and which listener it is for, so it is told that
    /// listener again and taken back as a server key; where a listener had
    /// only the one, it is current again, and where it had several, which of
    /// them was current is what was lost - see <see cref="ReconcileServerKeys"/>.
    /// </para>
    /// <para>
    /// <b>A certificate issued for a server key</b> arrives as any renewal of
    /// an identity that keeps its key does - see
    /// <see cref="TryAnswerRequest"/> - and is kept beside the carrier, told the
    /// same listener. It is recognised as that key's by its key pin, which is
    /// the one thing the two have in common - see <see cref="IssuedFor"/> -
    /// and nothing has to be written down for it.
    /// </para>
    /// <para>
    /// Which of a key's certificates a listener shows - the issued one while it
    /// is valid, the carrier otherwise - is decided elsewhere. What is kept
    /// from happening here is what would lock clients out: a new key taking
    /// over by itself, and the current key, or whatever a listener is showing
    /// right now, being deleted.
    /// </para>
    /// </remarks>
    public sealed partial class CertificateStore
    {

        #region Data

        /// <summary>
        /// The property of the index the server keys are kept under.
        /// </summary>
        public const String  ServerKeysProperty  = "serverKeys";

        /// <summary>
        /// What a carrier certificate is valid from: far in the past, so that a
        /// client whose clock believes it is 1970 does not refuse it for its
        /// dates (EVQI Transport, key pins, section 4, B0).
        /// </summary>
        public static readonly DateTimeOffset CarrierNotBefore  = new (1970,  1,  1,  0,  0,  0, TimeSpan.Zero);

        /// <summary>
        /// What a carrier certificate is valid until: 99991231235959Z, which
        /// RFC 5280 4.1.2.5 says for a certificate without a well-defined end.
        /// Nobody who pinned the key looks at it, and nothing about it may run
        /// out under a client that does.
        /// </summary>
        /// <remarks>
        /// Past what a local time can hold east of Greenwich, where .NET hands
        /// it back an hour short; the store reads it from the certificate's own
        /// bytes instead - see <see cref="CertificateEntry.ValidityOf"/>.
        /// </remarks>
        public static readonly DateTimeOffset CarrierNotAfter   = new (9999, 12, 31, 23, 59, 59, TimeSpan.Zero);

        /// <summary>
        /// What every carrier says of itself, as an organisational unit of its
        /// subject: that nothing in it but the key is meant to be believed.
        /// </summary>
        public const String  CarrierMark  = "Checked by its key pin only";

        /// <summary>
        /// A carrier's subject as this store writes it, read back: the key it
        /// carries and the listener it was made for. In whichever order the
        /// runtime writes the parts of a name, which is not the order they are
        /// in.
        /// </summary>
        private static readonly Regex carrierKey       = new (@"(?:^|,\s*)CN=Key pin carrier ([0-9a-f]{16})(?:,|$)",            RegexOptions.CultureInvariant);
        private static readonly Regex carrierListener  = new (@"(?:^|,\s*)OU=Listener ([A-Za-z][A-Za-z0-9_-]*)(?:,|$)",         RegexOptions.CultureInvariant);

        /// <summary>
        /// Every server key, by its key pin.
        /// </summary>
        private readonly Dictionary<KeyPin, ServerKey>         serverKeys  = [];

        /// <summary>
        /// The keys being made, whose carrier is on its way into the store and
        /// whose state is not to be taken for one that lost its carrier.
        /// </summary>
        private readonly HashSet<KeyPin>                       makingKeys  = [];

        /// <summary>
        /// What each listener is showing right now, as whoever chooses it said.
        /// </summary>
        private readonly Dictionary<CertificateUsage, String>  served      = [];

        #endregion

        #region Events

        /// <summary>
        /// A listener switched to its announced next server key - whoever
        /// asked for it: the listener, the key pin of the key that was current
        /// before, where there was one, and the key pin of the one current from
        /// now on.
        /// </summary>
        /// <remarks>
        /// Raised once the switch is written, outside the lock: what it sets
        /// off may read this store again. Raised after <see cref="OnChanged"/>,
        /// so that whoever chooses what a listener shows has chosen again by
        /// then. A listener that throws is caught and complained about; the
        /// switch has been made either way.
        /// </remarks>
        public event Action<CertificateUsage, KeyPin?, KeyPin>? OnServerKeySwitched;

        #endregion


        #region ServerKeyListeners / ServerKeys(Listener) / GetCurrentAndNextKey(Listener, out Next) / ServerKeyOf(...)

        /// <summary>
        /// Every listener that has a server key, in the order of their names.
        /// </summary>
        public IReadOnlyList<CertificateUsage> ServerKeyListeners
        {
            get
            {

                storeLock.Wait();

                try
                {
                    return [.. serverKeys.Values.Select (key => key.Listener).
                                                 Distinct().
                                                 OrderBy(listener => listener.ToString(), StringComparer.Ordinal)];
                }
                finally
                {
                    storeLock.Release();
                }

            }
        }

        /// <summary>
        /// Every server key of one listener, the newest first.
        /// </summary>
        /// <param name="Listener">The listener.</param>
        public IReadOnlyList<ServerKey> ServerKeys(CertificateUsage Listener)
        {

            storeLock.Wait();

            try
            {
                return [.. serverKeys.Values.Where            (key => key.Listener == Listener).
                                             OrderByDescending(key => key.CreatedAt).
                                             ThenBy           (key => key.Id, StringComparer.Ordinal)];
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// The current server key of a listener and its announced next key, as
        /// one pair: read together, so that a switch in between cannot show the
        /// key before it beside no next key, or the new current key as the next
        /// one as well.
        /// </summary>
        /// <param name="Listener">The listener.</param>
        /// <param name="Next">The announced next key, or null where none was made.</param>
        /// <returns>The current key, or null where there is none.</returns>
        public ServerKey? GetCurrentAndNextKey(CertificateUsage    Listener,
                                               out ServerKey?      Next)
        {

            storeLock.Wait();

            try
            {
                Next = NextKeyOf(Listener);
                return CurrentKeyOf(Listener);
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// The server key with the given key pin, or null.
        /// </summary>
        /// <param name="KeyPin">A key pin.</param>
        public ServerKey? ServerKeyOf(KeyPin? KeyPin)
        {

            if (KeyPin is null)
                return null;

            storeLock.Wait();

            try
            {
                return serverKeys.GetValueOrDefault(KeyPin);
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// The server key a TLS server identity of the store is a certificate
        /// of - its carrier, or one issued for it - or null for one that is not.
        /// </summary>
        /// <param name="Entry">An entry of the store.</param>
        public ServerKey? ServerKeyOf(CertificateEntry Entry)

            => Entry.Kind == CertificateKind.TLSServerIdentity
                   ? ServerKeyOf(Entry.KeyPin)
                   : null;

        #endregion

        #region CarrierOf(Key) / IssuedFor(Key)

        /// <summary>
        /// The carrier certificate of a server key, as the store holds it, or
        /// null where it is not in the store.
        /// </summary>
        /// <param name="Key">A server key.</param>
        public CertificateEntry? CarrierOf(ServerKey Key)

            => Get(Key.CarrierId, CertificateKind.TLSServerIdentity);

        /// <summary>
        /// Every certificate a certificate authority issued for a server key -
        /// every TLS server identity of the store with its key pin, but its
        /// carrier - the one that lasts longest first.
        /// </summary>
        /// <remarks>
        /// Found by the key pin rather than written down, because the key pin
        /// is what makes a certificate one of this key's: one that came in as
        /// a renewal, one somebody imported with the key, one put into the
        /// directory by hand - all of them are, and are found.
        /// </remarks>
        /// <param name="Key">A server key.</param>
        public IReadOnlyList<CertificateEntry> IssuedFor(ServerKey Key)

            => [.. ByKind(CertificateKind.TLSServerIdentity).
                   Where            (entry => entry.KeyPin == Key.KeyPin && entry.Id != Key.CarrierId).
                   OrderByDescending(entry => entry.NotAfter).
                   ThenBy           (entry => entry.Id, StringComparer.Ordinal)];

        #endregion

        #region Serving(Listener, Id) / ServedOn(Listener)

        /// <summary>
        /// Say which identity of the store a listener is showing from now on -
        /// or that it shows none, with null - so that it is not deleted from
        /// under it.
        /// </summary>
        /// <remarks>
        /// Said by whoever chooses what a listener shows, each time it chooses:
        /// this store keeps what it was told and refuses to delete it, the way
        /// a server that stopped speaking TLS by somebody deleting a file is not
        /// a decision anybody means to make.
        /// </remarks>
        /// <param name="Listener">The listener.</param>
        /// <param name="Id">The handle of the identity it shows, or null.</param>
        public void Serving(CertificateUsage  Listener,
                            String?           Id)
        {

            storeLock.Wait();

            try
            {
                if (Id is null)
                    served.Remove(Listener);
                else
                    served[Listener] = Id;
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// The handle of the identity a listener is showing, as it was last
        /// said with <see cref="Serving"/>, or null.
        /// </summary>
        /// <param name="Listener">The listener.</param>
        public String? ServedOn(CertificateUsage Listener)
        {

            storeLock.Wait();

            try
            {
                return served.GetValueOrDefault(Listener);
            }
            finally
            {
                storeLock.Release();
            }

        }

        #endregion


        #region TryCreateServerKey(Listener, Algorithm, AsNext, out Key, out Error [, out NotSaved])

        /// <summary>
        /// Generate a server key of a listener that its clients may pin,
        /// presented in a self-signed carrier certificate made from it - as the
        /// current key where the listener shows nothing yet, or as the
        /// announced next key.
        /// </summary>
        /// <param name="Listener">The listener it is a server key of, e.g. "ocpp".</param>
        /// <param name="Algorithm">One of <see cref="KeyAlgorithm.All"/>; P-256 when nothing is said.</param>
        /// <param name="AsNext">Whether this is the next key, announced ahead of a rollover and shown only once somebody switches to it.</param>
        /// <param name="Key">The server key that was made.</param>
        /// <param name="Error">Why none was.</param>
        public Boolean TryCreateServerKey(String                              Listener,
                                          String?                             Algorithm,
                                          Boolean                             AsNext,
                                          [NotNullWhen(true)]  out ServerKey?  Key,
                                          [NotNullWhen(false)] out String?     Error)

            => TryCreateServerKey(Listener, Algorithm, AsNext, out Key, out Error, out _);

        /// <summary>
        /// Generate a server key of a listener that its clients may pin - and
        /// say whether a refusal was the files' rather than the request's.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>No signing request and no names.</b> A key pin vouches for the key
        /// alone, so nothing has to be known about what this node is reachable
        /// as, and no certificate authority has to be asked. The key is shown in
        /// a carrier certificate that says what it is and what it is not: not
        /// an authority (basicConstraints CA:FALSE, no keyCertSign), for TLS
        /// servers only, valid from 1970 to 9999. A client that installed it as
        /// a root could otherwise be made to trust whatever its key signs (EVQI
        /// Transport, key pins, section 4, B0).
        /// </para>
        /// <para>
        /// <b>Never in place of what is shown.</b> Where the listener shows
        /// something already - a current server key, or any identity of the
        /// store that is switched on and may be shown on it, those for every
        /// listener among them - the new key has to be announced as the next
        /// one and switched to: a key made here never takes over by itself,
        /// because every client that checks the old certificate or pinned the
        /// old key would be locked out at once. And where nothing is shown yet,
        /// there is nothing to announce a next key after.
        /// </para>
        /// <para>
        /// <b>One write of the index.</b> The key is put into the index before
        /// its carrier goes in through the door every identity comes in by, so
        /// that the index written for the carrier carries the key as well: a
        /// node killed in between comes back with both or with neither. A
        /// carrier this machine turns out not to be able to hold up in a
        /// handshake is taken out again - unlike a certificate an authority
        /// issued, there is nothing in it worth keeping for the day the
        /// platform learns how.
        /// </para>
        /// </remarks>
        /// <param name="Listener">The listener it is a server key of, e.g. "ocpp".</param>
        /// <param name="Algorithm">One of <see cref="KeyAlgorithm.All"/>; P-256 when nothing is said.</param>
        /// <param name="AsNext">Whether this is the next key, announced ahead of a rollover and shown only once somebody switches to it.</param>
        /// <param name="Key">The server key that was made.</param>
        /// <param name="Error">Why none was.</param>
        /// <param name="NotSaved">True where the carrier or the index could not be written: nothing about the request was wrong, and no key was made.</param>
        public Boolean TryCreateServerKey(String                              Listener,
                                          String?                             Algorithm,
                                          Boolean                             AsNext,
                                          [NotNullWhen(true)]  out ServerKey?  Key,
                                          [NotNullWhen(false)] out String?     Error,
                                          out Boolean                         NotSaved)
        {

            Key       = null;
            Error     = null;
            NotSaved  = false;

            #region What was asked for

            if (!CertificateUsage.TryParse(Listener, out var listener))
            {
                Error = $"'{Listener}' is not a listener name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.";
                return false;
            }

            if (!Keeps(CertificateKind.TLSServerIdentity))
            {
                Error = $"This {NodeName} keeps no TLS server identity, and a server key is shown as one.";
                return false;
            }

            var algorithm = KeyAlgorithm.Find(Algorithm ?? DefaultAlgorithm);

            if (algorithm is null)
            {
                Error = $"'{Algorithm}' is not a key this {NodeName} generates ({String.Join(", ", KeyAlgorithm.All.Select(one => one.Id))}).";
                return false;
            }

            storeLock.Wait();

            try
            {
                if (!MayCreate(listener, AsNext, out Error))
                    return false;
            }
            finally
            {
                storeLock.Release();
            }

            #endregion

            #region The key, and its carrier

            AsymmetricCipherKeyPair pair;

            try
            {
                pair = algorithm.Generate();
            }
            catch (Exception e)
            {
                Error = $"No {algorithm.Name} key could be generated: {e.Message}";
                return false;
            }

            var publicKey  = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetDerEncoded();
            var keyPin     = KeyPin.FromSubjectPublicKeyInfo(publicKey);
            var keyId      = KeyId(publicKey);
            var createdAt  = Clock.GetUtcNow();

            Byte[] carrierDER;
            String content;

            try
            {

                carrierDER  = CreateCarrier(pair, algorithm, keyId, listener);

                content     = PemEncoding.WriteString("CERTIFICATE", carrierDER) + "\n" +
                              PemEncoding.WriteString("PRIVATE KEY", PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetDerEncoded()) + "\n";

            }
            catch (Exception e)
            {
                Error = $"No carrier certificate could be made for the new key ({algorithm.Name}): {e.Message}";
                return false;
            }

            var key = new ServerKey(
                          keyPin,
                          listener,
                          algorithm.Id,
                          createdAt,
                          Convert.ToHexStringLower(SHA256.HashData(carrierDER))[..CertificateEntry.IdLength],
                          AsNext,
                          AsNext ? null : createdAt
                      );

            #endregion

            #region In the index first, then in through the door every identity comes in by

            storeLock.Wait();

            try
            {

                // Asked again under the lock that puts it in: two keys made at
                // once must not both become the current one, or both the next.
                if (!MayCreate(listener, AsNext, out Error))
                    return false;

                serverKeys[keyPin] = key;
                makingKeys.Add(keyPin);

            }
            finally
            {
                storeLock.Release();
            }

            CertificateEntry? carrier;

            try
            {

                if (!Import(System.Text.Encoding.ASCII.GetBytes(content),
                            CertificateKind.TLSServerIdentity,
                            null,
                            null,
                            [ listener.ToString() ],
                            out carrier,
                            out var problem,
                            out NotSaved))
                {
                    Error = $"The carrier of the new key could not be put into the store: {problem}";
                }

            }
            finally
            {

                storeLock.Wait();

                try
                {

                    makingKeys.Remove(keyPin);

                    if (Error is not null)
                        serverKeys.Remove(keyPin);

                }
                finally
                {
                    storeLock.Release();
                }

            }

            if (Error is not null || carrier is null)
            {
                Error ??= "The carrier of the new key could not be put into the store.";
                return false;
            }

            #endregion

            #region Can this machine hold it up?

            // Read back the way a handshake reads it: a carrier that cannot be
            // loaded from its own file is a listener that would show nothing.
            String? cannot = null;

            if (TryLoadForHandshake(carrier, out var loaded, out var chain, out var unreadable))
            {
                using (loaded)
                {

                    foreach (var certificate in chain)
                        certificate.Dispose();

                    if (!KeyAlgorithm.CanBePresented(algorithm.Id, loaded))
                        cannot = $"{algorithm.Name} keys cannot be presented over TLS by this machine - the handshake fails.";

                }
            }

            else
                cannot = $"The carrier of the new key cannot be read back the way a handshake reads it: {unreadable}";

            if (cannot is not null)
            {

                storeLock.Wait();

                try
                {
                    serverKeys.Remove(keyPin);
                }
                finally
                {
                    storeLock.Release();
                }

                if (!Remove(carrier.Id, CertificateKind.TLSServerIdentity, out var left, out _))
                    log.Warning($"Certificates: the carrier '{carrier.Id}' of a key this {NodeName} cannot hold up could not be taken out again - {left}",
                                "certificates");

                Error = cannot;
                return false;

            }

            #endregion

            log.Metrological(LogLevel.Notice,
                             AsNext
                                 ? $"Certificates: a new {algorithm.Name} key '{key.Id}' was generated as the next server key of the listener '{listener}', " +
                                   $"with the key pin {keyPin.ToHex()}, in the carrier '{carrier.Id}'. It is shown once somebody switches to it; until then, " +
                                    "hand its key pin to the clients."
                                 : $"Certificates: a new {algorithm.Name} key '{key.Id}' was generated as the server key of the listener '{listener}', " +
                                   $"with the key pin {keyPin.ToHex()}, and is shown in the carrier '{carrier.Id}' made from it.",
                             "certificates", "security");

            Key = key;
            return true;

        }

        #endregion

        #region TrySwitchToNextKey(Listener, IfNextKeyPinIs, out Key, out Error [, out NotSaved])

        /// <summary>
        /// Show a listener's announced next key from now on, where it is still
        /// the key with the given key pin: it becomes the current one, and the
        /// key before it is kept, no longer current, until somebody removes it.
        /// </summary>
        /// <param name="Listener">The listener.</param>
        /// <param name="IfNextKeyPinIs">The key pin the announced next key has to have; whichever it has where null.</param>
        /// <param name="Key">The key that is current now.</param>
        /// <param name="Error">Why nothing was switched.</param>
        public Boolean TrySwitchToNextKey(String                              Listener,
                                          KeyPin?                             IfNextKeyPinIs,
                                          [NotNullWhen(true)]  out ServerKey?  Key,
                                          [NotNullWhen(false)] out String?     Error)

            => TrySwitchToNextKey(Listener, IfNextKeyPinIs, out Key, out Error, out _);

        /// <summary>
        /// Show a listener's announced next key from now on, where it is still
        /// the key with the given key pin - and say whether a refusal was the
        /// index's rather than the request's.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Asked for, never done by itself: whether every client has the next
        /// key pin by now is known to whoever handed it out, and not to this
        /// store. A client that has not is refused at its next handshake.
        /// </para>
        /// <para>
        /// <b>Compare and switch.</b> Whoever names the pin - the CSMS, which
        /// handed exactly that pin to its stations - gets that key or nothing:
        /// the next key is compared under the same lock that switches, so a
        /// switch and a new next key made meanwhile on the command line cannot
        /// make it a switch to a key nobody handed out.
        /// </para>
        /// <para>
        /// One thing changes, the next key's: it stops being next and becomes
        /// the current one from now on - never earlier than the key it takes
        /// over from became current, so that a clock set back cannot leave the
        /// old key the newer one. The key before is current no longer because
        /// the newer of the two is, so there is no moment at which a switch
        /// leaves two current keys or none.
        /// </para>
        /// </remarks>
        /// <param name="Listener">The listener.</param>
        /// <param name="IfNextKeyPinIs">The key pin the announced next key has to have; whichever it has where null.</param>
        /// <param name="Key">The key that is current now.</param>
        /// <param name="Error">Why nothing was switched.</param>
        /// <param name="NotSaved">True where the index could not be written: nothing was switched.</param>
        public Boolean TrySwitchToNextKey(String                              Listener,
                                          KeyPin?                             IfNextKeyPinIs,
                                          [NotNullWhen(true)]  out ServerKey?  Key,
                                          [NotNullWhen(false)] out String?     Error,
                                          out Boolean                         NotSaved)
        {

            Key       = null;
            Error     = null;
            NotSaved  = false;

            if (!CertificateUsage.TryParse(Listener, out var listener))
            {
                Error = $"'{Listener}' is not a listener name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.";
                return false;
            }

            KeyPin?    before;
            ServerKey  switched;

            storeLock.Wait();

            try
            {

                var next = NextKeyOf(listener);

                if (next is null)
                {
                    Error = $"No next server key has been announced for the listener '{listener}', so there is nothing to switch to.";
                    return false;
                }

                if (IfNextKeyPinIs is not null && next.KeyPin != IfNextKeyPinIs)
                {
                    Error = $"The announced next key of the listener '{listener}' is '{next.Id}' with the key pin {next.KeyPin.ToHex()}, " +
                            $"not the key with the key pin {IfNextKeyPinIs.ToHex()}.";
                    return false;
                }

                if (!entries.ContainsKey((next.CarrierId, CertificateKind.TLSServerIdentity)))
                {
                    Error = $"The next key '{next.Id}' has lost its carrier '{next.CarrierId}' and cannot be shown.";
                    return false;
                }

                var current  = CurrentKeyOf(listener);
                var now      = Clock.GetUtcNow();

                if (current?.CurrentSince is DateTimeOffset since && since >= now)
                    now = since.AddTicks(1);

                before    = current?.KeyPin;
                switched  = next with { IsNext = false, CurrentSince = now };

                serverKeys[next.KeyPin] = switched;

                if (!TryWriteIndex(PutBack: true, out var problem))
                {

                    serverKeys[next.KeyPin] = next;

                    Error     = $"The switch to '{next.Id}' could not be written: {problem}";
                    NotSaved  = true;
                    return false;

                }

            }
            finally
            {
                storeLock.Release();
            }

            log.Metrological(LogLevel.Notice,
                             $"Certificates: the listener '{listener}' switched to the server key '{switched.Id}' with the key pin {switched.KeyPin.ToHex()}" +
                             (before is not null ? $", which takes over from the key pin {before.ToHex()}" : "") +
                              ". Clients that pinned only the key before are refused from their next handshake on.",
                             "certificates", "security");

            Changed();

            try
            {
                OnServerKeySwitched?.Invoke(listener, before, switched.KeyPin);
            }
            catch (Exception e)
            {
                log.Warning($"Certificates: whoever follows the server keys failed at the switch of the listener '{listener}' - {e.Message}",
                            "certificates");
            }

            Key = switched;
            return true;

        }

        #endregion


        #region (private) CurrentKeyOf(Listener) / NextKeyOf(Listener) / MayCreate(Listener, AsNext, out Error)

        /// <summary>
        /// The current server key of a listener: of its keys that are not the
        /// next one and have their carrier, the one that became current last -
        /// or null. Called under the lock.
        /// </summary>
        private ServerKey? CurrentKeyOf(CertificateUsage Listener)

            => serverKeys.Values.Where            (key => key.Listener == Listener &&
                                                          !key.IsNext               &&
                                                           key.CurrentSince.HasValue &&
                                                          (makingKeys.Contains(key.KeyPin) ||
                                                           entries.ContainsKey((key.CarrierId, CertificateKind.TLSServerIdentity)))).
                                 OrderByDescending(key => key.CurrentSince!.Value).
                                 ThenBy           (key => key.Id, StringComparer.Ordinal).
                                 FirstOrDefault();

        /// <summary>
        /// The announced next server key of a listener, or null. Called under
        /// the lock.
        /// </summary>
        private ServerKey? NextKeyOf(CertificateUsage Listener)

            => serverKeys.Values.FirstOrDefault(key => key.Listener == Listener && key.IsNext);

        /// <summary>
        /// Whether a server key of a listener may be made now, as the current
        /// one or as the next - or why not. Called under the lock.
        /// </summary>
        private Boolean MayCreate(CertificateUsage                  Listener,
                                  Boolean                           AsNext,
                                  [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            if (AsNext && NextKeyOf(Listener) is ServerKey next)
            {
                Error = $"'{next.Id}' is announced as the next server key of the listener '{Listener}' already. Switch to it, or remove its carrier, before announcing another.";
                return false;
            }

            var current = CurrentKeyOf(Listener);

            // An identity shows on the listener where it is switched on, may
            // be shown there - told the listener, or told nothing, which is
            // every listener - and is no certificate of a server key other
            // than the current one: a next key's, or one that was current once,
            // is not shown.
            var shown   = current?.CarrierId ??
                          entries.Values.FirstOrDefault(entry => entry.Kind == CertificateKind.TLSServerIdentity &&
                                                                 entry.HasPrivateKey                             &&
                                                                 entry.IsActive                                  &&
                                                                 entry.IsFor(Listener)                           &&
                                                                 (entry.KeyPin is null || !serverKeys.ContainsKey(entry.KeyPin)))?.Id;

            if (AsNext && shown is null)
            {
                Error = $"Nothing is shown on the listener '{Listener}' yet, so there is nothing to announce a next key after. Make the server key itself first.";
                return false;
            }

            if (!AsNext && shown is not null)
            {
                Error = $"'{shown}' is shown on the listener '{Listener}' already, and a new key does not take its place by itself: every client that " +
                         "checks it would be locked out at once. Announce the new key as the next one, hand its key pin to the clients, and switch to it.";
                return false;
            }

            return true;

        }

        #endregion

        #region (private) MayRemove(Targets, Doing, out Error) / MayRetell(Entry, Usages, out Error) / ForgetServerKeysWithoutCarrier()

        /// <summary>
        /// Whether the given registrations may be taken out of the store - or
        /// switched off, or moved to another kind, which takes them out of what
        /// a listener may show just the same - or why not. Called under the
        /// lock, by everything that does one of the three.
        /// </summary>
        /// <remarks>
        /// Two things stay. What a listener is showing right now: a listener
        /// without its certificate stops speaking TLS, and doing that by
        /// deleting a file is not a decision anybody means to make. And the
        /// carrier of a listener's current server key, whether or not it is
        /// shown right now: it is what the next handshake shows once a
        /// certificate issued for the key has run out, and taking it away would
        /// hand the clients that pinned the key another one.
        /// </remarks>
        /// <param name="Targets">What is to be taken out.</param>
        /// <param name="Doing">What is done to it, as the sentence says it: "removed", "switched off", "moved".</param>
        /// <param name="Error">Why not.</param>
        private Boolean MayRemove(IEnumerable<CertificateEntry>     Targets,
                                  String                            Doing,
                                  [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            foreach (var target in Targets.Where(entry => entry.Kind == CertificateKind.TLSServerIdentity))
            {

                if (served.FirstOrDefault(pair => pair.Value == target.Id) is { Value: not null } showing)
                {
                    Error = $"'{target.Label}' is what the listener '{showing.Key}' is showing right now, and is not {Doing}. " +
                             "Put the one that is to replace it in first, then try again.";
                    return false;
                }

                if (CarriedKey(target) is ServerKey key &&
                    CurrentKeyOf(key.Listener)?.KeyPin == key.KeyPin)
                {
                    Error = $"'{target.Label}' carries the current server key '{key.Id}' of the listener '{key.Listener}', which its clients pinned, and is not {Doing}. " +
                             "Announce a next key, switch to it, then try again.";
                    return false;
                }

            }

            return true;

        }

        /// <summary>
        /// Whether an identity may be told other usages - or why not. Called
        /// under the lock.
        /// </summary>
        /// <remarks>
        /// A carrier is its listener's, and told that listener alone: told
        /// another, it would no longer be shown where its clients pinned it,
        /// and told nothing - every listener - it would be shown where nobody
        /// pinned anything, by a web interface whose browsers would call it a
        /// certificate of nobody's. And what a listener is showing right now
        /// is not told something that leaves that listener out: it would stop
        /// being shown with nothing chosen in its place.
        /// </remarks>
        /// <param name="Entry">The identity.</param>
        /// <param name="Usages">What it would be told; null for every listener.</param>
        /// <param name="Error">Why not.</param>
        private Boolean MayRetell(CertificateEntry                  Entry,
                                  IReadOnlyList<CertificateUsage>?  Usages,
                                  [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            if (Entry.Kind != CertificateKind.TLSServerIdentity)
                return true;

            if (CarriedKey(Entry) is ServerKey key &&
                (Usages is null || !Usages.Contains(key.Listener)))
            {
                Error = $"'{Entry.Label}' carries the server key '{key.Id}' of the listener '{key.Listener}', and is shown there alone: it is not told " +
                        $"{(Usages is null ? "every listener" : "a list without it")}.";
                return false;
            }

            foreach (var showing in served.Where(pair => pair.Value == Entry.Id))
            {
                if (Usages is not null && !Usages.Contains(showing.Key))
                {
                    Error = $"'{Entry.Label}' is what the listener '{showing.Key}' is showing right now, and is not told a list without it. " +
                             "Put the one that is to replace it in first, then try again.";
                    return false;
                }
            }

            return true;

        }

        /// <summary>
        /// The server key an identity is the carrier of, or null. Called under
        /// the lock.
        /// </summary>
        private ServerKey? CarriedKey(CertificateEntry Entry)

            => Entry.Kind == CertificateKind.TLSServerIdentity
                   ? serverKeys.Values.FirstOrDefault(key => key.CarrierId == Entry.Id)
                   : null;

        /// <summary>
        /// The key pins whose certificates no generic choice may show: those of
        /// every server key that is not its listener's current one - an
        /// announced next key, which is shown once somebody switches to it, and
        /// one that was current once, which its clients no longer pin.
        /// </summary>
        /// <remarks>
        /// Asked by <see cref="UsableByKind"/> and <see cref="UsableFor"/>, so
        /// that whatever chooses by them - the web interface, a kind of node's
        /// own listener - cannot be the thing that switches the clients of a
        /// listener over before anybody asked for it. The carriers stay switched
        /// on: which of them is shown is the server keys' to say, and somebody
        /// switching a carrier off means the carrier, not the key.
        /// </remarks>
        private HashSet<KeyPin> PinsNotShown()
        {

            storeLock.Wait();

            try
            {
                return [.. serverKeys.Values.Where (key => CurrentKeyOf(key.Listener)?.KeyPin != key.KeyPin).
                                             Select(key => key.KeyPin)];
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// Whether an entry is a certificate of one of the given key pins, and
        /// so not to be shown by a generic choice - see <see cref="PinsNotShown"/>.
        /// </summary>
        private static Boolean NotShown(CertificateEntry  Entry,
                                        HashSet<KeyPin>   Pins)

            => Entry.Kind   == CertificateKind.TLSServerIdentity &&
               Entry.KeyPin is not null                        &&
               Pins.Contains(Entry.KeyPin);

        /// <summary>
        /// Forget every server key whose carrier is no longer in the store: it
        /// is a server key no more, and whatever was issued for it is an
        /// identity like any other. Called under the lock, before the index is
        /// written.
        /// </summary>
        private void ForgetServerKeysWithoutCarrier()
        {

            foreach (var key in serverKeys.Values.ToList())
            {

                if (makingKeys.Contains(key.KeyPin)                                                  ||
                    entries. ContainsKey((key.CarrierId, CertificateKind.TLSServerIdentity))         ||
                    setAside.ContainsKey((key.CarrierId, CertificateKind.TLSServerIdentity)))
                {
                    continue;
                }

                serverKeys.Remove(key.KeyPin);

                log.Metrological(LogLevel.Notice,
                                 $"Certificates: the server key '{key.Id}' of the listener '{key.Listener}' went with its carrier '{key.CarrierId}'" +
                                 $"{(key.IsNext ? "; no next key is announced any more" : "")}.",
                                 "certificates", "security");

            }

        }

        #endregion

        #region (private) ReadServerKeys(Index) / ServerKeysToJSON() / ReconcileServerKeys()

        /// <summary>
        /// The server keys the index remembers. Called under the lock, while
        /// the index is read.
        /// </summary>
        /// <remarks>
        /// One that cannot be read is named and skipped: its carrier is still
        /// in the store, and comes back as a server key from its own subject -
        /// see <see cref="ReconcileServerKeys"/>.
        /// </remarks>
        private void ReadServerKeys(JObject Index)
        {

            if (Index[ServerKeysProperty] is not JObject keys)
                return;

            foreach (var property in keys.Properties())
            {

                ServerKey? key    = null;
                String?    error  = "it is no object.";

                if (property.Value is not JObject json ||
                    !ServerKey.TryParse(property.Name, json, out key, out error))
                {
                    log.Warning($"Certificates: the index has a server key this {NodeName} could not read - {error}",
                                "certificates");
                    continue;
                }

                serverKeys[key.KeyPin] = key;

            }

        }

        /// <summary>
        /// The server keys as the index holds them: by key pin, those of one
        /// listener together, the oldest first. Called under the lock.
        /// </summary>
        private JObject ServerKeysToJSON()

            => new (serverKeys.Values.OrderBy(key => key.Listener.ToString(), StringComparer.Ordinal).
                                      ThenBy (key => key.CreatedAt).
                                      ThenBy (key => key.Id, StringComparer.Ordinal).
                                      Select (key => new JProperty(key.KeyPin.ToHex(), key.ToJSON())));

        /// <summary>
        /// The server keys the index remembers, against the carriers the
        /// directory holds - and the carriers it does not remember, taken back
        /// as server keys from their own subjects. Called under the lock, from
        /// <see cref="Reload"/>, before the index is written.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A key whose carrier is gone, or is now some other key's, is
        /// forgotten and said so: nothing could show it.
        /// </para>
        /// <para>
        /// A carrier nobody remembers - the index was lost, or it was copied in
        /// from a backup - says in its subject which key it carries and which
        /// listener it was made for, so it is told that listener again where
        /// it came back told nothing, and is a server key again. What its
        /// subject cannot say is whether it was the current key or the next:
        /// where the listener has no current key and this is the only one taken
        /// back for it, it is current, because a listener with one key showed
        /// that one; where several are, none of them is, because guessing would
        /// hand the clients a key that may not be the one they pinned - and
        /// that is said in the log, with every key pin, for somebody who knows.
        /// </para>
        /// </remarks>
        private void ReconcileServerKeys()
        {

            #region Remembered, against what was found

            foreach (var key in serverKeys.Values.ToList())
            {

                if (setAside.ContainsKey((key.CarrierId, CertificateKind.TLSServerIdentity)))
                    continue;

                if (entries.TryGetValue((key.CarrierId, CertificateKind.TLSServerIdentity), out var carrier) &&
                    carrier.KeyPin == key.KeyPin)
                {
                    continue;
                }

                serverKeys.Remove(key.KeyPin);

                log.Metrological(LogLevel.Notice,
                                 $"Certificates: the server key '{key.Id}' of the listener '{key.Listener}' was dropped from the index - " +
                                 $"its carrier '{key.CarrierId}' is no longer there.",
                                 "certificates", "security");

            }

            #endregion

            #region Found, and remembered by nobody

            var takenBack = new List<(CertificateEntry Carrier, CertificateUsage Listener)>();

            foreach (var entry in entries.Values.Where(entry => entry.Kind == CertificateKind.TLSServerIdentity &&
                                                                entry.HasPrivateKey                             &&
                                                                entry.KeyPin is not null                        &&
                                                                entry.Subject == entry.Issuer                   &&
                                                                entry.Subject.Contains("OU=" + CarrierMark, StringComparison.Ordinal) &&
                                                                !serverKeys.ContainsKey(entry.KeyPin)).
                                                  OrderBy(entry => entry.Id, StringComparer.Ordinal).
                                                  ToList())
            {

                var keyId     = carrierKey.     Match(entry.Subject);
                var listener  = carrierListener.Match(entry.Subject);

                if (!keyId.Success || !listener.Success ||
                    keyId.Groups[1].Value != entry.KeyPin!.ToHex()[..CertificateEntry.IdLength] ||
                    !CertificateUsage.TryParse(listener.Groups[1].Value, out var usage))
                {
                    continue;
                }

                // Told nothing is every listener - which a carrier is not.
                if (entry.Usages is null)
                    entries[(entry.Id, entry.Kind)] = entry with { Usages = [ usage ] };

                takenBack.Add((entries[(entry.Id, entry.Kind)], usage));

            }

            foreach (var group in takenBack.GroupBy(found => found.Listener))
            {

                var current = group.Count() == 1 && CurrentKeyOf(group.Key) is null;
                var now     = Clock.GetUtcNow();

                foreach (var (carrier, listener) in group)
                {

                    var key = new ServerKey(
                                  carrier.KeyPin!,
                                  listener,
                                  KeyAlgorithm.All.FirstOrDefault(algorithm => algorithm.Name == carrier.KeyAlgorithm)?.Id ?? carrier.KeyAlgorithm,
                                  carrier.ImportedAt,
                                  carrier.Id,
                                  IsNext:        false,
                                  CurrentSince:  current ? now : null
                              );

                    serverKeys[key.KeyPin] = key;

                    log.Metrological(LogLevel.Warning,
                                     $"Certificates: the carrier '{carrier.Id}' was not in the index and was taken back as the server key '{key.Id}' " +
                                     $"of the listener '{listener}', with the key pin {key.KeyPin.ToHex()}" +
                                     (current
                                          ? ", the current one: it is the only one of that listener."
                                          : ", not the current one: which of the listener's keys was current is not in the index any more. " +
                                            "Announce the one the clients pinned as the next key, and switch to it."),
                                     "certificates", "security");

                }

            }

            #endregion

        }

        #endregion

        #region (private static) CreateCarrier(KeyPair, Algorithm, KeyId, Listener)

        /// <summary>
        /// The self-signed carrier certificate of a server key, DER encoded.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>Built to be harmless when it is misused.</b> Nothing in it but the
        /// key is meant to be believed, so it claims as little as it can: no
        /// authority (basicConstraints CA:FALSE, critical), no keyCertSign, a
        /// digital signature for a TLS server and nothing else. A client that
        /// installed it as a root rather than pinning its key cannot be made by
        /// its key to trust a certificate it "issued" - provided the client's
        /// TLS stack honours what is written here (EVQI Transport, key pins,
        /// section 4, B0).
        /// </para>
        /// <para>
        /// A name that says what it is - the key it carries, the listener it
        /// was made for, and that it is checked by its key pin only - and no
        /// subject alternative name: there is no name it could be valid for
        /// that a client would check, and one that looked like this node's
        /// would invite checking it. The key and the listener are in it for
        /// the day the index is lost, when they are all that is left to say
        /// what it was. Dated from 1970 to 9999, for the same reason it names
        /// nothing.
        /// </para>
        /// <para>
        /// Built by Bouncy Castle, as the signing requests are, so that every
        /// kind of key in <see cref="KeyAlgorithm.All"/> gets one.
        /// </para>
        /// </remarks>
        private static Byte[] CreateCarrier(AsymmetricCipherKeyPair  KeyPair,
                                            KeyAlgorithm             Algorithm,
                                            String                   KeyId,
                                            CertificateUsage         Listener)
        {

            var name       = new X509Name($"CN=Key pin carrier {KeyId},OU={CarrierMark},OU=Listener {Listener}");
            var generator  = new X509V3CertificateGenerator();

            generator.SetSerialNumber(PKIFactory.RandomSerial());
            generator.SetIssuerDN    (name);
            generator.SetSubjectDN   (name);
            generator.SetNotBefore   (CarrierNotBefore.UtcDateTime);
            generator.SetNotAfter    (CarrierNotAfter. UtcDateTime);
            generator.SetPublicKey   (KeyPair.Public);

            generator.AddExtension(X509Extensions.BasicConstraints,  true,   new BasicConstraints(false));
            generator.AddExtension(X509Extensions.KeyUsage,          true,   new KeyUsage(KeyUsage.DigitalSignature));
            generator.AddExtension(X509Extensions.ExtendedKeyUsage,  false,  new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));

            return generator.Generate(new Asn1SignatureFactory(Algorithm.SignatureAlgorithm, KeyPair.Private)).GetEncoded();

        }

        #endregion

    }

}
