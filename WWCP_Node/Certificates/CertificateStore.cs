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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// Every certificate this node has been given: the roots it believes and
    /// the credentials it presents, on disk beside its accounts, and switchable
    /// one by one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The directory is the store and the index is its memory.</b> Each
    /// certificate is a file below <c>&lt;store&gt;/</c> in a directory named
    /// after its kind, and <c>index.json</c> beside them records the two things
    /// a file cannot say about itself: what somebody calls it, and whether it is
    /// switched on. So the store survives being copied to another machine, and a
    /// lost index costs labels and switches rather than certificates.
    /// </para>
    /// <para>
    /// <b>Both directions are supported, and that is the point.</b> Certificates
    /// arrive by import, which copies the file in; and certificates that are
    /// already in the directory - put there by hand, restored from a backup,
    /// carried over from another node - are picked up at every
    /// <see cref="Reload"/> and adopted. A file somebody dropped in is taken as
    /// meant, switched on, and named in the log, because a store that silently
    /// ignored it would be a store whose directory listing lies.
    /// </para>
    /// <para>
    /// <b>Private keys are stored unencrypted, which is a decision and not an
    /// oversight.</b> A PKCS#12 is opened with whatever password it arrived
    /// under and written back without one, so that any number of certificates
    /// per role work without any number of passwords to carry. What guards them
    /// is the file system: the store directory is created for its owner alone.
    /// Anybody who can read it can take this node's identity - and a
    /// vehicle's contract - so it belongs on a machine whose users are all
    /// trusted with exactly that, which <see cref="WarnAboutStoredKeys"/> says
    /// once at every start.
    /// </para>
    /// <para>
    /// Everything that changes the store takes <see cref="storeLock"/> and
    /// writes the index before returning, so a node that is killed between
    /// two requests comes back with what it last confirmed rather than with
    /// half of it.
    /// </para>
    /// </remarks>
    public sealed class CertificateStore
    {

        #region Data

        /// <summary>
        /// The index file, beside the certificates it is about.
        /// </summary>
        public const String  IndexFileName  = "index.json";

        /// <summary>
        /// What a file has to end in to be picked up as a certificate when the
        /// store is read.
        /// </summary>
        /// <remarks>
        /// The trust anchor extensions come from <c>TrustRoots.Load</c>, which
        /// is what eventually reads them, plus PKCS#12 for the credentials.
        /// A file with any other name is left alone rather than refused: a
        /// store directory is somewhere people also keep a README.
        /// </remarks>
        private static readonly String[] readableExtensions = [ ".pem", ".crt", ".cer", ".der", ".p12", ".pfx" ];

        private readonly SemaphoreSlim                        storeLock  = new (1, 1);
        private readonly Dictionary<String, CertificateEntry>  entries    = [];
        private readonly EventLog                              log;

        #endregion

        #region Properties

        /// <summary>
        /// Where this store keeps its certificates.
        /// </summary>
        public String Directory { get; }

        /// <summary>
        /// The kinds of certificate this store keeps: all of them, unless the
        /// kind of node it belongs to says otherwise.
        /// </summary>
        /// <remarks>
        /// Seven of the kinds are ISO 15118's, which a vehicle keeps, and four
        /// are TLS's in general - see <see cref="CertificateKind"/>. A kind of
        /// node keeps those it has a use for and no others, and a store that
        /// keeps none is no directory: nothing is made, read or written.
        /// </remarks>
        public IReadOnlyList<CertificateKind> Kinds { get; }

        /// <summary>
        /// What the node this store belongs to is called in a sentence:
        /// "electric vehicle".
        /// </summary>
        public String NodeName { get; }

        /// <summary>
        /// What a TLS root or a server certificate may be told it is for: the
        /// node's usages, and its kind's - the servers this node connects to.
        /// </summary>
        /// <remarks>
        /// A closed list per store, so that a usage somebody mistyped is
        /// refused where it is typed rather than quietly matching nothing - a
        /// TLS root "for ntp" would otherwise vouch for no time server, and
        /// nothing would say why.
        /// </remarks>
        public IReadOnlyList<String> Usages { get; }

        /// <summary>
        /// What a TLS identity may be told it is shown on: the listeners its
        /// kind of node names - a meter's "modbus" and "web" - and none by
        /// default, which leaves every identity for every listener.
        /// </summary>
        /// <remarks>
        /// A list of its own rather than more names among the usages: a server
        /// this node connects to and a listener of its own are different
        /// questions, and one list would let an identity be "for dns" and a
        /// root "for web", both of which mean nothing.
        /// </remarks>
        public IReadOnlyList<String> Listeners { get; }

        /// <summary>
        /// Everything in the store, roots before credentials and each group by
        /// label.
        /// </summary>
        public IReadOnlyList<CertificateEntry> Entries
        {
            get
            {

                storeLock.Wait();

                try
                {
                    return [.. entries.Values.
                                   OrderBy(entry => entry.Kind.SortOrder()).
                                   ThenBy (entry => entry.Label, StringComparer.OrdinalIgnoreCase)];
                }
                finally
                {
                    storeLock.Release();
                }

            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Sent after something in the store changed - a certificate put in,
        /// switched on or off, renamed, told other usages or taken out - and
        /// after every reload, which may have changed anything.
        /// </summary>
        /// <remarks>
        /// <para>
        /// For what a node derives from its store and has to ask again: which
        /// identity a listener shows, say, and a change of it in the log when
        /// it happened rather than at the next turn of a timer. Sent whoever
        /// changed it - a page of the web interface, or the node's own work,
        /// such as the certificate a signing request came back with - which a
        /// hook in the web interface would not see.
        /// </para>
        /// <para>
        /// Sent once the store's lock is released, so that a listener may ask
        /// the store what it holds now: the lock is not one a thread may take
        /// twice, and a listener that asked inside it would wait for itself.
        /// A listener that throws is caught and complained about; the change
        /// it was told of has been made either way.
        /// </para>
        /// </remarks>
        public event Action? OnChanged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A store over the given directory, which is created where it does not
        /// exist - unless the store keeps no kind of certificate at all.
        /// </summary>
        /// <param name="Directory">Where the certificates live.</param>
        /// <param name="Log">Where to say what was found, adopted and dropped.</param>
        /// <param name="Kinds">The kinds of certificate this store keeps; all of them by default.</param>
        /// <param name="NodeName">What the node the store belongs to is called in a sentence; "node" by default.</param>
        /// <param name="Usages">The usages the kind of node adds to the node's own, <see cref="CertificateUsages.All"/>.</param>
        /// <param name="Listeners">The listeners of the kind of node a TLS identity may be told it is shown on; none by default.</param>
        public CertificateStore(String                         Directory,
                                EventLog                       Log,
                                IEnumerable<CertificateKind>?  Kinds      = null,
                                String?                        NodeName   = null,
                                IEnumerable<String>?           Usages     = null,
                                IEnumerable<String>?           Listeners  = null)
        {

            this.Directory  = Path.GetFullPath(Directory);
            this.log        = Log;
            this.Kinds      = [.. (Kinds ?? CertificateKindExtensions.All).Distinct().OrderBy(kind => kind.SortOrder())];
            this.NodeName   = NodeName ?? "node";

            var usages      = new List<String>(CertificateUsages.All);

            foreach (var usage in Usages ?? [])
            {

                var name = usage?.Trim().ToLowerInvariant() ?? "";

                if (!CertificateUsages.IsUsageName(name))
                    throw new ArgumentException($"'{usage}' is not a usage name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.",
                                                nameof(Usages));

                if (!usages.Contains(name))
                    usages.Add(name);

            }

            this.Usages     = usages;
            this.Listeners  = NamesOf(Listeners, nameof(Listeners));

            CreateDirectories();

        }

        #endregion


        #region (private static) NamesOf(Names, Parameter)

        /// <summary>
        /// Names as a store keeps them - in lower case, each once, in the order
        /// given - or an exception for one that is no name.
        /// </summary>
        private static IReadOnlyList<String> NamesOf(IEnumerable<String>?  Names,
                                                     String                Parameter)
        {

            var names = new List<String>();

            foreach (var given in Names ?? [])
            {

                var name = given?.Trim().ToLowerInvariant() ?? "";

                if (!CertificateUsages.IsUsageName(name))
                    throw new ArgumentException($"'{given}' is not a name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.",
                                                Parameter);

                if (!names.Contains(name))
                    names.Add(name);

            }

            return names;

        }

        #endregion

        #region UsagesFor(Kind) / HasUsages(Kind)

        /// <summary>
        /// What a certificate of this kind may be told it is for in this store:
        /// the usages for a TLS root or a server certificate, the listeners for
        /// a TLS identity, and nothing for the other kinds.
        /// </summary>
        /// <remarks>
        /// What a page offers where a certificate is imported or changed, so
        /// that it offers only what the store would take.
        /// </remarks>
        public IReadOnlyList<String> UsagesFor(CertificateKind Kind)

            => Kind switch {
                   CertificateKind.TLSRoot      => Usages,
                   CertificateKind.TLSServer    => Usages,
                   CertificateKind.TLSIdentity  => Listeners,
                   _                            => []
               };

        /// <summary>
        /// Whether a certificate of this kind may be told what it is for in this
        /// store - which a TLS identity may only where the kind of node names
        /// listeners.
        /// </summary>
        public Boolean HasUsages(CertificateKind Kind)

            => UsagesFor(Kind).Count > 0;

        #endregion


        #region Reload()

        /// <summary>
        /// Read the directory and reconcile it with the index: keep what both
        /// know, adopt what only the directory has, and forget what only the
        /// index has.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The three outcomes are what makes a directory somebody can also use
        /// by hand. A file the index knows keeps its label and its switch. A
        /// file the index has never seen is adopted, switched on and named in
        /// the log - somebody put it there. An entry whose file is gone is
        /// dropped and named in the log, because a store that kept pointing at
        /// a missing certificate would fail at a handshake instead of here.
        /// </para>
        /// <para>
        /// A file that cannot be read as a certificate is named and skipped
        /// rather than thrown: one unreadable file in a directory of good ones
        /// should cost that one file, not the start.
        /// </para>
        /// </remarks>
        public void Reload()
        {

            var reloaded = false;

            storeLock.Wait();

            try
            {

                // A store that keeps nothing has no directory to read and no
                // index to write, and nothing to say at a start either: a line
                // saying "0 certificates" at every start of a node that never
                // keeps any is a line somebody has to learn to skip.
                if (Kinds.Count == 0)
                {
                    entries.Clear();
                    log.Debug($"Certificates: this {NodeName} keeps none.", "certificates");
                    return;
                }

                var remembered  = ReadIndex();
                var found       = new Dictionary<String, CertificateEntry>();
                var adopted     = 0;

                foreach (var kind in Kinds)
                {

                    var directory = Path.Combine(Directory, kind.Directory().Replace('/', Path.DirectorySeparatorChar));

                    if (!System.IO.Directory.Exists(directory))
                        continue;

                    foreach (var file in System.IO.Directory.EnumerateFiles(directory).
                                                            Where  (file => readableExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)).
                                                            OrderBy(file => file, StringComparer.Ordinal))
                    {

                        var relative = RelativeName(kind, Path.GetFileName(file));

                        if (!TryRead(file, out var certificate, out var chainLength, out var problem))
                        {
                            log.Warning($"Certificates: '{relative}' could not be read and was left where it is - {problem}",
                                        "certificates");
                            continue;
                        }

                        using (certificate)
                        {

                            var known = remembered.Values.FirstOrDefault(entry => entry.FileName == relative);

                            var entry = CertificateEntry.From(
                                            certificate,
                                            kind,
                                            relative,
                                            known?.Label,
                                            chainLength,
                                            known?.IsActive ?? true,
                                            known?.ImportedAt,
                                            known?.Usages
                                        );

                            if (found.ContainsKey(entry.Id))
                            {
                                log.Warning($"Certificates: '{relative}' is the same certificate as one already read and was skipped.",
                                            "certificates");
                                continue;
                            }

                            found.Add(entry.Id, entry);

                            if (known is null)
                            {
                                adopted++;
                                log.Metrological(LogLevel.Notice,
                                                 $"Certificates: adopted '{relative}' - {entry.Label}, {kind.Describe()}. It is switched on" +
                                                 $"{(kind.HasUsages() ? ", " + CertificateUsages.Describe(entry.Usages) : "")}.",
                                                 "certificates", "security");
                            }

                        }

                    }

                }

                foreach (var gone in remembered.Values.Where(entry => !found.ContainsKey(entry.Id)))
                    log.Metrological(LogLevel.Notice,
                                     $"Certificates: '{gone.FileName}' is no longer there and was dropped from the index.",
                                     "certificates", "security");

                entries.Clear();

                foreach (var entry in found)
                    entries.Add(entry.Key, entry.Value);

                WriteIndex();

                log.Info($"Certificates: {entries.Count} in '{Directory}'" +
                         $"{(adopted > 0 ? $", {adopted} of them newly adopted" : "")}" +
                         $" ({Summarise()}).",
                         "certificates");

                reloaded = true;

            }
            finally
            {
                storeLock.Release();
            }

            if (reloaded)
                Changed();

        }

        #endregion

        #region WarnAboutStoredKeys()

        /// <summary>
        /// Say once, at a start, that the private keys in this store are not
        /// encrypted.
        /// </summary>
        /// <remarks>
        /// Said every start rather than once ever, and as a warning rather than
        /// a note, because the fact does not stop being true and the person
        /// reading the console today is not necessarily the one who set the
        /// store up.
        ///
        /// What there is to take is said by the kinds this store keeps: the
        /// node's identity in every store that keeps a key, and a contract
        /// only in one that keeps contracts - a vehicle's. A gateway keeping
        /// its TLS identity here was warned about a contract it has no kind
        /// for, in the one line of the start that is meant to be believed.
        /// </remarks>
        public void WarnAboutStoredKeys()
        {

            var withKeys = Entries.Count(entry => entry.HasPrivateKey);

            if (withKeys > 0)
                log.Warning($"Certificates: {withKeys} private key(s) are stored unencrypted in '{Directory}'. " +
                            $"Anybody who can read that directory can take this {NodeName}'s identity" +
                            (Kinds.Contains(CertificateKind.Contract) ? " and its contract." : "."),
                            "certificates");

        }

        #endregion


        #region Import(Content, Kind, Password, Label, out Entry, out Error)

        /// <summary>
        /// Put a certificate into the store, copying it in - for every use,
        /// where its kind is kept for some uses and not others.
        /// </summary>
        /// <param name="Content">The file as it arrived.</param>
        /// <param name="Kind">What it is to be used for.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12.</param>
        /// <param name="Label">What to call it; its common name where this is not given.</param>
        public Boolean Import(Byte[]                                      Content,
                              CertificateKind                             Kind,
                              String?                                     Password,
                              String?                                     Label,
                              [NotNullWhen(true)]  out CertificateEntry?  Entry,
                              [NotNullWhen(false)] out String?            Error)

            => Import(Content, Kind, Password, Label, null, out Entry, out Error);

        #endregion

        #region Import(Content, Kind, Password, Label, Usages, out Entry, out Error)

        /// <summary>
        /// Put a certificate into the store, copying it in.
        /// </summary>
        /// <remarks>
        /// <para>
        /// What arrives may be PEM, DER or PKCS#12; what is written is the one
        /// format the reader for that kind accepts - see
        /// <see cref="CertificateKindExtensions.Extension"/>. A PKCS#12 is
        /// opened with <paramref name="Password"/> and written back without
        /// one.
        /// </para>
        /// <para>
        /// Importing the same certificate twice is not an error and not a
        /// duplicate: the id is the fingerprint, so the second import is the
        /// first entry, and the only thing it can change is the label. That is
        /// what makes "import everything in this directory" a safe thing to do
        /// twice.
        /// </para>
        /// <para>
        /// Everything refused here is refused with the reason in the sentence,
        /// because the alternative - a file that turns out to be the wrong kind
        /// halfway through a handshake - shows up as a station that appears to
        /// have hung up.
        /// </para>
        /// </remarks>
        /// <param name="Content">The file as it arrived.</param>
        /// <param name="Kind">What it is to be used for.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12.</param>
        /// <param name="Label">What to call it; its common name where this is not given.</param>
        /// <param name="Usages">What it may be used for, where its kind is kept for some uses and not others; null for every use. Given for a certificate already in the store, it is that certificate's usages from now on.</param>
        public Boolean Import(Byte[]                                      Content,
                              CertificateKind                             Kind,
                              String?                                     Password,
                              String?                                     Label,
                              IEnumerable<String>?                        Usages,
                              [NotNullWhen(true)]  out CertificateEntry?  Entry,
                              [NotNullWhen(false)] out String?            Error)
        {

            Entry  = null;
            Error  = null;

            // Before anything is read or written, so that a kind this store does
            // not keep is not half-imported, and a store that keeps nothing is
            // not given a directory by a refused import.
            if (!Kinds.Contains(Kind))
            {
                Error = $"This {NodeName} keeps no certificate of that kind: {Kind.Describe()}.";
                return false;
            }

            if (!TrySettleUsages(Kind, Usages, out var usages, out Error))
                return false;

            if (Content.Length == 0)
            {
                Error = "There is nothing in that file.";
                return false;
            }

            if (Label is { Length: > CertificateEntry.MaxLabelLength })
            {
                Error = $"A label may be at most {CertificateEntry.MaxLabelLength} characters long.";
                return false;
            }

            X509Certificate2Collection collection;

            try
            {
                collection = ReadCollection(Content, Password);
            }
            catch (Exception exception)
            {
                Error = exception.Message;
                return false;
            }

            if (collection.Count == 0)
            {
                Error = "That file holds no certificate.";
                return false;
            }

            // The leaf is the one with the private key where there is one, and
            // otherwise the first: the same rule the session's own loaders use,
            // so that what the store calls the leaf is what they will.
            var leaf = collection.FirstOrDefault(certificate => certificate.HasPrivateKey) ?? collection[0];

            if (!Suits(leaf, Kind, out Error))
            {
                Dispose(collection);
                return false;
            }

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                var thumbprint = CertificateEntry.ThumbprintOf(leaf);
                var id         = thumbprint[..CertificateEntry.IdLength];

                #region The same certificate again is the same entry

                if (entries.TryGetValue(id, out var existing))
                {

                    if (existing.Thumbprint != thumbprint)
                    {
                        Error = $"The handle '{id}' is already taken by a different certificate " +
                                 "({existing.Label}). Remove that one first.";
                        return false;
                    }

                    if (existing.Kind != Kind)
                    {
                        Error = $"That certificate is already in the store as a {existing.Kind.AsText()} " +
                                $"('{existing.Label}'). One certificate has one purpose - remove it first " +
                                 "to put it back as something else.";
                        return false;
                    }

                    var changed = false;

                    if (Label?.Trim() is { Length: > 0 } relabel && relabel != existing.Label)
                    {
                        existing  = existing with { Label = relabel };
                        changed   = true;
                        log.Info($"Certificates: '{existing.FileName}' is now called '{relabel}'.", "certificates");
                    }

                    // Usages given are the usages from now on; none given leaves
                    // the ones it has, because an import that said nothing about
                    // them said nothing about them.
                    if (Usages is not null && !SameUsages(existing.Usages, usages))
                    {
                        var were  = existing.Usages;
                        existing  = existing with { Usages = usages };
                        changed   = true;
                        log.Metrological(LogLevel.Notice,
                                         $"Certificates: {existing.Label} ({existing.Kind.AsText()}) is now {CertificateUsages.Describe(usages)}, " +
                                         $"where it was {CertificateUsages.Describe(were)}.",
                                         "certificates", "security");
                    }

                    if (changed)
                    {
                        entries[id]   = existing;
                        WriteIndex();
                        storeChanged  = true;
                    }
                    else
                        log.Info($"Certificates: {existing.Label} was already in the store; nothing changed.", "certificates");

                    Entry = existing;
                    return true;

                }

                #endregion

                var fileName  = RelativeName(Kind, id + Kind.Extension());
                var fullPath  = FullPath(fileName);

                try
                {
                    File.WriteAllBytes(fullPath, Serialise(collection, leaf, Kind));
                    Protect(fullPath);
                }
                catch (Exception exception)
                {
                    Error = $"That certificate could not be written to the store: {exception.Message}";
                    return false;
                }

                Entry = CertificateEntry.From(
                            leaf,
                            Kind,
                            fileName,
                            Label,
                            collection.Count - 1,
                            IsActive:  true,
                            Usages:    usages
                        );

                entries.Add(Entry.Id, Entry);
                WriteIndex();
                storeChanged = true;

                log.Metrological(LogLevel.Notice,
                                 $"Certificates: imported {Entry.Label} as {Kind.Describe()}, " +
                                 $"{Entry.KeyAlgorithm}, valid until {Entry.NotAfter.UtcDateTime:yyyy-MM-dd}, SHA-256 {Entry.Thumbprint}. It is switched on" +
                                 $"{(Kind.HasUsages() ? ", " + CertificateUsages.Describe(usages) : "")}.",
                                 "certificates", "security");

                // Said at the import as well as at a start, because the start
                // that matters happened before this key existed: a node that
                // only warned at construction would never mention the first
                // private key anybody put on it.
                if (Entry.HasPrivateKey)
                    log.Warning($"Certificates: the private key of {Entry.Label} is stored unencrypted in " +
                                $"'{Directory}'. Anybody who can read that directory can use it.",
                                "certificates");

                return true;

            }
            finally
            {

                storeLock.Release();
                Dispose(collection);

                if (storeChanged)
                    Changed();

            }

        }

        #endregion

        #region SetActive(Id, Active, out Entry, out Error)

        /// <summary>
        /// Switch one certificate on or off, leaving it where it is.
        /// </summary>
        /// <remarks>
        /// The difference between this and <see cref="Remove"/> is the whole
        /// reason both exist: a certificate somebody is taking out of service
        /// for an afternoon should not have to be imported again afterwards,
        /// and one whose key may have leaked should not merely be switched off.
        /// </remarks>
        public Boolean SetActive(String                                      Id,
                                 Boolean                                     Active,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)
        {

            Entry  = null;
            Error  = null;

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!entries.TryGetValue(Id, out var entry))
                {
                    Error = $"There is no certificate '{Id}' in this store.";
                    return false;
                }

                if (entry.IsActive != Active)
                {

                    Entry        = entry with { IsActive = Active };
                    entries[Id]  = Entry;

                    WriteIndex();
                    storeChanged = true;

                    log.Metrological(LogLevel.Notice,
                                     $"Certificates: {Entry.Label} ({Entry.Kind.AsText()}) was switched {(Active ? "on" : "off")}.",
                                     "certificates", "security");

                }
                else
                    Entry = entry;

                return true;

            }
            finally
            {

                storeLock.Release();

                if (storeChanged)
                    Changed();

            }

        }

        #endregion

        #region Relabel(Id, Label, out Entry, out Error)

        /// <summary>
        /// Change what a certificate is called.
        /// </summary>
        public Boolean Relabel(String                                      Id,
                               String?                                     Label,
                               [NotNullWhen(true)]  out CertificateEntry?  Entry,
                               [NotNullWhen(false)] out String?            Error)
        {

            Entry  = null;
            Error  = null;

            if (Label is { Length: > CertificateEntry.MaxLabelLength })
            {
                Error = $"A label may be at most {CertificateEntry.MaxLabelLength} characters long.";
                return false;
            }

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!entries.TryGetValue(Id, out var entry))
                {
                    Error = $"There is no certificate '{Id}' in this store.";
                    return false;
                }

                // A label taken back is not an empty label: it is the
                // certificate's own name again.
                var settled = Label?.Trim() is { Length: > 0 } given
                                  ? given
                                  : NameFromFile(entry);

                Entry        = entry with { Label = settled };
                entries[Id]  = Entry;

                WriteIndex();
                storeChanged = Entry.Label != entry.Label;

                return true;

            }
            finally
            {

                storeLock.Release();

                if (storeChanged)
                    Changed();

            }

        }

        #endregion

        #region SetUsages(Id, Usages, out Entry, out Error)

        /// <summary>
        /// Say what one certificate may be used for: the given usages, or every
        /// use where none are given.
        /// </summary>
        /// <remarks>
        /// A decision about trust, as switching it on is: a TLS root told it
        /// may vouch for the time servers is one that can make this node
        /// believe a time. So it is written into the metrological log like
        /// every other change of the store, tagged as a matter of security.
        /// </remarks>
        /// <param name="Id">The certificate's handle.</param>
        /// <param name="Usages">What it may be used for from now on; null for every use.</param>
        /// <param name="Entry">The certificate as it is now.</param>
        /// <param name="Error">Why not.</param>
        public Boolean SetUsages(String                                      Id,
                                 IEnumerable<String>?                        Usages,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)
        {

            Entry  = null;
            Error  = null;

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!entries.TryGetValue(Id, out var entry))
                {
                    Error = $"There is no certificate '{Id}' in this store.";
                    return false;
                }

                if (!TrySettleUsages(entry.Kind, Usages, out var usages, out Error))
                    return false;

                if (SameUsages(entry.Usages, usages))
                {
                    Entry = entry;
                    return true;
                }

                Entry        = entry with { Usages = usages };
                entries[Id]  = Entry;

                WriteIndex();
                storeChanged = true;

                log.Metrological(LogLevel.Notice,
                                 $"Certificates: {Entry.Label} ({Entry.Kind.AsText()}) is now {CertificateUsages.Describe(usages)}, " +
                                 $"where it was {CertificateUsages.Describe(entry.Usages)}.",
                                 "certificates", "security");

                return true;

            }
            finally
            {

                storeLock.Release();

                if (storeChanged)
                    Changed();

            }

        }

        #endregion

        #region Remove(Id, out Error)

        /// <summary>
        /// Take a certificate out of the store and delete its file.
        /// </summary>
        /// <remarks>
        /// The file goes. A store whose "delete" left the private key on the
        /// disk would be worse than one with no delete at all, because it would
        /// be believed.
        /// </remarks>
        public Boolean Remove(String                            Id,
                              [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!entries.TryGetValue(Id, out var entry))
                {
                    Error = $"There is no certificate '{Id}' in this store.";
                    return false;
                }

                var fullPath = FullPath(entry.FileName);

                try
                {
                    if (File.Exists(fullPath))
                        File.Delete(fullPath);
                }
                catch (Exception exception)
                {
                    Error = $"'{entry.FileName}' could not be deleted: {exception.Message}";
                    return false;
                }

                entries.Remove(Id);
                WriteIndex();
                storeChanged = true;

                log.Metrological(LogLevel.Notice,
                                 $"Certificates: {entry.Label} ({entry.Kind.AsText()}) was deleted from the store.",
                                 "certificates", "security");

                return true;

            }
            finally
            {

                storeLock.Release();

                if (storeChanged)
                    Changed();

            }

        }

        #endregion


        #region Get(Id) / ByKind(Kind) / UsableByKind(Kind) / UsableFor(Kind, Usage)

        /// <summary>
        /// One entry by its handle, or nothing.
        /// </summary>
        public CertificateEntry? Get(String? Id)
        {

            if (Id is null)
                return null;

            storeLock.Wait();

            try
            {
                return entries.GetValueOrDefault(Id);
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// The entry whose certificate has this SHA-256 fingerprint, of whatever
        /// kind it is kept as, or nothing.
        /// </summary>
        /// <remarks>
        /// The whole fingerprint and nothing shorter, written in any of the
        /// ways <see cref="CertificateEntry.TryParseFingerprint"/> reads. What
        /// a configuration holds a server to - its own certificate, or the root
        /// its chain has to end at - is found here by what it was written down
        /// as, rather than by a handle that means something to this store only.
        /// </remarks>
        /// <param name="Fingerprint">The SHA-256 fingerprint of the certificate.</param>
        public CertificateEntry? ByFingerprint(String? Fingerprint)
        {

            if (!CertificateEntry.TryParseFingerprint(Fingerprint, out var fingerprint))
                return null;

            storeLock.Wait();

            try
            {
                return entries.Values.FirstOrDefault(entry => String.Equals(entry.Thumbprint, fingerprint, StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// Everything of one kind, by label.
        /// </summary>
        public IReadOnlyList<CertificateEntry> ByKind(CertificateKind Kind)

            => [.. Entries.Where(entry => entry.Kind == Kind)];

        /// <summary>
        /// Everything of one kind this node would use right now: switched
        /// on, and inside its own validity.
        /// </summary>
        public IReadOnlyList<CertificateEntry> UsableByKind(CertificateKind Kind)

            => [.. Entries.Where(entry => entry.Kind == Kind && entry.IsUsable)];

        /// <summary>
        /// Everything of one kind this node would use right now for the given
        /// usage: switched on, inside its own validity, and for that use - or
        /// for every use, where it was never told which.
        /// </summary>
        /// <param name="Kind">A kind kept for some uses and not others.</param>
        /// <param name="Usage">The usage.</param>
        public IReadOnlyList<CertificateEntry> UsableFor(CertificateKind  Kind,
                                                        String           Usage)

            => [.. Entries.Where(entry => entry.Kind == Kind && entry.IsUsable && entry.IsFor(Usage))];

        #endregion

        #region TryLoad(Entry, out Certificate, out Error) / UsableCertificates(Kind)

        /// <summary>
        /// The certificate of one entry, read from its file.
        /// </summary>
        /// <remarks>
        /// The certificate the entry is about, with its private key where the
        /// file has one. Whoever asks owns what comes back, and disposes of it.
        /// </remarks>
        /// <param name="Entry">The entry.</param>
        /// <param name="Certificate">Its certificate.</param>
        /// <param name="Error">Why it could not be read, when it could not.</param>
        public Boolean TryLoad(CertificateEntry                              Entry,
                               [NotNullWhen(true)]  out X509Certificate2?  Certificate,
                               [NotNullWhen(false)] out String?            Error)

            => TryRead(FullPath(Entry), out Certificate, out _, out Error);

        /// <summary>
        /// The certificates of every entry of one kind this node would use right
        /// now - switched on, and inside its own validity - as far as they
        /// can be read.
        /// </summary>
        /// <remarks>
        /// For the roots a chain is built against. One whose file cannot be read
        /// any more is left out rather than failing the others: a root that is
        /// not there anchors nothing, which is what an unreadable one does too,
        /// and a start said so about it already.
        /// </remarks>
        /// <param name="Kind">The kind.</param>
        public IReadOnlyList<X509Certificate2> UsableCertificates(CertificateKind Kind)
        {

            var certificates = new List<X509Certificate2>();

            foreach (var entry in UsableByKind(Kind))
                if (TryLoad(entry, out var certificate, out _))
                    certificates.Add(certificate);

            return certificates;

        }

        #endregion

        #region FullPath(Entry) / FullPath(FileName)

        /// <summary>
        /// Where one entry's file actually is.
        /// </summary>
        public String FullPath(CertificateEntry Entry)

            => FullPath(Entry.FileName);

        /// <summary>
        /// Where a store-relative name actually is.
        /// </summary>
        public String FullPath(String FileName)

            => Path.Combine(Directory, FileName.Replace('/', Path.DirectorySeparatorChar));

        #endregion


        #region Summarise()

        /// <summary>
        /// What is in the store, by kind, as one line for a log entry.
        /// </summary>
        private String Summarise()
        {

            var parts = new List<String>();

            foreach (var kind in Kinds)
            {

                var all = entries.Values.Where(entry => entry.Kind == kind).ToArray();

                if (all.Length == 0)
                    continue;

                var usable = all.Count(entry => entry.IsUsable);

                parts.Add(usable == all.Length
                              ? $"{all.Length} {kind.AsText()}"
                              : $"{all.Length} {kind.AsText()} ({usable} usable)");

            }

            return parts.Count > 0
                       ? String.Join(", ", parts)
                       : "empty";

        }

        #endregion


        #region (private) Changed()

        /// <summary>
        /// Tell whoever follows this store that it changed - see
        /// <see cref="OnChanged"/>. Called with the lock released only.
        /// </summary>
        private void Changed()
        {

            var handler = OnChanged;

            if (handler is null)
                return;

            foreach (var listener in handler.GetInvocationList().Cast<Action>())
            {
                try
                {
                    listener();
                }
                catch (Exception exception)
                {
                    log.Warning($"Certificates: what follows this store failed when it changed: {exception.Message}",
                                "certificates");
                }
            }

        }

        #endregion

        #region TrySettleUsages(Kind, Usages, out Settled, out Error)

        /// <summary>
        /// The usages as this store keeps them - in lower case, each once, in
        /// the order it lists them - or why they cannot be kept.
        /// </summary>
        /// <remarks>
        /// None given is every use, and is what every certificate was before
        /// there were usages. An empty list is refused rather than kept: a
        /// certificate for no use at all is one to switch off, which says so.
        /// Asked from outside as well, before a change is made, so that what a
        /// node is asked about a change is what the store would keep - and so
        /// that a change refused for its usages is refused before anything of
        /// it is made.
        /// </remarks>
        public Boolean TrySettleUsages(CertificateKind                    Kind,
                                       IEnumerable<String>?               Usages,
                                       out IReadOnlyList<String>?         Settled,
                                       [NotNullWhen(false)] out String?   Error)
        {

            Settled  = null;
            Error    = null;

            if (Usages is null)
                return true;

            var allowed    = UsagesFor(Kind);
            var isIdentity = Kind == CertificateKind.TLSIdentity;

            if (allowed.Count == 0)
            {
                Error = isIdentity
                            ? $"A {Kind.AsText()} is shown on every listener of this {NodeName}, which names none an identity " +
                               "could be told of: only a TLS root and a server certificate are kept for some uses and not " +
                               "others, and a TLS identity is shown on the listeners a kind of node names."
                            : $"A {Kind.AsText()} is for what its kind says, and is not told what it is used for: " +
                               "only a TLS root and a server certificate are kept for some uses and not others, " +
                               "and a TLS identity is shown on some listeners and not others.";
                return false;
            }

            var given = Usages.Select(usage => usage?.Trim().ToLowerInvariant() ?? "").Distinct().ToList();

            if (given.Count == 0)
            {
                Error = isIdentity
                            ? "An identity shown on no listener at all is one to switch off. Name where it is shown - or nothing, for every listener."
                            : "A certificate for no use at all is one to switch off. Name what it is for - or nothing, for every use.";
                return false;
            }

            if (given.FirstOrDefault(usage => !allowed.Contains(usage)) is String unknown)
            {
                Error = isIdentity
                            ? $"'{unknown}' is not a listener of this {NodeName}. Its listeners are: {String.Join(", ", allowed)}."
                            : $"'{unknown}' is not a usage this {NodeName} knows. Its usages are: {String.Join(", ", allowed)}.";
                return false;
            }

            Settled = [.. allowed.Where(given.Contains)];
            return true;

        }

        #endregion

        #region (private static) SameUsages(Some, Others)

        /// <summary>
        /// Whether two sets of usages are the same set: both every use, or the
        /// same usages in whatever order.
        /// </summary>
        private static Boolean SameUsages(IReadOnlyList<String>?  Some,
                                          IReadOnlyList<String>?  Others)

            => Some is null || Others is null
                   ? Some is null && Others is null
                   : Some.Count == Others.Count && !Some.Except(Others, StringComparer.OrdinalIgnoreCase).Any();

        #endregion

        #region (private) CreateDirectories()

        /// <summary>
        /// Make the store and one directory per kind it keeps, readable by
        /// their owner alone where the platform has anything to say about it -
        /// and nothing at all for a store that keeps no kind.
        /// </summary>
        private void CreateDirectories()
        {

            if (Kinds.Count == 0)
                return;

            System.IO.Directory.CreateDirectory(Directory);
            Protect(Directory);

            foreach (var kind in Kinds)
                System.IO.Directory.CreateDirectory(
                    Path.Combine(Directory, kind.Directory().Replace('/', Path.DirectorySeparatorChar))
                );

        }

        #endregion

        #region (private static) Protect(Path)

        /// <summary>
        /// Keep everybody but the owner out, where the platform supports saying
        /// so in one call.
        /// </summary>
        /// <remarks>
        /// Unix only, and silent where it is not available. On Windows a new
        /// directory below the user's profile already inherits an ACL that
        /// grants the user and the administrators and nobody else, and rewriting
        /// that ACL here would be a larger promise than this can keep. The
        /// warning at every start is what covers the difference.
        /// </remarks>
        private static void Protect(String Path)
        {

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;

            try
            {

                var mode = System.IO.Directory.Exists(Path)
                               ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                               : UnixFileMode.UserRead | UnixFileMode.UserWrite;

                File.SetUnixFileMode(Path, mode);

            }
            catch (Exception)
            {
                // A store on a file system with no modes is still a store.
            }

        }

        #endregion

        #region (private static) RelativeName(Kind, FileName)

        /// <summary>
        /// A store-relative name, always with forward slashes so that an index
        /// written on one platform reads on the other.
        /// </summary>
        private static String RelativeName(CertificateKind  Kind,
                                           String           FileName)

            => $"{Kind.Directory()}/{FileName}";

        #endregion

        #region (private static) NameFromFile(Entry)

        /// <summary>
        /// What an entry is called when nobody has named it: its subject's
        /// common name as it was read, falling back to its handle.
        /// </summary>
        private static String NameFromFile(CertificateEntry Entry)
        {

            var common = Entry.Subject.Split(',').
                                       Select (part => part.Trim()).
                                       FirstOrDefault(part => part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));

            return common is { Length: > 3 }
                       ? common[3..]
                       : Entry.Id;

        }

        #endregion


        #region (private static) ReadCollection(Content, Password)

        /// <summary>
        /// Whatever arrived, as a collection of certificates.
        /// </summary>
        /// <remarks>
        /// PEM first because it is the only one that can be recognised by
        /// looking, then PKCS#12, then a bare DER certificate. The order
        /// matters only for the error somebody sees: a file that is none of
        /// these should be told it is not a certificate, not that its password
        /// was wrong.
        /// </remarks>
        private static X509Certificate2Collection ReadCollection(Byte[]   Content,
                                                                 String?  Password)
        {

            var collection = new X509Certificate2Collection();

            #region PEM, which may hold several

            var asText = LooksLikeText(Content)
                             ? System.Text.Encoding.UTF8.GetString(Content)
                             : null;

            if (asText is not null && asText.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {

                collection.ImportFromPem(asText);

                if (collection.Count == 0)
                    throw new ArgumentException("That file looks like PEM, and holds no certificate that can be read.");

                // A PEM that carries its key as well is one file for a whole
                // credential, and that is how most tools hand one over.
                // ImportFromPem takes the certificates and silently passes the
                // key by, so pairing it is done here or not at all.
                AttachPrivateKey(collection, asText, Password);

                return collection;

            }

            #endregion

            #region PKCS#12

            try
            {

                // Exportable, because a Vehicle certificate has to be handed to
                // the BouncyCastle backend and an OEM key has to become an ECDH
                // handle - neither of which works on a key loaded without it.
                collection.AddRange(
                    X509CertificateLoader.LoadPkcs12Collection(
                        Content,
                        Password,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet
                    )
                );

                if (collection.Count > 0)
                    return collection;

            }
            catch (CryptographicException exception)
            {

                // A DER certificate is not a PKCS#12 and fails here first, so
                // this is only an answer once that has been ruled out.
                if (TryReadDer(Content, collection))
                    return collection;

                // And a file that is not DER either was never a candidate for
                // any of this. Saying "wrong password?" about a text file sends
                // somebody looking for a password that does not exist, which is
                // a worse answer than none.
                if (!LooksLikeDer(Content))
                    throw new ArgumentException(
                              "That file is not a certificate that can be read (PEM, DER or PKCS#12).");

                throw new ArgumentException(
                          Password is null
                              ? $"That file could not be read. If it is a password-protected PKCS#12, give the password. ({exception.Message})"
                              : $"That file could not be read - wrong password? ({exception.Message})"
                      );

            }

            #endregion

            if (TryReadDer(Content, collection))
                return collection;

            throw new ArgumentException("That file is not a certificate that can be read (PEM, DER or PKCS#12).");

        }

        #endregion

        #region (private static) TryReadDer(Content, Collection)

        /// <summary>
        /// One bare DER certificate, where that is what it is.
        /// </summary>
        private static Boolean TryReadDer(Byte[]                      Content,
                                          X509Certificate2Collection  Collection)
        {

            try
            {
                Collection.Add(X509CertificateLoader.LoadCertificate(Content));
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }

        }

        #endregion

        #region (private static) AttachPrivateKey(Collection, Pem, Password)

        /// <summary>
        /// Where a PEM carries a private key beside its certificates, give it to
        /// the one it belongs to.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <see cref="X509Certificate2Collection.ImportFromPem"/> reads certificates and nothing else: a key
        /// block in the same file is passed over without a word. That is the right behaviour for a trust
        /// store and the wrong one for a credential, where one PEM holding a leaf, its sub-CAs and its key
        /// is how most tools hand a whole identity over - so the pairing happens here.
        /// </para>
        /// <para>
        /// Which certificate the key belongs to is not assumed from the order. Every certificate in the
        /// file is offered the key and the one it actually matches takes it, because a chain may be written
        /// leaf-first or root-first and both are common. The matching one is put at the front afterwards,
        /// so that everything downstream - which takes the first certificate, or the one with a key - finds
        /// the leaf where it expects it.
        /// </para>
        /// <para>
        /// An encrypted key block is opened with the same password an encrypted PKCS#12 would be, which is
        /// the one somebody already typed. A key that matches nothing in the file is an error rather than a
        /// silent omission: it is a file somebody believed was a whole credential, and the alternative is a
        /// certificate that is quietly refused two steps later for having no key.
        /// </para>
        /// </remarks>
        private static void AttachPrivateKey(X509Certificate2Collection  Collection,
                                             String                      Pem,
                                             String?                     Password)
        {

            var key = KeyBlockOf(Pem);

            if (key is null)
                return;

            // Whether the key is encrypted is a property of the block, not of
            // whether somebody happened to type a password: a PEM whose key is
            // in the clear must not be opened with the encrypted reader just
            // because a password was left in the form.
            var encrypted = key.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal);

            if (encrypted && Password is not { Length: > 0 })
                throw new ArgumentException(
                          "That file's private key is encrypted. Give the password that opens it.");

            for (var i = 0; i < Collection.Count; i++)
            {

                var certificate = Collection[i];

                if (certificate.HasPrivateKey)
                    return;

                X509Certificate2 paired;

                try
                {
                    paired = encrypted
                                 ? X509Certificate2.CreateFromEncryptedPem(certificate.ExportCertificatePem(), key, Password!)
                                 : X509Certificate2.CreateFromPem         (certificate.ExportCertificatePem(), key);
                }
                catch (ArgumentException)
                {
                    // Not this certificate's key. Try the next one.
                    continue;
                }
                catch (CryptographicException exception)
                {
                    // A key this node cannot open at all: wrong password, or
                    // a kind of key it does not carry. Worth saying once rather
                    // than once per certificate in the file.
                    throw new ArgumentException(
                              encrypted
                                  ? $"That file's private key could not be opened - wrong password? ({exception.Message})"
                                  : $"That file's private key is of a kind that cannot be read. ({exception.Message})");
                }

                // Round-tripped through PKCS#12 so that the key is exportable:
                // a key attached from PEM is ephemeral, and the store has to
                // write it out again - and the BouncyCastle backend and the OEM
                // ECDH unwrap both need to export it later.
                using (paired)
                {

                    var exportable = X509CertificateLoader.LoadPkcs12(
                                         paired.Export(X509ContentType.Pkcs12) ?? [],
                                         (String?) null,
                                         X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet
                                     );

                    Collection[i] = exportable;

                }

                // The one with the key is the leaf, wherever it was written.
                if (i > 0)
                {
                    (Collection[0], Collection[i]) = (Collection[i], Collection[0]);
                }

                return;

            }

            throw new ArgumentException(
                      "That file carries a private key that belongs to none of the certificates in it. " +
                      "A credential is one leaf, its key, and the sub-CAs above it.");

        }

        #endregion

        #region (private static) KeyBlockOf(Pem)

        /// <summary>
        /// The first private key block in a PEM, whichever of the four spellings it uses, or nothing.
        /// </summary>
        private static String? KeyBlockOf(String Pem)
        {

            foreach (var label in new[] { "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY" })
            {

                var opening = $"-----BEGIN {label}-----";
                var closing = $"-----END {label}-----";

                var from = Pem.IndexOf(opening, StringComparison.Ordinal);

                if (from < 0)
                    continue;

                var to = Pem.IndexOf(closing, from, StringComparison.Ordinal);

                if (to < 0)
                    continue;

                return Pem[from..(to + closing.Length)];

            }

            return null;

        }

        #endregion

        #region (private static) LooksLikeDer(Content)

        /// <summary>
        /// Whether a file could be DER at all - that is, whether it begins with
        /// an ASN.1 SEQUENCE.
        /// </summary>
        /// <remarks>
        /// Both a PKCS#12 and a DER certificate do. Used only to decide which
        /// sentence somebody gets back: a file that does not start this way was
        /// never a PKCS#12, so telling them their password might be wrong is
        /// sending them after something that does not exist.
        /// </remarks>
        private static Boolean LooksLikeDer(Byte[] Content)

            => Content.Length > 1 && Content[0] == 0x30;

        #endregion

        #region (private static) LooksLikeText(Content)

        /// <summary>
        /// Whether a file could be PEM at all, which is worth asking before
        /// decoding a megabyte of DER as UTF-8.
        /// </summary>
        private static Boolean LooksLikeText(Byte[] Content)
        {

            foreach (var b in Content.Take(64))
                if (b == 0)
                    return false;

            return true;

        }

        #endregion

        #region (private static) Suits(Leaf, Kind, out Error)

        /// <summary>
        /// Whether a certificate can be what somebody is importing it as.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Three checks, each of which stands for a failure that is otherwise
        /// discovered in the middle of a session. A credential without its
        /// private key cannot be presented. A trust anchor that is not
        /// self-signed is not an anchor - <c>X509ChainTrustMode.CustomRootTrust</c>
        /// requires the chain to end in a self-signed certificate that is in the
        /// store, so a Sub-CA imported as a root simply never anchors anything.
        /// And a trust anchor carrying a private key is somebody's CA key in the
        /// wrong place, which is refused rather than quietly stripped.
        /// </para>
        /// <para>
        /// A client root is the exception to the second: the listener that asks
        /// for it judges a client against the CA that issued it, and the CA that
        /// issues a node's clients and nothing else is the anchor that says who
        /// may connect - the root above it would let in the devices too. So a
        /// client root may be an issuing CA, and has to be a CA, which a
        /// self-signed root is by being one.
        /// </para>
        /// <para>
        /// The OEM curve is a warning at import and not a refusal, because
        /// ISO 15118-2 has no such requirement and a P-256 OEM certificate is
        /// perfectly real - it just cannot finish -20's contract provisioning.
        /// The session says so again where it matters.
        /// </para>
        /// </remarks>
        private static Boolean Suits(X509Certificate2                  Leaf,
                                     CertificateKind                   Kind,
                                     [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            if (Kind.NeedsPrivateKey() && !Leaf.HasPrivateKey)
            {
                Error = $"A {Kind.Describe()} has to carry its private key, and that file has none. " +
                         "It is probably a PKCS#12 that needs a password, or the public half of the pair.";
                return false;
            }

            if (Kind == CertificateKind.TLSServer && Leaf.HasPrivateKey)
            {
                Error = "That file carries a private key, and a server's certificate kept here must not: " +
                        "it is that server's key, in the wrong place. Import the certificate on its own.";
                return false;
            }

            if (Kind.IsTrustAnchor())
            {

                if (Leaf.HasPrivateKey)
                {
                    Error = "That file carries a private key, and a trust anchor must not. " +
                            "Import the certificate on its own.";
                    return false;
                }

                var selfSigned = String.Equals(Leaf.Subject, Leaf.Issuer, StringComparison.Ordinal);

                if (Kind == CertificateKind.ClientRoot)
                {

                    if (!selfSigned && !IsCA(Leaf))
                    {
                        Error = $"'{CertificateEntry.CommonNameOf(Leaf)}' is not a CA certificate. A client root is " +
                                 "the CA that signs the clients - a root, or the issuing CA below one - and not a client.";
                        return false;
                    }

                }

                else if (!selfSigned)
                {
                    Error = $"'{CertificateEntry.CommonNameOf(Leaf)}' is signed by somebody else and is therefore " +
                             "a sub-CA rather than a root. Only a self-signed certificate can be a trust anchor; " +
                             "a sub-CA travels with the certificate it signed.";
                    return false;
                }

            }

            return true;

        }

        #endregion

        #region (private static) IsCA(Certificate)

        /// <summary>
        /// Whether the certificate says it is a CA, in its basic constraints.
        /// </summary>
        private static Boolean IsCA(X509Certificate2 Certificate)

            => Certificate.Extensions.OfType<X509BasicConstraintsExtension>().
                                      FirstOrDefault()?.CertificateAuthority == true;

        #endregion

        #region (private static) Serialise(Collection, Leaf, Kind)

        /// <summary>
        /// The bytes to write for one import: PEM for a trust anchor, PKCS#12
        /// without a password for everything else.
        /// </summary>
        /// <remarks>
        /// The leaf is written first so that a reader taking "the first
        /// certificate" gets the one this is about. For a trust anchor there is
        /// only ever the one - the sub-CAs a root arrived with are not anchors
        /// and are dropped rather than promoted.
        /// </remarks>
        private static Byte[] Serialise(X509Certificate2Collection  Collection,
                                        X509Certificate2            Leaf,
                                        CertificateKind             Kind)
        {

            if (Kind.IsTrustAnchor())
                return System.Text.Encoding.ASCII.GetBytes(Leaf.ExportCertificatePem() + Environment.NewLine);

            var ordered = new X509Certificate2Collection(Leaf);

            foreach (var certificate in Collection)
                if (!ReferenceEquals(certificate, Leaf))
                    ordered.Add(certificate);

            return ordered.Export(X509ContentType.Pkcs12, password: (String?) null)
                       ?? throw new CryptographicException("That certificate could not be written as PKCS#12.");

        }

        #endregion

        #region (private static) TryRead(Path, out Certificate, out ChainLength, out Error)

        /// <summary>
        /// One file in the store, as the certificate it is about and how many
        /// others travel with it.
        /// </summary>
        private static Boolean TryRead(String                                  Path,
                                       [NotNullWhen(true)]  out X509Certificate2?  Certificate,
                                       out Int32                               ChainLength,
                                       [NotNullWhen(false)] out String?        Error)
        {

            Certificate  = null;
            ChainLength  = 0;
            Error        = null;

            try
            {

                var collection = ReadCollection(File.ReadAllBytes(Path), Password: null);

                Certificate  = collection.FirstOrDefault(certificate => certificate.HasPrivateKey) ?? collection[0];
                ChainLength  = collection.Count - 1;

                foreach (var other in collection)
                    if (!ReferenceEquals(other, Certificate))
                        other.Dispose();

                return true;

            }
            catch (Exception exception)
            {
                Error = exception.Message;
                return false;
            }

        }

        #endregion

        #region (private static) Dispose(Collection)

        /// <summary>
        /// Let go of everything that was read for one import.
        /// </summary>
        private static void Dispose(X509Certificate2Collection Collection)
        {

            foreach (var certificate in Collection)
                certificate.Dispose();

        }

        #endregion


        #region (private) ReadIndex() / WriteIndex()

        /// <summary>
        /// What the index remembers, by handle. A missing index is an empty
        /// one; a damaged index is named and then treated as empty, which costs
        /// labels and switches and no certificates.
        /// </summary>
        private Dictionary<String, CertificateEntry> ReadIndex()
        {

            var remembered  = new Dictionary<String, CertificateEntry>();
            var path        = Path.Combine(Directory, IndexFileName);

            if (!File.Exists(path))
                return remembered;

            try
            {

                var json = JObject.Parse(File.ReadAllText(path));

                if (json["certificates"] is not JArray array)
                    return remembered;

                foreach (var token in array.OfType<JObject>())
                {

                    if (!CertificateEntry.TryParse(token, out var entry, out var error))
                    {
                        log.Warning($"Certificates: the index has an entry this {NodeName} could not read - {error}",
                                    "certificates");
                        continue;
                    }

                    remembered[entry.Id] = entry;

                }

            }
            catch (Exception exception)
            {
                log.Warning($"Certificates: '{IndexFileName}' could not be read and the store was taken from its " +
                            $"directory alone, so labels and on/off are back to their defaults - {exception.Message}",
                            "certificates");
            }

            return remembered;

        }

        /// <summary>
        /// Write the index. Called from inside <see cref="storeLock"/> by
        /// everything that changes the store.
        /// </summary>
        private void WriteIndex()
        {

            var path = Path.Combine(Directory, IndexFileName);

            try
            {

                var json = new JObject(
                               new JProperty("certificates",
                                   new JArray(
                                       entries.Values.
                                           OrderBy(entry => entry.Kind.SortOrder()).
                                           ThenBy (entry => entry.Label, StringComparer.OrdinalIgnoreCase).
                                           Select (entry => entry.ToJSON())
                                   ))
                           );

                // Written beside and moved over, so that a node killed mid-write
                // comes back to the index it had rather than to half of a new one.
                var temporary = path + ".new";

                File.WriteAllText(temporary, json.ToString(Newtonsoft.Json.Formatting.Indented));
                File.Move(temporary, path, overwrite: true);

                Protect(path);

            }
            catch (Exception exception)
            {
                log.Error($"Certificates: '{IndexFileName}' could not be written, so labels and on/off will not " +
                          $"survive a restart - {exception.Message}",
                          "certificates");
            }

        }

        #endregion

    }

}
