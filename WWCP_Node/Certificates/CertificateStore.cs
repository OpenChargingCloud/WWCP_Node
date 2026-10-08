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
using System.Formats.Asn1;
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

        private readonly SemaphoreSlim                                                  storeLock  = new (1, 1);

        /// <summary>
        /// Every registration in the store: a certificate once for each kind it
        /// is kept as, by its handle and that kind.
        /// </summary>
        private readonly Dictionary<(String Id, CertificateKind Kind), CertificateEntry>  entries    = [];

        /// <summary>
        /// What the index remembers of kinds this node does not keep: not in
        /// the store, and written back into the index as it was read, for the
        /// day such a kind is kept again - switched off where it was, under
        /// its label.
        /// </summary>
        private readonly Dictionary<(String Id, CertificateKind Kind), CertificateEntry>  setAside   = [];
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
        /// What a TLS root or a server certificate is offered to be told it is
        /// for: the node's usages, and its kind's - the servers this node
        /// connects to.
        /// </summary>
        /// <remarks>
        /// What a page offers, and not all a certificate may be told: whoever
        /// looks after a node may mark a certificate with a usage of their own,
        /// which is offered from then on for as long as a certificate is marked
        /// with it - see <see cref="KnownUsages"/>.
        /// </remarks>
        public IReadOnlyList<CertificateUsage> Usages { get; }

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
        public IReadOnlyList<CertificateUsage> Listeners { get; }

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

            var usages      = new List<CertificateUsage>(CertificateUsages.All);

            foreach (var usage in NamesOf(Usages, nameof(Usages)))
                if (!usages.Contains(usage))
                    usages.Add(usage);

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
        private static IReadOnlyList<CertificateUsage> NamesOf(IEnumerable<String>?  Names,
                                                               String                Parameter)
        {

            var names = new List<CertificateUsage>();

            foreach (var given in Names ?? [])
            {

                if (!CertificateUsage.TryParse(given, out var name))
                    throw new ArgumentException($"'{given}' is not a name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.",
                                                Parameter);

                if (!names.Contains(name))
                    names.Add(name);

            }

            return names;

        }

        #endregion

        #region UsagesFor(Kind) / HasUsages(Kind) / KnownUsages(Kind)

        /// <summary>
        /// What a certificate of this kind is offered to be told it is for in
        /// this store by the node itself: the usages for a TLS root or a server
        /// certificate, the listeners for a TLS identity, and nothing for the
        /// other kinds.
        /// </summary>
        /// <remarks>
        /// What a page offers where a certificate is imported or changed, beside
        /// the usages somebody marked a certificate of the kind with - see
        /// <see cref="KnownUsages"/>.
        /// </remarks>
        public IReadOnlyList<CertificateUsage> UsagesFor(CertificateKind Kind)

            => Kind == CertificateKind.TLSRoot || Kind == CertificateKind.TLSServer
                   ? Usages
                   : Kind == CertificateKind.TLSIdentity
                         ? Listeners
                         : [];

        /// <summary>
        /// Whether a certificate of this kind may be told what it is for in this
        /// store: every kind may, by the usages the node offers it or by usages
        /// somebody marks it with.
        /// </summary>
        public Boolean HasUsages(CertificateKind Kind)

            => Kind.HasUsages();

        /// <summary>
        /// Every usage a certificate of this kind is offered: what the node
        /// offers it, then every usage a certificate in the store is marked
        /// with, in the order of their names.
        /// </summary>
        /// <remarks>
        /// Nothing remembers a usage somebody made up but the certificates
        /// marked with it: once the last of them is deleted, or told otherwise,
        /// it is offered no more.
        /// </remarks>
        public IReadOnlyList<CertificateUsage> KnownUsages(CertificateKind Kind)
        {

            var offered = new List<CertificateUsage>(UsagesFor(Kind));

            foreach (var usage in Entries.SelectMany(entry => entry.Usages ?? []).Distinct().Order())
                if (!offered.Contains(usage))
                    offered.Add(usage);

            return offered;

        }

        #endregion

        #region Keeps(Kind) / KindsKept

        /// <summary>
        /// Whether this store keeps certificates of the given kind: one it was
        /// made with, or one somebody made up - which a store keeps where it
        /// keeps any kind at all.
        /// </summary>
        public Boolean Keeps(CertificateKind Kind)

            => Kinds.Contains(Kind) ||
               (Kind.IsCustom && Kinds.Count > 0);

        /// <summary>
        /// Every kind there is a page for: the kinds this store was made with,
        /// then every made-up kind a certificate in it is kept as.
        /// </summary>
        public IReadOnlyList<CertificateKind> KindsKept
        {
            get
            {

                var kinds = new List<CertificateKind>(Kinds);

                foreach (var kind in Entries.Select(entry => entry.Kind).Where(kind => kind.IsCustom).Distinct().
                                             OrderBy(kind => kind.SortOrder()).ThenBy(kind => kind.AsText(), StringComparer.OrdinalIgnoreCase))
                    if (!kinds.Contains(kind))
                        kinds.Add(kind);

                return kinds;

            }
        }

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
                var found       = new Dictionary<(String Id, CertificateKind Kind), CertificateEntry>();
                var adopted     = 0;

                // Only the directories of the kinds kept are read, so an entry
                // of any other kind is not found - and is not gone either. It
                // was dropped from the index as if it were, the security log
                // saying of a file that was still there that it was "no longer
                // there", and a root switched off came back switched on when
                // its kind was kept again (found by the CSMS).
                setAside.Clear();

                foreach (var entry in remembered.Values.Where(entry => !Keeps(entry.Kind)))
                    setAside.Add((entry.Id, entry.Kind), entry);

                foreach (var kind in KindsToRead(remembered.Values))
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

                            // The same certificate in the directory of another
                            // kind is that certificate kept as that kind too; in
                            // the directory of this kind twice, it is one file
                            // too many.
                            if (found.ContainsKey((entry.Id, kind)))
                            {
                                log.Warning($"Certificates: '{relative}' is the same certificate as one already read and was skipped.",
                                            "certificates");
                                continue;
                            }

                            found.Add((entry.Id, kind), entry);

                            if (known is null)
                            {
                                adopted++;
                                log.Metrological(LogLevel.Notice,
                                                 $"Certificates: adopted '{relative}' - {entry.Label}, {kind.Describe(NodeName)}. It is switched on" +
                                                 $"{(kind.HasUsages() ? ", " + CertificateUsages.Describe(entry.Usages) : "")}.",
                                                 "certificates", "security");
                            }

                        }

                    }

                }

                foreach (var gone in remembered.Values.Where(entry => Keeps(entry.Kind) && !found.ContainsKey((entry.Id, entry.Kind))))
                    log.Metrological(LogLevel.Notice,
                                     $"Certificates: '{gone.FileName}' is no longer there and was dropped from the index.",
                                     "certificates", "security");

                // What a certificate is called is the certificate's, whichever
                // kinds it is kept as: the name the index remembers for one of
                // them - a file copied into another kind's directory takes the
                // name it has already - or else its own.
                foreach (var registrations in found.Values.GroupBy(entry => entry.Id).Where(group => group.Count() > 1).ToList())
                {

                    var label = registrations.OrderBy(entry => entry.Kind.SortOrder()).
                                              Select (entry => remembered.GetValueOrDefault((entry.Id, entry.Kind))?.Label).
                                              FirstOrDefault(name => name is { Length: > 0 })
                                ?? registrations.OrderBy(entry => entry.Kind.SortOrder()).First().Label;

                    foreach (var entry in registrations)
                        found[(entry.Id, entry.Kind)] = entry with { Label = label };

                }

                if (setAside.Count > 0)
                    log.Info($"Certificates: {setAside.Count} in the index of a kind this {NodeName} does not keep " +
                             $"({String.Join(", ", setAside.Values.Select(entry => entry.Kind.Describe(NodeName)).Distinct())}) " +
                             $"left as {(setAside.Count == 1 ? "it was" : "they were")}.",
                             "certificates");

                entries.Clear();

                foreach (var entry in found)
                    entries.Add(entry.Key, entry.Value);

                // What was read is what the directory holds, whether or not
                // the index can say so: that it could not is logged.
                TryWriteIndex(PutBack: false, out _);

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

        #region (private) KindsToRead(Remembered)

        /// <summary>
        /// The kinds whose directories a reading looks in: the kinds the store
        /// was made with, every made-up kind the index remembers, and every one
        /// whose directory is there below "custom/" - so that a made-up kind
        /// comes back with its certificates where the index did not.
        /// </summary>
        private IReadOnlyList<CertificateKind> KindsToRead(IEnumerable<CertificateEntry> Remembered)
        {

            var kinds = new List<CertificateKind>(Kinds);

            if (Kinds.Count == 0)
                return kinds;

            foreach (var kind in Remembered.Select(entry => entry.Kind).Where(kind => kind.IsCustom))
                if (!kinds.Contains(kind))
                    kinds.Add(kind);

            foreach (var group in Enum.GetValues<CertificateGroup>())
            {

                var below = Path.GetDirectoryName(CertificateKind.Custom("x", group).Directory().Replace('/', Path.DirectorySeparatorChar))!;
                var path  = Path.Combine(Directory, below);

                if (!System.IO.Directory.Exists(path))
                    continue;

                foreach (var directory in System.IO.Directory.EnumerateDirectories(path).Order(StringComparer.Ordinal))
                {

                    var name = Path.GetFileName(directory);

                    if (!CertificateKind.IsKindName(name) || CertificateKind.TryParse(name, out CertificateKind _))
                        continue;

                    var kind = CertificateKind.Custom(name, group);

                    if (!kinds.Contains(kind))
                        kinds.Add(kind);

                }

            }

            return kinds;

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


        #region (static) CouldImport(Content, Kind, Password, out Error)

        /// <summary>
        /// Whether a file would go into a store as the given kind, as far as the
        /// file alone can say: not empty, a certificate, opened by the password
        /// where it needs one, with a private key where its kind needs one and
        /// none where it may have none - asked before there is a store, by a
        /// command line that is to import it.
        /// </summary>
        /// <remarks>
        /// Refused only once the node had been made, a TLS identity without its
        /// key left the store, the log with the log book's signing key and an
        /// empty directory of accounts behind (found by the charging station and
        /// the hub). What only a store can say - that it keeps the kind, or has
        /// the certificate already as another - its Import says.
        /// </remarks>
        /// <param name="Content">The file as it is.</param>
        /// <param name="Kind">What it is to be used for.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12.</param>
        public static Boolean CouldImport(Byte[]                            Content,
                                          CertificateKind                   Kind,
                                          String?                           Password,
                                          [NotNullWhen(false)] out String?  Error)

            => CouldImport(Content, Kind, Password, out Error, out _);

        #endregion

        #region (static) CouldImport(Content, Kind, Password, out Error, out PasswordWanted)

        /// <summary>
        /// Whether a file would go into a store as the given kind, as far as the
        /// file alone can say - and whether what kept it out was a password none
        /// was given for.
        /// </summary>
        /// <remarks>
        /// A command line says where a password goes; the store cannot. A
        /// PKCS#12 given without one was refused with .NET's "... with the
        /// provided password, the password may be incorrect", where no password
        /// had been provided, and nothing said how to give one (found by the
        /// EMSP).
        /// </remarks>
        /// <param name="Content">The file as it is.</param>
        /// <param name="Kind">What it is to be used for.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12.</param>
        /// <param name="PasswordWanted">True where the file was refused because it opens only with a password, and none was given: a PKCS#12, or a PEM whose private key is encrypted.</param>
        public static Boolean CouldImport(Byte[]                            Content,
                                          CertificateKind                   Kind,
                                          String?                           Password,
                                          [NotNullWhen(false)] out String?  Error,
                                          out Boolean                       PasswordWanted)
        {

            if (!TryReadLeaf(Content, Kind, Password, out var collection, out _, out Error, out PasswordWanted))
                return false;

            Dispose(collection);

            return true;

        }

        #endregion

        #region (static) OpensOnlyWithAPassword(Content)

        /// <summary>
        /// Whether a file opens only with a password: a PKCS#12 that cannot be
        /// opened without one, or a PEM whose private key is encrypted - told
        /// as the store tells it, whatever the file is for.
        /// </summary>
        /// <remarks>
        /// For a kind that reads a PKCS#12 of its own, outside the store, such
        /// as the charging station's certificate for V2G: where it was given no
        /// password, it can say that one is wanted and where it goes, rather
        /// than pass .NET's "... with the provided password, the password may be
        /// incorrect" on (asked for by the charging station). A file that opens
        /// without a password, or is no certificate at all, does not.
        /// </remarks>
        /// <param name="Content">The file as it is.</param>
        public static Boolean OpensOnlyWithAPassword(Byte[] Content)
        {

            try
            {
                Dispose(ReadCollection(Content, null));
                return false;
            }
            catch (Exception exception)
            {
                return exception is PasswordWantedException;
            }

        }

        #endregion

        #region (private static) TryReadLeaf(Content, Kind, Password, out Collection, out Leaf, out Error, out PasswordWanted)

        /// <summary>
        /// What a file holds, and its leaf, where the file suits the kind by
        /// itself: what Import and CouldImport both ask before there is a store
        /// to ask anything of.
        /// </summary>
        private static Boolean TryReadLeaf(Byte[]                                              Content,
                                           CertificateKind                                     Kind,
                                           String?                                             Password,
                                           [NotNullWhen(true)]  out X509Certificate2Collection?  Collection,
                                           [NotNullWhen(true)]  out X509Certificate2?            Leaf,
                                           [NotNullWhen(false)] out String?                      Error,
                                           out Boolean                                         PasswordWanted)
        {

            if (!TryReadCollection(Content, Password, out Collection, out Leaf, out Error, out PasswordWanted))
                return false;

            if (!Suits(Leaf, Kind, out Error))
            {
                Dispose(Collection);
                Collection  = null;
                Leaf        = null;
                return false;
            }

            return true;

        }

        #endregion

        #region (private static) TryReadCollection(Content, Password, out Collection, out Leaf, out Error, out PasswordWanted)

        /// <summary>
        /// What a file holds, and its leaf - the one with the private key where
        /// there is one, and otherwise the first: the same rule the session's
        /// own loaders use, so that what the store calls the leaf is what they
        /// will.
        /// </summary>
        private static Boolean TryReadCollection(Byte[]                                                Content,
                                                 String?                                               Password,
                                                 [NotNullWhen(true)]  out X509Certificate2Collection?  Collection,
                                                 [NotNullWhen(true)]  out X509Certificate2?            Leaf,
                                                 [NotNullWhen(false)] out String?                      Error,
                                                 out Boolean                                           PasswordWanted)
        {

            Collection      = null;
            Leaf            = null;
            Error           = null;
            PasswordWanted  = false;

            if (Content.Length == 0)
            {
                Error = "There is nothing in that file.";
                return false;
            }

            X509Certificate2Collection collection;

            try
            {
                collection = ReadCollection(Content, Password);
            }
            catch (Exception exception)
            {
                Error           = exception.Message;
                PasswordWanted  = exception is PasswordWantedException;
                return false;
            }

            if (collection.Count == 0)
            {
                Error = "That file holds no certificate.";
                return false;
            }

            Collection  = collection;
            Leaf        = collection.FirstOrDefault(certificate => certificate.HasPrivateKey) ?? collection[0];

            return true;

        }

        #endregion

        #region (static) Inspect(Content, Password)

        /// <summary>
        /// What a file or a text holds, certificate by certificate, each with
        /// the certificates above it that came with it and its private key
        /// where it came with one - as it would be imported, without putting
        /// anything anywhere.
        /// </summary>
        /// <remarks>
        /// <para>
        /// For a page that is dropped a file on, or pasted a text into: it shows
        /// what is in it, and puts it into its box as PEM - a PKCS#12 or a DER
        /// file too, which a box of text could not show otherwise.
        /// </para>
        /// <para>
        /// A text may hold any number of certificates and keys. Every certificate
        /// that no other one in it was issued by is one import, with the ones
        /// above it that came with it; a key goes to the certificate it belongs
        /// to, wherever it was written, and one that belongs to none is refused,
        /// as an import refuses it.
        /// </para>
        /// </remarks>
        /// <param name="Content">The file or the text as it is.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12 or a PEM with an encrypted key.</param>
        public static CertificateInspection Inspect(Byte[]   Content,
                                                    String?  Password)

            => Inspect(Content, Password, _ => []);

        #endregion

        #region Inspect(Content, Password)

        /// <summary>
        /// What a file or a text holds, certificate by certificate - each with
        /// the kinds this store keeps it as already.
        /// </summary>
        /// <param name="Content">The file or the text as it is.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12 or a PEM with an encrypted key.</param>
        public CertificateInspection InspectFor(Byte[]   Content,
                                                String?  Password)

            => Inspect(Content, Password, id => [.. Registrations(id).Select(entry => entry.Kind)]);

        #endregion

        #region (private static) Inspect(Content, Password, KindsOf)

        private static CertificateInspection Inspect(Byte[]                                          Content,
                                                     String?                                         Password,
                                                     Func<String, IReadOnlyList<CertificateKind>>    KindsOf)
        {

            if (Content.Length == 0)
                return new CertificateInspection([], "There is nothing in that file.");

            var found = new X509Certificate2Collection();

            try
            {

                var asText = LooksLikeText(Content)
                                 ? System.Text.Encoding.UTF8.GetString(Content)
                                 : null;

                var keys   = asText is null ? [] : KeyBlocksOf(asText);

                if (asText is not null && (asText.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) || keys.Count > 0))
                {

                    if (asText.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                        found.ImportFromPem(asText);

                    if (found.Count == 0)
                        return new CertificateInspection([], keys.Count > 0
                                                                 ? "That text holds a private key, and no certificate it belongs to."
                                                                 : "That text looks like PEM, and holds no certificate that can be read.");

                    foreach (var key in keys)
                        PairKey(found, key, Password);

                }

                else
                    found = ReadCollection(Content, Password);

            }
            catch (PasswordWantedException exception)
            {
                Dispose(found);
                return new CertificateInspection([], exception.Message, PasswordWanted: true);
            }
            catch (Exception exception)
            {
                Dispose(found);
                return new CertificateInspection([], exception.Message);
            }

            try
            {

                // Each certificate once, the one with its key where it came
                // twice - as a PKCS#12 and its PEM, say.
                var all = found.GroupBy (certificate => CertificateEntry.ThumbprintOf(certificate)).
                                Select  (same        => same.FirstOrDefault(certificate => certificate.HasPrivateKey) ?? same.First()).
                                ToList();

                if (all.Count == 0)
                    return new CertificateInspection([], "That file holds no certificate.");

                static Boolean SelfSigned(X509Certificate2 Certificate)
                    => String.Equals(Certificate.Subject, Certificate.Issuer, StringComparison.Ordinal);

                // A leaf is what no other certificate in it was issued by; a
                // root on its own is a leaf of its own.
                var leaves = all.Where(candidate => !all.Any(other => !ReferenceEquals(other, candidate) &&
                                                                       !SelfSigned(other)                 &&
                                                                       String.Equals(other.Issuer, candidate.Subject, StringComparison.Ordinal))).
                                 ToList();

                if (leaves.Count == 0)
                    leaves = all;

                var inspected = new List<InspectedCertificate>();

                foreach (var leaf in leaves)
                {

                    var chain   = new List<X509Certificate2>();
                    var current = leaf;

                    while (!SelfSigned(current))
                    {

                        var issuer = all.FirstOrDefault(other => !ReferenceEquals(other, current) &&
                                                                 String.Equals(other.Subject, current.Issuer, StringComparison.Ordinal));

                        if (issuer is null || ReferenceEquals(issuer, leaf) || chain.Contains(issuer))
                            break;

                        chain.Add(issuer);
                        current = issuer;

                    }

                    var pem = new System.Text.StringBuilder();

                    pem.Append(leaf.ExportCertificatePem()).Append('\n');

                    foreach (var above in chain)
                        pem.Append(above.ExportCertificatePem()).Append('\n');

                    if (leaf.HasPrivateKey && PrivateKeyPemOf(leaf) is String key)
                        pem.Append(key).Append('\n');

                    var thumbprint = CertificateEntry.ThumbprintOf(leaf);

                    inspected.Add(new InspectedCertificate(
                                      pem.ToString(),
                                      thumbprint[..CertificateEntry.IdLength],
                                      thumbprint,
                                      CertificateEntry.CommonNameOf(leaf),
                                      leaf.Subject,
                                      leaf.Issuer,
                                      leaf.NotBefore.ToUniversalTime(),
                                      leaf.NotAfter. ToUniversalTime(),
                                      CertificateEntry.KeyAlgorithmOf(leaf),
                                      leaf.HasPrivateKey,
                                      chain.Count,
                                      IsCA(leaf),
                                      SelfSigned(leaf),
                                      KindsOf(thumbprint[..CertificateEntry.IdLength])
                                  ));

                }

                return new CertificateInspection(inspected);

            }
            finally
            {
                Dispose(found);
            }

        }

        #endregion

        #region Unsuitable(Certificate)

        /// <summary>
        /// For each kind this store keeps that the given certificate cannot be
        /// kept as, why not - as an import of it as that kind alone would say.
        /// </summary>
        /// <param name="Certificate">A certificate as <see cref="InspectFor"/> found it.</param>
        public IReadOnlyDictionary<CertificateKind, String> Unsuitable(InspectedCertificate Certificate)
        {

            var unsuitable = new Dictionary<CertificateKind, String>();

            if (!TryReadCollection(System.Text.Encoding.ASCII.GetBytes(Certificate.Pem), null, out var collection, out var leaf, out var error, out _))
            {
                foreach (var kind in KindsKept)
                    unsuitable[kind] = error;
                return unsuitable;
            }

            try
            {

                foreach (var kind in KindsKept)
                    if (!Suits(leaf, kind, out var refused))
                        unsuitable[kind] = refused;

                return unsuitable;

            }
            finally
            {
                Dispose(collection);
            }

        }

        #endregion

        #region (private static) PairKey(Collection, Key, Password)

        /// <summary>
        /// Give a private key to the certificate in the collection it belongs to -
        /// or say that it belongs to none.
        /// </summary>
        private static void PairKey(X509Certificate2Collection  Collection,
                                    String                      Key,
                                    String?                     Password)
        {

            var encrypted = Key.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal);

            if (encrypted && Password is not { Length: > 0 })
                throw new PasswordWantedException("That text's private key is encrypted, and no password was given.");

            for (var i = 0; i < Collection.Count; i++)
            {

                var certificate = Collection[i];

                if (certificate.HasPrivateKey)
                    continue;

                X509Certificate2 paired;

                try
                {
                    paired = encrypted
                                 ? X509Certificate2.CreateFromEncryptedPem(certificate.ExportCertificatePem(), Key, Password!)
                                 : X509Certificate2.CreateFromPem         (certificate.ExportCertificatePem(), Key);
                }
                catch (ArgumentException)
                {
                    continue;
                }
                catch (CryptographicException exception)
                {
                    throw new ArgumentException(
                              encrypted
                                  ? $"That text's private key could not be opened - wrong password? ({exception.Message})"
                                  : $"That text's private key is of a kind that cannot be read. ({exception.Message})");
                }

                using (paired)
                {
                    Collection[i] = X509CertificateLoader.LoadPkcs12(
                                        paired.Export(X509ContentType.Pkcs12) ?? [],
                                        (String?) null,
                                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet
                                    );
                }

                certificate.Dispose();
                return;

            }

            throw new ArgumentException(
                      "That text carries a private key that belongs to none of the certificates in it. " +
                      "A credential is one leaf, its key, and the sub-CAs above it.");

        }

        #endregion

        #region (private static) KeyBlocksOf(Pem) / PrivateKeyPemOf(Certificate)

        /// <summary>
        /// Every private key block in a PEM, whichever of the four spellings it uses, in the order written.
        /// </summary>
        private static IReadOnlyList<String> KeyBlocksOf(String Pem)
        {

            var blocks = new List<(Int32 At, String Block)>();

            foreach (var label in new[] { "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY" })
            {

                var opening = $"-----BEGIN {label}-----";
                var closing = $"-----END {label}-----";
                var from    = 0;

                while ((from = Pem.IndexOf(opening, from, StringComparison.Ordinal)) >= 0)
                {

                    var to = Pem.IndexOf(closing, from, StringComparison.Ordinal);

                    if (to < 0)
                        break;

                    blocks.Add((from, Pem[from..(to + closing.Length)]));
                    from = to + closing.Length;

                }

            }

            return [.. blocks.OrderBy(block => block.At).Select(block => block.Block)];

        }

        /// <summary>
        /// A certificate's private key as an unencrypted PKCS#8 PEM, or nothing
        /// where it has none that can be written out.
        /// </summary>
        private static String? PrivateKeyPemOf(X509Certificate2 Certificate)
        {

            try
            {

                using var ecdsa = Certificate.GetECDsaPrivateKey();

                if (ecdsa is not null)
                    return ecdsa.ExportPkcs8PrivateKeyPem();

                using var rsa = Certificate.GetRSAPrivateKey();

                return rsa?.ExportPkcs8PrivateKeyPem();

            }
            catch (CryptographicException)
            {
                return null;
            }

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

            => Import(Content, Kind, Password, Label, null, out Entry, out Error, out _);

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

            => Import(Content, Kind, Password, Label, Usages, out Entry, out Error, out _);

        /// <summary>
        /// Put a certificate into the store, copying it in - and say whether a
        /// refusal was the store's files' rather than the certificate's.
        /// </summary>
        /// <param name="Content">The file as it arrived.</param>
        /// <param name="Kind">What it is to be used for.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12.</param>
        /// <param name="Label">What to call it; its common name where this is not given.</param>
        /// <param name="Usages">What it may be used for; null for every use.</param>
        /// <param name="Entry">What went in.</param>
        /// <param name="Error">Why nothing did.</param>
        /// <param name="NotSaved">True where the certificate's file or the index could not be written: nothing about the certificate was wrong, and nothing went in.</param>
        public Boolean Import(Byte[]                                      Content,
                              CertificateKind                             Kind,
                              String?                                     Password,
                              String?                                     Label,
                              IEnumerable<String>?                        Usages,
                              [NotNullWhen(true)]  out CertificateEntry?  Entry,
                              [NotNullWhen(false)] out String?            Error,
                              out Boolean                                 NotSaved)
        {

            Entry = null;

            if (!Import(Content,
                        Password,
                        Label,
                        [ new CertificateRegistration(Kind, Usages is null ? null : [.. Usages]) ],
                        out var entries,
                        out Error,
                        out NotSaved))
            {
                return false;
            }

            Entry = entries[0];
            return true;

        }

        #endregion

        #region Import(Content, Password, Label, Registrations, out Entries, out Error, out NotSaved)

        /// <summary>
        /// Put a certificate into the store as every kind given, copying it in
        /// once for each - all of them or none.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Each kind a certificate is kept as is a registration of its own: a
        /// file in that kind's directory, written as that kind's reader takes
        /// it, switched on and told its usages on its own. What it is called is
        /// the certificate's - a label given here is the label of every kind it
        /// is kept as, and a kind added to a certificate already in the store
        /// takes the name it has there.
        /// </para>
        /// <para>
        /// Whatever can refuse one of the kinds is asked before anything is
        /// written, and a file or the index that cannot be written takes back
        /// what this import wrote: a certificate put in as an identity and a
        /// root, refused as the root, is not in the store as the identity
        /// either.
        /// </para>
        /// <para>
        /// A trust anchor and a server's certificate must not carry a private
        /// key, and a file that brings one along is refused as either - unless
        /// the same import puts it in as a kind that presents it as well. Then
        /// the key is where it belongs, with that kind, and the anchor or the
        /// server's certificate is kept without it.
        /// </para>
        /// </remarks>
        /// <param name="Content">The file as it arrived.</param>
        /// <param name="Password">What opens it, where it is a protected PKCS#12.</param>
        /// <param name="Label">What to call it; its common name, or the name it has in the store already, where this is not given.</param>
        /// <param name="Registrations">The kinds to keep it as, each with what it is for; at least one, and each kind once.</param>
        /// <param name="Entries">What it is in the store now, one entry per kind given, in the order given.</param>
        /// <param name="Error">Why nothing went in.</param>
        /// <param name="NotSaved">True where a file or the index could not be written: nothing about the certificate was wrong, and nothing went in.</param>
        public Boolean Import(Byte[]                                                    Content,
                              String?                                                   Password,
                              String?                                                   Label,
                              IReadOnlyList<CertificateRegistration>                    Registrations,
                              [NotNullWhen(true)]  out IReadOnlyList<CertificateEntry>?  Entries,
                              [NotNullWhen(false)] out String?                          Error,
                              out Boolean                                               NotSaved)
        {

            Entries   = null;
            Error     = null;
            NotSaved  = false;

            if (Registrations.Count == 0)
            {
                Error = "Name at least one kind to keep the certificate as.";
                return false;
            }

            if (Registrations.GroupBy(registration => registration.Kind).FirstOrDefault(group => group.Count() > 1) is { } twice)
            {
                Error = $"{twice.Key.CapitalisedWithArticle()} is named twice. Name each kind once.";
                return false;
            }

            // Before anything is read or written, so that a kind this store does
            // not keep is not half-imported, and a store that keeps nothing is
            // not given a directory by a refused import.
            if (Registrations.FirstOrDefault(registration => !Keeps(registration.Kind)) is { } unkept)
            {
                Error = $"This {NodeName} keeps no certificate of that kind: {unkept.Kind.Describe(NodeName)}.";
                return false;
            }

            var settled = new Dictionary<CertificateKind, IReadOnlyList<CertificateUsage>?>();

            foreach (var registration in Registrations)
            {

                if (!TrySettleUsages(registration.Kind, registration.Usages, out var usages, out Error))
                    return false;

                settled[registration.Kind] = usages;

            }

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

            if (!TryReadCollection(Content, Password, out var collection, out var leaf, out Error, out _))
                return false;

            // The key stays with the kinds that present it. An anchor or a
            // server's certificate put in beside one of them is kept without it;
            // put in alone, a key that came along is refused as before, because
            // then it is somebody's key in the wrong place.
            var presented  = Registrations.Any(registration => registration.Kind.NeedsPrivateKey());
            using var bare = leaf.HasPrivateKey && presented
                                 ? X509CertificateLoader.LoadCertificate(leaf.RawData)
                                 : null;

            X509Certificate2 LeafFor(CertificateKind Kind)

                => bare is not null && (Kind.IsTrustAnchor() || Kind.MustNotCarryPrivateKey())
                       ? bare
                       : leaf;

            foreach (var registration in Registrations)
            {
                if (!Suits(LeafFor(registration.Kind), registration.Kind, out Error))
                {
                    Dispose(collection);
                    return false;
                }
            }

            var storeChanged  = false;
            var written       = new List<String>();
            var before        = new Dictionary<(String Id, CertificateKind Kind), CertificateEntry>();
            var said          = new List<(LogLevel Level, String Line, Boolean Security)>();

            storeLock.Wait();

            try
            {

                var thumbprint  = CertificateEntry.ThumbprintOf(leaf);
                var id          = thumbprint[..CertificateEntry.IdLength];
                var others      = entries.Values.Where(entry => entry.Id == id).OrderBy(entry => entry.Kind.SortOrder()).ToList();

                if (others.FirstOrDefault(entry => entry.Thumbprint != thumbprint) is CertificateEntry taken)
                {
                    Error = $"The handle '{id}' is already taken by a different certificate " +
                            $"('{taken.Label}'). Remove that one first.";
                    return false;
                }

                foreach (var entry in others)
                    before[(entry.Id, entry.Kind)] = entry;

                var given   = Label?.Trim() is { Length: > 0 } trimmed ? trimmed : null;

                // Given, the label is the certificate's from now on, whichever
                // kinds it is kept as; not given, a kind added to a certificate
                // in the store takes the name it has there.
                var label   = given ?? others.FirstOrDefault()?.Label;

                var results = new List<CertificateEntry>();

                foreach (var registration in Registrations)
                {

                    var kind    = registration.Kind;
                    var usages  = settled[kind];

                    if (entries.TryGetValue((id, kind), out var existing))
                    {

                        // Usages given are the usages from now on; none given
                        // leaves the ones it has, because an import that said
                        // nothing about them said nothing about them.
                        if (registration.Usages is not null && !SameUsages(existing.Usages, usages))
                        {

                            said.Add((LogLevel.Notice,
                                      $"Certificates: {existing.Label} ({kind.AsText()}) is now {CertificateUsages.Describe(usages)}, " +
                                      $"where it was {CertificateUsages.Describe(existing.Usages)}.",
                                      true));

                            existing = existing with { Usages = usages };
                            entries[(id, kind)] = existing;

                        }

                        results.Add(existing);
                        continue;

                    }

                    var fileName  = RelativeName(kind, id + kind.Extension());
                    var fullPath  = FullPath(fileName);
                    var kindLeaf  = LeafFor(kind);

                    try
                    {
                        // A made-up kind has no directory until its first
                        // certificate.
                        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
                        File.WriteAllBytes(fullPath, Serialise(collection, kindLeaf, kind));
                        written.Add(fullPath);
                        Protect(fullPath);
                    }
                    catch (Exception exception)
                    {
                        Error     = $"That certificate could not be written to the store: {exception.Message}";
                        NotSaved  = true;
                        PutBack(written, before, id);
                        return false;
                    }

                    var imported = CertificateEntry.From(
                                       kindLeaf,
                                       kind,
                                       fileName,
                                       label,
                                       collection.Count - 1,
                                       IsActive:  true,
                                       Usages:    usages
                                   );

                    label ??= imported.Label;

                    entries.Add((id, kind), imported);
                    results.Add(imported);

                    said.Add((LogLevel.Notice,
                              $"Certificates: imported {imported.Label} as {kind.Describe(NodeName)}, " +
                              $"{imported.KeyAlgorithm}, valid until {imported.NotAfter.UtcDateTime:yyyy-MM-dd}, SHA-256 {imported.Thumbprint}. It is switched on" +
                              $"{(kind.HasUsages() ? ", " + CertificateUsages.Describe(usages) : "")}" +
                              $"{(others.Count > 0 ? $", and kept as {String.Join(" and ", others.Select(other => other.Kind.WithArticle()))} as well" : "")}.",
                              true));

                    if (imported.HasPrivateKey)
                        said.Add((LogLevel.Warning,
                                  $"Certificates: the private key of {imported.Label} is stored unencrypted in " +
                                  $"'{Directory}'. Anybody who can read that directory can use it.",
                                  false));

                }

                // A label given renames every kind it is kept as; a certificate
                // whose kinds went by different names would be two certificates
                // on a page that shows it once.
                if (given is not null)
                {
                    foreach (var entry in entries.Values.Where(entry => entry.Id == id && entry.Label != given).ToList())
                    {

                        if (before.ContainsKey((entry.Id, entry.Kind)))
                            said.Add((LogLevel.Info, $"Certificates: '{entry.FileName}' is now called '{given}'.", false));

                        entries[(entry.Id, entry.Kind)] = entry with { Label = given };

                    }
                }

                var changed = written.Count > 0 ||
                              entries.Values.Where(entry => entry.Id == id).Any(entry => !before.TryGetValue((entry.Id, entry.Kind), out var was) || was != entry);

                if (!changed)
                {
                    log.Info($"Certificates: {results[0].Label} was already in the store; nothing changed.", "certificates");
                    Entries = [.. Registrations.Select(registration => entries[(id, registration.Kind)])];
                    return true;
                }

                // The index says what it is called, that it is on, and what it
                // is for. Without it a file written here would come back at the
                // next start under its own name, switched on, for every use - so
                // everything this import did goes back out rather than in.
                if (!TryWriteIndex(PutBack: true, out Error))
                {
                    NotSaved = true;
                    PutBack(written, before, id);
                    return false;
                }

                storeChanged = true;

                foreach (var (level, line, security) in said)
                {
                    if (security)
                        log.Metrological(level, line, "certificates", "security");
                    else if (level == LogLevel.Warning)
                        log.Warning(line, "certificates");
                    else
                        log.Info(line, "certificates");
                }

                Entries = [.. Registrations.Select(registration => entries[(id, registration.Kind)])];
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

        #region (private) PutBack(Written, Before, Id)

        /// <summary>
        /// Take back what an import did that could not be finished: the files
        /// it wrote, and the registrations of the certificate as they were.
        /// Called from inside <see cref="storeLock"/>.
        /// </summary>
        private void PutBack(IEnumerable<String>                                                Written,
                             IReadOnlyDictionary<(String Id, CertificateKind Kind), CertificateEntry>  Before,
                             String                                                             Id)
        {

            foreach (var path in Written)
                Forget(path);

            foreach (var key in entries.Keys.Where(key => key.Id == Id).ToList())
                entries.Remove(key);

            foreach (var (key, entry) in Before)
                entries[key] = entry;

        }

        #endregion

        #region SetActive(Id, Active, out Entry, out Error)

        /// <summary>
        /// Switch one certificate on or off, as every kind it is kept as,
        /// leaving it where it is.
        /// </summary>
        /// <remarks>
        /// The difference between this and <see cref="Remove(String, out String?)"/>
        /// is the whole reason both exist: a certificate somebody is taking out
        /// of service for an afternoon should not have to be imported again
        /// afterwards, and one whose key may have leaked should not merely be
        /// switched off. Switched off as a whole, a certificate kept as two kinds
        /// is not left believed as the one somebody forgot.
        /// </remarks>
        public Boolean SetActive(String                                      Id,
                                 Boolean                                     Active,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)

            => SetActive(Id, null, Active, out Entry, out Error, out _);

        /// <summary>
        /// Switch one certificate on or off as every kind it is kept as - and say
        /// whether a refusal was the index's rather than the change's.
        /// </summary>
        /// <param name="NotSaved">True where the index could not be written: the certificate stays as it was.</param>
        public Boolean SetActive(String                                      Id,
                                 Boolean                                     Active,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error,
                                 out Boolean                                 NotSaved)

            => SetActive(Id, null, Active, out Entry, out Error, out NotSaved);

        /// <summary>
        /// Switch one certificate on or off as one kind it is kept as.
        /// </summary>
        public Boolean SetActive(String                                      Id,
                                 CertificateKind                             Kind,
                                 Boolean                                     Active,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)

            => SetActive(Id, Kind, Active, out Entry, out Error, out _);

        /// <summary>
        /// Switch one certificate on or off - as the given kind, or as every
        /// kind it is kept as - and say whether a refusal was the index's rather
        /// than the change's.
        /// </summary>
        /// <param name="Id">The certificate's handle.</param>
        /// <param name="Kind">The kind it is switched as; null for every kind it is kept as.</param>
        /// <param name="Active">On or off.</param>
        /// <param name="Entry">The certificate as the kind given, or as the first kind it is kept as, as it is now.</param>
        /// <param name="Error">Why not.</param>
        /// <param name="NotSaved">True where the index could not be written: the certificate stays as it was.</param>
        public Boolean SetActive(String                                      Id,
                                 CertificateKind?                            Kind,
                                 Boolean                                     Active,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error,
                                 out Boolean                                 NotSaved)
        {

            Entry     = null;
            Error     = null;
            NotSaved  = false;

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!TryRegistrations(Id, Kind, out var targets, out Error))
                    return false;

                var switched = targets.Where(entry => entry.IsActive != Active).ToList();

                foreach (var entry in switched)
                    entries[(entry.Id, entry.Kind)] = entry with { IsActive = Active };

                if (switched.Count > 0)
                {

                    if (!TryWriteIndex(PutBack: true, out Error))
                    {

                        foreach (var entry in switched)
                            entries[(entry.Id, entry.Kind)] = entry;

                        NotSaved = true;
                        return false;

                    }

                    storeChanged = true;

                    foreach (var entry in switched)
                        log.Metrological(LogLevel.Notice,
                                         $"Certificates: {entry.Label} ({entry.Kind.AsText()}) was switched {(Active ? "on" : "off")}.",
                                         "certificates", "security");

                }

                Entry = entries[(targets[0].Id, targets[0].Kind)];
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
        /// Change what a certificate is called - whichever kinds it is kept as,
        /// because the name is the certificate's.
        /// </summary>
        public Boolean Relabel(String                                      Id,
                               String?                                     Label,
                               [NotNullWhen(true)]  out CertificateEntry?  Entry,
                               [NotNullWhen(false)] out String?            Error)

            => Relabel(Id, Label, out Entry, out Error, out _);

        /// <summary>
        /// Change what a certificate is called - and say whether a refusal was
        /// the index's rather than the label's.
        /// </summary>
        /// <param name="NotSaved">True where the index could not be written: the certificate keeps the name it had.</param>
        public Boolean Relabel(String                                      Id,
                               String?                                     Label,
                               [NotNullWhen(true)]  out CertificateEntry?  Entry,
                               [NotNullWhen(false)] out String?            Error,
                               out Boolean                                 NotSaved)
        {

            Entry     = null;
            Error     = null;
            NotSaved  = false;

            if (Label is { Length: > CertificateEntry.MaxLabelLength })
            {
                Error = $"A label may be at most {CertificateEntry.MaxLabelLength} characters long.";
                return false;
            }

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!TryRegistrations(Id, null, out var targets, out Error))
                    return false;

                // A label taken back is not an empty label: it is the
                // certificate's own name again.
                var settled = Label?.Trim() is { Length: > 0 } given
                                  ? given
                                  : NameFromFile(targets[0]);

                foreach (var entry in targets)
                    entries[(entry.Id, entry.Kind)] = entry with { Label = settled };

                if (!TryWriteIndex(PutBack: true, out Error))
                {

                    foreach (var entry in targets)
                        entries[(entry.Id, entry.Kind)] = entry;

                    NotSaved = true;
                    return false;

                }

                Entry        = entries[(targets[0].Id, targets[0].Kind)];
                storeChanged = targets.Any(entry => entry.Label != settled);

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
        /// <para>
        /// A decision about trust, as switching it on is: a TLS root told it
        /// may vouch for the time servers is one that can make this node
        /// believe a time. So it is written into the metrological log like
        /// every other change of the store, tagged as a matter of security.
        /// </para>
        /// <para>
        /// Without a kind, a certificate kept as one kind is told; one kept as
        /// several has to be told as which, because what a root may vouch for
        /// and where an identity is shown are different questions.
        /// </para>
        /// </remarks>
        /// <param name="Id">The certificate's handle.</param>
        /// <param name="Usages">What it may be used for from now on; null for every use.</param>
        /// <param name="Entry">The certificate as it is now.</param>
        /// <param name="Error">Why not.</param>
        public Boolean SetUsages(String                                      Id,
                                 IEnumerable<String>?                        Usages,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)

            => SetUsages(Id, null, Usages, out Entry, out Error, out _);

        /// <summary>
        /// Say what one certificate may be used for - and say whether a refusal
        /// was the index's rather than the usages'.
        /// </summary>
        /// <param name="NotSaved">True where the index could not be written: the certificate is for what it was for.</param>
        public Boolean SetUsages(String                                      Id,
                                 IEnumerable<String>?                        Usages,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error,
                                 out Boolean                                 NotSaved)

            => SetUsages(Id, null, Usages, out Entry, out Error, out NotSaved);

        /// <summary>
        /// Say what one certificate may be used for as one kind it is kept as.
        /// </summary>
        public Boolean SetUsages(String                                      Id,
                                 CertificateKind                             Kind,
                                 IEnumerable<String>?                        Usages,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)

            => SetUsages(Id, Kind, Usages, out Entry, out Error, out _);

        /// <summary>
        /// Say what one certificate may be used for as the given kind, or as the
        /// one kind it is kept as - and say whether a refusal was the index's
        /// rather than the usages'.
        /// </summary>
        /// <param name="Id">The certificate's handle.</param>
        /// <param name="Kind">The kind it is told as; null where it is kept as one kind only.</param>
        /// <param name="Usages">What it may be used for from now on; null for every use.</param>
        /// <param name="Entry">The certificate as it is now.</param>
        /// <param name="Error">Why not.</param>
        /// <param name="NotSaved">True where the index could not be written: the certificate is for what it was for.</param>
        public Boolean SetUsages(String                                      Id,
                                 CertificateKind?                            Kind,
                                 IEnumerable<String>?                        Usages,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error,
                                 out Boolean                                 NotSaved)
        {

            Entry     = null;
            Error     = null;
            NotSaved  = false;

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!TryRegistrations(Id, Kind, out var targets, out Error))
                    return false;

                if (targets.Count > 1)
                {
                    Error = $"'{targets[0].Label}' is kept as {String.Join(" and ", targets.Select(entry => entry.Kind.WithArticle()))}. " +
                             "Say as which of them it is told what it is for.";
                    return false;
                }

                var entry = targets[0];

                if (!TrySettleUsages(entry.Kind, Usages, out var usages, out Error))
                    return false;

                if (SameUsages(entry.Usages, usages))
                {
                    Entry = entry;
                    return true;
                }

                var reused = entry with { Usages = usages };
                entries[(entry.Id, entry.Kind)] = reused;

                if (!TryWriteIndex(PutBack: true, out Error))
                {
                    entries[(entry.Id, entry.Kind)] = entry;
                    NotSaved = true;
                    return false;
                }

                Entry        = reused;
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
        /// Take a certificate out of the store as every kind it is kept as, and
        /// delete its files.
        /// </summary>
        /// <remarks>
        /// The files go. A store whose "delete" left the private key on the
        /// disk would be worse than one with no delete at all, because it would
        /// be believed.
        /// </remarks>
        public Boolean Remove(String                            Id,
                              [NotNullWhen(false)] out String?  Error)

            => Remove(Id, null, out Error, out _);

        /// <summary>
        /// Take a certificate out of the store as every kind it is kept as, and
        /// delete its files - and say whether a refusal was a file's rather than
        /// the request's.
        /// </summary>
        /// <param name="NotSaved">True where a file could not be deleted: the certificate stays in the store as that kind.</param>
        public Boolean Remove(String                            Id,
                              [NotNullWhen(false)] out String?  Error,
                              out Boolean                       NotSaved)

            => Remove(Id, null, out Error, out NotSaved);

        /// <summary>
        /// Take a certificate out of the store as one kind it is kept as, and
        /// delete that kind's file of it.
        /// </summary>
        public Boolean Remove(String                            Id,
                              CertificateKind                   Kind,
                              [NotNullWhen(false)] out String?  Error)

            => Remove(Id, Kind, out Error, out _);

        /// <summary>
        /// Take a certificate out of the store - as the given kind, or as every
        /// kind it is kept as - and delete those files of it; and say whether a
        /// refusal was a file's rather than the request's.
        /// </summary>
        /// <remarks>
        /// Taken out as one kind of several, the certificate stays in the store
        /// as the others, under its name.
        /// </remarks>
        /// <param name="Id">The certificate's handle.</param>
        /// <param name="Kind">The kind it is taken out as; null for every kind it is kept as.</param>
        /// <param name="Error">Why not.</param>
        /// <param name="NotSaved">True where a file could not be deleted: the certificate stays in the store as that kind.</param>
        public Boolean Remove(String                            Id,
                              CertificateKind?                  Kind,
                              [NotNullWhen(false)] out String?  Error,
                              out Boolean                       NotSaved)
        {

            Error     = null;
            NotSaved  = false;

            var storeChanged = false;

            storeLock.Wait();

            try
            {

                if (!TryRegistrations(Id, Kind, out var targets, out Error))
                    return false;

                foreach (var entry in targets)
                {

                    var fullPath = FullPath(entry.FileName);

                    try
                    {
                        if (File.Exists(fullPath))
                            File.Delete(fullPath);
                    }
                    catch (Exception exception)
                    {

                        Error     = $"'{entry.FileName}' could not be deleted: {exception.Message}";
                        NotSaved  = true;

                        // What was deleted before is gone, and is said so.
                        if (storeChanged)
                            TryWriteIndex(PutBack: false, out _);

                        return false;

                    }

                    entries.Remove((entry.Id, entry.Kind));
                    storeChanged = true;

                    var left = entries.Values.Where(other => other.Id == entry.Id).ToList();

                    log.Metrological(LogLevel.Notice,
                                     left.Count == 0
                                         ? $"Certificates: {entry.Label} ({entry.Kind.AsText()}) was deleted from the store."
                                         : $"Certificates: {entry.Label} is no longer kept as {entry.Kind.WithArticle()}; it is still kept as " +
                                           $"{String.Join(" and ", left.Select(other => other.Kind.WithArticle()))}.",
                                     "certificates", "security");

                }

                // The files are gone, and the entries with them, whether or not
                // the index can say so: an entry whose file is not there is
                // dropped at the next reading. That it could not be written is
                // logged.
                TryWriteIndex(PutBack: false, out _);

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

        #region (private) TryRegistrations(Id, Kind, out Registrations, out Error)

        /// <summary>
        /// A certificate as the given kind, or as every kind it is kept as, in
        /// the order the kinds are shown in - or why there is none. Called from
        /// inside <see cref="storeLock"/>.
        /// </summary>
        private Boolean TryRegistrations(String                                                  Id,
                                         CertificateKind?                                        Kind,
                                         [NotNullWhen(true)]  out List<CertificateEntry>?        Registrations,
                                         [NotNullWhen(false)] out String?                        Error)
        {

            Registrations  = [.. entries.Values.Where(entry => entry.Id == Id && (Kind is null || entry.Kind == Kind.Value)).
                                                OrderBy(entry => entry.Kind.SortOrder()).
                                                ThenBy (entry => entry.Kind.AsText(), StringComparer.OrdinalIgnoreCase)];
            Error          = null;

            if (Registrations.Count > 0)
                return true;

            Error = Kind is CertificateKind kind && entries.Values.Any(entry => entry.Id == Id)
                        ? $"The certificate '{Id}' is not kept as {kind.WithArticle()} in this store."
                        : $"There is no certificate '{Id}' in this store.";

            Registrations = null;
            return false;

        }

        #endregion


        #region Get(Id) / Get(Id, Kind) / Registrations(Id) / ByKind(Kind) / UsableByKind(Kind) / UsableFor(Kind, Usage)

        /// <summary>
        /// One certificate by its handle - as the first kind it is kept as, in
        /// the order the kinds are shown in - or nothing.
        /// </summary>
        /// <remarks>
        /// A certificate kept as several kinds is several entries, one per kind:
        /// whoever asks for one of them by name asks <see cref="Get(String?, CertificateKind)"/>,
        /// and whoever wants all of them, <see cref="Registrations"/>.
        /// </remarks>
        public CertificateEntry? Get(String? Id)

            => Id is null
                   ? null
                   : Registrations(Id).FirstOrDefault();

        /// <summary>
        /// One certificate by its handle as the given kind, or nothing.
        /// </summary>
        public CertificateEntry? Get(String?          Id,
                                     CertificateKind  Kind)
        {

            if (Id is null)
                return null;

            storeLock.Wait();

            try
            {
                return entries.GetValueOrDefault((Id, Kind));
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// One certificate as every kind it is kept as, in the order the kinds
        /// are shown in - empty where it is not in the store.
        /// </summary>
        public IReadOnlyList<CertificateEntry> Registrations(String Id)
        {

            storeLock.Wait();

            try
            {
                return [.. entries.Values.Where(entry => entry.Id == Id).
                                          OrderBy(entry => entry.Kind.SortOrder()).
                                          ThenBy (entry => entry.Kind.AsText(), StringComparer.OrdinalIgnoreCase)];
            }
            finally
            {
                storeLock.Release();
            }

        }

        /// <summary>
        /// The entry whose certificate has this SHA-256 fingerprint, of whatever
        /// kind it is kept as - one that is usable where there is one - or nothing.
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
                return entries.Values.Where  (entry => String.Equals(entry.Thumbprint, fingerprint, StringComparison.OrdinalIgnoreCase)).
                                      OrderBy(entry => entry.IsUsable ? 0 : 1).
                                      ThenBy (entry => entry.Kind.SortOrder()).
                                      FirstOrDefault();
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
        /// <param name="Kind">A kind.</param>
        /// <param name="Usage">The usage.</param>
        public IReadOnlyList<CertificateEntry> UsableFor(CertificateKind   Kind,
                                                        CertificateUsage  Usage)

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

            foreach (var kind in entries.Values.Select(entry => entry.Kind).Concat(Kinds).Distinct().OrderBy(kind => kind.SortOrder()))
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
                                       out IReadOnlyList<CertificateUsage>?  Settled,
                                       [NotNullWhen(false)] out String?   Error)
        {

            Settled  = null;
            Error    = null;

            if (Usages is null)
                return true;

            var isIdentity = Kind == CertificateKind.TLSIdentity;
            var given      = new List<CertificateUsage>();

            foreach (var usage in Usages)
            {

                if (!CertificateUsage.TryParse(usage, out var name))
                {
                    Error = $"'{usage}' is not a usage name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.";
                    return false;
                }

                if (!given.Contains(name))
                    given.Add(name);

            }

            if (given.Count == 0)
            {
                Error = isIdentity
                            ? "An identity shown on no listener at all is one to switch off. Name where it is shown - or nothing, for every listener."
                            : "A certificate for no use at all is one to switch off. Name what it is for - or nothing, for every use.";
                return false;
            }

            // What the node offers first, in its order, then what somebody made
            // up, in the order of the names: the order is the store's, so that
            // two requests naming the same usages keep the same list.
            var offered = UsagesFor(Kind);

            Settled = [.. offered.Where(given.Contains), .. given.Where(usage => !offered.Contains(usage)).Order()];
            return true;

        }

        #endregion

        #region (private static) SameUsages(Some, Others)

        /// <summary>
        /// Whether two sets of usages are the same set: both every use, or the
        /// same usages in whatever order.
        /// </summary>
        private static Boolean SameUsages(IReadOnlyList<CertificateUsage>?  Some,
                                          IReadOnlyList<CertificateUsage>?  Others)

            => Some is null || Others is null
                   ? Some is null && Others is null
                   : Some.Count == Others.Count && !Some.Except(Others).Any();

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

                // And a file that is not a PKCS#12 either was never a candidate
                // for any of this. Saying "wrong password?" about it sends
                // somebody looking for a password that does not exist, which is
                // a worse answer than none.
                if (!LooksLikePkcs12(Content))
                    throw new ArgumentException(
                              "That file is not a certificate that can be read (PEM, DER or PKCS#12).");

                // Without a password, .NET's own sentence speaks of "the provided
                // password", and there was none.
                if (Password is not { Length: > 0 })
                    throw new PasswordWantedException(
                              "That file is a PKCS#12 that could not be opened without a password.");

                throw new ArgumentException(
                          $"That file could not be read - wrong password? ({exception.Message})");

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
                throw new PasswordWantedException(
                          "That file's private key is encrypted, and no password was given.");

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

        #region (private static) LooksLikePkcs12(Content)

        /// <summary>
        /// Whether a file is built as a PKCS#12 is: an ASN.1 SEQUENCE of a
        /// version and of data, which a password guards (RFC 7292, 4).
        /// </summary>
        /// <remarks>
        /// Used only to decide which sentence somebody gets back: a file that is
        /// not built this way was never a PKCS#12, so telling them a password
        /// might open it, or might be wrong, is sending them after something
        /// that does not exist. Asked of how the file is built rather than of
        /// its first byte, which is a SEQUENCE's in a certificate, in a key and
        /// in a PKCS#12 alike: a key in DER was told to give its password.
        /// </remarks>
        private static Boolean LooksLikePkcs12(Byte[] Content)
        {

            try
            {

                var pfx = new AsnReader(Content, AsnEncodingRules.BER).ReadSequence();

                pfx.ReadInteger();

                return pfx.ReadSequence().ReadObjectIdentifier() == "1.2.840.113549.1.7.1";

            }
            catch (AsnContentException)
            {
                return false;
            }

        }

        #endregion

        #region (private) PasswordWantedException

        /// <summary>
        /// A file that opens only with a password, and none was given: told
        /// apart from every other file that could not be read, so that whoever
        /// asked can say where a password goes.
        /// </summary>
        private sealed class PasswordWantedException(String Message) : ArgumentException(Message);

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
                Error = $"{Kind.CapitalisedWithArticle()} has to carry its private key, and that file has none. " +
                         "It is probably a PKCS#12 that needs a password, or the public half of the pair.";
                return false;
            }

            if (Kind.Group == CertificateGroup.Recognised && Leaf.HasPrivateKey)
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

                if (Kind.MayBeIssuingCA)
                {

                    if (!selfSigned && !IsCA(Leaf))
                    {
                        Error = Kind == CertificateKind.ClientRoot
                                    ? $"'{CertificateEntry.CommonNameOf(Leaf)}' is not a CA certificate. A client root is " +
                                       "the CA that signs the clients - a root, or the issuing CA below one - and not a client."
                                    : $"'{CertificateEntry.CommonNameOf(Leaf)}' is not a CA certificate, and {Kind.WithArticle()} " +
                                       "has to be one: a root, or a CA below one.";
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

            // Compared by what they are rather than which object: the leaf
            // written may be a copy without its key, beside the one that came
            // with it.
            foreach (var certificate in Collection)
                if (!certificate.RawData.AsSpan().SequenceEqual(Leaf.RawData))
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

        #region (private static) Forget(FullPath)

        /// <summary>
        /// Take a file this store wrote away again, where what it was written
        /// for did not go in - as far as that goes: one that cannot be taken
        /// away either is left, and adopted as what it is at the next reading.
        /// </summary>
        private static void Forget(String FullPath)
        {

            try
            {
                if (File.Exists(FullPath))
                    File.Delete(FullPath);
            }
            catch (Exception)
            {
                // Left where it is, see above.
            }

        }

        #endregion


        #region (private) ReadIndex() / TryWriteIndex(PutBack, out Error)

        /// <summary>
        /// What the index remembers, by handle. A missing index is an empty
        /// one; a damaged index is named and then treated as empty, which costs
        /// labels and switches and no certificates.
        /// </summary>
        private Dictionary<(String Id, CertificateKind Kind), CertificateEntry> ReadIndex()
        {

            var remembered  = new Dictionary<(String Id, CertificateKind Kind), CertificateEntry>();
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

                    if (!CertificateEntry.TryParse(token, Kinds, out var entry, out var error))
                    {
                        log.Warning($"Certificates: the index has an entry this {NodeName} could not read - {error}",
                                    "certificates");
                        continue;
                    }

                    remembered[(entry.Id, entry.Kind)] = entry;

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
        /// <remarks>
        /// Where it cannot be written, that is logged, and said: a change that
        /// is nothing but the index - a label, on or off, what a certificate is
        /// for - is put back and refused, where it had been answered as done
        /// and was gone at the next start. The log says which of the two it
        /// was: that labels and on/off would not survive a restart was said of
        /// changes that had been put back (found by the gateway).
        /// </remarks>
        /// <param name="PutBack">Whether the change it is written for is put back where it cannot be.</param>
        private Boolean TryWriteIndex(Boolean                          PutBack,
                                      [NotNullWhen(false)] out String? Error)
        {

            Error = null;

            var path = Path.Combine(Directory, IndexFileName);

            try
            {

                var json = new JObject(
                               new JProperty("certificates",
                                   new JArray(
                                       entries.Values.
                                           Concat (setAside.Values).
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

                return true;

            }
            catch (Exception exception)
            {

                log.Error(PutBack
                              ? $"Certificates: '{IndexFileName}' could not be written, so the change was not made - " +
                                $"{exception.Message}"
                              : $"Certificates: '{IndexFileName}' could not be written, so labels and on/off will not " +
                                $"survive a restart - {exception.Message}",
                          "certificates");

                Error = $"'{path}' could not be written: {exception.Message}";
                return false;

            }

        }

        #endregion

    }

}
