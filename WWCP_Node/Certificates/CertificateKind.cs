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

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// Which of the three things a node does with a certificate a kind is:
    /// believe it, present it, or recognise somebody by it.
    /// </summary>
    public enum CertificateGroup
    {

        /// <summary>
        /// A root somebody's chain has to end at: believed, any number at once,
        /// and never with a private key.
        /// </summary>
        TrustAnchor,

        /// <summary>
        /// What this node presents or verifies with: with its private key,
        /// unless it only ever verifies.
        /// </summary>
        Credential,

        /// <summary>
        /// Neither believed nor presented: somebody else's certificate, kept to
        /// recognise them by, and never with a private key.
        /// </summary>
        Recognised

    }


    /// <summary>
    /// What a certificate in a node's store is <i>for</i>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Eleven kinds come with every node, in groups that behave differently in
    /// every respect that matters. A <b>trust anchor</b> is a public certificate
    /// that says which chains the node believes; there may be any number of
    /// them active at once, and none of them is ever chosen for a session. A
    /// <b>credential</b> is something the node presents or verifies with,
    /// carries a private key in every case but one, and is chosen - exactly one
    /// per role - where something asks for one. A <b>recognised</b> certificate
    /// is somebody else's, kept to know them by.
    /// </para>
    /// <para>
    /// Seven of them are ISO 15118's, which a vehicle keeps. The other four are
    /// TLS's in general, which any kind of node may keep: the roots a server it
    /// connects to may chain to - a time server's, a backend's - and the roots a
    /// client connecting to it has to chain to; the certificate a server it
    /// connects to presents, kept so that it can be recognised by its
    /// fingerprint; and what the node presents itself, with its private key.
    /// </para>
    /// <para>
    /// The three roots are kept apart rather than pooled, because they answer
    /// three different questions and pooling them answers all three with the
    /// widest of them. An OEM root vouches for what a vehicle was born with; a
    /// Mobility Operator root vouches for who pays; a V2G root vouches for the
    /// station at the other end of the cable. One bag of roots would let an OEM
    /// root vouch for a contract, which is not a subtlety - it is the whole
    /// difference between a vehicle that checks who is charging it and one that
    /// checks that somebody signed something.
    /// </para>
    /// <para>
    /// <b>More kinds than these.</b> A kind of node may define its own, with
    /// <see cref="Define"/>, and whoever looks after a node may make up a kind of
    /// their own where they import a certificate - <see cref="Custom"/>, which
    /// says only which of the three groups it is in. A made-up kind is a mark,
    /// not a behaviour: nothing in the node uses a certificate for it until a
    /// configuration or code names it. It is kept for as long as a certificate
    /// is kept as it, and forgotten with the last one: nothing but the
    /// certificates remembers it.
    /// </para>
    /// <para>
    /// The names follow the CharIN V2G second-generation PKI Certificate
    /// Policy, as they do in <see cref="ISO15118.VehicleCredentials"/> and for
    /// the same reason: ISO 15118-20's own naming is not consistent with
    /// itself, and the Policy's is.
    /// </para>
    /// </remarks>
    public readonly struct CertificateKind : IId<CertificateKind>
    {

        #region Data

        /// <summary>
        /// The longest a kind may be called.
        /// </summary>
        public const Int32 MaxLength = 32;

        /// <summary>
        /// Every kind defined in code - the node's own and those its kinds of
        /// node define - by name, so that a kind written down is read back as
        /// the kind it is, with what it does.
        /// </summary>
        private static readonly ConcurrentDictionary<String, CertificateKind> defined = new (StringComparer.OrdinalIgnoreCase);

        private readonly String  InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Which of the three things a node does with a certificate this kind is.
        /// </summary>
        public CertificateGroup  Group                    { get; }

        /// <summary>
        /// One line saying what this kind is for, of "this node".
        /// </summary>
        public String            Description              { get; }

        /// <summary>
        /// This kind's name with the article it is said with: "an OEM root".
        /// </summary>
        public String            NameWithArticle          { get; }

        /// <summary>
        /// Where certificates of this kind live below the store, as a relative path.
        /// </summary>
        public String            RelativeDirectory        { get; }

        /// <summary>
        /// Where this kind comes in the order everything is shown and written in.
        /// </summary>
        public Int32             Position                 { get; }

        /// <summary>
        /// Whether a file of this kind is only useful with the private key in it.
        /// </summary>
        public Boolean           WantsPrivateKey          { get; }

        /// <summary>
        /// Whether a trust anchor of this kind may be a CA somebody else signed -
        /// the CA that issues a node's clients - rather than a self-signed root.
        /// </summary>
        public Boolean           MayBeIssuingCA           { get; }

        /// <summary>
        /// Whether this kind was made up where a certificate was imported, rather
        /// than defined in code: a mark nothing in the node acts on by itself.
        /// </summary>
        public Boolean           IsCustom                 { get; }

        /// <summary>
        /// Indicates whether this kind is null or empty.
        /// </summary>
        public Boolean           IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this kind is NOT null or empty.
        /// </summary>
        public Boolean           IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of this kind's name.
        /// </summary>
        public UInt64            Length
            => (UInt64) (InternalId?.Length ?? 0);

        #endregion

        #region Constructor(s)

        private CertificateKind(String            Name,
                                CertificateGroup  Group,
                                String            Description,
                                String            NameWithArticle,
                                String            Directory,
                                Int32             SortOrder,
                                Boolean           NeedsPrivateKey,
                                Boolean           MayBeIssuingCA,
                                Boolean           IsCustom)
        {

            this.InternalId       = Name;
            this.Group            = Group;
            this.Description      = Description;
            this.NameWithArticle  = NameWithArticle;
            this.RelativeDirectory = Directory;
            this.Position          = SortOrder;
            this.WantsPrivateKey  = NeedsPrivateKey;
            this.MayBeIssuingCA   = MayBeIssuingCA;
            this.IsCustom         = IsCustom;

        }

        #endregion


        #region (static) IsKindName(Text)

        /// <summary>
        /// Whether the given text may name a kind: a letter, then letters,
        /// digits, '-' or '_', at most <see cref="MaxLength"/> characters.
        /// </summary>
        public static Boolean IsKindName(String? Text)
        {

            if (String.IsNullOrEmpty(Text) || Text.Length > MaxLength)
                return false;

            if (!Char.IsAsciiLetter(Text[0]))
                return false;

            foreach (var character in Text)
                if (!Char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))
                    return false;

            return true;

        }

        #endregion

        #region (static) Define(Name, Group, Description, NameWithArticle, Directory, SortOrder, NeedsPrivateKey = null, MayBeIssuingCA = false)

        /// <summary>
        /// Define a kind of certificate in code: what a kind of node keeps beyond
        /// the kinds every node knows, with what it is called and where it lives.
        /// </summary>
        /// <remarks>
        /// Defined once per name: defined again, the first definition is the one
        /// there is, so that a static field of a kind of node and a test that
        /// defines the same kind agree on what it is.
        /// </remarks>
        /// <param name="Name">How it is written in the configuration file, the index and on the JSON API: "backendRoot".</param>
        /// <param name="Group">Which of the three things a node does with it.</param>
        /// <param name="Description">One line saying what it is for, of "this node".</param>
        /// <param name="NameWithArticle">Its name with the article it is said with: "a backend root".</param>
        /// <param name="Directory">Where its certificates live below the store, as a relative path with forward slashes.</param>
        /// <param name="SortOrder">Where it comes in the order everything is shown in.</param>
        /// <param name="NeedsPrivateKey">Whether a certificate of it is only useful with its private key; a credential's is by default.</param>
        /// <param name="MayBeIssuingCA">Whether a trust anchor of it may be a CA somebody else signed.</param>
        public static CertificateKind Define(String            Name,
                                             CertificateGroup  Group,
                                             String            Description,
                                             String            NameWithArticle,
                                             String            Directory,
                                             Int32             SortOrder,
                                             Boolean?          NeedsPrivateKey  = null,
                                             Boolean           MayBeIssuingCA   = false)
        {

            if (!IsKindName(Name))
                throw new ArgumentException($"'{Name}' is not a kind name: a letter, then letters, digits, '-' or '_', at most {MaxLength} characters.",
                                            nameof(Name));

            return defined.GetOrAdd(Name,
                                    _ => new CertificateKind(Name,
                                                             Group,
                                                             Description,
                                                             NameWithArticle,
                                                             Directory,
                                                             SortOrder,
                                                             NeedsPrivateKey ?? Group == CertificateGroup.Credential,
                                                             Group == CertificateGroup.TrustAnchor && MayBeIssuingCA,
                                                             IsCustom: false));

        }

        #endregion

        #region (static) Custom(Name, Group)

        /// <summary>
        /// A kind somebody made up where they imported a certificate: a mark in
        /// one of the three groups, which nothing in the node acts on by itself.
        /// </summary>
        /// <remarks>
        /// A trust anchor of a made-up kind has to be a CA, as a client root has:
        /// what it is for is nobody's to know but whoever made it up, and a CA
        /// is what a chain can end at. A credential of one carries its key.
        /// </remarks>
        /// <param name="Name">The name it was given.</param>
        /// <param name="Group">Which of the three groups it is in.</param>
        public static CertificateKind Custom(String            Name,
                                             CertificateGroup  Group)
        {

            if (!IsKindName(Name))
                throw new ArgumentException($"'{Name}' is not a kind name: a letter, then letters, digits, '-' or '_', at most {MaxLength} characters.",
                                            nameof(Name));

            if (defined.TryGetValue(Name, out var known))
                return known;

            var (directory, order) = Group switch {
                CertificateGroup.TrustAnchor  => ("custom/roots",       8),
                CertificateGroup.Credential   => ("custom/credentials", 16),
                _                             => ("custom/recognised",  17)
            };

            return new CertificateKind(Name,
                                       Group,
                                       Group switch {
                                           CertificateGroup.TrustAnchor  => $"{Name} - a root of a kind made up, believed by this node",
                                           CertificateGroup.Credential   => $"{Name} - a certificate of a kind made up, presented by this node with its private key",
                                           _                             => $"{Name} - somebody else's certificate, of a kind made up, kept to recognise them by"
                                       },
                                       // Said with the article of what it is, and the
                                       // name after it: how a name somebody made up is
                                       // said is nobody's to know.
                                       Group switch {
                                           CertificateGroup.TrustAnchor  => $"a root of the kind '{Name}'",
                                           CertificateGroup.Credential   => $"a certificate of the kind '{Name}'",
                                           _                             => $"a recognised certificate of the kind '{Name}'"
                                       },
                                       $"{directory}/{Name}",
                                       order,
                                       NeedsPrivateKey:  Group == CertificateGroup.Credential,
                                       MayBeIssuingCA:   Group == CertificateGroup.TrustAnchor,
                                       IsCustom:         true);

        }

        #endregion

        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given text as a kind defined in code.
        /// </summary>
        /// <param name="Text">A text representation of a kind.</param>
        public static CertificateKind Parse(String Text)

            => TryParse(Text, out var kind)
                   ? kind
                   : throw new ArgumentException($"Unknown certificate kind: '{Text}'!", nameof(Text));

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a kind defined in code.
        /// </summary>
        /// <param name="Text">A text representation of a kind.</param>
        public static CertificateKind? TryParse(String? Text)

            => TryParse(Text, out var kind)
                   ? kind
                   : null;

        #endregion

        #region (static) TryParse(Text, out Kind)

        /// <summary>
        /// Try to parse the given text as a kind defined in code - case-insensitive,
        /// because the difference between "oemRoot" and "oemroot" is not a
        /// difference anybody means.
        /// </summary>
        /// <param name="Text">A text representation of a kind.</param>
        /// <param name="Kind">The kind.</param>
        public static Boolean TryParse(String? Text, out CertificateKind Kind)
        {

            if (Text is not null && defined.TryGetValue(Text.Trim(), out Kind))
                return true;

            Kind = default;
            return false;

        }

        #endregion

        #region (static) TryParse(Text, Group, out Kind)

        /// <summary>
        /// A kind defined in code, or else a made-up kind of the given group -
        /// what the index and an import say of a kind: its name, and its group
        /// where it is one somebody made up.
        /// </summary>
        /// <param name="Text">A text representation of a kind.</param>
        /// <param name="Group">The group of a made-up kind; null where only a kind defined in code will do.</param>
        /// <param name="Kind">The kind.</param>
        public static Boolean TryParse(String?                               Text,
                                       CertificateGroup?                     Group,
                                       [NotNullWhen(true)] out CertificateKind?  Kind)
        {

            Kind = null;

            if (TryParse(Text, out CertificateKind known))
            {
                Kind = known;
                return true;
            }

            var name = Text?.Trim();

            if (Group is null || !IsKindName(name))
                return false;

            Kind = Custom(name!, Group.Value);
            return true;

        }

        #endregion

        #region (static) TryParseGroup(Text, out Group) / AsText(Group)

        /// <summary>
        /// A group as it is written in the index and on the JSON API.
        /// </summary>
        public static String AsText(CertificateGroup Group)

            => Group switch {
                   CertificateGroup.TrustAnchor  => "trustAnchor",
                   CertificateGroup.Credential   => "credential",
                   _                             => "recognised"
               };

        /// <summary>
        /// A group as somebody wrote it, or nothing.
        /// </summary>
        public static Boolean TryParseGroup(String? Text, out CertificateGroup Group)
        {

            foreach (var candidate in Enum.GetValues<CertificateGroup>())
            {
                if (String.Equals(AsText(candidate), Text?.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    Group = candidate;
                    return true;
                }
            }

            Group = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this kind.
        /// </summary>
        public CertificateKind Clone()

            => new (InternalId.CloneString(),
                    Group,
                    Description,
                    NameWithArticle,
                    RelativeDirectory,
                    Position,
                    WantsPrivateKey,
                    MayBeIssuingCA,
                    IsCustom);

        #endregion


        #region Static definitions

        /// <summary>
        /// A <b>V2G root</b>: what a station's certificate has to chain to.
        /// </summary>
        /// <remarks>
        /// The one the store has always had, under the older name
        /// "trust roots". It is checked at the TLS handshake, against the
        /// certificate the station presents.
        /// </remarks>
        public static CertificateKind V2GRoot { get; }
            = Define("v2gRoot", CertificateGroup.TrustAnchor,
                     "V2G root - what a station's certificate must chain to",
                     "a V2G root", "roots/v2g", 0);

        /// <summary>
        /// A <b>Mobility Operator root</b>: what a contract certificate has to
        /// chain to.
        /// </summary>
        /// <remarks>
        /// Checked twice, and the second time is the one that earns its keep.
        /// Once against the contract certificate the node carries, when it
        /// is loaded - a contract nobody vouches for is worth knowing about
        /// before the session rather than after it. And once against the
        /// contract certificate an ISO 15118-20 station <i>issues</i> during
        /// CertificateInstallation, which arrives over the wire from a party
        /// the node has no other reason to believe.
        /// </remarks>
        public static CertificateKind MORoot { get; }
            = Define("moRoot", CertificateGroup.TrustAnchor,
                     "Mobility Operator root - what a contract certificate must chain to",
                     "a Mobility Operator root", "roots/mo", 1);

        /// <summary>
        /// An <b>OEM root</b>: what an OEM provisioning certificate has to
        /// chain to.
        /// </summary>
        /// <remarks>
        /// Checked against the OEM provisioning certificate the node
        /// carries. A vehicle validating its own birth certificate sounds
        /// circular and is not: the OEM certificate is the identity a station
        /// is asked to issue a contract against, so a vehicle that cannot say
        /// which OEM vouched for it is about to ask for a contract it cannot
        /// justify.
        /// </remarks>
        public static CertificateKind OEMRoot { get; }
            = Define("oemRoot", CertificateGroup.TrustAnchor,
                     "OEM root - what an OEM provisioning certificate must chain to",
                     "an OEM root", "roots/oem", 2);

        /// <summary>
        /// The <b>Vehicle</b> certificate: who this vehicle is.
        /// </summary>
        /// <remarks>
        /// Presented in the TLS handshake, and for ISO 15118-20 what a
        /// station's resume binding is computed over.
        /// </remarks>
        public static CertificateKind Vehicle { get; }
            = Define("vehicle", CertificateGroup.Credential,
                     "Vehicle certificate - who this vehicle is",
                     "a vehicle certificate", "vehicle", 10);

        /// <summary>
        /// A <b>contract</b> certificate: who pays.
        /// </summary>
        /// <remarks>
        /// The one kind a vehicle plausibly holds several of - one per
        /// contract, and ISO 15118-2 and -20 need not be the same one - which
        /// is most of the reason this store exists at all.
        /// </remarks>
        public static CertificateKind Contract { get; }
            = Define("contract", CertificateGroup.Credential,
                     "contract certificate - who pays",
                     "a contract certificate", "contract", 11);

        /// <summary>
        /// The <b>OEM provisioning</b> certificate: what the vehicle was born
        /// with.
        /// </summary>
        /// <remarks>
        /// Its key has to be P-521, because the contract key a -20 station
        /// sends back is unwrapped by an ECDH against the station's ephemeral
        /// secp521r1 key. A P-256 one takes part in an exchange it cannot
        /// finish, which is why the store says so at import rather than letting
        /// it fail as an undecryptable response.
        /// </remarks>
        public static CertificateKind OEMProvisioning { get; }
            = Define("oemProvisioning", CertificateGroup.Credential,
                     "OEM provisioning certificate - what this vehicle was born with",
                     "an OEM provisioning certificate", "oem", 12);

        /// <summary>
        /// The public key a station's signed tariff is checked against.
        /// </summary>
        /// <remarks>
        /// A credential with no private key: the signing half lives at the
        /// station, and this side only ever verifies.
        /// </remarks>
        public static CertificateKind TariffVerification { get; }
            = Define("tariffVerification", CertificateGroup.Credential,
                     "tariff certificate - what a station's signed tariff is checked with",
                     "a tariff certificate", "tariff", 13,
                     NeedsPrivateKey: false);

        /// <summary>
        /// A <b>TLS root</b>: what a server this node connects to may chain to -
        /// a time server's key exchange, a backend.
        /// </summary>
        /// <remarks>
        /// Believed beside the roots of the machine rather than instead of them:
        /// a time server with a CA of its own is reached through one of these,
        /// and one with a certificate from a public CA is reached as it always
        /// was. A server held to a root by its fingerprint finds it here - see
        /// <see cref="CertificateStore.ByFingerprint"/>.
        /// </remarks>
        public static CertificateKind TLSRoot { get; }
            = Define("tlsRoot", CertificateGroup.TrustAnchor,
                     "TLS root - what a server this node connects to may chain to: a time server, a backend",
                     "a TLS root", "roots/tls", 3);

        /// <summary>
        /// A <b>client root</b>: what a client connecting to this node has to
        /// chain to - a root, or the issuing CA below one that signs the
        /// clients and nothing else.
        /// </summary>
        /// <remarks>
        /// The one trust anchor that may be signed by somebody else. What a
        /// client is judged by is the listener that asks for it, and the CA that
        /// issues a node's clients is the anchor that says who may connect: the
        /// root above it would let in whatever else it signed as well - the
        /// devices, say. What it may not be is a certificate that is no CA at
        /// all.
        /// </remarks>
        public static CertificateKind ClientRoot { get; }
            = Define("clientRoot", CertificateGroup.TrustAnchor,
                     "client root - what a client connecting to this node has to chain to: a root, or the CA that issues the clients",
                     "a client root", "roots/clients", 4,
                     MayBeIssuingCA: true);

        /// <summary>
        /// A <b>server certificate</b>: what a server this node connects to
        /// presents, kept so that it can be recognised by its fingerprint.
        /// </summary>
        /// <remarks>
        /// Somebody else's certificate, and so never with a private key: that
        /// server's key in this store would be a key in the wrong place, as a
        /// root's would.
        /// </remarks>
        public static CertificateKind TLSServer { get; }
            = Define("tlsServer", CertificateGroup.Recognised,
                     "server certificate - what a server this node connects to presents, kept to be recognised by its fingerprint",
                     "a server certificate", "tls/servers", 14);

        /// <summary>
        /// A <b>TLS identity</b>: what this node presents in TLS, with its
        /// private key - its web interface's certificate, or the one it shows a
        /// server that asks for one.
        /// </summary>
        /// <remarks>
        /// Kept for some uses and not others: a node with more than one listener
        /// - a meter's Modbus/TLS port and its web interface - says which each
        /// identity is shown on, by the listeners its kind names
        /// (<see cref="CertificateStore.Listeners"/>).
        /// </remarks>
        public static CertificateKind TLSIdentity { get; }
            = Define("tlsIdentity", CertificateGroup.Credential,
                     "TLS identity - what this node presents in TLS, with its private key",
                     "a TLS identity", "tls/identity", 15);

        #endregion


        #region Operator overloading

        /// <summary>
        /// Compares two kinds: the same name is the same kind.
        /// </summary>
        public static Boolean operator == (CertificateKind Kind1, CertificateKind Kind2)
            => Kind1.Equals(Kind2);

        /// <summary>
        /// Compares two kinds: another name is another kind.
        /// </summary>
        public static Boolean operator != (CertificateKind Kind1, CertificateKind Kind2)
            => !Kind1.Equals(Kind2);

        /// <summary>
        /// Compares two kinds by their names.
        /// </summary>
        public static Boolean operator < (CertificateKind Kind1, CertificateKind Kind2)
            => Kind1.CompareTo(Kind2) < 0;

        /// <summary>
        /// Compares two kinds by their names.
        /// </summary>
        public static Boolean operator <= (CertificateKind Kind1, CertificateKind Kind2)
            => Kind1.CompareTo(Kind2) <= 0;

        /// <summary>
        /// Compares two kinds by their names.
        /// </summary>
        public static Boolean operator > (CertificateKind Kind1, CertificateKind Kind2)
            => Kind1.CompareTo(Kind2) > 0;

        /// <summary>
        /// Compares two kinds by their names.
        /// </summary>
        public static Boolean operator >= (CertificateKind Kind1, CertificateKind Kind2)
            => Kind1.CompareTo(Kind2) >= 0;

        #endregion

        #region IComparable<CertificateKind> Members

        /// <summary>
        /// Compares two kinds by their names.
        /// </summary>
        public Int32 CompareTo(Object? Object)

            => Object is CertificateKind kind
                   ? CompareTo(kind)
                   : throw new ArgumentException("The given object is not a certificate kind!", nameof(Object));

        /// <summary>
        /// Compares two kinds by their names.
        /// </summary>
        public Int32 CompareTo(CertificateKind Kind)

            => String.Compare(InternalId, Kind.InternalId, StringComparison.OrdinalIgnoreCase);

        #endregion

        #region IEquatable<CertificateKind> Members

        /// <summary>
        /// Whether the given object is the same kind.
        /// </summary>
        public override Boolean Equals(Object? Object)

            => Object is CertificateKind kind &&
                   Equals(kind);

        /// <summary>
        /// Whether the given kind is the same kind: the same name, in whatever case.
        /// </summary>
        public Boolean Equals(CertificateKind Kind)

            => String.Equals(InternalId, Kind.InternalId, StringComparison.OrdinalIgnoreCase);

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// The hash code of this kind's name, in whatever case.
        /// </summary>
        public override Int32 GetHashCode()

            => InternalId is null
                   ? 0
                   : StringComparer.OrdinalIgnoreCase.GetHashCode(InternalId);

        #endregion

        #region (override) ToString()

        /// <summary>
        /// This kind as it is written in the configuration file and on the JSON API.
        /// </summary>
        public override String ToString()

            => InternalId ?? "";

        #endregion

    }


    /// <summary>
    /// What each kind of certificate is called, where it is kept, and what a
    /// file has to be to count as one.
    /// </summary>
    public static class CertificateKindExtensions
    {

        #region IsTrustAnchor(this Kind)

        /// <summary>
        /// Whether this kind is a root somebody chains to, rather than
        /// something the node presents.
        /// </summary>
        public static Boolean IsTrustAnchor(this CertificateKind Kind)

            => Kind.Group == CertificateGroup.TrustAnchor;

        #endregion

        #region NeedsPrivateKey(this Kind)

        /// <summary>
        /// Whether a file of this kind is only useful with the private key in
        /// it.
        /// </summary>
        /// <remarks>
        /// Roots must <i>not</i> carry one - see <see cref="MustNotCarryPrivateKey"/>
        /// - and the tariff verification key does not need one. Everything else
        /// is an identity the node proves, and cannot prove without the key.
        /// </remarks>
        public static Boolean NeedsPrivateKey(this CertificateKind Kind)

            => Kind.WantsPrivateKey;

        #endregion

        #region MustNotCarryPrivateKey(this Kind)

        /// <summary>
        /// Whether a file of this kind is refused when it carries a private key.
        /// </summary>
        /// <remarks>
        /// A root with a private key is somebody's CA key in the wrong place,
        /// and a server's certificate with one is that server's key in the wrong
        /// place. Both are refused rather than quietly stripped: whoever put the
        /// key into the file has a key to worry about, and should hear so.
        /// </remarks>
        public static Boolean MustNotCarryPrivateKey(this CertificateKind Kind)

            => Kind.Group != CertificateGroup.Credential;

        #endregion

        #region HasUsages(this Kind)

        /// <summary>
        /// Whether a certificate of this kind may be told what it is for, beside
        /// its kind - see <see cref="CertificateUsage"/>: every kind may.
        /// </summary>
        /// <remarks>
        /// A TLS root vouches for servers and a server certificate is one
        /// server's, and which servers is the question a usage answers: the
        /// name servers, the time servers, a backend. A TLS identity is what
        /// this node shows, and where is the question: a node with two
        /// listeners shows each its own. The other kinds say by their kind what
        /// they are for, and are told nothing by the node itself - but whoever
        /// looks after it may mark any certificate with a usage of their own,
        /// for a configuration or code to name later.
        /// </remarks>
        public static Boolean HasUsages(this CertificateKind Kind)

            => Kind.IsNotNullOrEmpty;

        #endregion

        #region Directory(this Kind)

        /// <summary>
        /// Where certificates of this kind live below the store, as a relative
        /// path.
        /// </summary>
        /// <remarks>
        /// The roots sit together under one directory because they are one
        /// thought - "what this node believes" - and because a store
        /// somebody looks at with a file manager should show that at a glance.
        /// A made-up kind lives below "custom/", in the directory of its group,
        /// so that its group is known from where its files are.
        /// </remarks>
        public static String Directory(this CertificateKind Kind)

            => Kind.RelativeDirectory;

        #endregion

        #region Extension(this Kind)

        /// <summary>
        /// What a stored file of this kind is called at the end.
        /// </summary>
        /// <remarks>
        /// <para>
        /// PEM for a trust anchor, PKCS#12 for everything the node
        /// presents or verifies with. Not a preference but what the readers on
        /// the other side already accept: <c>TrustRoots.Load</c> scans a
        /// directory for PEM and DER and deliberately ignores PKCS#12, because
        /// a trust anchor has no business carrying a private key; and
        /// <c>Credentials</c> reads PKCS#12 and nothing else.
        /// </para>
        /// <para>
        /// So the tariff verification key is kept as PKCS#12 although it has no
        /// private half - the file is a bag of certificates either way, and a
        /// store that wrote it as PEM would be a store whose files its own
        /// loader could not open.
        /// </para>
        /// </remarks>
        public static String Extension(this CertificateKind Kind)

            => Kind.IsTrustAnchor()
                   ? ".pem"
                   : ".p12";

        #endregion

        #region AsText(this Kind) / TryParseKind(Text, out Kind)

        /// <summary>
        /// This kind as it is written in the configuration file and on the
        /// JSON API.
        /// </summary>
        public static String AsText(this CertificateKind Kind)

            => Kind.ToString();

        /// <summary>
        /// A kind defined in code as somebody wrote it, or nothing.
        /// </summary>
        /// <remarks>
        /// Case-insensitive, because the difference between "oemRoot" and
        /// "oemroot" is not a difference anybody means.
        /// </remarks>
        public static Boolean TryParseKind(String? Text, out CertificateKind Kind)

            => CertificateKind.TryParse(Text, out Kind);

        #endregion

        #region Describe(this Kind)

        /// <summary>
        /// One line saying what this kind is for, for a log entry or a page
        /// that has to name it to somebody who has not read ISO 15118.
        /// </summary>
        public static String Describe(this CertificateKind Kind)

            => Kind.Description;


        /// <summary>
        /// What this kind is for, said of a kind of node: "what a server this
        /// roaming hub connects to may chain to".
        /// </summary>
        /// <remarks>
        /// Said of "this node", a line in a usage, a list or a log that says
        /// "this roaming hub" everywhere else read as if it were somebody
        /// else's certificate (found by the hub and the EV).
        /// </remarks>
        /// <param name="Kind">The kind of certificate.</param>
        /// <param name="NodeName">What the node is called in a sentence: "roaming hub".</param>
        public static String Describe(this CertificateKind  Kind,
                                      String                NodeName)

            => Kind.Describe().Replace("this node", $"this {NodeName}", StringComparison.Ordinal);

        #endregion

        #region WithArticle(this Kind) / CapitalisedWithArticle(this Kind)

        /// <summary>
        /// This kind's name with the article it is said with, for a sentence
        /// that names one: "an OEM root", "a TLS root".
        /// </summary>
        /// <remarks>
        /// Written down with each name rather than worked out from its first
        /// letter, because it goes by how the name is said: "an OEM root" but
        /// "a V2G root". A sentence that put "A" in front of whatever came
        /// next refused a keyless OEM provisioning certificate as "A OEM
        /// provisioning certificate - what this vehicle was born with has to
        /// carry its private key", with the whole of <see cref="Describe(CertificateKind)"/>
        /// in the middle of it.
        /// </remarks>
        public static String WithArticle(this CertificateKind Kind)

            => Kind.NameWithArticle;

        /// <summary>
        /// The same at the start of a sentence: "An OEM root".
        /// </summary>
        public static String CapitalisedWithArticle(this CertificateKind Kind)
        {

            var named = Kind.WithArticle();

            return Char.ToUpperInvariant(named[0]) + named[1..];

        }

        #endregion

        #region SortOrder(this Kind)

        /// <summary>
        /// Where this kind comes in the order everything is shown and written
        /// in: what the node believes first, what it presents second.
        /// </summary>
        /// <remarks>
        /// Spelled out with each kind rather than taken from the order they were
        /// defined in, so that somebody adding a kind does not silently reorder
        /// every page and every index file.
        /// </remarks>
        public static Int32 SortOrder(this CertificateKind Kind)

            => Kind.Position;

        #endregion

        #region All

        /// <summary>
        /// Every kind every node knows, in the order a page shows them:
        /// what it believes first, what it presents second.
        /// </summary>
        public static readonly IReadOnlyList<CertificateKind> All = [
            CertificateKind.V2GRoot,
            CertificateKind.MORoot,
            CertificateKind.OEMRoot,
            CertificateKind.TLSRoot,
            CertificateKind.ClientRoot,
            CertificateKind.Vehicle,
            CertificateKind.Contract,
            CertificateKind.OEMProvisioning,
            CertificateKind.TariffVerification,
            CertificateKind.TLSServer,
            CertificateKind.TLSIdentity
        ];

        /// <summary>
        /// The kinds of ISO 15118, which a vehicle keeps: the three roots and
        /// the four credentials.
        /// </summary>
        public static readonly IReadOnlyList<CertificateKind> ISO15118 = [
            CertificateKind.V2GRoot,
            CertificateKind.MORoot,
            CertificateKind.OEMRoot,
            CertificateKind.Vehicle,
            CertificateKind.Contract,
            CertificateKind.OEMProvisioning,
            CertificateKind.TariffVerification
        ];

        /// <summary>
        /// The kinds of TLS in general, which any kind of node may keep.
        /// </summary>
        public static readonly IReadOnlyList<CertificateKind> TLS = [
            CertificateKind.TLSRoot,
            CertificateKind.ClientRoot,
            CertificateKind.TLSServer,
            CertificateKind.TLSIdentity
        ];

        #endregion

    }

}
