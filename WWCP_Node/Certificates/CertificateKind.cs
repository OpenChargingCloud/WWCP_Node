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

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// What a certificate in a node's store is <i>for</i>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Eleven kinds, in two groups that behave differently in every respect that
    /// matters. A <b>trust anchor</b> is a public certificate that says which
    /// chains the node believes; there may be any number of them active at
    /// once, and none of them is ever chosen for a session. A <b>credential</b>
    /// is something the node presents or verifies with, carries a private
    /// key in every case but two, and is chosen - exactly one per role - where
    /// something asks for one.
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
    /// The names follow the CharIN V2G second-generation PKI Certificate
    /// Policy, as they do in <see cref="ISO15118.VehicleCredentials"/> and for
    /// the same reason: ISO 15118-20's own naming is not consistent with
    /// itself, and the Policy's is.
    /// </para>
    /// </remarks>
    public enum CertificateKind
    {

        /// <summary>
        /// A <b>V2G root</b>: what a station's certificate has to chain to.
        /// </summary>
        /// <remarks>
        /// The one the store has always had, under the older name
        /// "trust roots". It is checked at the TLS handshake, against the
        /// certificate the station presents.
        /// </remarks>
        V2GRoot,

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
        MORoot,

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
        OEMRoot,

        /// <summary>
        /// The <b>Vehicle</b> certificate: who this vehicle is.
        /// </summary>
        /// <remarks>
        /// Presented in the TLS handshake, and for ISO 15118-20 what a
        /// station's resume binding is computed over.
        /// </remarks>
        Vehicle,

        /// <summary>
        /// A <b>contract</b> certificate: who pays.
        /// </summary>
        /// <remarks>
        /// The one kind a vehicle plausibly holds several of - one per
        /// contract, and ISO 15118-2 and -20 need not be the same one - which
        /// is most of the reason this store exists at all.
        /// </remarks>
        Contract,

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
        OEMProvisioning,

        /// <summary>
        /// The public key a station's signed tariff is checked against.
        /// </summary>
        /// <remarks>
        /// A credential with no private key: the signing half lives at the
        /// station, and this side only ever verifies.
        /// </remarks>
        TariffVerification,

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
        TLSRoot,

        /// <summary>
        /// A <b>client root</b>: what a client connecting to this node has to
        /// chain to.
        /// </summary>
        ClientRoot,

        /// <summary>
        /// A <b>server certificate</b>: what a server this node connects to
        /// presents, kept so that it can be recognised by its fingerprint.
        /// </summary>
        /// <remarks>
        /// Somebody else's certificate, and so never with a private key: that
        /// server's key in this store would be a key in the wrong place, as a
        /// root's would.
        /// </remarks>
        TLSServer,

        /// <summary>
        /// A <b>TLS identity</b>: what this node presents in TLS, with its
        /// private key - its web interface's certificate, or the one it shows a
        /// server that asks for one.
        /// </summary>
        TLSIdentity

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

            => Kind is CertificateKind.V2GRoot
                    or CertificateKind.MORoot
                    or CertificateKind.OEMRoot
                    or CertificateKind.TLSRoot
                    or CertificateKind.ClientRoot;

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

            => Kind is CertificateKind.Vehicle
                    or CertificateKind.Contract
                    or CertificateKind.OEMProvisioning
                    or CertificateKind.TLSIdentity;

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

            => Kind.IsTrustAnchor() ||
               Kind == CertificateKind.TLSServer;

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
        /// </remarks>
        public static String Directory(this CertificateKind Kind)

            => Kind switch {
                   CertificateKind.V2GRoot             => "roots/v2g",
                   CertificateKind.MORoot              => "roots/mo",
                   CertificateKind.OEMRoot             => "roots/oem",
                   CertificateKind.Vehicle             => "vehicle",
                   CertificateKind.Contract            => "contract",
                   CertificateKind.OEMProvisioning     => "oem",
                   CertificateKind.TariffVerification  => "tariff",
                   CertificateKind.TLSRoot             => "roots/tls",
                   CertificateKind.ClientRoot          => "roots/clients",
                   CertificateKind.TLSServer           => "tls/servers",
                   CertificateKind.TLSIdentity         => "tls/identity",
                   _                                   => throw new ArgumentOutOfRangeException(nameof(Kind), Kind, "Unknown certificate kind.")
               };

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

            => Kind switch {
                   CertificateKind.V2GRoot             => "v2gRoot",
                   CertificateKind.MORoot              => "moRoot",
                   CertificateKind.OEMRoot             => "oemRoot",
                   CertificateKind.Vehicle             => "vehicle",
                   CertificateKind.Contract            => "contract",
                   CertificateKind.OEMProvisioning     => "oemProvisioning",
                   CertificateKind.TariffVerification  => "tariffVerification",
                   CertificateKind.TLSRoot             => "tlsRoot",
                   CertificateKind.ClientRoot          => "clientRoot",
                   CertificateKind.TLSServer           => "tlsServer",
                   CertificateKind.TLSIdentity         => "tlsIdentity",
                   _                                   => throw new ArgumentOutOfRangeException(nameof(Kind), Kind, "Unknown certificate kind.")
               };

        /// <summary>
        /// A kind as somebody wrote it, or nothing.
        /// </summary>
        /// <remarks>
        /// Case-insensitive, because the difference between "oemRoot" and
        /// "oemroot" is not a difference anybody means.
        /// </remarks>
        public static Boolean TryParseKind(String? Text, out CertificateKind Kind)
        {

            foreach (var candidate in All)
            {
                if (String.Equals(candidate.AsText(), Text?.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    Kind = candidate;
                    return true;
                }
            }

            Kind = default;
            return false;

        }

        #endregion

        #region Describe(this Kind)

        /// <summary>
        /// One line saying what this kind is for, for a log entry or a page
        /// that has to name it to somebody who has not read ISO 15118.
        /// </summary>
        public static String Describe(this CertificateKind Kind)

            => Kind switch {
                   CertificateKind.V2GRoot             => "V2G root - what a station's certificate must chain to",
                   CertificateKind.MORoot              => "Mobility Operator root - what a contract certificate must chain to",
                   CertificateKind.OEMRoot             => "OEM root - what an OEM provisioning certificate must chain to",
                   CertificateKind.Vehicle             => "Vehicle certificate - who this vehicle is",
                   CertificateKind.Contract            => "contract certificate - who pays",
                   CertificateKind.OEMProvisioning     => "OEM provisioning certificate - what this vehicle was born with",
                   CertificateKind.TariffVerification  => "tariff certificate - what a station's signed tariff is checked with",
                   CertificateKind.TLSRoot             => "TLS root - what a server this node connects to may chain to: a time server, a backend",
                   CertificateKind.ClientRoot          => "client root - what a client connecting to this node has to chain to",
                   CertificateKind.TLSServer           => "server certificate - what a server this node connects to presents, kept to be recognised by its fingerprint",
                   CertificateKind.TLSIdentity         => "TLS identity - what this node presents in TLS, with its private key",
                   _                                   => throw new ArgumentOutOfRangeException(nameof(Kind), Kind, "Unknown certificate kind.")
               };

        #endregion

        #region SortOrder(this Kind)

        /// <summary>
        /// Where this kind comes in the order everything is shown and written
        /// in: what the node believes first, what it presents second.
        /// </summary>
        /// <remarks>
        /// Spelled out rather than taken from the enum's own numbering, so that
        /// somebody adding a kind in the middle of the enum does not silently
        /// reorder every page and every index file.
        /// </remarks>
        public static Int32 SortOrder(this CertificateKind Kind)

            => Kind switch {
                   CertificateKind.V2GRoot             =>  0,
                   CertificateKind.MORoot              =>  1,
                   CertificateKind.OEMRoot             =>  2,
                   CertificateKind.TLSRoot             =>  3,
                   CertificateKind.ClientRoot          =>  4,
                   CertificateKind.Vehicle             => 10,
                   CertificateKind.Contract            => 11,
                   CertificateKind.OEMProvisioning     => 12,
                   CertificateKind.TariffVerification  => 13,
                   CertificateKind.TLSServer           => 14,
                   CertificateKind.TLSIdentity         => 15,
                   _                                   => Int32.MaxValue
               };

        #endregion

        #region All

        /// <summary>
        /// Every kind the store knows, in the order a page shows them:
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
