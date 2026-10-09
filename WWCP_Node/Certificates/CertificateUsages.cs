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

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// What a certificate in the store may be used for, beside what kind of
    /// certificate it is: the servers a TLS root may vouch for, the servers a
    /// server certificate may be recognised as, the listeners a TLS server
    /// identity is shown on - or whatever somebody marked it for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A kind says what a certificate is - a root, somebody else's server
    /// certificate - and a usage says whom it is about. One root may vouch for
    /// the name servers and the time servers alike, which is why a certificate
    /// has any number of usages rather than one.
    /// </para>
    /// <para>
    /// The node brings two, the name servers and the time servers it asks; a
    /// kind of node may add its own - a backend it dials, the listeners it has.
    /// And whoever looks after a node may mark a certificate with a usage
    /// nobody defined: a mark, which nothing in the node acts on until a
    /// configuration or code names it. Such a usage is known for as long as a
    /// certificate is marked with it, and forgotten with the last one: nothing
    /// but the certificates remembers it.
    /// </para>
    /// <para>
    /// A usage is a name, written the way a resource of a role is written: a
    /// letter, then letters, digits, '-' or '_', in lower case.
    /// </para>
    /// </remarks>
    public readonly struct CertificateUsage : IId<CertificateUsage>
    {

        #region Data

        private readonly String InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this usage is null or empty.
        /// </summary>
        public Boolean  IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this usage is NOT null or empty.
        /// </summary>
        public Boolean  IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of this usage's name.
        /// </summary>
        public UInt64   Length
            => (UInt64) (InternalId?.Length ?? 0);

        #endregion

        #region Constructor(s)

        private CertificateUsage(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given text as a usage.
        /// </summary>
        /// <param name="Text">A text representation of a usage.</param>
        public static CertificateUsage Parse(String Text)

            => TryParse(Text, out var usage)
                   ? usage
                   : throw new ArgumentException($"'{Text}' is not a usage name: a letter, then letters, digits, '-' or '_', at most {CertificateUsages.MaxLength} characters.",
                                                 nameof(Text));

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a usage.
        /// </summary>
        /// <param name="Text">A text representation of a usage.</param>
        public static CertificateUsage? TryParse(String? Text)

            // Null as what it is: the conversion from a text would otherwise
            // take it as one, and throw for it.
            => TryParse(Text, out var usage)
                   ? usage
                   : (CertificateUsage?) null;

        #endregion

        #region (static) TryParse(Text, out Usage)

        /// <summary>
        /// Try to parse the given text as a usage - in lower case, which is what
        /// a usage is compared in.
        /// </summary>
        /// <param name="Text">A text representation of a usage.</param>
        /// <param name="Usage">The usage.</param>
        public static Boolean TryParse(String? Text, out CertificateUsage Usage)
        {

            var name = Text?.Trim().ToLowerInvariant();

            if (CertificateUsages.IsUsageName(name))
            {
                Usage = new CertificateUsage(name!);
                return true;
            }

            Usage = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this usage.
        /// </summary>
        public CertificateUsage Clone()
            => new (InternalId.CloneString());

        #endregion


        #region Static definitions

        /// <summary>
        /// The name servers a node asks over TLS or HTTPS.
        /// </summary>
        public static CertificateUsage DNS  { get; }
            = new (CertificateUsages.DNS);

        /// <summary>
        /// The time servers a node asks, at their NTS key exchange.
        /// </summary>
        public static CertificateUsage NTS  { get; }
            = new (CertificateUsages.NTS);

        #endregion


        #region Conversions

        /// <summary>
        /// A usage written as text, as configurations and kinds of node have
        /// always written them - refused where it is no usage name.
        /// </summary>
        public static implicit operator CertificateUsage(String Text)
            => Parse(Text);

        /// <summary>
        /// A usage as text.
        /// </summary>
        public static implicit operator String(CertificateUsage Usage)
            => Usage.ToString();

        #endregion

        #region Operator overloading

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public static Boolean operator == (CertificateUsage Usage1, CertificateUsage Usage2)
            => Usage1.Equals(Usage2);

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public static Boolean operator != (CertificateUsage Usage1, CertificateUsage Usage2)
            => !Usage1.Equals(Usage2);

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public static Boolean operator < (CertificateUsage Usage1, CertificateUsage Usage2)
            => Usage1.CompareTo(Usage2) < 0;

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public static Boolean operator <= (CertificateUsage Usage1, CertificateUsage Usage2)
            => Usage1.CompareTo(Usage2) <= 0;

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public static Boolean operator > (CertificateUsage Usage1, CertificateUsage Usage2)
            => Usage1.CompareTo(Usage2) > 0;

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public static Boolean operator >= (CertificateUsage Usage1, CertificateUsage Usage2)
            => Usage1.CompareTo(Usage2) >= 0;

        #endregion

        #region IComparable<CertificateUsage> Members

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public Int32 CompareTo(Object? Object)

            => Object is CertificateUsage usage
                   ? CompareTo(usage)
                   : throw new ArgumentException("The given object is not a certificate usage!", nameof(Object));

        /// <summary>
        /// Compares two usages.
        /// </summary>
        public Int32 CompareTo(CertificateUsage Usage)

            => String.Compare(InternalId, Usage.InternalId, StringComparison.Ordinal);

        #endregion

        #region IEquatable<CertificateUsage> Members

        /// <summary>
        /// Whether the given object is the same usage.
        /// </summary>
        public override Boolean Equals(Object? Object)

            => Object is CertificateUsage usage &&
                   Equals(usage);

        /// <summary>
        /// Whether the given usage is the same usage.
        /// </summary>
        public Boolean Equals(CertificateUsage Usage)

            => String.Equals(InternalId, Usage.InternalId, StringComparison.Ordinal);

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// The hash code of this usage.
        /// </summary>
        public override Int32 GetHashCode()
            => InternalId?.GetHashCode() ?? 0;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// This usage as it is written.
        /// </summary>
        public override String ToString()
            => InternalId ?? "";

        #endregion

    }


    /// <summary>
    /// What every node says about usages: the names it brings, what a name may
    /// be, and how usages are said in a sentence.
    /// </summary>
    public static class CertificateUsages
    {

        /// <summary>
        /// The name servers a node asks over TLS or HTTPS.
        /// </summary>
        public const String  DNS          = "dns";

        /// <summary>
        /// The time servers a node asks, at their NTS key exchange.
        /// </summary>
        public const String  NTS          = "nts";

        /// <summary>
        /// The longest a usage may be called.
        /// </summary>
        public const Int32   MaxLength    = 32;

        /// <summary>
        /// The node's own.
        /// </summary>
        public static readonly IReadOnlyList<CertificateUsage>  All = [ CertificateUsage.DNS, CertificateUsage.NTS ];


        #region IsUsageName(Text)

        /// <summary>
        /// Whether the given text may name a usage: a letter, then letters,
        /// digits, '-' or '_' - lower case, which is what a usage is compared in.
        /// </summary>
        public static Boolean IsUsageName(String? Text)
        {

            if (String.IsNullOrEmpty(Text) || Text.Length > MaxLength)
                return false;

            if (Text[0] is < 'a' or > 'z')
                return false;

            foreach (var character in Text)
                if (character is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_'))
                    return false;

            return true;

        }

        #endregion

        #region Describe(Usages)

        /// <summary>
        /// The usages of a certificate in a sentence: "for every use", or "for
        /// dns and nts".
        /// </summary>
        /// <param name="Usages">The usages, or null for every one.</param>
        public static String Describe(IReadOnlyList<CertificateUsage>? Usages)

            => Usages is null         ? "for every use"
             : Usages.Count == 0      ? "for no use"
             : Usages.Count == 1      ? $"for {Usages[0]}"
             : $"for {String.Join(", ", Usages.Take(Usages.Count - 1))} and {Usages[^1]}";

        #endregion

    }

}
