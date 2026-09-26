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
    /// What a certificate in the store may be used for, beside what kind of
    /// certificate it is: the servers a TLS root may vouch for, the servers a
    /// server certificate may be recognised as.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A kind says what a certificate is - a root, somebody else's server
    /// certificate - and a usage says whom it is about. One root may vouch for
    /// the name servers and the time servers alike, which is why a certificate
    /// has any number of usages rather than one: kept twice, under two kinds,
    /// it would be two entries to switch off when it is withdrawn, and the one
    /// forgotten would still be believed.
    /// </para>
    /// <para>
    /// The node brings two, the name servers and the time servers it asks; a
    /// kind of node may add its own - a backend it dials, say. A usage is a
    /// name, written the way a resource of a role is written.
    /// </para>
    /// </remarks>
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
        public static readonly IReadOnlyList<String>  All = [ DNS, NTS ];


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
        public static String Describe(IReadOnlyList<String>? Usages)

            => Usages is null         ? "for every use"
             : Usages.Count == 0      ? "for no use"
             : Usages.Count == 1      ? $"for {Usages[0]}"
             : $"for {String.Join(", ", Usages.Take(Usages.Count - 1))} and {Usages[^1]}";

        #endregion

    }

}
