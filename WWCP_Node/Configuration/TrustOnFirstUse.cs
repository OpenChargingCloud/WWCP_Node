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

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// What a server with no pin of its own is held to from the first time it
    /// is believed: nothing, the root its chain ended at, or its certificate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Learned, and then written into the configuration file like a pin
    /// somebody typed, because that is what it is from then on: shown on the
    /// page beside the server, changed there, and taken away there.
    /// </para>
    /// <para>
    /// Only from a certificate that was believed anyway - issued for the
    /// server's name, its chain ending at a root this node trusts. Trust on
    /// first use narrows what is believed, as every pin does, and never widens
    /// it: a server with a certificate it signed itself is believed by
    /// importing that certificate as a TLS root, not by being the first to be
    /// asked.
    /// </para>
    /// <para>
    /// The root rather than the certificate is usually what to learn: a
    /// server's certificate is renewed every few months, and a pin on it
    /// turns every renewal into a mismatch, where its root stays for years.
    /// </para>
    /// </remarks>
    public enum TrustOnFirstUse
    {

        /// <summary>
        /// Nothing is learned.
        /// </summary>
        None,

        /// <summary>
        /// The root the chain of the first believed certificate ended at.
        /// </summary>
        Root,

        /// <summary>
        /// The first believed certificate itself.
        /// </summary>
        Certificate

    }


    /// <summary>
    /// What a <see cref="TrustOnFirstUse"/> is called in the configuration file.
    /// </summary>
    public static class TrustOnFirstUseExtensions
    {

        /// <summary>
        /// The word the configuration file uses: "root" or "certificate", and
        /// null for nothing.
        /// </summary>
        public static String? AsText(this TrustOnFirstUse TrustOnFirstUse)

            => TrustOnFirstUse switch {
                   TrustOnFirstUse.Root         => "root",
                   TrustOnFirstUse.Certificate  => "certificate",
                   _                            => null
               };

        /// <summary>
        /// The word as somebody wrote it, in any case.
        /// </summary>
        public static Boolean TryParse(String?              Text,
                                       out TrustOnFirstUse  TrustOnFirstUse)
        {

            switch (Text?.Trim().ToLowerInvariant())
            {

                case "root":
                    TrustOnFirstUse = TrustOnFirstUse.Root;
                    return true;

                case "certificate":
                    TrustOnFirstUse = TrustOnFirstUse.Certificate;
                    return true;

                default:
                    TrustOnFirstUse = TrustOnFirstUse.None;
                    return false;

            }

        }

    }

}
