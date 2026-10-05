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

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// The SSH key a node made up for its first account at a first start, as
    /// the banner shows it once: the fingerprint it is let in with, and its
    /// private key in OpenSSH's format, which ssh reads as it is and PuTTYgen
    /// imports. Kept in memory for the banner, and written nowhere.
    /// </summary>
    /// <param name="Account">The account it lets in.</param>
    /// <param name="Fingerprint">Its SHA-256 fingerprint, "SHA256:...".</param>
    /// <param name="PrivateKey">Its private key, from "-----BEGIN OPENSSH PRIVATE KEY-----" to "-----END OPENSSH PRIVATE KEY-----".</param>
    public sealed record GeneratedSSHKey(String  Account,
                                         String  Fingerprint,
                                         String  PrivateKey);

}
