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
    /// One kind a certificate is to be kept as, and what it is for as that
    /// kind - what an import is told for each kind it puts a certificate in as.
    /// </summary>
    /// <remarks>
    /// One certificate may be kept as several kinds at once: a self-signed
    /// identity that is also the root its peers are judged against, a root that
    /// anchors the servers this node connects to and its clients alike. Each
    /// kind it is kept as is a registration of its own, with a file in that
    /// kind's directory, switched on and off on its own and told its own usages;
    /// what it is called is the certificate's, and the same for all of them.
    /// </remarks>
    /// <param name="Kind">The kind.</param>
    /// <param name="Usages">What it is for as that kind, where the kind is kept for some uses and not others; null for every use - and, for a registration already there, for leaving its usages as they are.</param>
    public sealed record CertificateRegistration(CertificateKind         Kind,
                                                 IReadOnlyList<String>?  Usages  = null);

}
