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

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a node says about its certificate store, the same for every kind of
    /// node, and what a kind of node adds to it.
    /// </summary>
    /// <remarks>
    /// Written once here and not by each kind of node: the vehicle's, the
    /// charging station's, the local controller's and the gateway's were the
    /// same lines, copied, and one of them missed a fix the others had - a
    /// page offering a TLS identity uses the store refuses.
    /// </remarks>
    public partial class WWCPNode
    {

        #region CertificatesJSON()

        /// <summary>
        /// Everything in this node's certificate store, grouped the way it is
        /// shown.
        /// </summary>
        /// <remarks>
        /// Groups and not one list. The roots are what this node <i>believes</i>
        /// of a server it connects to: any number may be on at once. The
        /// identities are what it <i>presents</i> in TLS, with their private
        /// keys. The server certificates are neither: what it
        /// <i>recognises</i>, kept for a server to be held to by its
        /// fingerprint. A page that put them in one table would have to explain
        /// that difference in a column heading.
        /// </remarks>
        public JObject CertificatesJSON()
        {

            // The kinds this store keeps: a page offering a kind the store
            // refuses would be offering a refusal.
            var kinds  = Certificates.Kinds;
            var byKind = new JObject();

            foreach (var kind in kinds)
                byKind.Add(kind.AsText(),
                           new JArray(Certificates.ByKind(kind).Select(entry => entry.ToJSON(WithDiagnostics: true))));

            var json = new JObject(

                           new JProperty("directory",    Certificates.Directory),

                           new JProperty("trustAnchors", new JArray(
                               kinds.Where(kind =>  kind.IsTrustAnchor()).Select(kind => kind.AsText())
                           )),

                           new JProperty("credentials",  new JArray(
                               kinds.Where(kind => !kind.IsTrustAnchor() && !kind.MustNotCarryPrivateKey()).Select(kind => kind.AsText())
                           )),

                           // Neither believed nor presented, and never with a key:
                           // a server certificate, kept to recognise a server by.
                           // Shown among what a node presents, it read as something
                           // the node would present.
                           new JProperty("recognised",   new JArray(
                               kinds.Where(kind => !kind.IsTrustAnchor() &&  kind.MustNotCarryPrivateKey()).Select(kind => kind.AsText())
                           )),

                           new JProperty("kinds",        new JObject(
                               kinds.Select(kind =>
                                   new JProperty(kind.AsText(), new JObject(
                                       new JProperty("description",     kind.Describe(Kind.Name)),
                                       new JProperty("trustAnchor",     kind.IsTrustAnchor()),
                                       new JProperty("needsPrivateKey", kind.NeedsPrivateKey()),
                                       // Whether one of the kind is told what it is
                                       // for in this store, and what it may be told -
                                       // the store's word and not the kind's: a TLS
                                       // identity is told the listeners a kind of node
                                       // names, and most name none, so it is told
                                       // nothing. Asked of the kind, a page offered an
                                       // identity "dns" and "nts", which the store
                                       // refuses.
                                       new JProperty("hasUsages",       Certificates.HasUsages(kind)),
                                       new JProperty("usages",          new JArray(Certificates.UsagesFor(kind)))
                                   )))
                           )),

                           // What a TLS root or a server certificate may be told it is
                           // for - the services it vouches for - as it was said
                           // before every kind said its own above.
                           new JProperty("usages",       new JArray(Certificates.Usages)),

                           new JProperty("certificates", byKind),

                           // Said here because this is the page where somebody is
                           // looking at the consequences of it, rather than only in
                           // the log at a start.
                           new JProperty("keysAreUnencrypted", Certificates.Entries.Any(entry => entry.HasPrivateKey))

                       );

            CompleteCertificatesJSON(json);

            return json;

        }

        #endregion

        #region (protected virtual) CompleteCertificatesJSON(JSON)

        /// <summary>
        /// Add what this kind of node says about its store beyond what every
        /// node says: which certificates it has chosen for what, say, so that a
        /// page can mark them without reading other settings as well.
        /// </summary>
        /// <param name="JSON">What every node says about its store, to be added to.</param>
        protected virtual void CompleteCertificatesJSON(JObject JSON)
        { }

        #endregion

        #region (virtual) WhatUses(Handle)

        /// <summary>
        /// What of this node uses the certificate with the given handle, as the
        /// sentence a refusal to delete it says - or null where nothing does.
        /// </summary>
        /// <remarks>
        /// Asked before a certificate is deleted: deleting it anyway would leave
        /// the node configured to use something that is not there, which is
        /// found out the next time it is used rather than here - and switching
        /// it off is mostly what somebody taking a certificate out of service
        /// meant. Nothing by default; a kind of node that chooses certificates
        /// for something says what.
        /// </remarks>
        /// <param name="Handle">The handle the certificate is asked for by, as the store spells it: the first 16 digits of its fingerprint, in lower case.</param>
        public virtual String? WhatUses(String Handle)
            => null;

        #endregion

        #region (virtual) WhatWouldLose(Entry, ActiveAfter, UsagesAfter)

        /// <summary>
        /// What of this node would be left without a certificate it needs, were
        /// the given one switched on or off and told the given usages, as the
        /// sentence a refusal of that change says - or null where nothing would.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Asked before a certificate is changed or deleted, and before any of
        /// the change is made: a listener whose only identity is switched off,
        /// or told it is for another listener, has nothing to show at the next
        /// handshake - which the node finds out there, and whoever clicked does
        /// not. Nothing by default; a kind of node whose listeners or clients
        /// need a certificate to be there says which - a meter's.
        /// </para>
        /// <para>
        /// Not the question <see cref="WhatUses"/> answers. That is what names
        /// a certificate, which switching it off leaves alone and deleting it
        /// does not: switching off is how a vehicle's chosen credential is
        /// taken out of service. This is what needs it to be on, which
        /// switching it off takes away as much as deleting it does. So a
        /// deletion asks both, and a change this one.
        /// </para>
        /// </remarks>
        /// <param name="Entry">The certificate as it is now.</param>
        /// <param name="ActiveAfter">Whether it would be switched on afterwards; false for a deletion.</param>
        /// <param name="UsagesAfter">What it would be for afterwards, as the store keeps usages; null for every use.</param>
        public virtual String? WhatWouldLose(CertificateEntry        Entry,
                                             Boolean                 ActiveAfter,
                                             IReadOnlyList<String>?  UsagesAfter)
            => null;

        #endregion

    }

}
