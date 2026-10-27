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

using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.TCP;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The certificate the web interface of a node shows at every handshake:
    /// out of the node's certificate store, or out of a pair of PEM files - see
    /// <see cref="WebCertificateSource"/> - asked anew at every handshake, so
    /// that a certificate renewed under a running node is shown from the next
    /// connection on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Out of the store</b>: the TLS server identities for the listener
    /// <see cref="Listener"/>, or told no listener, which are switched on and
    /// valid now - the one whose validity began last, so that a certificate
    /// put in before the old one runs out takes over on the day it becomes
    /// valid, without anybody being there. Each certificate is read from its
    /// file once and kept; the store is asked which of them at every
    /// handshake, which is a look into a list of a handful.
    /// </para>
    /// <para>
    /// <b>Out of files</b>: Hermod's <see cref="ServerCertificateFile"/>, which
    /// looks at the files no more often than every ten seconds, by their
    /// content rather than by their time stamps - certbot replaces symbolic
    /// links, and a deploy hook copies with the times of the original - and
    /// keeps the certificate before where the new one does not read: half of a
    /// renewal, the certificate copied and the key not yet, is no reason to
    /// show nothing. Said in the log, once per change.
    /// </para>
    /// <para>
    /// <b>With nothing to show, a connection is refused</b>, and not served in
    /// the clear: Hermod goes on without TLS where it is handed no certificate,
    /// which on a port somebody configured for HTTPS would be the one outcome
    /// worse than none. The log says so once, when it begins, and again when
    /// there is something to show.
    /// </para>
    /// </remarks>
    public sealed class WebServerCertificate
    {

        #region Data

        /// <summary>
        /// The listener of the node a TLS server identity is told it is shown
        /// on, where it is told: the web interface.
        /// </summary>
        public const String  Listener  = "web";

        private readonly CertificateStore                         store;
        private readonly ServerCertificateFile?                   files;
        private readonly EventLog                                 log;
        private readonly String                                   nodeName;

        private readonly Lock                                     cacheLock  = new ();
        private readonly Dictionary<String, ServerCertificateChain?>  loaded     = [];

        private          String?                                  shown;
        private          Boolean                                  saidNone;

        #endregion

        #region Properties

        /// <summary>
        /// Where the certificate comes from.
        /// </summary>
        public WebCertificateSource  Source    { get; }

        /// <summary>
        /// What is shown now, with its intermediates - read again first where
        /// the files changed - or null while there is nothing to show.
        /// </summary>
        public ServerCertificateChain? Current
        {
            get
            {

                var current = Source.IsStore
                                  ? FromTheStore()
                                  : files!.Current;

                SayWhatChanged(current);

                return current;

            }
        }

        /// <summary>
        /// The entry of the store shown now, or null - for files, and while
        /// there is nothing to show.
        /// </summary>
        public CertificateEntry? StoreEntry
            => Source.IsStore
                   ? Candidates.FirstOrDefault(entry => Load(entry) is not null)
                   : null;

        /// <summary>
        /// Why the files as they are now were not taken, or null where they
        /// were - or where the certificate comes from the store.
        /// </summary>
        public String? LastError
            => files?.LastError;

        /// <summary>
        /// The identities of the store the web interface could show now, the
        /// one it shows first.
        /// </summary>
        public IReadOnlyList<CertificateEntry> Candidates

            => Source.IsStore
                   ? [.. store.UsableFor(CertificateKind.TLSServerIdentity, Listener).
                               OrderByDescending(entry => entry.NotBefore).
                               ThenByDescending (entry => entry.NotAfter).
                               ThenByDescending (entry => entry.Id, StringComparer.Ordinal)]
                   : [];

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The certificate the web interface of a node shows.
        /// </summary>
        /// <param name="Source">Where it comes from: the store, or files - whose paths are as they are read.</param>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Log">Where a certificate taken, or one that would not be, is said.</param>
        /// <param name="NodeName">What the node is called in a sentence.</param>
        public WebServerCertificate(WebCertificateSource  Source,
                                    CertificateStore      Store,
                                    EventLog              Log,
                                    String                NodeName)
        {

            this.Source    = Source;
            this.store     = Store;
            this.log       = Log;
            this.nodeName  = NodeName;

            if (!Source.IsStore)
            {

                // Read for the first time here. That they are not there yet is
                // not a reason not to start: a node waiting for its first
                // certificate from certbot has to be running for certbot to
                // reach it.
                this.files = new ServerCertificateFile(Source.FullChain!, Source.PrivateKey);

                this.files.OnLoadFailed += error => log.Warning($"The certificate of the web interface was not taken from {Source}: {error} " +
                                                                (shown is not null
                                                                     ? "The one before is shown still."
                                                                     : "Every connection is refused until it can be read."),
                                                                "web", "tls", "security");

                if (this.files.LastError is String error)
                    log.Warning($"The certificate of the web interface could not be read from {Source}: {error}", "web", "tls", "security");

            }

        }

        #endregion


        #region ChainFor(TCPServer, TCPClient)

        /// <summary>
        /// What the HTTP server asks at every handshake: the certificate and its
        /// intermediates - or an exception where there is nothing to show, which
        /// ends the connection rather than leaving it to go on without TLS.
        /// </summary>
        public ServerCertificateChain ChainFor(ITCPServer  TCPServer,
                                               TcpClient   TCPClient)

            => Current ?? throw new InvalidOperationException($"This {nodeName} has no certificate for its web interface to show.");

        #endregion

        #region ToJSON()

        /// <summary>
        /// What the web interface shows, as the Configuration page says it:
        /// where it comes from, and the certificate itself.
        /// </summary>
        public JObject ToJSON()
        {

            var current = Source.IsStore ? FromTheStore() : files!.Current;
            var entry   = StoreEntry;

            return new JObject(
                       new JProperty("certificate",  Source.IsStore ? WebTLSConfiguration.StoreText : "files"),
                       new JProperty("fullchain",    Source.FullChain),
                       new JProperty("privateKey",   Source.PrivateKey),
                       new JProperty("label",        entry?.Label),
                       new JProperty("shows",        current?.Certificate.Subject),
                       new JProperty("thumbprint",   current is not null ? CertificateEntry.ThumbprintOf(current.Certificate) : null),
                       new JProperty("notAfter",     current?.Certificate.NotAfter.ToUniversalTime().ToString("o")),
                       new JProperty("problem",      current is null
                                                         ? LastError ?? (Source.IsStore
                                                                             ? $"The store holds no TLS server identity for '{Listener}' that is switched on and valid now."
                                                                             : "The files hold no certificate yet.")
                                                         : LastError)
                   );

        }

        #endregion

        #region (override) ToString()

        public override String ToString()
        {

            var current = Source.IsStore ? FromTheStore() : files!.Current;

            return current is null
                       ? $"nothing yet from {Source}"
                       : $"{current.Certificate.Subject}, until {current.Certificate.NotAfter.ToUniversalTime():yyyy-MM-dd}, from " +
                         (Source.IsStore && StoreEntry is CertificateEntry entry
                              ? $"the store's '{entry.Label}'"
                              : Source.ToString());

        }

        #endregion


        #region (private) FromTheStore()

        /// <summary>
        /// The newest identity for the web interface that this machine can
        /// present, or null.
        /// </summary>
        private ServerCertificateChain? FromTheStore()
        {

            foreach (var entry in Candidates)
                if (Load(entry) is ServerCertificateChain chain)
                    return chain;

            return null;

        }

        #endregion

        #region (private) Load(Entry)

        /// <summary>
        /// The identity of an entry as a TLS server takes it, or null where it
        /// cannot be read - read once per certificate.
        /// </summary>
        private ServerCertificateChain? Load(CertificateEntry Entry)
        {

            lock (cacheLock)
                if (loaded.TryGetValue(Entry.Thumbprint, out var known))
                    return known;

            ServerCertificateChain? chain = null;

            try
            {
                var path  = store.FullPath(Entry);
                chain     = ServerCertificateChain.FromPkcs12(File.ReadAllBytes(path), null, path);
            }
            catch (Exception e)
            {
                log.Warning($"The TLS server identity '{Entry.Label}' cannot be shown on the web interface: {e.Message}", "web", "tls", "security");
            }

            lock (cacheLock)
                loaded[Entry.Thumbprint] = chain;

            return chain;

        }

        #endregion

        #region (private) SayWhatChanged(Current)

        /// <summary>
        /// Say so in the log when the web interface shows another certificate
        /// than at the handshake before - one renewed, one that became valid -
        /// or nothing any more.
        /// </summary>
        private void SayWhatChanged(ServerCertificateChain? Current)
        {

            var now = Current is not null
                          ? CertificateEntry.ThumbprintOf(Current.Certificate)
                          : null;

            String?  before;
            Boolean  saidNoneBefore;

            lock (cacheLock)
            {

                before          = shown;
                saidNoneBefore  = saidNone;

                if (now is not null)
                {
                    shown     = now;
                    saidNone  = false;
                }
                else
                    saidNone  = true;

            }

            if (now is not null && !String.Equals(before, now, StringComparison.Ordinal))
                log.Notice($"The web interface shows {Current!.Certificate.Subject} ({now}), valid until {Current.Certificate.NotAfter.ToUniversalTime():yyyy-MM-dd HH:mm} UTC, from {Source}.",
                           "web", "tls", "security");

            else if (now is null && !saidNoneBefore)
                log.Error($"The web interface has no certificate to show from {Source}: every connection to it is refused until there is one.",
                          "web", "tls", "security");

        }

        #endregion

    }

}
