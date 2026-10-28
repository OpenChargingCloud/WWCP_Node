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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// Where the certificate the web interface shows comes from: the node's
    /// certificate store, or a pair of PEM files somebody else keeps up to
    /// date - certbot's fullchain.pem and privkey.pem, say.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The store is what a node has for everything it presents, and what its
    /// certificate pages manage: the TLS server identity for the listener
    /// "web" - or one told no listener, which is for every listener - valid
    /// now, switched on, and the newest of them, asked at every handshake. A
    /// certificate put in before the old one runs out takes over on the day it
    /// becomes valid.
    /// </para>
    /// <para>
    /// The files are what a machine that already renews its certificates has:
    /// read again whenever their content changes, looked at no more often than
    /// every few seconds, and the certificate before kept where the new one
    /// does not read - half of a renewal, the certificate copied and the key
    /// not yet, is not a reason to show nothing.
    /// </para>
    /// </remarks>
    /// <param name="FullChain">The PEM file with the certificate and its intermediates; null for the store.</param>
    /// <param name="PrivateKey">The PEM file with its private key; null where the key is in the first file.</param>
    public sealed record WebCertificateSource(String?  FullChain   = null,
                                              String?  PrivateKey  = null)
    {

        #region Properties

        /// <summary>
        /// The node's certificate store.
        /// </summary>
        public static WebCertificateSource Store { get; } = new ();

        /// <summary>
        /// Whether the certificate comes from the node's certificate store.
        /// </summary>
        public Boolean IsStore
            => FullChain is null;

        #endregion


        #region Beside(ConfigurationFile)

        /// <summary>
        /// The files as the node reads them: a relative path measured from the
        /// configuration file that names it, as the certificate store's own
        /// directory is, and not from wherever the process was started.
        /// </summary>
        /// <param name="ConfigurationFile">The configuration file.</param>
        public WebCertificateSource Beside(String ConfigurationFile)
        {

            if (IsStore)
                return this;

            var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(ConfigurationFile)) ?? "";

            return new (System.IO.Path.GetFullPath(FullChain!, directory),
                        PrivateKey is not null
                            ? System.IO.Path.GetFullPath(PrivateKey, directory)
                            : null);

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The source as the file writes it: "store", or the two files.
        /// </summary>
        public JToken ToJSON()

            => IsStore
                   ? WebTLSConfiguration.StoreText
                   : PrivateKey is not null
                         ? new JObject(
                               new JProperty("fullchain",   FullChain),
                               new JProperty("privateKey",  PrivateKey)
                           )
                         : new JObject(
                               new JProperty("fullchain",   FullChain)
                           );

        #endregion

        #region (override) ToString()

        public override String ToString()

            => IsStore
                   ? "the certificate store"
                   : PrivateKey is not null
                         ? $"{FullChain} and {PrivateKey}"
                         : FullChain!;

        #endregion

    }


    /// <summary>
    /// The "tls" of the "web" section: the web interface, its JSON API and its
    /// sign-in served over TLS by the node itself, with which certificate, and
    /// whether a port of plain HTTP beside it sends browsers there.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The other way to have HTTPS is a reverse proxy in front of the node that
    /// does it - nginx, as every one of these programs has been run so far -
    /// and then the node is told who that proxy is in "trustedProxies" instead,
    /// and this is left out. Both may be said: a proxy may speak HTTPS to the
    /// node as well.
    /// </para>
    /// <para>
    /// The port is the web interface's own, which then speaks HTTPS only: one
    /// port, one protocol. The redirect is a second port, of plain HTTP, that
    /// answers every request with a permanent redirect to the same path over
    /// HTTPS and with nothing else - no page, no API, no sign-in; switched off
    /// unless a port is given.
    /// </para>
    /// </remarks>
    /// <param name="Certificate">Where the certificate comes from; the certificate store where absent.</param>
    /// <param name="RedirectPort">The port of plain HTTP that redirects to HTTPS; none where absent.</param>
    public sealed record WebTLSConfiguration(WebCertificateSource?  Certificate   = null,
                                             IPPort?                RedirectPort  = null)
    {

        #region Data

        /// <summary>
        /// The name of this part of the "web" section.
        /// </summary>
        public const String  Name           = "tls";

        /// <summary>
        /// What says "the certificate store" in the file.
        /// </summary>
        public const String  StoreText      = "store";

        /// <summary>
        /// The longest a path may be written.
        /// </summary>
        public const Int32   MaxPathLength  = 4096;

        #endregion


        #region (static) TryParse(JSON, Path, out Configuration, out Error)

        /// <summary>
        /// The "tls" of the "web" section, or the one sentence that says what is
        /// wrong with it.
        /// </summary>
        /// <remarks>
        /// Nothing but what is read may be said in it: a key spelt wrongly is a
        /// setting that does not happen, and this one decides whether passwords
        /// cross the network in the clear.
        /// </remarks>
        /// <param name="JSON">The "tls" object.</param>
        /// <param name="Path">Where it is in the document: "web.tls".</param>
        /// <param name="Configuration">What it says.</param>
        /// <param name="Error">What is wrong with it.</param>
        public static Boolean TryParse(JObject                                       JSON,
                                       String                                        Path,
                                       [NotNullWhen(true)]  out WebTLSConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?               Error)
        {

            Configuration = null;

            if (!OnlyThese(JSON, Path, [ "certificate", "redirectPort" ], out Error) ||
                !ConfigurationReader.TryReadPort(JSON, "redirectPort", Path, out var redirectPort, out Error))
                return false;

            WebCertificateSource? certificate = null;

            switch (JSON["certificate"])
            {

                case null:
                case { Type: JTokenType.Null }:
                    break;

                case JValue { Type: JTokenType.String } text:

                    if (!String.Equals(text.Value<String>()?.Trim(), StoreText, StringComparison.OrdinalIgnoreCase))
                    {
                        Error = $"'{Path}.certificate' is '{text.Value<String>()}', and may be \"{StoreText}\" or {{ \"fullchain\": \"<file>\", \"privateKey\": \"<file>\" }}.";
                        return false;
                    }

                    certificate = WebCertificateSource.Store;
                    break;

                case JObject files:

                    if (!OnlyThese(files, $"{Path}.certificate", [ "fullchain", "privateKey" ], out Error) ||
                        !ConfigurationReader.TryReadString(files, "fullchain",   $"{Path}.certificate", MaxPathLength, out var fullChain,  out Error) ||
                        !ConfigurationReader.TryReadString(files, "privateKey",  $"{Path}.certificate", MaxPathLength, out var privateKey, out Error))
                        return false;

                    if (fullChain is null)
                    {
                        Error = $"'{Path}.certificate.fullchain' is missing: the PEM file with the certificate and its intermediates - certbot's fullchain.pem.";
                        return false;
                    }

                    certificate = new WebCertificateSource(fullChain, privateKey);
                    break;

                default:
                    Error = $"'{Path}.certificate' may be \"{StoreText}\" or {{ \"fullchain\": \"<file>\", \"privateKey\": \"<file>\" }}.";
                    return false;

            }

            Configuration = new WebTLSConfiguration(certificate, redirectPort);

            return true;

        }

        #endregion

        #region (internal static) OnlyThese(JSON, Path, Names, out Error)

        /// <summary>
        /// Whether the object says nothing but the given fields - or the one
        /// sentence that names the first it says beside them.
        /// </summary>
        internal static Boolean OnlyThese(JObject                           JSON,
                                          String                            Path,
                                          IReadOnlyList<String>             Names,
                                          [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            foreach (var property in JSON.Properties())
                if (!Names.Contains(property.Name, StringComparer.Ordinal))
                {
                    Error = $"'{Path}' says '{property.Name}', and may say nothing but '{String.Join("', '", Names)}'.";
                    return false;
                }

            return true;

        }

        #endregion

        #region Over(Below)

        /// <summary>
        /// This, where it says something, and what the given one says where it
        /// does not: a switch on the command line over the file.
        /// </summary>
        /// <param name="Below">What the configuration file says, or null.</param>
        public WebTLSConfiguration Over(WebTLSConfiguration? Below)

            => new (Certificate   ?? Below?.Certificate,
                    RedirectPort  ?? Below?.RedirectPort);

        #endregion

        #region ToJSON()

        /// <summary>
        /// The "tls" as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (Certificate  is not null)  json.Add("certificate",   Certificate.ToJSON());
            if (RedirectPort is not null)  json.Add("redirectPort",  RedirectPort.Value.ToUInt16());

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"HTTPS with a certificate from {(Certificate ?? WebCertificateSource.Store)}" +
               (RedirectPort is not null ? $", redirected to from port {RedirectPort}" : "");

        #endregion

    }

}
