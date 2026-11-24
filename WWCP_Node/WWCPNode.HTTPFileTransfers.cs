/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    #region HTTPFileServer

    /// <summary>
    /// A file server a node uploads to over HTTP or HTTPS: an entry of
    /// "httpFileServers" in its configuration file. A request chooses among
    /// these, and never introduces one - as it chooses among the SSH peers
    /// that are file servers for "sftp://".
    /// </summary>
    /// <remarks>
    /// <para>
    /// { "id": "logs", "url": "https://logs.example.com/upload/{id}/",
    ///   "user": "station-17", "password": "..." }
    /// </para>
    /// <para>
    /// The URL is the directory everything below it may be uploaded to:
    /// scheme, host and port as they are, and its path as a prefix - "{id}"
    /// standing for the identity of the node. Who signs in, and with which
    /// password, is said here - or by the request, whose URL may carry a
    /// login and a password, as OCPP's GetLog gives them: those go before
    /// these. Over http:// a password crosses the network in the clear, and
    /// the log says so at every upload. An https server is believed by the
    /// TLS roots the node keeps for its connections, and by the machine's.
    /// </para>
    /// </remarks>
    /// <param name="Id">The name of the file server, as whoever configured it called it.</param>
    /// <param name="URL">The directory uploads may go to, with everything below it.</param>
    /// <param name="User">The login of HTTP Basic authentication, or null for none.</param>
    /// <param name="Password">Its password.</param>
    public sealed record HTTPFileServer(String   Id,
                                        Uri      URL,
                                        String?  User      = null,
                                        String?  Password  = null)
    {

        #region Data

        /// <summary>
        /// The section of the configuration file.
        /// </summary>
        public const String  SectionName  = "httpFileServers";

        /// <summary>
        /// How many HTTP file servers a node may have.
        /// </summary>
        public const Int32   MaxServers   = 8;

        private static readonly Regex  id  = new ("^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$", RegexOptions.CultureInvariant);

        #endregion

        #region Properties

        /// <summary>
        /// "http" or "https".
        /// </summary>
        public String   Scheme
            => URL.Scheme.ToLowerInvariant();

        /// <summary>
        /// The host in the form two hosts are compared in; null where it is
        /// neither a DNS name nor an IP address.
        /// </summary>
        public String?  Host
            => SFTPLocation.NormalizeHost(URL.Host);

        /// <summary>
        /// Its port.
        /// </summary>
        public Int32    Port
            => URL.Port;

        /// <summary>
        /// Whether it is spoken to over TLS.
        /// </summary>
        public Boolean  IsSecure
            => Scheme == "https";

        /// <summary>
        /// Why this is no file server a node may hold, or null where it is one.
        /// </summary>
        public String? Problem
            => !id.IsMatch(Id)
                   ? $"'{Id}' is no name of a file server: letters, digits, '.', '_' and '-', at most 50 of them"
             : Scheme is not ("http" or "https")
                   ? $"'{Id}' is no http:// or https:// URL"
             : Host is null
                   ? $"the host of '{Id}' is neither a DNS name nor an IP address"
             : URL.UserInfo.Length > 0 || URL.Query.Length > 0 || URL.Fragment.Length > 0
                   ? $"the URL of '{Id}' carries a login, a query or a fragment: the login is \"user\" and \"password\""
             : (User is null) != (Password is null)
                   ? $"'{Id}' has a user without a password, or a password without a user"
             : null;

        #endregion


        #region AllowsDirectory(EscapedPath, Identity)

        /// <summary>
        /// Whether an upload may go to the given directory: it lies in the
        /// directory of the URL, or is it.
        /// </summary>
        /// <param name="EscapedPath">The path of the request, as <see cref="Uri.AbsolutePath"/> has it.</param>
        /// <param name="Identity">What "{id}" stands for.</param>
        public Boolean AllowsDirectory(String  EscapedPath,
                                       String  Identity)
        {

            var prefix  = URL.AbsolutePath.Replace(Uri.EscapeDataString(SSHFileTransfers.IdentityMark), Uri.EscapeDataString(Identity), StringComparison.Ordinal).
                                           Replace(SSHFileTransfers.IdentityMark,                        Uri.EscapeDataString(Identity), StringComparison.Ordinal);

            if (!prefix.EndsWith('/'))
                prefix += "/";

            var path    = EscapedPath.EndsWith('/') ? EscapedPath : EscapedPath + "/";

            return path.StartsWith(prefix, StringComparison.Ordinal);

        }

        #endregion

        #region (static) TryParse(JSON, Path, out Server, out Error)

        /// <summary>
        /// Read one entry of "httpFileServers".
        /// </summary>
        public static Boolean TryParse(JToken                                   JSON,
                                       String                                   Path,
                                       [NotNullWhen(true)]  out HTTPFileServer? Server,
                                       [NotNullWhen(false)] out String?         Error)
        {

            Server = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object: {{ \"id\", \"url\", \"user\", \"password\" }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadString(json, "id",       Path,   50, out var serverId, out Error) ||
                !ConfigurationReader.TryReadString(json, "url",      Path, 1024, out var url,      out Error) ||
                !ConfigurationReader.TryReadString(json, "user",     Path,  128, out var user,     out Error) ||
                !ConfigurationReader.TryReadString(json, "password", Path,  512, out var password, out Error))
            {
                return false;
            }

            if (serverId is null || url is null)
            {
                Error = $"'{Path}' needs an \"id\" and a \"url\".";
                return false;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                Error = $"'{Path}.url': '{url}' is no URL.";
                return false;
            }

            var server = new HTTPFileServer(serverId, uri, user, password);

            if (server.Problem is String problem)
            {
                Error = $"'{Path}': {problem}.";
                return false;
            }

            Server = server;
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The entry, with its password.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("id",   Id),
                           new JProperty("url",  URL.ToString())
                       );

            if (User     is not null) json.Add("user",     User);
            if (Password is not null) json.Add("password", Password);

            return json;

        }

        #endregion

        #region ToString()

        /// <summary>
        /// Its name and URL - never its password.
        /// </summary>
        public override String ToString()
            => $"'{Id}' ({URL})";

        #endregion

    }

    #endregion


    /// <summary>
    /// File transfers of a node over HTTP and HTTPS, on somebody's request: a
    /// file of the node uploaded with a PUT to a file server of its
    /// configuration - OCPP's GetLog and GetDiagnostics with an "http://" or
    /// "https://" URL.
    /// </summary>
    /// <remarks>
    /// The same rules as over SFTP (<see cref="JudgeFileTransfer"/>): a request
    /// chooses among the file servers the node holds and never introduces one,
    /// a refusal is an answer before anything is sent, and nothing is written
    /// over - the PUT says "If-None-Match: *", and a server that has the file
    /// answers 412. One difference, as OCPP's GetLog has it: the URL may carry
    /// the login and the password the node signs in with there, HTTP Basic,
    /// and they go before those of the configuration.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Events

        /// <summary>
        /// An HTTP file server showed a TLS certificate the node does not
        /// believe: the security event InvalidFileServerCertificate.
        /// </summary>
        public event Action<HTTPFileServer, String>?  OnHTTPFileServerCertificateRefused;

        #endregion

        #region HTTPFileServers

        /// <summary>
        /// The HTTP file servers of this node: "httpFileServers" of its
        /// configuration file, as it stands - read when a request is judged,
        /// so that a change of the file counts from the next request on. An
        /// entry that is wrong is left out, and the log says why.
        /// </summary>
        public IReadOnlyList<HTTPFileServer> HTTPFileServers
        {
            get
            {

                if (!ConfigFile.TryLoadDocument(out var document, out var error))
                {
                    Log.Warning($"The HTTP file servers could not be read: {error}", Kind.Tag, "http", "filetransfer");
                    return [];
                }

                if (document[HTTPFileServer.SectionName] is not JToken section || section.Type == JTokenType.Null)
                    return [];

                if (section is not JArray entries)
                {
                    Log.Warning($"'{HTTPFileServer.SectionName}' must be an array of file servers.", Kind.Tag, "http", "filetransfer");
                    return [];
                }

                var servers = new List<HTTPFileServer>();

                for (var i = 0; i < entries.Count && servers.Count < HTTPFileServer.MaxServers; i++)
                {

                    if (HTTPFileServer.TryParse(entries[i], $"{HTTPFileServer.SectionName}[{i}]", out var server, out var problem))
                    {
                        if (!servers.Any(known => String.Equals(known.Id, server.Id, StringComparison.OrdinalIgnoreCase)))
                            servers.Add(server);
                    }
                    else
                        Log.Warning($"An HTTP file server is left out: {problem}", Kind.Tag, "http", "filetransfer");

                }

                return servers;

            }
        }

        #endregion

        #region IsHTTPFileTransfer(URL)

        /// <summary>
        /// Whether the given URL is one of HTTP or HTTPS: one for
        /// <see cref="UploadFileOverHTTPAsync"/>.
        /// </summary>
        public static Boolean IsHTTPFileTransfer(String? URL)
        {
            var url = URL?.TrimStart() ?? "";
            return url.StartsWith("http://",  StringComparison.OrdinalIgnoreCase) ||
                   url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region JudgeHTTPFileTransfer(URL)

        /// <summary>
        /// What a request for an upload over HTTP comes to, decided without the
        /// network: InvalidURL for a URL that is none, or carries a login, a
        /// query or what leaves its directory; FileServerNotPermitted for one
        /// that lies in the directory of no HTTP file server of this node.
        /// </summary>
        /// <param name="URL">The directory the request names.</param>
        public FileTransferJudgement JudgeHTTPFileTransfer(String? URL)
        {

            var judgement = JudgeHTTP(URL);

            if (!judgement.IsAllowed)
            {

                Log.Warning($"A request for an upload to {Shown(URL)} is refused: {judgement.Why}.",
                            Kind.Tag, "http", "filetransfer", "security");

                if (judgement.Refusal == FileTransferRefusal.FileServerNotPermitted)
                    try { OnFileTransferRefused?.Invoke(judgement, FileTransferDirections.Upload); } catch (Exception) { }

            }

            return judgement;

        }

        /// <summary>
        /// A URL as a log may show it: without what is in front of its host.
        /// </summary>
        private static String Shown(String? URL)

            => Uri.TryCreate(URL?.Trim(), UriKind.Absolute, out var uri)
                   ? uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped)
                   : "a location that could not be read";

        private FileTransferJudgement JudgeHTTP(String? URL)
        {

            static FileTransferJudgement Invalid(String Why)
                => new (FileTransferRefusal.InvalidURL, Why);

            // 1. The URL.
            if (!Uri.TryCreate(URL?.Trim(), UriKind.Absolute, out var location) ||
                location.Scheme.ToLowerInvariant() is not ("http" or "https"))
            {
                return Invalid("it is no http:// or https:// URL");
            }

            // A login and a password the node is to sign in with there, as OCPP's
            // GetLog may give them: a login it is, or no URL.
            if (location.UserInfo.Length > 0 && CredentialsOf(location) is null)
                return Invalid("its login is empty, or has a control character in it");

            if (location.Query.Length > 0 || location.Fragment.Length > 0)
                return Invalid("it carries a query or a fragment");

            var path = location.AbsolutePath;

            if (path.Contains("%2f", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("%5c", StringComparison.OrdinalIgnoreCase) ||
                path.Contains('\\') ||
                Uri.UnescapeDataString(path).Split('/').Any(segment => segment is ".." or ".") ||
                Uri.UnescapeDataString(path).Any(character => character < 0x20 || character == 0x7f))
            {
                return Invalid("its path leaves its directory, or has a control character in it");
            }

            if (SFTPLocation.NormalizeHost(location.Host) is not String host)
                return Invalid("its host is neither a DNS name nor an IP address");

            // 2. A file server of that scheme, host and port, whose directory it lies in.
            //    Compared as text: a name is never resolved to compare it.
            var scheme  = location.Scheme.ToLowerInvariant();
            var servers = HTTPFileServers.Where(candidate => candidate.Scheme == scheme   &&
                                                             candidate.Host   == host     &&
                                                             candidate.Port   == location.Port).
                                          ToArray();

            if (servers.Length == 0)
                return new (FileTransferRefusal.FileServerNotPermitted, $"{scheme}://{host}:{location.Port} is no HTTP file server of this {Kind.Name}");

            if (servers.FirstOrDefault(candidate => candidate.AllowsDirectory(path, FileTransferIdentity)) is not HTTPFileServer server)
                return new (FileTransferRefusal.FileServerNotPermitted, $"'{path}' lies in no directory of the HTTP file server{(servers.Length == 1 ? $" '{servers[0].Id}'" : "s of its host")}");

            return new (FileTransferRefusal.None,
                        $"to the HTTP file server '{server.Id}'",
                        HTTPLocation:  location,
                        HTTPServer:    server);

        }

        /// <summary>
        /// The login and the password of the URL, unescaped; null where it
        /// carries none, or none that is one.
        /// </summary>
        private static (String User, String Password)? CredentialsOf(Uri Location)
        {

            if (Location.UserInfo.Length == 0)
                return null;

            var colon     = Location.UserInfo.IndexOf(':');
            var user      = Uri.UnescapeDataString(colon < 0 ? Location.UserInfo : Location.UserInfo[..colon]);
            var password  = colon < 0 ? "" : Uri.UnescapeDataString(Location.UserInfo[(colon + 1)..]);

            return user.Length == 0 || (user + password).Any(Char.IsControl)
                       ? null
                       : (user, password);

        }

        #endregion

        #region UploadFileOverHTTPAsync(URL, Content, FileName, ...)

        /// <summary>
        /// Upload a file to the directory an "http://" or "https://" URL names,
        /// with a PUT of the file under its name there: one attempt.
        /// </summary>
        /// <remarks>
        /// "If-None-Match: *": nothing is written over, a server that has the
        /// file answers 412. An attempt that failed is not taken up again: the
        /// next one starts anew.
        /// </remarks>
        /// <param name="URL">The directory.</param>
        /// <param name="Content">The file, read from its current position to its end.</param>
        /// <param name="FileName">The name it gets there.</param>
        /// <param name="Progress">Told the number of bytes sent so far.</param>
        public async Task<FileTransferResult> UploadFileOverHTTPAsync(String?            URL,
                                                                      Stream             Content,
                                                                      String             FileName,
                                                                      IProgress<Int64>?  Progress           = null,
                                                                      CancellationToken  CancellationToken  = default)
        {

            var judgement = JudgeHTTPFileTransfer(URL);

            if (!judgement.IsAllowed)
                return new (FileTransferOutcome.Refused, judgement.Why, judgement);

            if (!SFTPLocation.IsFileName(FileName))
                return new (FileTransferOutcome.Refused, $"'{FileName}' is no name of a file to upload", judgement);

            var server    = judgement.HTTPServer!;
            var directory = judgement.HTTPLocation!;
            // Without the login and password of the URL: they go in the Authorization.
            var target    = new Uri(directory.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped).TrimEnd('/') + "/" + Uri.EscapeDataString(FileName));
            var what      = target.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
            var sent      = 0L;
            String? certificateRefused = null;

            FileTransferResult Ended(FileTransferOutcome Outcome, String Why)
            {

                var said = $"The upload to {what} ({judgement.Why}) " +
                           (Outcome == FileTransferOutcome.Done
                                ? $"is done: {sent} bytes."
                                : $"ended as {Outcome}: {Why}");

                if (Outcome == FileTransferOutcome.Done)
                    Log.Info(said, Kind.Tag, "http", "filetransfer");
                else
                    Log.Warning(said, Kind.Tag, "http", "filetransfer");

                return new (Outcome, Why, judgement, sent, target.AbsolutePath);

            }

            // Without a byte moving for too long, a transfer counts as lost.
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            void StillAlive() { try { idle.CancelAfter(FileTransferIdleTimeout); } catch (ObjectDisposedException) { } }

            using var handler = NameResolution.HTTPHandler(dnsClient);

            handler.ConnectTimeout     = FileTransferConnectTimeout;
            handler.AllowAutoRedirect  = false;
            handler.UseCookies         = false;
            handler.PreAuthenticate    = false;

            // The roots this node keeps for its connections, and the machine's: as a
            // connection over wss:// believes its server. Nothing is learned here.
            handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => {

                using var shown = certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

                var judged = JudgeServer(ConnectionsCertificateUsage,
                                         directory.IdnHost,
                                         null,
                                         shown,
                                         chain,
                                         errors,
                                         Evidence:  false);

                if (!judged.Accepted)
                    certificateRefused = WhyRefused(judged);

                return judged.Accepted;

            };

            using var client  = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };

            try
            {

                var body    = new CountingStream(Content, count => { sent = count; StillAlive(); Progress?.Report(count); });
                var content = new StreamContent(body);

                content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

                if (Content.CanSeek)
                    content.Headers.ContentLength = Math.Max(0, Content.Length - Content.Position);

                using var request = new HttpRequestMessage(HttpMethod.Put, target) { Content = content };

                // The name is to be free: nothing is written over.
                request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("WWCP-Node", "1.0"));

                // The login of the URL, where it carries one, before that of the configuration.
                var credentials = CredentialsOf(directory) ??
                                  (server.User is String user && server.Password is String password
                                       ? (user, password)
                                       : null);

                if (credentials is (String login, String secret))
                {

                    request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{login}:{secret}")));

                    if (!server.IsSecure)
                        Log.Warning($"The upload to {what} signs in as '{login}' over http://: its password crosses the network in the clear.",
                                    Kind.Tag, "http", "filetransfer", "security");

                }

                StillAlive();

                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, idle.Token).ConfigureAwait(false);

                var status = (Int32) response.StatusCode;
                var said   = $"HTTP {status} {response.ReasonPhrase}";

                return status switch {
                           >= 200 and < 300                => Ended(FileTransferOutcome.Done,              ""),
                           412                             => Ended(FileTransferOutcome.FileExists,        $"{said}: '{target.AbsolutePath}' is there already, and nothing is written over."),
                           401                             => Ended(FileTransferOutcome.LoginRefused,      $"{said}: the server did not take the login{(server.User is null ? ", as there is none" : $" '{server.User}'")}."),
                           403                             => Ended(FileTransferOutcome.PermissionDenied,  said),
                           404                             => Ended(FileTransferOutcome.NoSuchFile,        said),
                           405 or 501                      => Ended(FileTransferOutcome.MethodNotAllowed,  $"{said}: the server takes no PUT there."),
                           413                             => Ended(FileTransferOutcome.TooLarge,          said),
                           408 or 429 or >= 500            => Ended(FileTransferOutcome.Failed,            said),
                           _                               => Ended(FileTransferOutcome.RejectedByServer,  said)
                       };

            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                return Ended(FileTransferOutcome.Cancelled, "it was cancelled.");
            }
            catch (OperationCanceledException)
            {
                return Ended(FileTransferOutcome.Unreachable, $"no byte moved for {FileTransferIdleTimeout.TotalSeconds:0} seconds.");
            }
            catch (HttpRequestException problem) when (certificateRefused is not null || problem.InnerException is AuthenticationException)
            {

                var why = certificateRefused ?? problem.InnerException?.Message ?? problem.Message;

                Log.Metrological(LogLevel.Warning,
                                 $"The HTTP file server '{server.Id}' ({server.URL.GetLeftPart(UriPartial.Authority)}) showed a TLS certificate this {Kind.Name} does not believe: {why} " +
                                 "Nothing was sent to it, and it is not asked again for this request.",
                                 Kind.Tag, "http", "filetransfer", "security");

                try { OnHTTPFileServerCertificateRefused?.Invoke(server, why); } catch (Exception) { }

                return Ended(FileTransferOutcome.CertificateRefused, why);

            }
            catch (Exception problem) when (problem is HttpRequestException or SocketException or IOException or TimeoutException)
            {
                return Ended(FileTransferOutcome.Unreachable, $"{problem.GetType().Name}: {problem.Message}");
            }

        }

        #endregion

        #region (private) CountingStream

        /// <summary>
        /// A stream that reads another one, from its position to its end, and
        /// says how many bytes were read - and leaves it open: it is its
        /// owner's to read again or dispose.
        /// </summary>
        private sealed class CountingStream(Stream Inner, Action<Int64> Counted) : Stream
        {

            private Int64 count;

            public override Boolean  CanRead   => true;
            public override Boolean  CanSeek   => false;
            public override Boolean  CanWrite  => false;
            public override Int64    Length    => throw new NotSupportedException();
            public override Int64    Position  { get => count; set => throw new NotSupportedException(); }

            public override Int32 Read(Byte[] Buffer, Int32 Offset, Int32 Count)
                => Told(Inner.Read(Buffer, Offset, Count));

            public override async ValueTask<Int32> ReadAsync(Memory<Byte> Buffer, CancellationToken CancellationToken = default)
                => Told(await Inner.ReadAsync(Buffer, CancellationToken).ConfigureAwait(false));

            public override Task<Int32> ReadAsync(Byte[] Buffer, Int32 Offset, Int32 Count, CancellationToken CancellationToken)
                => ReadAsync(Buffer.AsMemory(Offset, Count), CancellationToken).AsTask();

            private Int32 Told(Int32 Read)
            {
                if (Read > 0)
                {
                    count += Read;
                    Counted(count);
                }
                return Read;
            }

            public override void   Flush()                                         { }
            public override Int64  Seek    (Int64 Offset, SeekOrigin Origin)        => throw new NotSupportedException();
            public override void   SetLength(Int64 Value)                          => throw new NotSupportedException();
            public override void   Write   (Byte[] Buffer, Int32 Offset, Int32 Count) => throw new NotSupportedException();

        }

        #endregion

    }

}
