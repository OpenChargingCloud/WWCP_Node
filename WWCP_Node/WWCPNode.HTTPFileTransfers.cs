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
    /// A file server a node uploads to, or downloads from, over HTTP or HTTPS:
    /// an entry of "httpFileServers" in its configuration file. A request
    /// chooses among these, and never introduces one - as it chooses among the
    /// SSH peers that are file servers for "sftp://".
    /// </summary>
    /// <remarks>
    /// <para>
    /// { "id": "logs", "url": "https://logs.example.com/upload/{id}/",
    ///   "directions": [ "upload" ], "user": "station-17", "password": "..." }
    /// </para>
    /// <para>
    /// The URL is the directory everything below it may be uploaded to, or
    /// downloaded from: scheme, host and port as they are, and its path as a
    /// prefix - "{id}" standing for the identity of the node. "directions"
    /// says which way, "upload", "download" or both - both where it says
    /// nothing. Who signs in, and with which password, is said here - or by
    /// the request, whose URL may carry a login and a password, as OCPP's
    /// GetLog and UpdateFirmware give them: those go before these. Over
    /// http:// a password crosses the network in the clear, and the log says
    /// so at every transfer. An https server is believed by the TLS roots the
    /// node keeps for its connections, and by the machine's.
    /// </para>
    /// </remarks>
    /// <param name="Id">The name of the file server, as whoever configured it called it.</param>
    /// <param name="URL">The directory files may go to or come from, with everything below it.</param>
    /// <param name="User">The login of HTTP Basic authentication, or null for none.</param>
    /// <param name="Password">Its password.</param>
    /// <param name="Directions">The ways it may be used; both where none is given.</param>
    public sealed record HTTPFileServer(String                   Id,
                                        Uri                      URL,
                                        String?                  User        = null,
                                        String?                  Password    = null,
                                        FileTransferDirections?  Directions  = null)
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
        /// The ways it may be used.
        /// </summary>
        public FileTransferDirections Ways
            => Directions ?? (FileTransferDirections.Upload | FileTransferDirections.Download);

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
             : Ways == FileTransferDirections.None
                   ? $"'{Id}' may be used in no direction"
             : null;

        #endregion


        #region Allows(Direction) / AllowsPath(Direction, EscapedPath, Identity)

        /// <summary>
        /// Whether it may be used in the given direction.
        /// </summary>
        public Boolean Allows(FileTransferDirections Direction)
            => Direction != FileTransferDirections.None && (Ways & Direction) == Direction;

        /// <summary>
        /// Whether a file may go to, or come from, the given path: it lies in
        /// the directory of the URL.
        /// </summary>
        /// <param name="Direction">Upload: the path is the directory, which may be that of the URL. Download: the path is the file, below it.</param>
        /// <param name="EscapedPath">The path of the request, as <see cref="Uri.AbsolutePath"/> has it.</param>
        /// <param name="Identity">What "{id}" stands for.</param>
        public Boolean AllowsPath(FileTransferDirections  Direction,
                                  String                  EscapedPath,
                                  String                  Identity)
        {

            var prefix  = URL.AbsolutePath.Replace(Uri.EscapeDataString(SSHFileTransfers.IdentityMark), Uri.EscapeDataString(Identity), StringComparison.Ordinal).
                                           Replace(SSHFileTransfers.IdentityMark,                        Uri.EscapeDataString(Identity), StringComparison.Ordinal);

            if (!prefix.EndsWith('/'))
                prefix += "/";

            if (Direction == FileTransferDirections.Download)
                return EscapedPath.Length > prefix.Length &&
                       EscapedPath.StartsWith(prefix, StringComparison.Ordinal) &&
                       !EscapedPath.EndsWith('/');

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
                Error = $"'{Path}' must be an object: {{ \"id\", \"url\", \"directions\", \"user\", \"password\" }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadString (json, "id",         Path,   50,      out var serverId,        out Error) ||
                !ConfigurationReader.TryReadString (json, "url",        Path, 1024,      out var url,             out Error) ||
                !ConfigurationReader.TryReadStrings(json, "directions", Path,    2,  16, out var directionTexts,  out Error) ||
                !ConfigurationReader.TryReadString (json, "user",       Path,  128,      out var user,            out Error) ||
                !ConfigurationReader.TryReadString (json, "password",   Path,  512,      out var password,        out Error))
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

            FileTransferDirections? directions = null;

            if (directionTexts is not null)
            {

                directions = FileTransferDirections.None;

                foreach (var text in directionTexts)
                {
                    switch (text.Trim().ToLowerInvariant())
                    {
                        case "upload":    directions |= FileTransferDirections.Upload;    break;
                        case "download":  directions |= FileTransferDirections.Download;  break;
                        default:
                            Error = $"'{Path}.directions': '{text}' is neither \"upload\" nor \"download\".";
                            return false;
                    }
                }

            }

            var server = new HTTPFileServer(serverId, uri, user, password, directions);

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

            if (Directions is not null)
            {

                var directions = new JArray();

                if (Allows(FileTransferDirections.Upload))    directions.Add("upload");
                if (Allows(FileTransferDirections.Download))  directions.Add("download");

                json.Add("directions", directions);

            }

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
    /// "https://" URL -, and a file downloaded with a GET from one - OCPP's
    /// UpdateFirmware.
    /// </summary>
    /// <remarks>
    /// The same rules as over SFTP (<see cref="JudgeFileTransfer"/>): a request
    /// chooses among the file servers the node holds and never introduces one,
    /// a refusal is an answer before anything is sent, nothing is written over
    /// - the PUT says "If-None-Match: *", and a server that has the file
    /// answers 412 -, and a download takes up where the attempt before stopped,
    /// with a Range. A redirect is not followed: it would lead to a server the
    /// configuration does not name. One difference, as OCPP has it: the URL may
    /// carry the login and the password the node signs in with there, HTTP
    /// Basic, and they go before those of the configuration.
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
        /// <see cref="UploadFileOverHTTPAsync"/> and <see cref="DownloadFileOverHTTPAsync"/>.
        /// </summary>
        public static Boolean IsHTTPFileTransfer(String? URL)
        {
            var url = URL?.TrimStart() ?? "";
            return url.StartsWith("http://",  StringComparison.OrdinalIgnoreCase) ||
                   url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region JudgeHTTPFileTransfer(URL, Direction = Upload)

        /// <summary>
        /// What a request for a transfer over HTTP comes to, decided without
        /// the network: InvalidURL for a URL that is none, carries a query or
        /// what leaves its directory, or - for a download - names no file;
        /// FileServerNotPermitted for one that lies in the directory of no HTTP
        /// file server of this node that may be used this way.
        /// </summary>
        /// <param name="URL">Upload: the directory the request names. Download: the file.</param>
        /// <param name="Direction">Which way.</param>
        public FileTransferJudgement JudgeHTTPFileTransfer(String?                 URL,
                                                           FileTransferDirections  Direction   = FileTransferDirections.Upload)

            => JudgeHTTPFileTransfer(URL, Direction, Redirected: false);

        /// <summary>
        /// The same for a URL a request named, or - where Redirected - one an
        /// HTTP file server sent a download on to: that may carry a query, as
        /// the signed URL of a content delivery network does, and must lie in
        /// the directory of an HTTP file server of this node that may be used
        /// for downloads as much as a URL of a request.
        /// </summary>
        private FileTransferJudgement JudgeHTTPFileTransfer(String?                 URL,
                                                            FileTransferDirections  Direction,
                                                            Boolean                 Redirected)
        {

            var judgement = JudgeHTTP(URL, Direction, AllowQuery: Redirected);

            if (!judgement.IsAllowed)
            {

                Log.Warning($"{(Redirected ? "A redirect" : "A request")} for {(Direction == FileTransferDirections.Download ? "a download from" : "an upload to")} {Shown(URL)} is refused: {judgement.Why}.",
                            Kind.Tag, "http", "filetransfer", "security");

                if (judgement.Refusal == FileTransferRefusal.FileServerNotPermitted)
                    try { OnFileTransferRefused?.Invoke(judgement, Direction); } catch (Exception) { }

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

        private FileTransferJudgement JudgeHTTP(String?                 URL,
                                                FileTransferDirections  Direction,
                                                Boolean                 AllowQuery  = false)
        {

            static FileTransferJudgement Invalid(String Why)
                => new (FileTransferRefusal.InvalidURL, Why);

            if (Direction is not (FileTransferDirections.Upload or FileTransferDirections.Download))
                return Invalid("a transfer goes in one direction");

            // 1. The URL.
            if (!Uri.TryCreate(URL?.Trim(), UriKind.Absolute, out var location) ||
                location.Scheme.ToLowerInvariant() is not ("http" or "https"))
            {
                return Invalid("it is no http:// or https:// URL");
            }

            // A login and a password the node is to sign in with there, as OCPP
            // may give them: a login it is, or no URL.
            if (location.UserInfo.Length > 0 && CredentialsOf(location) is null)
                return Invalid("its login is empty, or has a control character in it");

            if ((location.Query.Length > 0 && !AllowQuery) || location.Fragment.Length > 0)
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

            // A download names a file.
            if (Direction == FileTransferDirections.Download && !SFTPLocation.IsFileName(FileNameOf(location)))
                return Invalid("it names no file");

            if (SFTPLocation.NormalizeHost(location.Host) is not String host)
                return Invalid("its host is neither a DNS name nor an IP address");

            // 2. A file server of that scheme, host and port, that may be used this way,
            //    whose directory it lies in. Compared as text: a name is never resolved
            //    to compare it.
            var scheme  = location.Scheme.ToLowerInvariant();
            var way     = Direction == FileTransferDirections.Download ? "downloads" : "uploads";
            var servers = HTTPFileServers.Where(candidate => candidate.Scheme == scheme   &&
                                                             candidate.Host   == host     &&
                                                             candidate.Port   == location.Port).
                                          ToArray();

            if (servers.Length == 0)
                return new (FileTransferRefusal.FileServerNotPermitted, $"{scheme}://{host}:{location.Port} is no HTTP file server of this {Kind.Name}");

            var ofThisWay = servers.Where(candidate => candidate.Allows(Direction)).ToArray();

            if (ofThisWay.Length == 0)
                return new (FileTransferRefusal.FileServerNotPermitted, $"the HTTP file server{(servers.Length == 1 ? $" '{servers[0].Id}' is" : "s of its host are")} not allowed {way}");

            if (ofThisWay.FirstOrDefault(candidate => candidate.AllowsPath(Direction, path, FileTransferIdentity)) is not HTTPFileServer server)
                return new (FileTransferRefusal.FileServerNotPermitted, $"'{path}' lies in no directory the HTTP file server{(ofThisWay.Length == 1 ? $" '{ofThisWay[0].Id}' is" : "s of its host are")} allowed {way} {(Direction == FileTransferDirections.Download ? "from" : "to")}");

            return new (FileTransferRefusal.None,
                        $"{(Direction == FileTransferDirections.Download ? "from" : "to")} the HTTP file server '{server.Id}'",
                        HTTPLocation:  location,
                        HTTPServer:    server);

        }

        /// <summary>
        /// The name of the file the URL names: its last segment, unescaped.
        /// </summary>
        public static String FileNameOf(Uri Location)
            => Uri.UnescapeDataString(Location.AbsolutePath[(Location.AbsolutePath.LastIndexOf('/') + 1)..]);

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

            var judgement = JudgeHTTPFileTransfer(URL, FileTransferDirections.Upload);

            if (!judgement.IsAllowed)
                return new (FileTransferOutcome.Refused, judgement.Why, judgement);

            if (!SFTPLocation.IsFileName(FileName))
                return new (FileTransferOutcome.Refused, $"'{FileName}' is no name of a file to upload", judgement);

            // Without the login and password of the URL: they go in the Authorization.
            var directory = judgement.HTTPLocation!;
            var target    = new Uri(directory.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped).TrimEnd('/') + "/" + Uri.EscapeDataString(FileName));
            var sent      = 0L;

            return await TransferOverHTTP(
                             judgement,
                             FileTransferDirections.Upload,
                             target,
                             () => sent,
                             async (client, stillAlive, redirected, cancellationToken) => {

                                 var body    = new CountingStream(Content, count => { sent = count; stillAlive(); Progress?.Report(count); });
                                 var content = new StreamContent(body);

                                 content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

                                 if (Content.CanSeek)
                                     content.Headers.ContentLength = Math.Max(0, Content.Length - Content.Position);

                                 using var request = new HttpRequestMessage(HttpMethod.Put, target) { Content = content };

                                 // The name is to be free: nothing is written over.
                                 request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);

                                 SignIn(request, judgement);

                                 using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

                                 var status = (Int32) response.StatusCode;

                                 return status is >= 200 and < 300
                                            ? (FileTransferOutcome.Done, "")
                                            : status == 412
                                                  ? (FileTransferOutcome.FileExists, $"{Said(response)}: '{target.AbsolutePath}' is there already, and nothing is written over.")
                                                  : Failed(response, judgement);

                             },
                             CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion

        #region DownloadFileOverHTTPAsync(URL, Destination, Offset, MaxSize, ...)

        /// <summary>
        /// Download the file an "http://" or "https://" URL names into a
        /// stream, with a GET: one attempt, which takes up where the one before
        /// stopped.
        /// </summary>
        /// <remarks>
        /// <para>
        /// From an offset on, the GET asks for the rest with a Range - and,
        /// where the attempt before learned what the file was (its strong
        /// entity tag, or else the time it was last written), with an
        /// If-Range, so that a server whose file changed meanwhile sends the
        /// new one whole rather than the rest of it. A server that answers with
        /// the whole file - 200 - sends the same file where it says the same
        /// validator, and is read from the offset on, what came before being
        /// passed over; where it says another, or none while the attempt
        /// before had one, the file changed: what the attempt before brought is
        /// cut away from the destination, and the new file read from its first
        /// byte - or, where the destination cannot be cut back, Changed, for
        /// the caller to start anew. A 416 that says the file is as long as the
        /// offset: there was nothing left to fetch.
        /// </para>
        /// <para>
        /// A redirect - 301, 302, 303, 307, 308 - is followed where it leads to
        /// a file an HTTP file server of the configuration may serve for
        /// downloads, and nowhere else: not from https to http, not more than
        /// <see cref="MaxHTTPRedirects"/> times. Its URL may carry a query, as
        /// the signed URL of a content delivery network does. The login of the
        /// request's URL goes along only to the server the request named; any
        /// other server is signed in to as the configuration says of it.
        /// </para>
        /// <para>
        /// The server says who it is, not what the file is: whether a firmware
        /// image is genuine and may be installed is decided after the download,
        /// by its signature, in the logic above.
        /// </para>
        /// </remarks>
        /// <param name="URL">The file.</param>
        /// <param name="Destination">Where its bytes go, in order: from its current position on, the bytes the attempt before brought just in front of it.</param>
        /// <param name="Offset">The first byte to read: what an attempt before brought already.</param>
        /// <param name="MaxSize">The most the whole file may have; a larger one is refused before a byte of it is written, where the server says its size.</param>
        /// <param name="Validator">What the attempt before learned the file was (<see cref="FileTransferResult.Validator"/>), to be sure the rest is of the same file; null where it learned nothing.</param>
        /// <param name="Progress">Told the position in the remote file reached so far.</param>
        public async Task<FileTransferResult> DownloadFileOverHTTPAsync(String?            URL,
                                                                        Stream             Destination,
                                                                        Int64              Offset             = 0,
                                                                        Int64?             MaxSize            = null,
                                                                        String?            Validator          = null,
                                                                        IProgress<Int64>?  Progress           = null,
                                                                        CancellationToken  CancellationToken  = default)
        {

            var judgement = JudgeHTTPFileTransfer(URL, FileTransferDirections.Download);

            if (!judgement.IsAllowed)
                return new (FileTransferOutcome.Refused, judgement.Why, judgement);

            var origin     = judgement.HTTPLocation!;
            var target     = new Uri(origin.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped));
            var written    = 0L;
            String? learned = null;

            var result = await TransferOverHTTP(
                             judgement,
                             FileTransferDirections.Download,
                             target,
                             () => written,
                             async (client, stillAlive, redirected, cancellationToken) => {

                                 var hop       = judgement;
                                 var location  = target;

                                 for (var redirects = 0; ; redirects++)
                                 {

                                     using var request = new HttpRequestMessage(HttpMethod.Get, location);

                                     if (Offset > 0)
                                     {

                                         request.Headers.Range = new RangeHeaderValue(Offset, null);

                                         // Only the rest of the same file, or else the new file whole.
                                         if (Validator is not null)
                                             request.Headers.TryAddWithoutValidation("If-Range", Validator);

                                     }

                                     // The login of the request's URL goes along to its own server only.
                                     SignIn(request, hop, SameServer(location, origin) ? CredentialsOf(origin) : null);

                                     using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

                                     var status = (Int32) response.StatusCode;

                                     #region A redirect

                                     if (status is 301 or 302 or 303 or 307 or 308)
                                     {

                                         if (response.Headers.Location is not Uri sentTo)
                                             return (FileTransferOutcome.RejectedByServer, $"{Said(response)}: a redirect to nowhere.");

                                         var next = sentTo.IsAbsoluteUri ? sentTo : new Uri(location, sentTo);

                                         if (redirects >= MaxHTTPRedirects)
                                             return (FileTransferOutcome.RejectedByServer, $"{Said(response)}: a redirect, to {Shown(next.ToString())}, after {MaxHTTPRedirects} already - it is not followed.");

                                         if (location.Scheme == Uri.UriSchemeHttps && next.Scheme != Uri.UriSchemeHttps)
                                             return (FileTransferOutcome.RejectedByServer, $"{Said(response)}: a redirect from https:// to {Shown(next.ToString())} is not followed - the file would come over a connection nobody vouches for.");

                                         var judged = JudgeHTTPFileTransfer(next.ToString(), FileTransferDirections.Download, Redirected: true);

                                         if (!judged.IsAllowed)
                                             return (FileTransferOutcome.RejectedByServer, $"{Said(response)}: a redirect, to {Shown(next.ToString())}, is not followed - {judged.Why}.");

                                         Log.Info($"The download from {Shown(location.ToString())} is sent on to {Shown(next.ToString())}, {judged.Why}.",
                                                  Kind.Tag, "http", "filetransfer");

                                         hop       = judged;
                                         location  = new Uri(judged.HTTPLocation!.GetComponents(UriComponents.HttpRequestUrl, UriFormat.UriEscaped));

                                         redirected(hop);

                                         continue;

                                     }

                                     #endregion

                                     var range  = response.Content.Headers.ContentRange;
                                     var shown  = ValidatorOf(response);

                                     // Nothing was left to fetch.
                                     if (status == 416 && Offset > 0 && range?.Length == Offset)
                                     {
                                         learned = Validator;
                                         return (FileTransferOutcome.Done, "");
                                     }

                                     if (status is not (200 or 206))
                                         return Failed(response, hop);

                                     learned = shown;

                                     Int64? total;
                                     var    skip      = 0L;
                                     var    position  = Offset;

                                     if (status == 206)
                                     {

                                         if (range?.From != Offset)
                                             return (FileTransferOutcome.RejectedByServer, $"{Said(response)}: the server sent the file from byte {range?.From}, and not from {Offset}.");

                                         total = range.Length ?? (response.Content.Headers.ContentLength is Int64 length ? Offset + length : null);

                                     }

                                     else if (Offset > 0 && Validator is not null && shown != Validator)
                                     {

                                         // Another file than the one the attempt before brought the
                                         // beginning of: that beginning is cut away, and this one read
                                         // from its first byte.
                                         if (!Destination.CanSeek)
                                             return (FileTransferOutcome.Changed, $"{Said(response)}: the file changed since the attempt before ({Validator}, now {shown ?? "unknown"}), and what it brought is no part of it.");

                                         var start = Destination.Position - Offset;

                                         Destination.SetLength(start);
                                         Destination.Position = start;

                                         Log.Info($"The file at {Shown(location.ToString())} changed since the attempt before ({Validator}, now {shown ?? "unknown"}): it is fetched anew from its first byte.",
                                                  Kind.Tag, "http", "filetransfer");

                                         total     = response.Content.Headers.ContentLength;
                                         position  = 0;

                                     }

                                     else
                                     {
                                         // The whole file, the same one: what an attempt before brought is passed over.
                                         total = response.Content.Headers.ContentLength;
                                         skip  = Offset;
                                     }

                                     if (MaxSize is Int64 max && total > max)
                                         return (FileTransferOutcome.TooLarge, $"the file has {total} bytes, and at most {max} are taken.");

                                     return await Read(response, total, skip, position, stillAlive, cancellationToken).ConfigureAwait(false);

                                 }

                             },
                             CancellationToken
                         ).ConfigureAwait(false);

            return result with { Validator = learned };


            // The body of an answer into the destination: what is to be passed
            // over first, then every byte up to the end, or to the most taken.
            async Task<(FileTransferOutcome, String)> Read(HttpResponseMessage  Response,
                                                           Int64?               Total,
                                                           Int64                Skip,
                                                           Int64                Position,
                                                           Action               StillAlive,
                                                           CancellationToken    Cancel)
            {

                await using var body = await Response.Content.ReadAsStreamAsync(Cancel).ConfigureAwait(false);

                var buffer    = new Byte[64 * 1024];
                var skip      = Skip;
                var position  = Position;

                while (true)
                {

                    var read = await body.ReadAsync(buffer, Cancel).ConfigureAwait(false);

                    if (read == 0)
                        break;

                    StillAlive();

                    var from = 0;

                    if (skip > 0)
                    {
                        from  = (Int32) Math.Min(skip, read);
                        skip -= from;
                    }

                    if (from == read)
                        continue;

                    if (MaxSize is Int64 most && position + (read - from) > most)
                        return (FileTransferOutcome.TooLarge, $"the file has more than the {most} bytes that are taken.");

                    await Destination.WriteAsync(buffer.AsMemory(from, read - from), Cancel).ConfigureAwait(false);

                    written  += read - from;
                    position += read - from;

                    Progress?.Report(position);

                }

                await Destination.FlushAsync(Cancel).ConfigureAwait(false);

                if (skip > 0 || (Total is Int64 expected && position != expected))
                    return (FileTransferOutcome.Unreachable, $"the connection ended at byte {position}{(Total is null ? "" : $" of {Total}")}.");

                return (FileTransferOutcome.Done, "");

            }

        }

        #endregion

        #region MaxHTTPRedirects / (private static) SameServer(A, B) / (private static) ValidatorOf(Response)

        /// <summary>
        /// How many redirects a download follows at most, one after the other.
        /// </summary>
        public const Int32 MaxHTTPRedirects = 5;

        /// <summary>
        /// Whether both URLs name the same server: scheme, host and port.
        /// </summary>
        private static Boolean SameServer(Uri A, Uri B)

            => String.Equals(A.Scheme, B.Scheme, StringComparison.OrdinalIgnoreCase) &&
               String.Equals(A.IdnHost, B.IdnHost, StringComparison.OrdinalIgnoreCase) &&
               A.Port == B.Port;

        /// <summary>
        /// What an answer says the file it carries is, as an If-Range may name
        /// it again (RFC 9110, Section 13.1.5): its entity tag where it is a
        /// strong one, or else the time it was last written; null where it
        /// says neither.
        /// </summary>
        private static String? ValidatorOf(HttpResponseMessage Response)
        {

            if (Response.Headers.ETag is EntityTagHeaderValue tag && !tag.IsWeak)
                return tag.Tag;

            return Response.Content.Headers.LastModified is DateTimeOffset written
                       ? written.ToUniversalTime().ToString("r", System.Globalization.CultureInfo.InvariantCulture)
                       : null;

        }

        #endregion


        #region (private) SignIn(Request, Judgement) / Said(Response) / Failed(Response, Judgement)

        /// <summary>
        /// Sign in as the URL says, or else as the configuration says, where
        /// either says anything - or, after a redirect to the server the
        /// request named, as the request's URL said.
        /// </summary>
        private void SignIn(HttpRequestMessage         Request,
                            FileTransferJudgement      Judgement,
                            (String, String)?          Carried  = null)
        {

            var server      = Judgement.HTTPServer!;

            // The login of the URL, where it carries one, before that of the configuration.
            var credentials = Carried ??
                              CredentialsOf(Judgement.HTTPLocation!) ??
                              (server.User is String user && server.Password is String password
                                   ? (user, password)
                                   : null);

            if (credentials is not (String login, String secret))
                return;

            Request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{login}:{secret}")));

            if (!server.IsSecure)
                Log.Warning($"The transfer with {Request.RequestUri?.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped)} signs in as '{login}' over http://: its password crosses the network in the clear.",
                            Kind.Tag, "http", "filetransfer", "security");

        }

        private static String Said(HttpResponseMessage Response)
            => $"HTTP {(Int32) Response.StatusCode} {Response.ReasonPhrase}";

        /// <summary>
        /// What a status that is no success comes to - the same both ways.
        /// </summary>
        private static (FileTransferOutcome, String) Failed(HttpResponseMessage    Response,
                                                            FileTransferJudgement  Judgement)
        {

            var said = Said(Response);

            return (Int32) Response.StatusCode switch {
                       401                   => (FileTransferOutcome.LoginRefused,      $"{said}: the server did not take the login{(Judgement.HTTPServer!.User is null && Judgement.HTTPLocation!.UserInfo.Length == 0 ? ", as there is none" : "")}."),
                       403                   => (FileTransferOutcome.PermissionDenied,  said),
                       404 or 410            => (FileTransferOutcome.NoSuchFile,        said),
                       405 or 501            => (FileTransferOutcome.MethodNotAllowed,  $"{said}: the server does not take this method there."),
                       413                   => (FileTransferOutcome.TooLarge,          said),
                       408 or 429 or >= 500  => (FileTransferOutcome.Failed,            said),
                       >= 300 and < 400      => (FileTransferOutcome.RejectedByServer,  $"{said}: a redirect, to {Response.Headers.Location?.GetLeftPart(UriPartial.Path) ?? "nowhere"}, is not followed - an upload goes to the server the request named, and a download follows only 301, 302, 303, 307 and 308."),
                       _                     => (FileTransferOutcome.RejectedByServer,  said)
                   };

        }

        #endregion

        #region (private) TransferOverHTTP(Judgement, Direction, Target, Bytes, Move, CancellationToken)

        /// <summary>
        /// Make the HTTP client the judgement says, let the transfer ask its
        /// server, and say how it ended.
        /// </summary>
        private async Task<FileTransferResult> TransferOverHTTP(FileTransferJudgement                                                                                          Judgement,
                                                                FileTransferDirections                                                                                         Direction,
                                                                Uri                                                                                                            Target,
                                                                Func<Int64>                                                                                                    Bytes,
                                                                Func<HttpClient, Action, Action<FileTransferJudgement>, CancellationToken, Task<(FileTransferOutcome, String)>>  Move,
                                                                CancellationToken                                                                                              CancellationToken)
        {

            // The server asked now: the one the request named, or the one a
            // redirect it may follow sent it on to.
            var hop                 = Judgement;
            var what                = $"{(Direction == FileTransferDirections.Download ? "download from" : "upload to")} {Target.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped)}";
            String? certificateRefused = null;

            FileTransferResult Ended(FileTransferOutcome Outcome, String Why)
            {

                var said = $"The {what} ({Judgement.Why}) " +
                           (Outcome == FileTransferOutcome.Done
                                ? $"is done: {Bytes()} bytes."
                                : $"ended as {Outcome}: {Why}");

                if (Outcome == FileTransferOutcome.Done)
                    Log.Info(said, Kind.Tag, "http", "filetransfer");
                else
                    Log.Warning(said, Kind.Tag, "http", "filetransfer");

                return new (Outcome, Why, Judgement, Bytes(), Target.AbsolutePath);

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
                                         hop.HTTPLocation!.IdnHost,
                                         null,
                                         shown,
                                         chain,
                                         errors,
                                         Evidence:  false);

                if (!judged.Accepted)
                    certificateRefused = WhyRefused(judged);

                return judged.Accepted;

            };

            using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };

            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("WWCP-Node", "1.0"));

            try
            {

                StillAlive();

                var (outcome, why) = await Move(client, StillAlive, next => hop = next, idle.Token).ConfigureAwait(false);

                return Ended(outcome, why);

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

                var why    = certificateRefused ?? problem.InnerException?.Message ?? problem.Message;
                var server = hop.HTTPServer!;

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
