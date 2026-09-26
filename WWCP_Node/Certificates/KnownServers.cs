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

using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// The certificate a server was last believed with.
    /// </summary>
    /// <param name="Service">What the server is to the node: "nts", "dns".</param>
    /// <param name="Server">Its name or its address, as the node asks it.</param>
    /// <param name="Certificate">The SHA-256 fingerprint of the certificate it showed.</param>
    /// <param name="Root">The SHA-256 fingerprint of the root its chain ended at, or null.</param>
    /// <param name="Since">When it was first believed with that certificate.</param>
    public sealed record KnownServer(String          Service,
                                     String          Server,
                                     String          Certificate,
                                     String?         Root,
                                     DateTimeOffset  Since);


    /// <summary>
    /// What every server this node connects to was last believed with, kept
    /// between starts - so that a server showing another certificate than
    /// before is noticed, whether or not anything holds it to one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A pin says what a server has to show; this says what it did show, and
    /// the difference between the two is the difference between a rule and a
    /// witness. A certificate renewed on schedule and a certificate somebody
    /// in between presents look alike to a node that holds its servers to
    /// nothing - here the second is at least a line in the log, with both
    /// fingerprints in it.
    /// </para>
    /// <para>
    /// Only what was believed is kept: a certificate that was refused is
    /// already in the log as a refusal, and remembering it would make the
    /// genuine one look like a change the next time. One file beside the
    /// configuration, in the spirit of SSH's known_hosts: fingerprints only,
    /// nothing secret, and a damaged file costs the memory and nothing else.
    /// </para>
    /// </remarks>
    public sealed class KnownServers
    {

        #region Data

        /// <summary>
        /// What the file is called, beside the configuration file.
        /// </summary>
        public const String DefaultFileName = "known-servers.json";

        private readonly Lock                              padlock  = new ();
        private readonly Dictionary<String, KnownServer>  known    = [];
        private readonly EventLog                          log;

        #endregion

        #region Properties

        /// <summary>
        /// Where the memory is kept between starts.
        /// </summary>
        public String Path { get; }

        /// <summary>
        /// Every server remembered, by service and name.
        /// </summary>
        public IReadOnlyList<KnownServer> All
        {
            get
            {
                lock (padlock)
                    return [.. known.Values.OrderBy(server => server.Service, StringComparer.Ordinal).
                                            ThenBy (server => server.Server,  StringComparer.OrdinalIgnoreCase)];
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The memory kept in the given file, read from it where it exists.
        /// </summary>
        /// <param name="Path">The file.</param>
        /// <param name="Log">Where to say that it could not be read or written.</param>
        public KnownServers(String    Path,
                            EventLog  Log)
        {

            this.Path  = System.IO.Path.GetFullPath(Path);
            this.log   = Log;

            Read();

        }

        #endregion


        #region Get(Service, Server)

        /// <summary>
        /// What the given server was last believed with, or null.
        /// </summary>
        public KnownServer? Get(String  Service,
                                String  Server)
        {
            lock (padlock)
                return known.GetValueOrDefault(Key(Service, Server));
        }

        #endregion

        #region Observe(Service, Server, Certificate, Root, At)

        /// <summary>
        /// Remember that the given server was believed with the given
        /// certificate, and answer with what it was believed with before -
        /// null the first time.
        /// </summary>
        /// <remarks>
        /// Written to the file only when it is news - the first time, and a
        /// change - and not at every round, which would be a write every
        /// quarter of an hour for every server to say that nothing happened.
        /// </remarks>
        public KnownServer? Observe(String          Service,
                                    String          Server,
                                    String          Certificate,
                                    String?         Root,
                                    DateTimeOffset  At)
        {

            lock (padlock)
            {

                var key       = Key(Service, Server);
                var previous  = known.GetValueOrDefault(key);

                if (previous is not null &&
                    String.Equals(previous.Certificate, Certificate, StringComparison.OrdinalIgnoreCase) &&
                    String.Equals(previous.Root,        Root,        StringComparison.OrdinalIgnoreCase))
                {
                    return previous;
                }

                known[key] = new KnownServer(Service, Server, Certificate, Root, At);

                Write();

                return previous;

            }

        }

        #endregion


        #region (private static) Key(Service, Server)

        private static String Key(String  Service,
                                  String  Server)

            => $"{Service.ToLowerInvariant()} {Server.TrimEnd('.').ToLowerInvariant()}";

        #endregion

        #region (private) Read() / Write()

        private void Read()
        {

            if (!File.Exists(Path))
                return;

            try
            {

                var json = JObject.Parse(File.ReadAllText(Path));

                foreach (var entry in json["servers"]?.Children<JObject>() ?? [])
                {

                    var service      = entry.Value<String>("service");
                    var server       = entry.Value<String>("server");
                    var certificate  = entry.Value<String>("certificate");

                    if (service is null || server is null || certificate is null)
                        continue;

                    var since        = entry["since"] is JToken token && token.Type != JTokenType.Null &&
                                       DateTimeOffset.TryParse(token.Type == JTokenType.Date
                                                                   ? token.ToObject<DateTime>().ToString("o")
                                                                   : token.Value<String>(),
                                                               System.Globalization.CultureInfo.InvariantCulture,
                                                               System.Globalization.DateTimeStyles.AdjustToUniversal |
                                                               System.Globalization.DateTimeStyles.AssumeUniversal,
                                                               out var parsed)
                                           ? parsed
                                           : DateTimeOffset.MinValue;

                    known[Key(service, server)] = new KnownServer(service, server, certificate, entry.Value<String>("root"), since);

                }

            }
            catch (Exception exception)
            {
                log.Warning($"Known servers: '{Path}' could not be read, so every server will be seen as for the first time - {exception.Message}",
                            "certificates", "security");
            }

        }

        /// <summary>
        /// Write the memory. Called from inside <see cref="padlock"/>.
        /// </summary>
        private void Write()
        {

            try
            {

                var json = new JObject(
                               new JProperty("servers", new JArray(
                                   known.Values.
                                         OrderBy(server => server.Service, StringComparer.Ordinal).
                                         ThenBy (server => server.Server,  StringComparer.OrdinalIgnoreCase).
                                         Select (server => new JObject(
                                                               new JProperty("service",      server.Service),
                                                               new JProperty("server",       server.Server),
                                                               new JProperty("certificate",  server.Certificate),
                                                               new JProperty("root",         server.Root),
                                                               new JProperty("since",        server.Since.ToString("o"))
                                                           ))
                               ))
                           );

                // Written beside and moved over, so that a node killed mid-write
                // comes back to the memory it had rather than to half of one.
                var temporary = Path + ".new";

                File.WriteAllText(temporary, json.ToString(Newtonsoft.Json.Formatting.Indented));
                File.Move(temporary, Path, overwrite: true);

            }
            catch (Exception exception)
            {
                log.Error($"Known servers: '{Path}' could not be written, so a change of certificate may go unnoticed after a restart - {exception.Message}",
                          "certificates", "security");
            }

        }

        #endregion

    }

}
