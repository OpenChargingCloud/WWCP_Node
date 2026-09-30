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

using System.Globalization;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// What somebody who just started a node needs to know, as the console
    /// says it once the node is up: where it answers, what it was built from,
    /// where its files are, whom it asks for names and the time - and the
    /// kind's own lines where they belong among them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every kind of node wrote these lines itself, and they had come apart:
    /// one had no line for its log files, one printed its only time server
    /// untrimmed and not the one its group asks, one had its accounts a column
    /// to the left of everything else.
    /// </para>
    /// <para>
    /// The values begin where the longest label leaves room for two spaces,
    /// at <see cref="Column"/> or further in - the roaming hub's "traffic
    /// stream" put all of its at 18 - and the lines of what the node was
    /// built from begin there too.
    /// </para>
    /// </remarks>
    public static class NodeBanner
    {

        #region Data

        /// <summary>
        /// Where the values begin, unless a label is longer.
        /// </summary>
        public const Int32 Column = 17;

        #endregion


        #region Banner(this Node, BesideTheInterfaces = null, OfTheKind = null, AfterTheTimeServers = null)

        /// <summary>
        /// The banner, line by line, beginning and ending with an empty one.
        /// </summary>
        /// <param name="Node">The node, started.</param>
        /// <param name="BesideTheInterfaces">The kind's own lines after the node's interfaces: its other listeners.</param>
        /// <param name="OfTheKind">The kind's own lines after the node's files: what it is and whom it talks to.</param>
        /// <param name="AfterTheTimeServers">The kind's own lines after the time servers.</param>
        public static IReadOnlyList<String> Banner(this WWCPNode                                Node,
                                                   IEnumerable<(String Label, String Value)>?  BesideTheInterfaces  = null,
                                                   IEnumerable<(String Label, String Value)>?  OfTheKind            = null,
                                                   IEnumerable<(String Label, String Value)>?  AfterTheTimeServers  = null)
        {

            var beside  = BesideTheInterfaces?.ToArray() ?? [];
            var ofKind  = OfTheKind?.          ToArray() ?? [];
            var after   = AfterTheTimeServers?.ToArray() ?? [];

            var extPath = WWCPNode.ExtAPIPath.ToString().Trim('/');

            #region The node's lines, in their places

            var interfaces = new (String Label, String Value)[] {
                ("web interface",  Node.WebInterfaceURL.ToString()),
                ("JSON API",       $"{Node.APIURL}v1/status"),
                ("event stream",   $"{Node.APIURL}v1/events"),
                ("HTTPExt API",    $"{Node.WebInterfaceURL}{extPath}/")
            };

            (String Label, String Value) frontend = ("frontend from", Node.WebInterface is not null
                                                 ? Node.Frontend.Description
                                                 : "nothing - a browser asking for '/' gets nothing to render");

            var files = new List<(String Label, String Value)> {
                ("configuration",  Node.ConfigFile.Path),
                ("accounts",       $"{Node.ExtAPI.Users.Count()} user(s) in {Node.AccountsPath}"),
                ("sign in at",     $"{Node.WebInterfaceURL}{extPath}/login"),
                ("log files",      Node.LogPath ?? "none (--no-log-file)")
            };

            if (Node.Certificates.Kinds.Count > 0)
                files.Add(("certificates", $"{Node.Certificates.Entries.Count} in {Node.Certificates.Directory}"));

            (String Label, String Value) nameServers = ("name servers", Node.DNSEnabled
                                                   ? String.Join("\n", Node.DNSClient.DNSServers.Select(NameServer))
                                                   : "switched off");

            var timeServers = TimeServers(Node);

            #endregion

            var column = Math.Max(Column,
                                  2 + interfaces.Concat(beside).
                                                 Append(frontend).
                                                 Concat(files).
                                                 Concat(ofKind).
                                                 Append(nameServers).
                                                 Concat(timeServers).
                                                 Concat(after).
                                                 Max(line => line.Label.Length) + 2);

            var lines = new List<String> { "" };

            void Add(IEnumerable<(String Label, String Value)> Lines)
            {
                foreach (var (label, value) in Lines)
                {

                    var said = value.Split('\n');

                    lines.Add($"  {label}".PadRight(column) + said[0].TrimEnd('\r'));

                    foreach (var more in said.Skip(1))
                        lines.Add(new String(' ', column) + more.TrimEnd('\r'));

                }
            }

            Add(interfaces);
            Add(beside);
            Add([ frontend ]);

            lines.AddRange(Node.BuiltFrom.BannerLines(column));

            Add(files);
            Add(ofKind);
            Add([ nameServers ]);
            Add(TimeServers(Node, NodeUsage.Width - column));
            Add(after);

            lines.AddRange(FirstStartBox(Node));

            lines.Add("");

            return lines;

        }

        #endregion

        #region FirstStartBox(this Node)

        /// <summary>
        /// The account a node made up at its first start and the password it
        /// shows this once, in a box; nothing where there were accounts already.
        /// </summary>
        /// <remarks>
        /// The scheme is named rather than called "a hash", and read from the
        /// implementation rather than typed here, so the box cannot end up
        /// describing a scheme no longer used; "i=600000" is also how the
        /// accounts file writes it down, which is where somebody checking this
        /// will look.
        /// </remarks>
        /// <param name="Node">The node.</param>
        public static IEnumerable<String> FirstStartBox(this WWCPNode Node)
        {

            if (Node.GeneratedPassword is null)
                yield break;

            yield return "";
            yield return  "  ┌─ First start: there were no accounts, so one was made up for you ─────────";
            yield return $"  │  user      {WWCPNode.DefaultAdminUser}";
            yield return $"  │  password  {Node.GeneratedPassword}";
            yield return $"  │  It is shown here once and kept only as a {SecurePassword.PBKDF2SHA256} hash";
            yield return $"  │  over {SecurePassword.DefaultIterations} iterations. Write it down.";
            yield return  "  └───────────────────────────────────────────────────────────────────────────";

        }

        #endregion


        #region (static) NameServer(Server)

        /// <summary>
        /// One name server, for a line of its own, as people write it: an IPv6
        /// address in the short form of RFC 5952, as the page shows it -
        /// "tls://[2001:db8::53]:853" - a name without the root's dot, and the
        /// server's own timeout, if it has one, as the file says it: 0.5
        /// seconds, not 0.
        /// </summary>
        /// <remarks>
        /// Not Hermod's ToString(), which spells every group of an IPv6 address
        /// out and keeps doing so: the log says a server that way, and the name
        /// under which a node keeps what it knows of a server is spelled out
        /// alike (see WWCPNode.NameOf). A machine's own name servers, IPv6 among
        /// them, made one line of 247 characters with it, and a timeout after a
        /// comma among the servers read as one more of them. Public for a kind
        /// that says its name servers in a banner of its own, as the energy
        /// meter does (asked for by the meter).
        /// </remarks>
        /// <param name="Server">A name server the node asks.</param>
        public static String NameServer(DNSServerConfig Server)
        {

            var host = Server.DomainName?.Trimmed
                           ?? Server.IPAddress switch {
                                  null                   => "<unknown>",
                                  { IsIPv6: true } ipv6  => $"[{ipv6.ToString(IPv6Format.Short)}]",
                                  var ipv4               => ipv4.ToString()
                              };

            return $"{Server.Transport.ToString().ToLowerInvariant()}://{host}:{Server.Port}" +
                   (Server.QueryTimeout is TimeSpan timeout
                        ? $", timeout: {timeout.TotalSeconds.ToString(CultureInfo.InvariantCulture)} sec."
                        : "");

        }

        #endregion

        #region (private static) TimeServers(Node, Room = Int32.MaxValue)

        /// <summary>
        /// The time servers, one line per band - a band is what is asked at
        /// once, so two bands on one line would read as six equal servers when
        /// it is two and then four - and how many of them must answer.
        /// </summary>
        /// <remarks>
        /// Without the root's dot, which a domain name prints itself with: four
        /// names in a row, each ending in a dot, read as four typing mistakes.
        /// And the one server the group asks rather than the single client's: a
        /// list of one in the file leaves that client where it was.
        /// </remarks>
        /// <param name="Node">The node.</param>
        /// <param name="Room">How wide a band's line may be beside the column: one that is wider goes on below it.</param>
        private static List<(String Label, String Value)> TimeServers(WWCPNode  Node,
                                                                      Int32     Room = Int32.MaxValue)
        {

            var bands  = Node.TimeSources.Bands();
            var asked  = bands.SelectMany(band => band).ToArray();
            var lines  = new List<(String Label, String Value)>();

            if (asked.Length <= 1)
            {
                lines.Add(("time server", $"{(asked.Length == 1 ? asked[0].Hostname : Node.NTSClient.Hostname).Trimmed}" +
                                          (Node.NTSEnabled ? "" : " (switched off)")));
                return lines;
            }

            for (var i = 0; i < bands.Count; i++)
                lines.Add((i == 0 ? "time servers" : "",
                           Fitted(bands[i].Select(source => source.Hostname.Trimmed).ToArray(),
                                  bands.Count > 1 ? $"   (priority {bands[i][0].Priority})" : "",
                                  Room)));

            lines.Add(("", $"at least {Node.TimeSources.MinServers} of them must answer" +
                           (Node.NTSEnabled ? "" : " - and NTS is switched off")));

            return lines;

        }

        #endregion

        #region (private static) Fitted(Names, After, Room)

        /// <summary>
        /// A band's servers, as many to a line as fit in the room beside the
        /// column and the rest on the lines below it - broken after a server's
        /// comma, never in its name - and what is said after them on the last.
        /// </summary>
        /// <remarks>
        /// The PTB's four, which every node asks where its file names none, made
        /// one line of 83 columns (found by the CSMS).
        /// </remarks>
        /// <param name="Names">The servers of the band.</param>
        /// <param name="After">What is said after the last of them.</param>
        /// <param name="Room">How wide a line may be.</param>
        private static String Fitted(IReadOnlyList<String>  Names,
                                     String                 After,
                                     Int32                  Room)
        {

            var lines  = new List<String>();
            var line   = "";

            for (var i = 0; i < Names.Count; i++)
            {

                var name = Names[i] + (i < Names.Count - 1 ? "," : After);

                if (line.Length > 0 && line.Length + 1 + name.Length > Room)
                {
                    lines.Add(line);
                    line = name;
                }

                else
                    line = line.Length > 0 ? $"{line} {name}" : name;

            }

            lines.Add(line);

            return String.Join("\n", lines);

        }

        #endregion

    }

}
