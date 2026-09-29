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

using System.Text;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// What -h shows: the switches every kind of node has - see
    /// <see cref="NodeArguments"/> - in the words every kind of node had,
    /// and a kind's own where they belong among them.
    /// </summary>
    /// <remarks>
    /// Written for 80 columns, and wrapped here rather than by hand: a kind's
    /// name and its program's are of different lengths, and the paragraph
    /// about the prompt had been wrapped four ways by eight kinds. What a kind
    /// adds is written as the kind wrote it.
    /// </remarks>
    public sealed class NodeUsage
    {

        #region Data

        /// <summary>
        /// How wide the usage is written.
        /// </summary>
        public const Int32 Width = 80;

        /// <summary>
        /// Where the explanation of a switch begins.
        /// </summary>
        public const Int32 Column = 20;

        private readonly String[]           synopsis;
        private readonly CertificateKind[]  certificateKinds;
        private readonly String[]           afterTheWebInterface;
        private readonly String[]           beforeTheLog;

        #endregion

        #region Properties

        /// <summary>
        /// What the program is called at a prompt: "LocalControllerCLI".
        /// </summary>
        public String    Program              { get; }

        /// <summary>
        /// The kind of node: what the usage calls it.
        /// </summary>
        public NodeKind  Kind                 { get; }

        /// <summary>
        /// The port the web interface listens on without --port.
        /// </summary>
        public IPPort    DefaultPort          { get; }

        /// <summary>
        /// Where 'npm run watch' is run for --frontend: "libs/LocalController/LocalController/Frontend".
        /// </summary>
        public String    FrontendSources      { get; }

        /// <summary>
        /// What --config is explained with.
        /// </summary>
        public String    ConfigurationSays    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The usage of a kind of node's program.
        /// </summary>
        /// <param name="Program">What the program is called at a prompt: "LocalControllerCLI".</param>
        /// <param name="Kind">The kind of node.</param>
        /// <param name="DefaultPort">The port the web interface listens on without --port.</param>
        /// <param name="FrontendSources">Where 'npm run watch' is run for --frontend, from the repository root.</param>
        /// <param name="ConfigurationSays">What --config is explained with; by default what every node keeps there - see <see cref="DefaultConfigurationSays(NodeKind)"/>.</param>
        /// <param name="CertificateKinds">The kinds of certificate this kind of node keeps, which --import-certificate takes; all of them by default.</param>
        /// <param name="Synopsis">The kind's own switches in the first lines, one bracketed item each: "[--name &lt;name&gt;]".</param>
        /// <param name="AfterTheWebInterface">The kind's own lines after the web interface's switches - its other listeners - ending with an empty one.</param>
        /// <param name="BeforeTheLog">The kind's own lines before the log's switches - its own sections - ending with an empty one.</param>
        public NodeUsage(String                         Program,
                         NodeKind                       Kind,
                         IPPort                         DefaultPort,
                         String                         FrontendSources,
                         String?                        ConfigurationSays      = null,
                         IEnumerable<CertificateKind>?  CertificateKinds       = null,
                         IEnumerable<String>?           Synopsis               = null,
                         IEnumerable<String>?           AfterTheWebInterface   = null,
                         IEnumerable<String>?           BeforeTheLog           = null)
        {

            this.Program               = Program;
            this.Kind                  = Kind;
            this.DefaultPort           = DefaultPort;
            this.FrontendSources       = FrontendSources;
            this.ConfigurationSays     = ConfigurationSays ?? DefaultConfigurationSays(Kind);
            this.certificateKinds      = (CertificateKinds ?? CertificateKindExtensions.All).ToArray();
            this.synopsis              = Synopsis?.            ToArray() ?? [];
            this.afterTheWebInterface  = AfterTheWebInterface?.ToArray() ?? [];
            this.beforeTheLog          = BeforeTheLog?.        ToArray() ?? [];

        }

        #endregion


        #region (static) DefaultConfigurationSays(Kind)

        /// <summary>
        /// What --config says of a kind of node that keeps nothing of its own
        /// in the configuration file: the name servers and the time servers.
        /// </summary>
        /// <param name="Kind">The kind of node.</param>
        public static String DefaultConfigurationSays(NodeKind Kind)

            => $"where the name servers and the time servers of this {Kind.Name} live (default: " +
               $"{WWCPConfigFile.DefaultFileName} below the repository root). Without the file the {Kind.Name} " +
                "runs on the system defaults; the Configuration pages of the web interface write it, and every " +
                "change there takes effect at once.";

        #endregion

        #region Lines()

        /// <summary>
        /// The usage, line by line.
        /// </summary>
        public IEnumerable<String> Lines()
        {

            #region The switches in one place

            var usage = $"Usage: {Program} ";

            foreach (var line in WrapItems([ "[--port <number>]", "[--any]", "[--frontend <dist directory>]",
                                             "[--accounts <dir>]", "[--config <file>]",
                                             "[--verbose | --quiet]", "[--no-trace]",
                                             "[--log-file <dir>]", "[--no-log-file]",
                                             "[--certificates <dir>]", "[--import-certificate <kind>=<file>]",
                                             "[--certificate-password <pw>]", "[--list-certificates]",
                                             .. synopsis ],
                                           usage,
                                           new String(' ', usage.Length)))
                yield return line;

            yield return "";

            #endregion

            #region The web interface

            yield return "Web interface:";

            foreach (var line in Switch("--port <number>",   $"TCP port to listen on (default: {DefaultPort})"))
                yield return line;

            foreach (var line in Switch("--any",             "listen on all addresses instead of 127.0.0.1"))
                yield return line;

            foreach (var line in Switch("--frontend <dir>",  "serve the web interface from a directory on disk instead of the bundle " +
                                                            $"embedded in the assembly - use it together with 'npm run watch' in {FrontendSources}"))
                yield return line;

            yield return "";

            foreach (var line in afterTheWebInterface)
                yield return line;

            #endregion

            #region The accounts

            yield return "Accounts:";

            foreach (var line in Switch("--accounts <dir>",  $"where the accounts live (default: {WWCPNode.DefaultAccountsPath}/ below the repository " +
                                                              "root): the users, their roles, the organizations and the API keys. Without them a " +
                                                             $"password is made up at the first start for the user '{WWCPNode.DefaultAdminUser}' " +
                                                              "and shown once."))
                yield return line;

            yield return "";

            #endregion

            #region The configuration

            yield return "Configuration:";

            foreach (var line in Switch("--config <file>",   ConfigurationSays))
                yield return line;

            yield return "";

            #endregion

            #region The certificate store

            foreach (var line in Wrap($"The certificate store: what this {Kind.Name} believes, presents and recognises a server by, " +
                                       "one file per certificate, each switched on and off on its own:", "", ""))
                yield return line;

            foreach (var line in Switch("--certificates <dir>",
                                        $"where the store is (default: {CertificatesConfiguration.DefaultDirectory}/ beside the configuration " +
                                         "file, or what the file's certificates.directory says; a directory given here is measured " +
                                        $"from where the {Kind.Name} is started). Certificates already in it are read again at every " +
                                         "start, so copying one in is a way to install it. The web interface manages the same store."))
                yield return line;

            foreach (var line in Switch("--import-certificate <kind>=<file>",
                                        $"copy a certificate into the store before the {Kind.Name} starts, as PEM, DER or PKCS#12. " +
                                         "A root is a certificate on its own; a TLS identity has to bring its private key, so a PEM " +
                                        $"for one carries the key beside it. May be given several times. <kind> is one of:"))
                yield return line;

            var nameWidth = certificateKinds.Length > 0
                                ? certificateKinds.Max(kind => kind.AsText().Length)
                                : 0;

            foreach (var kind in certificateKinds)
            {

                var name = $"{new String(' ', Column + 2)}{kind.AsText().PadRight(nameWidth)}  ";

                foreach (var line in Wrap(WhatItIsFor(kind), name, new String(' ', name.Length)))
                    yield return line;

            }

            foreach (var line in Switch("--certificate-password <pw>",
                                         "what opens a protected PKCS#12 being imported. Used once and not kept: the store holds what " +
                                         "it has without a password. A password given here stands in the process list for every other " +
                                        $"user of the machine, so prefer the environment: {NodeProgram.CertificatePasswordVariable(Kind)}"))
                yield return line;

            foreach (var line in Switch("--list-certificates",
                                         "print the store at the start, with the handle of each certificate"))
                yield return line;

            yield return "";

            foreach (var line in beforeTheLog)
                yield return line;

            #endregion

            #region The log

            yield return "Log:";

            foreach (var line in Switch("-v, --verbose",     "write every entry to the console, down to the debug ones"))
                yield return line;

            foreach (var line in Switch("-q, --quiet",       "write only warnings and worse"))
                yield return line;

            foreach (var line in Switch("    --no-trace",    "do not pick up what the libraries below write with DebugX"))
                yield return line;

            foreach (var line in Switch("--log-file <dir>",  $"where the log files go (default: {WWCPNode.DefaultLogPath}/ below the repository root): " +
                                                              "one file per UTC day, every entry down to the debug ones, and nothing is ever deleted."))
                yield return line;

            foreach (var line in Switch("    --no-log-file", "do not write one. Then what the console did not show, and what falls out of the web " +
                                                            $"interface's last {EventLog.DefaultCapacity} entries, is gone."))
                yield return line;

            yield return "";

            yield return "Whatever the console shows, the web interface shows the whole log under 'Logs'.";

            yield return "";

            #endregion

            #region The prompt

            foreach (var line in Wrap("Once it is up, the console is a prompt: 'help' lists what can be typed there, Tab completes it, " +
                                     $"and 'quit' or Ctrl+C stops the {Kind.Name}. Started where there is no terminal - from a script, " +
                                      "under a service manager, in CI, or with the output going into a file - there is no prompt and it " +
                                      "simply runs, until Ctrl+C or the SIGTERM of a service manager stops it.", "", ""))
                yield return line;

            #endregion

        }

        #endregion

        #region WriteTo(Writer)

        /// <summary>
        /// Write the usage.
        /// </summary>
        /// <param name="Writer">Where to: the console, usually.</param>
        public void WriteTo(TextWriter Writer)
        {
            foreach (var line in Lines())
                Writer.WriteLine(line);
        }

        #endregion


        #region (static) Switch(Name, Says)

        /// <summary>
        /// A switch and what it does: on the switch's line where the switch
        /// leaves room before <see cref="Column"/>, on the lines below it where
        /// it does not, and wrapped at <see cref="Width"/> either way.
        /// </summary>
        /// <param name="Name">The switch as it is typed, with what it takes: "--port &lt;number&gt;".</param>
        /// <param name="Says">What it does, as one paragraph.</param>
        public static IEnumerable<String> Switch(String Name,
                                                 String Says)
        {

            var start = $"  {Name}";
            var below = new String(' ', Column);

            if (start.Length + 1 < Column)
                return Wrap(Says, start.PadRight(Column), below);

            if (start.Length + 1 == Column)
                return Wrap(Says, start + " ", below);

            return [ start, .. Wrap(Says, below, below) ];

        }

        #endregion

        #region (static) Wrap(Text, First, Next)

        /// <summary>
        /// A paragraph broken between words at <see cref="Width"/>, its first
        /// line begun with one prefix and every other line with another. A word
        /// longer than a line - a path - is put on a line of its own rather
        /// than cut.
        /// </summary>
        /// <param name="Text">The paragraph.</param>
        /// <param name="First">What its first line begins with.</param>
        /// <param name="Next">What every line after it begins with.</param>
        public static IEnumerable<String> Wrap(String  Text,
                                               String  First,
                                               String  Next)

            => WrapItems(Text.Split(' ', StringSplitOptions.RemoveEmptyEntries), First, Next);

        #endregion

        #region (private static) WrapItems(Items, First, Next)

        private static IEnumerable<String> WrapItems(IEnumerable<String>  Items,
                                                     String               First,
                                                     String               Next)
        {

            var line   = new StringBuilder(First);
            var empty  = true;

            foreach (var item in Items)
            {

                if (!empty && line.Length + 1 + item.Length > Width)
                {
                    yield return line.ToString();
                    line.Clear().Append(Next);
                    empty = true;
                }

                if (!empty)
                    line.Append(' ');

                line.Append(item);
                empty = false;

            }

            if (!empty)
                yield return line.ToString();

        }

        #endregion

        #region (private static) WhatItIsFor(Kind)

        /// <summary>
        /// What a kind of certificate is for, without its name in front, which
        /// the list of kinds already begins the line with.
        /// </summary>
        private static String WhatItIsFor(CertificateKind Kind)
        {

            var described = Kind.Describe();
            var dash      = described.IndexOf(" - ", StringComparison.Ordinal);

            return dash >= 0
                       ? described[(dash + 3)..]
                       : described;

        }

        #endregion

    }

}
