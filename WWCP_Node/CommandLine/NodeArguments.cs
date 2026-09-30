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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// What the command line of every kind of node says: where the web
    /// interface listens and what it serves, where the accounts, the
    /// configuration and the log files are, how much of the log the console
    /// shows, and what goes into the certificate store at the start - and,
    /// as it was typed, everything else, which is the kind's to read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every kind of node read these switches with a loop of its own, the
    /// same cases in the same words; the certificate store's four were in
    /// five of them, measured from two different places. The words that
    /// explain them are <see cref="NodeUsage"/>'s.
    /// </para>
    /// <para>
    /// A switch this does not know is left for the kind, with the words that
    /// follow it: "--name EV01" arrives in <see cref="Rest"/> as it was typed,
    /// so a kind reads its own switches with the loop it had - and a word
    /// neither knows is the kind's to call unknown.
    /// </para>
    /// </remarks>
    public sealed class NodeArguments
    {

        #region Data

        private readonly List<(CertificateKind Kind, String File)>  imports  = [];
        private readonly List<String>                               rest     = [];

        /// <summary>
        /// What --import-certificate named that is no kind of certificate at
        /// all: said with the kinds of the node where the node is known - see
        /// <see cref="Refused(NodeUsage, TextWriter?, TextWriter?)"/>.
        /// </summary>
        private String? notAKind;

        #endregion

        #region Properties

        /// <summary>
        /// The port of the web interface (--port), or null for the kind's own.
        /// </summary>
        public IPPort?   Port                 { get; private set; }

        /// <summary>
        /// Whether the web interface listens on every address (--any), not only on 127.0.0.1.
        /// </summary>
        public Boolean   AnyAddress           { get; private set; }

        /// <summary>
        /// The directory the web interface is served from (--frontend) instead of the bundle a kind embeds.
        /// </summary>
        public String?   FrontendDirectory    { get; private set; }

        /// <summary>
        /// Where the accounts are (--accounts), or null for below the repository root.
        /// </summary>
        public String?   AccountsPath         { get; private set; }

        /// <summary>
        /// Where the configuration file is (--config), or null for below the repository root.
        /// </summary>
        public String?   ConfigFilePath       { get; private set; }

        /// <summary>
        /// Whether the console shows every entry of the log, down to the debug ones (-v, --verbose).
        /// </summary>
        public Boolean   Verbose              { get; private set; }

        /// <summary>
        /// Whether the console shows only warnings and worse (-q, --quiet).
        /// </summary>
        public Boolean   Quiet                { get; private set; }

        /// <summary>
        /// Whether what the libraries below write with DebugX is left where it is (--no-trace).
        /// </summary>
        public Boolean   NoTrace              { get; private set; }

        /// <summary>
        /// Where the log files go (--log-file), or null for below the repository root.
        /// </summary>
        public String?   LogPath              { get; private set; }

        /// <summary>
        /// Whether no log files are written at all (--no-log-file), whatever --log-file said.
        /// </summary>
        public Boolean   NoLogFile            { get; private set; }

        /// <summary>
        /// Where the certificate store is (--certificates), measured from where the node is
        /// started, as every other path on this command line is - or null for what the
        /// configuration file says.
        /// </summary>
        public String?   CertificatesPath     { get; private set; }

        /// <summary>
        /// What opens a protected PKCS#12 being imported (--certificate-password).
        /// </summary>
        public String?   CertificatePassword  { get; private set; }

        /// <summary>
        /// Whether the store is printed at the start (--list-certificates).
        /// </summary>
        public Boolean   ListCertificates     { get; private set; }

        /// <summary>
        /// What goes into the store at the start (--import-certificate kind=file), in the order given.
        /// </summary>
        public IReadOnlyList<(CertificateKind Kind, String File)> CertificateImports
            => imports;

        /// <summary>
        /// Whether the usage was asked for (-h, --help).
        /// </summary>
        public Boolean   WantsHelp            { get; private set; }

        /// <summary>
        /// Why the command line cannot be followed, in the words the console shows; null when it can.
        /// </summary>
        public String?   Problem              { get; private set; }

        /// <summary>
        /// Everything this does not know, as it was typed and in its order: the kind's.
        /// </summary>
        public IReadOnlyList<String> Rest
            => rest;


        /// <summary>
        /// Where the web interface listens: every address with --any, 127.0.0.1 otherwise.
        /// </summary>
        public IIPAddress  HTTPHostname
            => AnyAddress
                   ? IPvXAddress.Any
                   : IPv4Address.Localhost;

        /// <summary>
        /// How much of the log the console shows.
        /// </summary>
        public LogLevel    ConsoleLogLevel
            => Verbose ? LogLevel.Debug
             : Quiet   ? LogLevel.Warning
             :           LogLevel.Info;

        /// <summary>
        /// The web interface from the directory --frontend named, or null for the kind's embedded one.
        /// </summary>
        public IStaticContentSource? Frontend
            => FrontendDirectory is not null
                   ? new FileSystemContentSource(FrontendDirectory)
                   : null;

        #endregion

        #region Constructor(s)

        private NodeArguments()
        { }

        #endregion


        #region (static) Parse(Arguments)

        /// <summary>
        /// Read what every kind of node reads from its command line, and leave
        /// the rest for the kind. Stops at -h or --help, and at the first
        /// switch that cannot be followed - see <see cref="Problem"/>.
        /// </summary>
        /// <param name="Arguments">The command line, as Main was handed it.</param>
        public static NodeArguments Parse(IReadOnlyList<String> Arguments)
        {

            var parsed = new NodeArguments();

            for (var i = 0; i < Arguments.Count; i++)
            {
                switch (Arguments[i])
                {

                    case "--port":
                        if (i + 1 < Arguments.Count && UInt16.TryParse(Arguments[i + 1], out var port))
                        {
                            parsed.Port = IPPort.Parse(port);
                            i++;
                        }
                        else
                            return parsed.Refusing("Missing or invalid port number after --port!");
                        break;

                    case "--any":
                        parsed.AnyAddress = true;
                        break;

                    case "--frontend":
                        if (!TryTakeValue(Arguments, ref i, out var frontend))
                            return parsed.Refusing("Missing directory after --frontend!");
                        parsed.FrontendDirectory = frontend;
                        break;

                    case "--accounts":
                        if (!TryTakeValue(Arguments, ref i, out var accounts))
                            return parsed.Refusing("Missing directory after --accounts!");
                        parsed.AccountsPath = accounts;
                        break;

                    case "--config":
                        if (!TryTakeValue(Arguments, ref i, out var config))
                            return parsed.Refusing("Missing file after --config!");
                        parsed.ConfigFilePath = config;
                        break;

                    case "-v":
                    case "--verbose":
                        parsed.Verbose = true;
                        break;

                    case "-q":
                    case "--quiet":
                        parsed.Quiet = true;
                        break;

                    case "--no-trace":
                        parsed.NoTrace = true;
                        break;

                    case "--log-file":
                        if (!TryTakeValue(Arguments, ref i, out var logPath))
                            return parsed.Refusing("Missing directory after --log-file!");
                        parsed.LogPath = logPath;
                        break;

                    case "--no-log-file":
                        parsed.NoLogFile = true;
                        break;

                    // Measured from where the node is started, as every other
                    // path on this command line is. Handed on relative, the
                    // node would measure it from the configuration file, which
                    // is where the file's own certificates.directory is from.
                    case "--certificates":
                        if (!TryTakeValue(Arguments, ref i, out var certificates))
                            return parsed.Refusing("Missing directory after --certificates!");
                        parsed.CertificatesPath = Path.GetFullPath(certificates);
                        break;

                    case "--certificate-password":
                        if (!TryTakeValue(Arguments, ref i, out var password))
                            return parsed.Refusing("Missing password after --certificate-password!");
                        parsed.CertificatePassword = password;
                        break;

                    case "--list-certificates":
                        parsed.ListCertificates = true;
                        break;

                    // Whether this kind of node keeps that kind of certificate
                    // is the kind's to say, which the command line does not
                    // know yet - see Refused(Usage). Here only whether it is
                    // a kind of certificate at all.
                    case "--import-certificate":

                        if (!TryTakeValue(Arguments, ref i, out var import))
                            return parsed.Refusing("Missing <kind>=<file> after --import-certificate!");

                        var split = import.IndexOf('=');

                        if (split <= 0 || split == import.Length - 1)
                            return parsed.Refusing($"--import-certificate wants <kind>=<file>, and '{import}' is not that.");

                        if (!CertificateKindExtensions.TryParseKind(import[..split], out var kind))
                        {
                            parsed.notAKind = import[..split];
                            return parsed.Refusing($"'{import[..split]}' is not a kind of certificate. " +
                                                   $"Use one of {String.Join(", ", CertificateKindExtensions.All.Select(one => one.AsText()))}.");
                        }

                        parsed.imports.Add((kind, import[(split + 1)..]));
                        break;

                    case "-h":
                    case "--help":
                        parsed.WantsHelp = true;
                        return parsed;

                    default:
                        parsed.rest.Add(Arguments[i]);
                        break;

                }
            }

            if (parsed.Verbose && parsed.Quiet)
                return parsed.Refusing("--verbose and --quiet ask for opposite things!");

            if (parsed.FrontendDirectory is not null && !Directory.Exists(parsed.FrontendDirectory))
                return parsed.Refusing($"The frontend directory '{parsed.FrontendDirectory}' does not exist!");

            return parsed;

        }

        #endregion

        #region (static) TryTakeValue(Arguments, ref Index, out Value)

        /// <summary>
        /// The word after the switch at the given index, and the index moved
        /// onto it - unless there is none, or the next word is a switch of its
        /// own: "--accounts --verbose" is a directory left out, not one called
        /// "--verbose".
        /// </summary>
        /// <param name="Arguments">The command line.</param>
        /// <param name="Index">Where the switch is, and afterwards where its value was.</param>
        /// <param name="Value">The value.</param>
        public static Boolean TryTakeValue(IReadOnlyList<String>              Arguments,
                                           ref Int32                          Index,
                                           [NotNullWhen(true)] out String?    Value)
        {

            if (Index + 1 < Arguments.Count && !Arguments[Index + 1].StartsWith("--"))
            {
                Value = Arguments[++Index];
                return true;
            }

            Value = null;
            return false;

        }

        #endregion


        #region AccountsPathBelow(Root) / ConfigFilePathBelow(Root) / LogPathBelow(Root)

        /// <summary>
        /// Where the accounts are: what --accounts said, or the node's default below the given root.
        /// </summary>
        /// <param name="Root">The repository root - see <see cref="NodeProgram.RepositoryRoot(String)"/>.</param>
        public String AccountsPathBelow(String Root)

            => AccountsPath ?? Path.Combine(Root, WWCPNode.DefaultAccountsPath);

        /// <summary>
        /// Where the configuration file is: what --config said, or the default below the given root.
        /// </summary>
        /// <param name="Root">The repository root - see <see cref="NodeProgram.RepositoryRoot(String)"/>.</param>
        public String ConfigFilePathBelow(String Root)

            => ConfigFilePath ?? Path.Combine(Root, WWCPConfigFile.DefaultFileName);

        /// <summary>
        /// Where the log files go - on unless it is switched off: a console
        /// nobody was watching kept nothing, and the log a browser shows goes
        /// with the process, so the one place a question about last night can
        /// still be answered from is a file. Null with --no-log-file.
        /// </summary>
        /// <param name="Root">The repository root - see <see cref="NodeProgram.RepositoryRoot(String)"/>.</param>
        public String? LogPathBelow(String Root)

            => NoLogFile
                   ? null
                   : LogPath ?? Path.Combine(Root, WWCPNode.DefaultLogPath);

        #endregion

        #region Refused(Usage, Out = null, Error = null)

        /// <summary>
        /// What Main returns when this command line is not to be run: 0 after
        /// the usage for -h, 2 after the problem for a switch that cannot be
        /// followed, for a certificate of a kind the node does not keep, or for
        /// one in a file that is not there; null when it is to be run.
        /// </summary>
        /// <remarks>
        /// A kind the node does not keep is said here, before the node is made,
        /// in the node's words and with its kinds. Said once the node was made,
        /// it came after nine lines of log and a mobility operator's root the
        /// EMSP had made meanwhile, and named all eleven kinds there are before
        /// that (found by the hub, the EMSP, the gateway and the CSMS). So is a
        /// file that is not there, which had left a certificate store and a log
        /// with the signing key of the log book behind (found by the hub).
        /// </remarks>
        /// <param name="Usage">What -h shows, with the kinds of certificate the node keeps.</param>
        /// <param name="Out">Where the usage goes; the console by default.</param>
        /// <param name="Error">Where the problem goes; the console's error stream by default.</param>
        public Int32? Refused(NodeUsage    Usage,
                              TextWriter?  Out    = null,
                              TextWriter?  Error  = null)
        {

            if (WantsHelp)
            {
                Usage.WriteTo(Out ?? Console.Out);
                return 0;
            }

            if (Problem is not null)
            {
                (Error ?? Console.Error).WriteLine(notAKind is not null
                                                       ? NotKeptBy(Usage, notAKind)
                                                       : Problem);
                return 2;
            }

            foreach (var (kind, file) in imports)
            {

                if (!Usage.CertificateKinds.Contains(kind))
                {
                    (Error ?? Console.Error).WriteLine(NotKeptBy(Usage, kind.AsText()));
                    return 2;
                }

                if (!File.Exists(file))
                {
                    (Error ?? Console.Error).WriteLine(NoFile(file));
                    return 2;
                }

            }

            return null;

        }

        #endregion

        #region (internal static) NoFile(File)

        /// <summary>
        /// A file to import that is not there.
        /// </summary>
        internal static String NoFile(String File)

            => $"--import-certificate: there is no file '{File}'.";

        #endregion

        #region (private static) NotKeptBy(Usage, Kind)

        /// <summary>
        /// A kind of certificate the node does not keep, said with the ones it does.
        /// </summary>
        private static String NotKeptBy(NodeUsage  Usage,
                                        String     Kind)

            => $"'{Kind}' is not a kind of certificate this {Usage.Kind.Name} keeps. " +
               (Usage.CertificateKinds.Count > 0
                    ? $"Use one of {String.Join(", ", Usage.CertificateKinds.Select(kind => kind.AsText()))}."
                    : "It keeps none.");

        #endregion

        #region Unknown(Argument, Usage, Out = null, Error = null)

        /// <summary>
        /// What Main returns for a word neither the node nor the kind knows:
        /// 2, after saying which, and the usage.
        /// </summary>
        /// <param name="Argument">The word.</param>
        /// <param name="Usage">What is shown after it.</param>
        /// <param name="Out">Where the usage goes; the console by default.</param>
        /// <param name="Error">Where the word goes; the console's error stream by default.</param>
        public static Int32 Unknown(String       Argument,
                                    NodeUsage    Usage,
                                    TextWriter?  Out    = null,
                                    TextWriter?  Error  = null)
        {

            (Error ?? Console.Error).WriteLine($"Unknown argument '{Argument}'!");
            Usage.WriteTo(Out ?? Console.Out);

            return 2;

        }

        #endregion

        #region RefuseTheRest(Usage, Out = null, Error = null)

        /// <summary>
        /// For a kind with no switches of its own: 2, and the first word of
        /// <see cref="Rest"/> called unknown, where there is any; null otherwise.
        /// </summary>
        /// <param name="Usage">What is shown after the word.</param>
        /// <param name="Out">Where the usage goes; the console by default.</param>
        /// <param name="Error">Where the word goes; the console's error stream by default.</param>
        public Int32? RefuseTheRest(NodeUsage    Usage,
                                    TextWriter?  Out    = null,
                                    TextWriter?  Error  = null)

            => rest.Count > 0
                   ? Unknown(rest[0], Usage, Out, Error)
                   : null;

        #endregion


        #region (private) Refusing(Problem)

        private NodeArguments Refusing(String Problem)
        {
            this.Problem = Problem;
            return this;
        }

        #endregion

    }

}
