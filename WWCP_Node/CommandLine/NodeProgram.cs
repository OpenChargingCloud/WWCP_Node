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

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// What the program of every kind of node does between its command line
    /// and its banner: find where its files go, say why it could not be set
    /// up or could not start, and put into the certificate store what the
    /// command line brought.
    /// </summary>
    public static class NodeProgram
    {

        #region (static) RepositoryRoot(Marker)

        /// <summary>
        /// The directory holding the given file - a kind's solution, say,
        /// "LocalControllerCLI.slnx" - looked up from the binary and from the
        /// current directory; the current directory when neither leads to it.
        /// </summary>
        /// <remarks>
        /// The accounts, the configuration and the log files default to a
        /// place below it, so that they do not end up in bin/ - where the next
        /// "dotnet clean" would take a node's accounts with it.
        /// </remarks>
        /// <param name="Marker">The file the repository root holds.</param>
        public static String RepositoryRoot(String Marker)

            => RepositoryRoot(Marker, AppContext.BaseDirectory, Environment.CurrentDirectory);


        /// <summary>
        /// The directory holding the given file, looked up from each of the
        /// given directories in turn, and the last of them when none leads to it.
        /// </summary>
        /// <param name="Marker">The file the repository root holds.</param>
        /// <param name="Starts">Where to look up from; the last is also what is taken when nothing is found.</param>
        public static String RepositoryRoot(String           Marker,
                                            params String[]  Starts)
        {

            foreach (var start in Starts)
            {

                var directory = new DirectoryInfo(start);

                while (directory is not null)
                {

                    if (File.Exists(Path.Combine(directory.FullName, Marker)))
                        return directory.FullName;

                    directory = directory.Parent;

                }

            }

            return Starts[^1];

        }

        #endregion

        #region (static) CouldNotBeSetUp(Kind, Problem, Verbose, Error = null)

        /// <summary>
        /// What Main returns when the node could not even be made: 1, after
        /// saying why - and with the whole exception where --verbose asked for
        /// it, the one moment the stack trace is worth more than a tidy console.
        /// </summary>
        /// <param name="Kind">The kind of node that could not be made.</param>
        /// <param name="Problem">Why.</param>
        /// <param name="Verbose">Whether --verbose was given.</param>
        /// <param name="Error">Where to say it; the console's error stream by default.</param>
        public static Int32 CouldNotBeSetUp(NodeKind     Kind,
                                            Exception    Problem,
                                            Boolean      Verbose,
                                            TextWriter?  Error = null)
        {

            Error ??= Console.Error;

            Error.WriteLine($"The {Kind.Name} could not be set up: {Problem.Message}");

            if (Verbose)
                Error.WriteLine(Problem);

            return 1;

        }

        #endregion

        #region Started(this Node, Verbose, AdviceOfTheKind = null, Error = null, SwitchOf = null)

        /// <summary>
        /// Start the node: null once it has started, or what Main returns when
        /// it could not - 1, after saying why, and for a port which one, whose,
        /// and what somebody can do about it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// What somebody starting a second copy of a node used to get was a
        /// stack trace under the operating system's own words for a port in
        /// use - in German on a German Windows - with neither the port nor what
        /// it was for named anywhere. A second copy is the usual answer only
        /// where the address is in use; a port below 1024 on Linux wants rights
        /// instead (found by the energy meter), and anything else is said as
        /// it is. So is whatever else a start fails with, which ran past Main
        /// as an unhandled exception (found by the energy meter as well).
        /// </para>
        /// <para>
        /// The one account of a first start is made before the port is opened,
        /// and what it was given is shown once: a start that ended at its port
        /// shows it all the same. It had made the account and never shown the
        /// password, and the next start found "1 user(s)" and nobody who could
        /// sign in (found by the EMSP, the gateway and the CSMS).
        /// </para>
        /// </remarks>
        /// <param name="Node">The node to start.</param>
        /// <param name="Verbose">Whether --verbose was given: then the whole exception as well.</param>
        /// <param name="AdviceOfTheKind">What to do about a port of the kind's own that is in use - the charging station server's, say, set in the configuration file; null for the web interface's.</param>
        /// <param name="Error">Where to say it; the console's error stream by default.</param>
        /// <param name="SwitchOf">The switch that sets a port, where it is not --port: "--http-port" for the energy meter's web interface; null where no switch sets it.</param>
        public static async Task<Int32?> Started(this WWCPNode                               Node,
                                                 Boolean                                     Verbose,
                                                 Func<PortUnavailableException, String?>?   AdviceOfTheKind  = null,
                                                 TextWriter?                                 Error            = null,
                                                 Func<PortUnavailableException, String?>?   SwitchOf         = null)
        {

            try
            {
                await Node.Start();
                return null;
            }
            catch (PortUnavailableException problem)
            {

                Error ??= Console.Error;

                Error.WriteLine($"The {Node.Kind.Name} could not start: {problem.Message}.");

                foreach (var line in AdviceOn(Node.Kind, problem, AdviceOfTheKind, OperatingSystem.IsWindows(), Environment.ProcessPath, SwitchOf))
                    Error.WriteLine(line);

                return CouldNotStart(Node, problem, Verbose, Error);

            }
            catch (Exception problem)
            {

                Error ??= Console.Error;

                Error.WriteLine($"The {Node.Kind.Name} could not start: {problem.Message}");

                return CouldNotStart(Node, problem, Verbose, Error);

            }

        }

        #endregion

        #region (private static) CouldNotStart(Node, Problem, Verbose, Error)

        /// <summary>
        /// The rest of what a start that failed says: the whole exception where
        /// --verbose asked for it, and the password of a first start's account.
        /// </summary>
        private static Int32 CouldNotStart(WWCPNode    Node,
                                           Exception   Problem,
                                           Boolean     Verbose,
                                           TextWriter  Error)
        {

            if (Verbose)
                Error.WriteLine(Problem);

            foreach (var line in Node.FirstStartBox())
                Error.WriteLine(line);

            return 1;

        }

        #endregion

        #region (static) AdviceOn(Kind, Problem, AdviceOfTheKind, OnWindows, Program, SwitchOf = null)

        /// <summary>
        /// What somebody can do about a port a node could not have.
        /// </summary>
        /// <remarks>
        /// Started as "dotnet LocalControllerCLI.dll", the program is dotnet
        /// itself, and setcap on it would give the ports below 1024 to every
        /// .NET program on the machine (found by the hub and the gateway): the
        /// right goes to a published program instead.
        /// </remarks>
        /// <param name="Kind">The kind of node.</param>
        /// <param name="Problem">Which port, whose and why.</param>
        /// <param name="AdviceOfTheKind">The kind's advice on a port of its own that is in use; null for the web interface's.</param>
        /// <param name="OnWindows">Whether this runs on Windows, where no port wants rights.</param>
        /// <param name="Program">The program's path, for setcap.</param>
        /// <param name="SwitchOf">The switch that sets a port, where it is not --port; null where no switch sets it.</param>
        public static IEnumerable<String> AdviceOn(NodeKind                                   Kind,
                                                   PortUnavailableException                   Problem,
                                                   Func<PortUnavailableException, String?>?  AdviceOfTheKind,
                                                   Boolean                                    OnWindows,
                                                   String?                                    Program,
                                                   Func<PortUnavailableException, String?>?  SwitchOf  = null)
        {

            var port    = Problem.Port.ToUInt16();

            // The meter's web interface is --http-port, its Modbus/TLS server
            // --port; the web interface of every other kind is --port.
            var option  = SwitchOf?.Invoke(Problem)
                              ?? (Problem.Whose == NodePort.WebInterface ? "--port" : null);

            if (Problem.Because == SocketError.AccessDenied && port < 1024 && !OnWindows)
            {

                if (IsDotnet(Program))
                {
                    yield return $"Port {port} is privileged. Either start this as root, or publish it and, once:";
                    yield return  "  sudo setcap cap_net_bind_service=+ep <the published program>";
                    yield return $"or pick a port above 1024{(option is not null ? $" with {option}" : "")}.";
                    yield return  "Not on dotnet itself, which runs this now: that would give the ports below";
                    yield return  "1024 to every .NET program on this machine.";
                    yield break;
                }

                yield return $"Port {port} is privileged. Either start this as root, or once:";
                yield return $"  sudo setcap cap_net_bind_service=+ep {Program ?? "<this program>"}";
                yield return $"or pick a port above 1024{(option is not null ? $" with {option}" : "")}.";
                yield break;

            }

            if (Problem.Because == SocketError.AddressAlreadyInUse)
                yield return AdviceOfTheKind?.Invoke(Problem)
                                 ?? $"Another copy of this {Kind.Name} already running is the usual answer. Stop it, " +
                                    $"or give this one another port{(option is not null ? $" with {option} <number>" : "")}.";

        }

        #endregion

        #region (private static) IsDotnet(Program)

        /// <summary>
        /// Whether the program running is the dotnet host - "dotnet X.dll",
        /// or "dotnet run" - rather than a program of its own.
        /// </summary>
        private static Boolean IsDotnet(String? Program)

            => Program is not null &&
               Path.GetFileNameWithoutExtension(Program).Equals("dotnet", StringComparison.OrdinalIgnoreCase);

        #endregion


        #region (static) CertificatePasswordVariable(Kind)

        /// <summary>
        /// The environment variable a certificate's password is read from where
        /// --certificate-password did not give one: the kind's product in
        /// capitals, "LOCALCONTROLLER_CERT_PASSWORD" - which is what the EV,
        /// the gateway and the roaming hub had called theirs already.
        /// </summary>
        /// <param name="Kind">The kind of node.</param>
        public static String CertificatePasswordVariable(NodeKind Kind)

            => $"{Kind.Product.ToUpperInvariant()}_CERT_PASSWORD";

        #endregion

        #region ImportCertificates(this Node, Arguments, out Imported, Out = null, Error = null)

        /// <summary>
        /// Put into the node's certificate store what --import-certificate
        /// brought: null once all of it is in, or what Main returns where
        /// something could not be - 2, after saying which and why.
        /// </summary>
        /// <remarks>
        /// Before the start, so that a root imported here is believed by the
        /// first key exchange with a time server, and not only by the one
        /// after it. What went in is handed back, for a kind that names a
        /// certificate somewhere else - the vehicle's session.
        /// </remarks>
        /// <param name="Node">The node, made and not yet started.</param>
        /// <param name="Arguments">The command line.</param>
        /// <param name="Imported">What went in, in the order given.</param>
        /// <param name="Out">Where each certificate that went in is named; the console by default.</param>
        /// <param name="Error">Where a problem is said; the console's error stream by default.</param>
        public static Int32? ImportCertificates(this WWCPNode                           Node,
                                                NodeArguments                           Arguments,
                                                out IReadOnlyList<CertificateEntry>     Imported,
                                                TextWriter?                             Out    = null,
                                                TextWriter?                             Error  = null)
        {

            Out   ??= Console.Out;
            Error ??= Console.Error;

            var imported = new List<CertificateEntry>();
            Imported     = imported;

            foreach (var (kind, file) in Arguments.CertificateImports)
            {

                if (!Node.Certificates.Kinds.Contains(kind))
                {
                    Error.WriteLine($"'{kind.AsText()}' is not a kind of certificate this {Node.Kind.Name} keeps. " +
                                    $"Use one of {String.Join(", ", Node.Certificates.Kinds.Select(one => one.AsText()))}.");
                    return 2;
                }

                if (!File.Exists(file))
                {
                    Error.WriteLine($"--import-certificate: there is no file '{file}'.");
                    return 2;
                }

                Byte[] content;

                try
                {
                    content = File.ReadAllBytes(file);
                }
                catch (Exception problem)
                {
                    Error.WriteLine($"--import-certificate: '{file}' could not be read: {problem.Message}");
                    return 2;
                }

                if (!Node.Certificates.Import(content,
                                              kind,
                                              Arguments.CertificatePassword ?? Environment.GetEnvironmentVariable(CertificatePasswordVariable(Node.Kind)),
                                              Label: null,
                                              out var entry,
                                              out var refused))
                {
                    Error.WriteLine($"--import-certificate: {file} could not be imported as {kind.AsText()}: {refused}");
                    return 2;
                }

                Out.WriteLine($"  imported       {entry.Label} as {kind.AsText()}, handle {entry.Id}");

                imported.Add(entry);

            }

            return null;

        }

        #endregion

        #region ListCertificates(this Node, Beside = null, Out = null)

        /// <summary>
        /// What is in the node's certificate store, as a table: whether each
        /// one is switched on, until when, and what a root or a server
        /// certificate is kept for - for somebody at a console rather than on
        /// the web interface, which is what --list-certificates is for.
        /// </summary>
        /// <param name="Node">The node.</param>
        /// <param name="Beside">What a kind says beside a certificate, where it says anything: the vehicle's "&lt;- chosen".</param>
        /// <param name="Out">Where the table goes; the console by default.</param>
        public static void ListCertificates(this WWCPNode                       Node,
                                            Func<CertificateEntry, String?>?    Beside  = null,
                                            TextWriter?                         Out     = null)
        {

            Out ??= Console.Out;

            Out.WriteLine();
            Out.WriteLine($"  Certificates in {Node.Certificates.Directory}");
            Out.WriteLine();

            var entries = Node.Certificates.Entries;

            if (entries.Count == 0)
            {
                Out.WriteLine("  (empty - put one there with --import-certificate <kind>=<file>)");
                Out.WriteLine();
                return;
            }

            foreach (var kind in Node.Certificates.Kinds)
            {

                var ofKind = entries.Where(entry => entry.Kind == kind).ToArray();

                if (ofKind.Length == 0)
                    continue;

                Out.WriteLine($"  {kind.Describe(Node.Kind.Name)}");

                foreach (var entry in ofKind)
                {

                    var state = !entry.IsActive       ? "off"
                              :  entry.IsExpired      ? "EXPIRED"
                              :  entry.IsNotYetValid  ? "not yet valid"
                              :                         "on";

                    var beside = Beside?.Invoke(entry);

                    Out.WriteLine($"    {entry.Id}  {state,-13}  until {entry.NotAfter.UtcDateTime:yyyy-MM-dd}  {entry.Label}" +
                                  (Node.Certificates.HasUsages(kind) ? $"  ({CertificateUsages.Describe(entry.Usages)})" : "") +
                                  (beside is not null ? $"  {beside}" : ""));

                }

                Out.WriteLine();

            }

        }

        #endregion

    }

}
