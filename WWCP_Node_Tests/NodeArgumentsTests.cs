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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The command line every kind of node reads alike: what each switch
    /// sets, what is refused and in which words - the words eight kinds had
    /// written eight times - and everything else left for the kind as it was
    /// typed. And what -h shows of it.
    /// </summary>
    [TestFixture]
    public class NodeArgumentsTests
    {

        #region Data

        private static readonly NodeKind TestKind = new ("test node", "test", "TestNode", "Test", "test");

        private static NodeUsage Usage(IEnumerable<CertificateKind>? CertificateKinds  = null,
                                       IEnumerable<String>?          Synopsis          = null,
                                       IEnumerable<String>?          After             = null,
                                       IEnumerable<String>?          Before            = null,
                                       String                        Program           = "TestNodeCLI",
                                       NodeKind?                     Kind              = null,
                                       String?                       CertificatesSays  = null)

            => new (Program,
                    Kind ?? TestKind,
                    IPPort.Parse(4711),
                    "libs/Test/Test/Frontend",
                    CertificateKinds:      CertificateKinds,
                    Synopsis:              Synopsis,
                    AfterTheWebInterface:  After,
                    BeforeTheLog:          Before,
                    CertificatesSays:      CertificatesSays);

        /// <summary>
        /// A root certificate in a PEM file of its own, made for the test that
        /// asks for it and taken away after it.
        /// </summary>
        private String ARoot()
        {

            using var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var       request = new CertificateRequest("CN=A Root For The Command Line", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            using var root    = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            return Kept(".pem", System.Text.Encoding.ASCII.GetBytes(root.ExportCertificatePem()));

        }

        /// <summary>
        /// A file of this content in the temporary directory, taken away after
        /// the test.
        /// </summary>
        private String Kept(String Extension, Byte[] Content)
        {
            var file = Path.Combine(Path.GetTempPath(), $"command-line-{Guid.NewGuid():N}{Extension}");
            File.WriteAllBytes(file, Content);
            kept.Add(file);
            return file;
        }

        private readonly List<String> kept = [];

        [TearDown]
        public void TakeTheFilesAway()
        {
            foreach (var file in kept)
                File.Delete(file);
            kept.Clear();
        }

        /// <summary>
        /// What the error stream was told, its lines joined as one.
        /// </summary>
        private static String Flat(StringWriter Said)

            => String.Join(" ", Said.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));

        /// <summary>
        /// The lines of what the error stream was told that are wider than a
        /// terminal, but for a word too long for any line - a path - which has
        /// one of its own.
        /// </summary>
        private static IEnumerable<String> TooWide(StringWriter Said)

            => Said.ToString().Split(Environment.NewLine).Where(line => line.Length > NodeUsage.Width && line.Contains(' '));

        #endregion


        #region EverySwitchEveryNodeHasIsRead()

        /// <summary>
        /// Each switch sets what it says it sets, and nothing is left over.
        /// </summary>
        [Test]
        public void EverySwitchEveryNodeHasIsRead()
        {

            var frontend  = Directory.CreateTempSubdirectory("node-frontend-").FullName;

            try
            {

                var parsed = NodeArguments.Parse([ "--port", "8080", "--any", "--frontend", frontend,
                                                   "--accounts", "people", "--config", "node.json",
                                                   "-v", "--no-trace", "--log-file", "logs-here",
                                                   "--certificate-password", "secret", "--list-certificates",
                                                   "--import-certificate", "tlsRoot=root.pem",
                                                   "--import-certificate", "tlsServer=server.pem" ]);

                Assert.Multiple(() => {
                    Assert.That(parsed.Problem,              Is.Null);
                    Assert.That(parsed.Port,                 Is.EqualTo(IPPort.Parse(8080)));
                    Assert.That(parsed.HTTPHostname,         Is.EqualTo(IPvXAddress.Any));
                    Assert.That(parsed.FrontendDirectory,    Is.EqualTo(frontend));
                    Assert.That(parsed.Frontend,             Is.Not.Null);
                    Assert.That(parsed.AccountsPath,         Is.EqualTo("people"));
                    Assert.That(parsed.ConfigFilePath,       Is.EqualTo("node.json"));
                    Assert.That(parsed.ConsoleLogLevel,      Is.EqualTo(LogLevel.Debug));
                    Assert.That(parsed.NoTrace,              Is.True);
                    Assert.That(parsed.LogPathBelow("root"), Is.EqualTo("logs-here"));
                    Assert.That(parsed.CertificatePassword,  Is.EqualTo("secret"));
                    Assert.That(parsed.ListCertificates,     Is.True);
                    Assert.That(parsed.CertificateImports,   Is.EqualTo(new[] { (CertificateKind.TLSRoot,   "root.pem"),
                                                                                (CertificateKind.TLSServer, "server.pem") }));
                    Assert.That(parsed.Rest,                 Is.Empty);
                });

            }
            finally
            {
                Directory.Delete(frontend);
            }

        }

        #endregion

        #region WithoutSwitchesTheNodeListensOnlyHereAndWritesBelowTheRoot()

        /// <summary>
        /// No switch at all: 127.0.0.1, the kind's own port and frontend, the
        /// console at information, and every file below the repository root -
        /// the log files too, since a console nobody watched keeps nothing.
        /// </summary>
        [Test]
        public void WithoutSwitchesTheNodeListensOnlyHereAndWritesBelowTheRoot()
        {

            var parsed = NodeArguments.Parse([]);
            var root   = Path.Combine("repository", "root");

            Assert.Multiple(() => {
                Assert.That(parsed.Problem,                    Is.Null);
                Assert.That(parsed.Port,                       Is.Null);
                Assert.That(parsed.HTTPHostname,               Is.EqualTo(IPv4Address.Localhost));
                Assert.That(parsed.Frontend,                   Is.Null);
                Assert.That(parsed.ConsoleLogLevel,            Is.EqualTo(LogLevel.Info));
                Assert.That(parsed.AccountsPathBelow(root),    Is.EqualTo(Path.Combine(root, WWCPNode.DefaultAccountsPath)));
                Assert.That(parsed.ConfigFilePathBelow(root),  Is.EqualTo(Path.Combine(root, Configuration.WWCPConfigFile.DefaultFileName)));
                Assert.That(parsed.LogPathBelow(root),         Is.EqualTo(Path.Combine(root, WWCPNode.DefaultLogPath)));
                Assert.That(parsed.CertificatesPath,           Is.Null, "the configuration file's to say");
                Assert.That(NodeArguments.Parse([ "--log-file", "x", "--no-log-file" ]).LogPathBelow(root), Is.Null, "--no-log-file wins");
                Assert.That(NodeArguments.Parse([ "-q" ]).ConsoleLogLevel, Is.EqualTo(LogLevel.Warning));
            });

        }

        #endregion

        #region WhatTheNodeDoesNotKnowIsLeftForTheKindAsItWasTyped()

        /// <summary>
        /// A kind's switches and their values arrive in the kind's hands in the
        /// order they were typed, the node's taken out from between them - so a
        /// kind reads its own with the loop it had.
        /// </summary>
        [Test]
        public void WhatTheNodeDoesNotKnowIsLeftForTheKindAsItWasTyped()
        {

            var parsed = NodeArguments.Parse([ "--name", "EV01", "--port", "8080", "--vin", "WVWZZZ", "-q", "--sdp" ]);

            Assert.Multiple(() => {
                Assert.That(parsed.Problem,  Is.Null);
                Assert.That(parsed.Port,     Is.EqualTo(IPPort.Parse(8080)));
                Assert.That(parsed.Quiet,    Is.True);
                Assert.That(parsed.Rest,     Is.EqualTo(new[] { "--name", "EV01", "--vin", "WVWZZZ", "--sdp" }));
            });

            var i = 0;

            Assert.Multiple(() => {
                Assert.That(NodeArguments.TryTakeValue(parsed.Rest, ref i, out var name), Is.True);
                Assert.That(name, Is.EqualTo("EV01"));
                Assert.That(i,    Is.EqualTo(1), "the index is moved onto the value");
                i = 4;
                Assert.That(NodeArguments.TryTakeValue(parsed.Rest, ref i, out _), Is.False, "nothing after --sdp");
            });

        }

        #endregion

        #region ASwitchWithoutItsValueIsRefusedInItsOwnWords(Arguments, Problem)

        /// <summary>
        /// A switch whose value is missing - or is the next switch - is refused
        /// in the words every kind of node used, and nothing after it is read.
        /// </summary>
        [TestCase(new[] { "--port" },                          "Missing or invalid port number after --port!")]
        [TestCase(new[] { "--port", "70000" },                 "Missing or invalid port number after --port!")]
        [TestCase(new[] { "--frontend" },                      "Missing directory after --frontend!")]
        [TestCase(new[] { "--accounts", "--verbose" },         "Missing directory after --accounts!")]
        [TestCase(new[] { "--config" },                        "Missing file after --config!")]
        [TestCase(new[] { "--log-file" },                      "Missing directory after --log-file!")]
        [TestCase(new[] { "--certificates" },                  "Missing directory after --certificates!")]
        [TestCase(new[] { "--certificate-password" },          "Missing password after --certificate-password!")]
        [TestCase(new[] { "--import-certificate" },            "Missing <kind>=<file> after --import-certificate!")]
        [TestCase(new[] { "--import-certificate", "root.pem" }, "--import-certificate wants <kind>=<file>, and 'root.pem' is not that.")]
        [TestCase(new[] { "--import-certificate", "tlsRoot=" }, "--import-certificate wants <kind>=<file>, and 'tlsRoot=' is not that.")]
        [TestCase(new[] { "--verbose", "--quiet" },            "--verbose and --quiet ask for opposite things!")]
        public void ASwitchWithoutItsValueIsRefusedInItsOwnWords(String[] Arguments, String Problem)
        {

            var parsed  = NodeArguments.Parse(Arguments);
            var said    = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(parsed.Problem,                                         Is.EqualTo(Problem));
                Assert.That(parsed.Refused(Usage(), TextWriter.Null, said),         Is.EqualTo(2));
                Assert.That(said.ToString().TrimEnd(),                              Is.EqualTo(Problem));
            });

        }

        #endregion

        #region AnImportIsAKindOfCertificateAndAFile()

        /// <summary>
        /// --import-certificate names a kind there is: anything else is refused
        /// with the kinds there are. Whether the node keeps that kind is the
        /// node's to say once it is there.
        /// </summary>
        [Test]
        public void AnImportIsAKindOfCertificateAndAFile()
        {

            var parsed = NodeArguments.Parse([ "--import-certificate", "nothing=root.pem" ]);

            Assert.Multiple(() => {
                Assert.That(parsed.Problem, Does.StartWith("'nothing' is not a kind of certificate. Use one of "));
                Assert.That(parsed.Problem, Does.Contain("tlsRoot").And.Contain("v2gRoot"));
                Assert.That(NodeArguments.Parse([ "--import-certificate", "tlsIdentity=a=b.p12" ]).CertificateImports,
                            Is.EqualTo(new[] { (CertificateKind.TLSIdentity, "a=b.p12") }),
                            "split at the first '='");
            });

        }

        #endregion

        #region TheCertificateStoreIsMeasuredFromWhereTheNodeIsStarted()

        /// <summary>
        /// A relative --certificates is measured from where the node is started,
        /// as every other path on its command line is - handed on relative, the
        /// node would measure it from the configuration file.
        /// </summary>
        [Test]
        public void TheCertificateStoreIsMeasuredFromWhereTheNodeIsStarted()

            => Assert.That(NodeArguments.Parse([ "--certificates", "store" ]).CertificatesPath,
                           Is.EqualTo(Path.GetFullPath("store")));

        #endregion

        #region HelpIsTheUsageAndNothingElse()

        /// <summary>
        /// -h stops reading: whatever follows is neither refused nor left for
        /// the kind, and Main returns 0 after the usage.
        /// </summary>
        [Test]
        public void HelpIsTheUsageAndNothingElse()
        {

            var parsed  = NodeArguments.Parse([ "-h", "--port" ]);
            var shown   = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(parsed.WantsHelp,                               Is.True);
                Assert.That(parsed.Problem,                                 Is.Null);
                Assert.That(parsed.Refused(Usage(), shown, TextWriter.Null), Is.EqualTo(0));
                Assert.That(shown.ToString(),                               Does.StartWith("Usage: TestNodeCLI [--port <number>]"));
            });

        }

        #endregion

        #region AWordNeitherKnowsIsUnknown()

        /// <summary>
        /// A kind with no switches of its own calls the first word left over
        /// unknown, and shows the usage after it; with nothing left over it
        /// goes on.
        /// </summary>
        [Test]
        public void AWordNeitherKnowsIsUnknown()
        {

            var said   = new StringWriter();
            var shown  = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(NodeArguments.Parse([ "-v", "--bogus", "x" ]).RefuseTheRest(Usage(), shown, said), Is.EqualTo(2));
                Assert.That(said.ToString().TrimEnd(),  Is.EqualTo("Unknown argument '--bogus'!"));
                Assert.That(shown.ToString(),           Does.StartWith("Usage: "));
                Assert.That(NodeArguments.Parse([ "-v" ]).RefuseTheRest(Usage()), Is.Null);
            });

        }

        #endregion

        #region AFrontendDirectoryThatIsNotThereIsSaidSo()

        [Test]
        public void AFrontendDirectoryThatIsNotThereIsSaidSo()
        {

            var nowhere = Path.Combine(Path.GetTempPath(), $"no-frontend-{Guid.NewGuid():N}");

            Assert.That(NodeArguments.Parse([ "--frontend", nowhere ]).Problem,
                        Is.EqualTo($"The frontend directory '{nowhere}' does not exist!"));

        }

        #endregion


        #region TheUsageNamesTheKindItsPortAndWhereItsFrontendIsBuilt()

        /// <summary>
        /// What -h shows is the kind's: its program, its port, where its
        /// frontend is built, its name where the prompt is explained, and the
        /// variable a certificate's password is read from.
        /// </summary>
        [Test]
        public void TheUsageNamesTheKindItsPortAndWhereItsFrontendIsBuilt()
        {

            var usage = String.Join("\n", Usage().Lines());

            Assert.Multiple(() => {
                Assert.That(usage, Does.StartWith("Usage: TestNodeCLI [--port <number>] [--any]"));
                Assert.That(usage, Does.Contain("(default: 4711)"));
                Assert.That(usage, Does.Contain("'npm run watch' in libs/Test/Test/Frontend"));
                Assert.That(usage, Does.Contain("stops the test node"));
                Assert.That(usage, Does.Contain("TESTNODE_CERT_PASSWORD"));
                Assert.That(usage, Does.Contain($"last {EventLog.DefaultCapacity} entries"));
                Assert.That(usage, Does.Contain("SIGTERM"));
            });

        }

        #endregion

        #region NoLineOfTheUsageIsWiderThanEightyColumns()

        /// <summary>
        /// Wrapped at 80 columns, whatever the kind and its program are called.
        /// </summary>
        [Test]
        public void NoLineOfTheUsageIsWiderThanEightyColumns()
        {

            var usage = Usage(Program:  "ModbusTLSEnergyMeterCLI",
                              Kind:     new NodeKind("Modbus/TLS energy meter", "meter", "ModbusTLSEnergyMeter", "Meter", "meter"),
                              Synopsis: [ "[--listen <address>]", "[--idle-timeout <s>]", "[--selftest [<role>]]" ]);

            Assert.That(usage.Lines().Where(line => line.Length > NodeUsage.Width), Is.Empty);

        }

        #endregion

        #region TheKindsOwnLinesStandWhereTheyBelong()

        /// <summary>
        /// A kind's switches in the first lines, its other listeners after the
        /// web interface's switches, its own sections before the log's.
        /// </summary>
        [Test]
        public void TheKindsOwnLinesStandWhereTheyBelong()
        {

            var lines = Usage(Synopsis:  [ "[--kiosk-port <n>]" ],
                              After:     [ "Display:", "  --kiosk-port <n>  the display's port", "" ],
                              Before:    [ "V2G:", "  --v2g             the wire below the cable", "" ]).Lines().ToList();

            var usageEnds   = lines.IndexOf("");
            var accounts    = lines.IndexOf("Accounts:");
            var display     = lines.IndexOf("Display:");
            var web         = lines.IndexOf("Web interface:");
            var v2g         = lines.IndexOf("V2G:");
            var log         = lines.IndexOf("Log:");
            var store       = lines.FindIndex(line => line.StartsWith("The certificate store"));

            Assert.Multiple(() => {
                Assert.That(lines.Take(usageEnds).Any(line => line.Contains("[--kiosk-port <n>]")), Is.True, "in the usage lines");
                Assert.That(display, Is.GreaterThan(web).And.LessThan(accounts));
                Assert.That(v2g,     Is.GreaterThan(store).And.LessThan(log));
            });

        }

        #endregion

        #region OnlyTheKindsOfCertificateTheNodeKeepsAreListed()

        [Test]
        public void OnlyTheKindsOfCertificateTheNodeKeepsAreListed()
        {

            var usage = Usage(CertificateKinds: [ CertificateKind.TLSRoot, CertificateKind.TLSServer ]).Lines().ToArray();

            Assert.Multiple(() => {
                Assert.That(usage.Any(line => line.TrimStart().StartsWith("tlsRoot ")),    Is.True);
                Assert.That(usage.Any(line => line.TrimStart().StartsWith("tlsServer ")),  Is.True);
                Assert.That(usage.Any(line => line.TrimStart().StartsWith("v2gRoot ")),    Is.False);
            });

        }

        #endregion

        #region AKindOfCertificateTheNodeDoesNotKeepIsRefusedBeforeItIsMade()

        /// <summary>
        /// A kind of certificate the node does not keep is refused with the
        /// command line, before the node is made - made first, the EMSP had a
        /// mobility operator's root and nine lines of log before it said no -
        /// and the kinds named are the node's, not all eleven there are (found
        /// by the hub, the EMSP, the gateway and the CSMS).
        /// </summary>
        [Test]
        public void AKindOfCertificateTheNodeDoesNotKeepIsRefusedBeforeItIsMade()
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            var another  = new StringWriter();
            var nothing  = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(NodeArguments.Parse([ "--import-certificate", "v2gRoot=root.pem" ]).Refused(Usage(tls), TextWriter.Null, another),
                            Is.EqualTo(2));
                Assert.That(Flat(another),
                            Is.EqualTo("'v2gRoot' is not a kind of certificate this test node keeps. Use one of tlsRoot, tlsServer, tlsIdentity."));
                Assert.That(TooWide(another), Is.Empty);
                Assert.That(NodeArguments.Parse([ "--import-certificate", "nothing=root.pem" ]).Refused(Usage(tls), TextWriter.Null, nothing),
                            Is.EqualTo(2));
                Assert.That(Flat(nothing),
                            Is.EqualTo("'nothing' is not a kind of certificate this test node keeps. Use one of tlsRoot, tlsServer, tlsIdentity."));
                Assert.That(NodeArguments.Parse([ "--import-certificate", $"tlsRoot={ARoot()}" ]).Refused(Usage(tls)),
                            Is.Null);
            });

        }

        #endregion

        #region AFileThatIsNotThereIsRefusedBeforeTheNodeIsMade()

        /// <summary>
        /// A file to import that is not there is refused with the command line
        /// too, before the node is made: said once the node was made, it left
        /// behind a certificate store and a log with the signing key of the
        /// log book, for nothing (found by the hub).
        /// </summary>
        [Test]
        public void AFileThatIsNotThereIsRefusedBeforeTheNodeIsMade()
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            var missing  = Path.Combine(Path.GetTempPath(), $"not-there-{Guid.NewGuid():N}.pem");
            var said     = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(NodeArguments.Parse([ "--import-certificate", $"tlsRoot={ARoot()}",
                                                  "--import-certificate", $"tlsServer={missing}" ]).Refused(Usage(tls), TextWriter.Null, said),
                            Is.EqualTo(2));
                Assert.That(Flat(said),
                            Is.EqualTo($"--import-certificate: there is no file '{missing}'."));
            });

        }

        #endregion

        #region AFileThatWouldNotGoInIsRefusedBeforeTheNodeIsMade(What)

        /// <summary>
        /// A file to import that is there and would not go in as the kind it is
        /// given as - no certificate at all, a PKCS#12 whose password was not
        /// given, a certificate without the key its kind needs - is refused
        /// with the command line too, before the node is made, in the words the
        /// import would have said it in, and in lines of 80 columns. Refused
        /// once the node was made, it left behind a certificate store, a log
        /// with the log book's signing key and an empty directory of accounts
        /// (found by the charging station and the hub), and it was one line of
        /// 355 columns (found by the hub).
        /// </summary>
        [TestCase("no certificate")]
        [TestCase("no password")]
        [TestCase("no key")]
        public void AFileThatWouldNotGoInIsRefusedBeforeTheNodeIsMade(String What)
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            var (kind, file) = What switch {
                "no certificate"  => ("tlsRoot",      Kept(".pem", System.Text.Encoding.ASCII.GetBytes("This is a note, and no certificate at all.\n"))),
                "no password"     => ("tlsIdentity",  AnIdentityWithAPassword()),
                "no key"          => ("tlsIdentity",  ARoot()),
                _                 => throw new ArgumentException(What)
            };

            var said = new StringWriter();

            Assert.Multiple(() => {

                Assert.That(NodeArguments.Parse([ "--import-certificate", $"{kind}={file}" ]).Refused(Usage(tls), TextWriter.Null, said),
                            Is.EqualTo(2));

                Assert.That(Flat(said), Does.StartWith($"--import-certificate: {file} could not be imported as {kind}: "));

                if (What == "no key")
                    Assert.That(Flat(said), Does.EndWith("could not be imported as tlsIdentity: A TLS identity has to carry its private key, " +
                                                         "and that file has none. It is probably a PKCS#12 that needs a password, " +
                                                         "or the public half of the pair."));

                Assert.That(TooWide(said), Is.Empty);

            });

        }

        /// <summary>
        /// A TLS identity with its key, in a PKCS#12 that a password opens.
        /// </summary>
        private String AnIdentityWithAPassword()
        {

            using var key       = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var       request   = new CertificateRequest("CN=An Identity For The Command Line", key, HashAlgorithmName.SHA256);
            using var identity  = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            return Kept(".p12", identity.Export(X509ContentType.Pkcs12, "opensesame")!);

        }

        #endregion

        #region AFileWhosePasswordIsGivenIsNotRefused(Given)

        /// <summary>
        /// A PKCS#12 whose password is given - with --certificate-password, or
        /// in the kind's environment variable where the switch gives none - is
        /// not refused: it is asked with the password the import is handed.
        /// </summary>
        [TestCase("--certificate-password")]
        [TestCase("the environment")]
        public void AFileWhosePasswordIsGivenIsNotRefused(String Given)
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            var file      = AnIdentityWithAPassword();
            var variable  = NodeProgram.CertificatePasswordVariable(TestKind);
            var was       = Environment.GetEnvironmentVariable(variable);
            var said      = new StringWriter();

            String[] arguments = Given == "--certificate-password"
                                     ? [ "--import-certificate", $"tlsIdentity={file}", "--certificate-password", "opensesame" ]
                                     : [ "--import-certificate", $"tlsIdentity={file}" ];

            try
            {

                Environment.SetEnvironmentVariable(variable, Given == "the environment" ? "opensesame" : null);

                Assert.That(NodeArguments.Parse(arguments).Refused(Usage(tls), TextWriter.Null, said), Is.Null, said.ToString());

            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, was);
            }

        }

        #endregion

        #region AFileThatOpensOnlyWithAPasswordSaysWhereThePasswordGoes(What)

        /// <summary>
        /// A file that opens only with a password, and was given none - a
        /// PKCS#12, or a PEM whose key is encrypted - is refused with just that,
        /// and with where the password goes: the switch, or the kind's variable.
        /// A PKCS#12 was refused with .NET's "... with the provided password, the
        /// password may be incorrect", where none had been provided, and nothing
        /// said how to give one (found by the EMSP). An empty password is none.
        /// </summary>
        [TestCase("a PKCS#12")]
        [TestCase("a PKCS#12, with an empty password")]
        [TestCase("a PEM whose key is encrypted")]
        public void AFileThatOpensOnlyWithAPasswordSaysWhereThePasswordGoes(String What)
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            var (file, refused) = What == "a PEM whose key is encrypted"
                                      ? (AnIdentityWhoseKeyIsEncryptedInPem(), "That file's private key is encrypted, and no password was given.")
                                      : (AnIdentityWithAPassword(),            "That file is a PKCS#12 that could not be opened without a password.");

            String[] arguments = What == "a PKCS#12, with an empty password"
                                     ? [ "--import-certificate", $"tlsIdentity={file}", "--certificate-password", "" ]
                                     : [ "--import-certificate", $"tlsIdentity={file}" ];

            var variable  = NodeProgram.CertificatePasswordVariable(TestKind);
            var was       = Environment.GetEnvironmentVariable(variable);
            var said      = new StringWriter();

            try
            {

                Environment.SetEnvironmentVariable(variable, null);

                Assert.Multiple(() => {
                    Assert.That(NodeArguments.Parse(arguments).Refused(Usage(tls), TextWriter.Null, said), Is.EqualTo(2));
                    Assert.That(Flat(said), Is.EqualTo($"--import-certificate: {file} could not be imported as tlsIdentity: {refused} " +
                                                       $"Give the password with --certificate-password, or in {variable}."));
                    Assert.That(TooWide(said), Is.Empty);
                });

            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, was);
            }

        }

        /// <summary>
        /// A TLS identity whose key is in the same PEM, encrypted with a password.
        /// </summary>
        private String AnIdentityWhoseKeyIsEncryptedInPem()
        {

            using var key       = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var       request   = new CertificateRequest("CN=An Identity Whose Key Is Locked", key, HashAlgorithmName.SHA256);
            using var identity  = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            return Kept(".pem", System.Text.Encoding.ASCII.GetBytes(
                                    identity.ExportCertificatePem() + "\n" +
                                    key.ExportEncryptedPkcs8PrivateKeyPem("opensesame",
                                                                          new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)) + "\n"));

        }

        #endregion

        #region AWrongPasswordIsNotToldWhereAPasswordGoes()

        /// <summary>
        /// A PKCS#12 given with a password that does not open it is refused as
        /// it was, "wrong password?", and not told where a password goes: one
        /// was given.
        /// </summary>
        [Test]
        public void AWrongPasswordIsNotToldWhereAPasswordGoes()
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            var file  = AnIdentityWithAPassword();
            var said  = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(NodeArguments.Parse([ "--import-certificate", $"tlsIdentity={file}", "--certificate-password", "not the one" ]).
                                          Refused(Usage(tls), TextWriter.Null, said),
                            Is.EqualTo(2));
                Assert.That(Flat(said), Does.StartWith($"--import-certificate: {file} could not be imported as tlsIdentity: " +
                                                       "That file could not be read - wrong password? ("));
                Assert.That(Flat(said), Does.Not.Contain("Give the password with"));
            });

        }

        #endregion

        #region AFileThatIsNoPkcs12IsNotAskedForAPassword()

        /// <summary>
        /// A file that is DER and neither a certificate nor a PKCS#12 - a key -
        /// is refused as no certificate that can be read, and not asked for a
        /// password: its first byte, which a PKCS#12's is too, had it told "If
        /// it is a password-protected PKCS#12, give the password".
        /// </summary>
        [Test]
        public void AFileThatIsNoPkcs12IsNotAskedForAPassword()
        {

            CertificateKind[] tls = [ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ];

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var       file = Kept(".der", key.ExportPkcs8PrivateKey());
            var       said = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(NodeArguments.Parse([ "--import-certificate", $"tlsRoot={file}" ]).Refused(Usage(tls), TextWriter.Null, said),
                            Is.EqualTo(2));
                Assert.That(Flat(said), Is.EqualTo($"--import-certificate: {file} could not be imported as tlsRoot: " +
                                                   "That file is not a certificate that can be read (PEM, DER or PKCS#12)."));
            });

        }

        #endregion

        #region ADashBetweenWordsNeverBeginsALine()

        /// <summary>
        /// A dash between words stays with the word before it: broken before
        /// it, a line began "- which", which reads as a switch (found in the
        /// charging station's --v2g-loopback).
        /// </summary>
        [Test]
        public void ADashBetweenWordsNeverBeginsALine()
        {

            // "well" ends at column 79, where the dash no longer fits.
            var text   = new String('x', 74) + " well - which of the two sockets";
            var lines  = NodeUsage.Wrap(text, "", "").ToArray();

            Assert.Multiple(() => {
                Assert.That(lines.Where(line => line.TrimStart().StartsWith("- ")),  Is.Empty);
                Assert.That(lines.Where(line => line.Length > NodeUsage.Width),     Is.Empty);
                Assert.That(String.Join(" ", lines),                                Is.EqualTo(text));
            });

        }

        #endregion

        #region ANumberNeverBeginsALine()

        /// <summary>
        /// A number stays with the word before it: broken before it, "could
        /// not be given port" ended a line and "18261: something else is
        /// already listening on it" began the next (found by the hub and the
        /// CSMS).
        /// </summary>
        [Test]
        public void ANumberNeverBeginsALine()
        {

            var text   = "The roaming hub could not start: The web interface could not be given port 18261: " +
                         "something else is already listening on it.";

            var lines  = NodeUsage.Wrap(text, "", "").ToArray();

            Assert.Multiple(() => {
                Assert.That(lines.Where(line => Char.IsAsciiDigit(line.TrimStart()[0])),  Is.Empty);
                Assert.That(lines[0],                                                    Does.EndWith("could not be given"));
                Assert.That(lines.Where(line => line.Length > NodeUsage.Width),          Is.Empty);
                Assert.That(String.Join(" ", lines),                                     Is.EqualTo(text));
            });

        }

        #endregion

        #region ANumberThatBeginsAParagraphStaysWhereItIs()

        /// <summary>
        /// A number with no word before it - the first of a paragraph - begins
        /// the first line, and a dash kept with its word keeps a number after
        /// it as well.
        /// </summary>
        [Test]
        public void ANumberThatBeginsAParagraphStaysWhereItIs()
        {

            Assert.Multiple(() => {
                Assert.That(NodeUsage.Wrap("443 is the port the web interface listens on.", "", "").Single(),
                            Is.EqualTo("443 is the port the web interface listens on."));
                Assert.That(String.Join("|", NodeUsage.Wrap(new String('x', 70) + " again - 30 seconds later", "", "")),
                            Is.EqualTo(new String('x', 70) + "|again - 30 seconds later"));
            });

        }

        #endregion

        #region TheLogsSwitchesStandInTwoColumns()

        /// <summary>
        /// In the log's section a switch with a short form begins at column 2,
        /// and one without at column 6, below the long form of the ones above -
        /// --log-file stood at column 2 between two at 6 (found by the CSMS).
        /// </summary>
        [Test]
        public void TheLogsSwitchesStandInTwoColumns()
        {

            var log = Usage().Lines().
                          SkipWhile(line => line != "Log:").
                          Skip(1).
                          TakeWhile(line => line.Length > 0).
                          Where(line => line.TrimStart().StartsWith('-')).
                          ToArray();

            Assert.That(log.Select(line => line.Length - line.TrimStart().Length), Is.EqualTo(new[] { 2, 2, 6, 6, 6 }),
                        String.Join("\n", log));

        }

        #endregion

        #region WhatHasToBringItsPrivateKeyIsSaidOfTheKindsTheNodeKeeps()

        /// <summary>
        /// What has to bring its private key is said of the kinds the node
        /// keeps: "a TLS identity" was all it said, above a list with the
        /// vehicle's, the contract's and the OEM's in it (found by the EV).
        /// </summary>
        [Test]
        public void WhatHasToBringItsPrivateKeyIsSaidOfTheKindsTheNodeKeeps()
        {

            static String Said(NodeUsage Usage) => String.Join(" ", Usage.Lines().Select(line => line.Trim()));

            Assert.Multiple(() => {
                Assert.That(Said(Usage()),
                            Does.Contain("a vehicle, contract, oemProvisioning, tlsIdentity or tlsServerIdentity has to bring its private key"));
                Assert.That(Said(Usage([ CertificateKind.TLSRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ])),
                            Does.Contain("a tlsIdentity has to bring its private key"));
                Assert.That(Said(Usage([ CertificateKind.V2GRoot, CertificateKind.TLSRoot ])),
                            Does.Not.Contain("private key"));
            });

        }

        #endregion

        #region TheKindsOfCertificateAreSaidOfTheKindOfNode()

        /// <summary>
        /// "What this node presents" in a usage that says "this roaming hub"
        /// everywhere else read as if it were somebody else's (found by the hub
        /// and the EV): the kinds are said of the kind of node.
        /// </summary>
        [Test]
        public void TheKindsOfCertificateAreSaidOfTheKindOfNode()
        {

            var said = String.Join(" ", Usage([ CertificateKind.TLSRoot, CertificateKind.ClientRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ]).
                                            Lines().Select(line => line.Trim()));

            Assert.Multiple(() => {
                Assert.That(said, Does.Contain("what a server this test node connects to may chain to"));
                Assert.That(said, Does.Contain("who this test node is to a server that asks"));
                Assert.That(said, Does.Not.Contain("this node"));
            });

        }

        #endregion

        #region WhatAKindSaysOfItsStoreStandsBelowItsKinds()

        /// <summary>
        /// Below the kinds, that a root or a server certificate holds for every
        /// use until the web interface narrows it, as the EV had said it, and
        /// what the kind says of its store itself - the hub's "used by nothing
        /// here yet" was gone with its own usage.
        /// </summary>
        [Test]
        public void WhatAKindSaysOfItsStoreStandsBelowItsKinds()
        {

            var lines     = Usage([ CertificateKind.TLSRoot, CertificateKind.ClientRoot, CertificateKind.TLSServer, CertificateKind.TLSIdentity ],
                                  CertificatesSays: "clientRoot and tlsIdentity are kept, and used by nothing here yet.").Lines().ToList();
            var said      = String.Join(" ", lines.Select(line => line.Trim()));
            var kinds     = lines.FindIndex(line => line.TrimStart().StartsWith("tlsIdentity "));
            var password  = lines.FindIndex(line => line.TrimStart().StartsWith("--certificate-password"));
            var between   = String.Join(" ", lines.Skip(kinds + 1).Take(password - kinds - 1).Select(line => line.Trim()));

            Assert.Multiple(() => {
                Assert.That(said,     Does.Contain("A tlsRoot or tlsServer imported here holds for every use until the web interface narrows it."));
                Assert.That(between,  Does.Contain("clientRoot and tlsIdentity are kept, and used by nothing here yet."), "below the kinds, above the next switch");
                Assert.That(String.Join(" ", Usage([ CertificateKind.V2GRoot, CertificateKind.TLSIdentity ]).Lines()),
                            Does.Not.Contain("for every use"), "a TLS identity is told its uses by its node's listeners");
            });

        }

        #endregion

        #region ASynopsisIsBrokenBetweenItsSwitchesOnly()

        /// <summary>
        /// A kind whose synopsis is its own - the energy meter's - breaks it
        /// between its switches, as the node's is broken: Wrap, which breaks
        /// between words, would part "[--listen &lt;address&gt;]".
        /// </summary>
        [Test]
        public void ASynopsisIsBrokenBetweenItsSwitchesOnly()
        {

            String[] switches = [ "[--port <number>]", "[--any | --listen <address>]", "[--idle-timeout <seconds>]", "[--write-timeout <seconds>]",
                                  "[--http-port <number>]", "[--https]", "[--config <file>]", "[--data <directory>]", "[--selftest [<role>]]" ];

            var first  = "Usage: ModbusTLSEnergyMeterCLI ";
            var lines  = NodeUsage.WrapItems(switches, first, new String(' ', first.Length)).ToArray();

            Assert.Multiple(() => {
                Assert.That(lines.Length,                                           Is.GreaterThan(1));
                Assert.That(lines.Where(line => line.Length > NodeUsage.Width),     Is.Empty);
                Assert.That(switches.All(item => lines.Any(line => line.Contains(item))), Is.True, String.Join("\n", lines));
            });

        }

        #endregion

    }

}
