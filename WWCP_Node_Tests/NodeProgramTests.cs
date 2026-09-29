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

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the program of every kind of node does between its command line
    /// and its prompt: the banner - the same lines in the same places, where
    /// eight kinds had let them come apart - why a node could not be set up
    /// or could not start, and what the command line puts into the
    /// certificate store.
    /// </summary>
    [TestFixture]
    public class NodeProgramTests
    {

        #region Data

        private String  directory  = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeTheDirectory()
        {
            directory = Path.Combine(Path.GetTempPath(), $"node-program-{Guid.NewGuid().ToString("N")[..12]}");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void LetTheDirectoryGo()
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // A file let go of a moment too late; the temporary directory
                // is the system's to clear.
            }
        }

        #endregion

        #region (helper) Node(Port = null, CertificateKinds = null)

        /// <summary>
        /// A node of no particular kind in this test's directory, with no
        /// accounts yet: made, not started.
        /// </summary>
        private WWCPNode Node(IPPort?                        Port              = null,
                              IEnumerable<CertificateKind>?  CertificateKinds  = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            return new WWCPNode(
                       HTTPPort:          Port ?? IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       CertificateKinds:  CertificateKinds,
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        #endregion

        #region (helper) Root(Name)

        /// <summary>
        /// A self-signed CA certificate, as PEM, in a file of this test's directory.
        /// </summary>
        private String Root(String Name)
        {

            using var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var       request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

            var file = Path.Combine(directory, $"{Name}.pem");

            File.WriteAllText(file, certificate.ExportCertificatePem());

            return file;

        }

        #endregion


        #region TheBannerSaysWhereTheNodeAnswersAndWhereItsFilesAre()

        /// <summary>
        /// The node's lines, their values from the node, all at column 17 -
        /// begun and ended with an empty line, and the password made up at the
        /// first start in its box.
        /// </summary>
        [Test]
        public async Task TheBannerSaysWhereTheNodeAnswersAndWhereItsFilesAre()
        {

            await using var node = await TestPorts.StartedOnFreshPorts(() => Node());

            var banner = node.Banner();

            Assert.Multiple(() => {
                Assert.That(banner[0],                                          Is.Empty);
                Assert.That(banner[^1],                                         Is.Empty);
                Assert.That(banner, Has.Some.EqualTo($"  web interface  {node.WebInterfaceURL}"));
                Assert.That(banner, Has.Some.EqualTo($"  JSON API       {node.APIURL}v1/status"));
                Assert.That(banner, Has.Some.EqualTo($"  event stream   {node.APIURL}v1/events"));
                Assert.That(banner, Has.Some.EqualTo($"  HTTPExt API    {node.WebInterfaceURL}ext/"));
                Assert.That(banner, Has.Some.EqualTo($"  configuration  {node.ConfigFile.Path}"));
                Assert.That(banner, Has.Some.EqualTo($"  accounts       1 user(s) in {node.AccountsPath}"));
                Assert.That(banner, Has.Some.EqualTo($"  sign in at     {node.WebInterfaceURL}ext/login"));
                Assert.That(banner, Has.Some.EqualTo( "  log files      none (--no-log-file)"));
                Assert.That(banner, Has.Some.EqualTo($"  certificates   0 in {node.Certificates.Directory}"));
                Assert.That(banner, Has.Some.EqualTo( "  name servers   switched off"));
                Assert.That(banner, Has.Some.StartsWith("  built from     "));
                Assert.That(banner, Has.Some.StartsWith("  time server"));
                Assert.That(banner, Has.Some.EqualTo( "  │  user      root"));
                Assert.That(banner, Has.Some.EqualTo($"  │  password  {node.GeneratedPassword}"));
            });

        }

        #endregion

        #region ALongerLabelMovesEveryValueFurtherIn()

        /// <summary>
        /// A kind's label longer than the node's moves every value further in,
        /// the node's and the lines of what it was built from as well - the
        /// roaming hub's "traffic stream" put all of its at 18.
        /// </summary>
        [Test]
        public async Task ALongerLabelMovesEveryValueFurtherIn()
        {

            await using var node = Node();

            var banner = node.Banner(BesideTheInterfaces: [ ("traffic stream", "somewhere") ]);

            Assert.Multiple(() => {
                Assert.That(banner, Has.Some.EqualTo($"  web interface   {node.WebInterfaceURL}"));
                Assert.That(banner, Has.Some.EqualTo( "  traffic stream  somewhere"));
                Assert.That(banner.Where(line => line.StartsWith("  built from")),
                            Has.All.Matches<String>(line => line[18] != ' ' && line[17] == ' '),
                            "the first repository at 18");
            });

        }

        #endregion

        #region TheKindsLinesStandInTheirPlaces()

        /// <summary>
        /// A kind's listeners after the node's interfaces, what it is after the
        /// node's files, and what comes after the time servers after them - and
        /// a value of two lines goes on below its first.
        /// </summary>
        [Test]
        public async Task TheKindsLinesStandInTheirPlaces()
        {

            await using var node = Node();

            var banner = node.Banner(BesideTheInterfaces:  [ ("display",  "http://127.0.0.1:1/") ],
                                     OfTheKind:            [ ("OCPP node", "lc001"), ("meter cert", "CN=meter\nvalid until 2027") ],
                                     AfterTheTimeServers:  [ ("V2G",       "switched off") ]).ToList();

            var index = (String start) => banner.FindIndex(line => line.StartsWith(start));

            Assert.Multiple(() => {
                Assert.That(index("  display"),       Is.GreaterThan(index("  HTTPExt API")).And.LessThan(index("  frontend from")));
                Assert.That(index("  OCPP node"),     Is.GreaterThan(index("  certificates")).And.LessThan(index("  name servers")));
                Assert.That(index("  V2G"),           Is.GreaterThan(index("  time server")));
                Assert.That(banner[index("  meter cert") + 1], Is.EqualTo("                 valid until 2027"));
            });

        }

        #endregion


        #region ANodeWhosePortIsTakenSaysWhichAndWhatToDo()

        /// <summary>
        /// A second copy of a node - here something else on its port - is not
        /// a stack trace: which port, whose, and what to do, and Main returns 1.
        /// </summary>
        [Test]
        public async Task ANodeWhosePortIsTakenSaysWhichAndWhatToDo()
        {

            var squatter = new TcpListener(System.Net.IPAddress.Loopback, 0);
            squatter.Start();

            try
            {

                var port  = (UInt16) ((IPEndPoint) squatter.LocalEndpoint).Port;
                var said  = new StringWriter();

                await using var node = Node(IPPort.Parse(port));

                var exit = await node.Started(Verbose: false, Error: said);

                Assert.Multiple(() => {
                    Assert.That(exit,            Is.EqualTo(1));
                    Assert.That(said.ToString(), Does.StartWith($"The WWCP node could not start: The web interface could not be given port {port}"));
                    Assert.That(said.ToString(), Does.Contain("Another copy of this WWCP node already running is the usual answer. " +
                                                              "Stop it, or give this one another port with --port <number>."));
                });

            }
            finally
            {
                squatter.Stop();
            }

        }

        #endregion

        #region WhatToDoAboutAPortDependsOnWhyAndWhose(Because, OnWindows, Advice)

        /// <summary>
        /// A second copy is the usual answer only where the address is in use;
        /// a port below 1024 wants rights on Linux, not on Windows; anything
        /// else is said as it is. And a port of the kind's own is the kind's
        /// to advise on.
        /// </summary>
        [TestCase(SocketError.AddressAlreadyInUse, false, "Another copy of this test node already running is the usual answer. Stop it, or give this one another port with --port <number>.")]
        [TestCase(SocketError.AccessDenied,        false, "Port 80 is privileged. Either start this as root, or once:|  sudo setcap cap_net_bind_service=+ep /usr/bin/node|or pick a port above 1024 with --port.")]
        [TestCase(SocketError.AccessDenied,        true,  "")]
        [TestCase(SocketError.AddressNotAvailable, false, "")]
        public void WhatToDoAboutAPortDependsOnWhyAndWhose(SocketError Because, Boolean OnWindows, String Advice)
        {

            var kind     = new NodeKind("test node", "test", "TestNode", "Test", "test");
            var problem  = new PortUnavailableException(IPPort.Parse(80), new SocketException((Int32) Because));

            Assert.Multiple(() => {
                Assert.That(String.Join("|", NodeProgram.AdviceOn(kind, problem, null, OnWindows, "/usr/bin/node")), Is.EqualTo(Advice));
                Assert.That(NodeProgram.AdviceOn(kind,
                                                 new PortUnavailableException(IPPort.Parse(9000), new SocketException((Int32) SocketError.AddressAlreadyInUse), new NodePort("The display")),
                                                 _ => "Stop whatever has it, or give the display another port with --kiosk-port <number>.",
                                                 false,
                                                 null),
                            Is.EqualTo(new[] { "Stop whatever has it, or give the display another port with --kiosk-port <number>." }));
            });

        }

        #endregion

        #region AFirstStartThatCannotHaveItsPortStillShowsThePasswordItMadeUp()

        /// <summary>
        /// The account is made before the port is opened, and the password
        /// made up for it is shown once: a first start that ended at a port in
        /// use made the account and never showed it, and the next start found
        /// "1 user(s)" and nobody who could sign in (found by the EMSP, the
        /// gateway and the CSMS).
        /// </summary>
        [Test]
        public async Task AFirstStartThatCannotHaveItsPortStillShowsThePasswordItMadeUp()
        {

            var squatter = new TcpListener(System.Net.IPAddress.Loopback, 0);
            squatter.Start();

            try
            {

                var port  = (UInt16) ((IPEndPoint) squatter.LocalEndpoint).Port;
                var said  = new StringWriter();

                await using var node = Node(IPPort.Parse(port));

                var exit  = await node.Started(Verbose: false, Error: said);
                var text  = said.ToString();

                Assert.Multiple(() => {
                    Assert.That(exit,                    Is.EqualTo(1));
                    Assert.That(node.GeneratedPassword,  Is.Not.Null, "the account was made before the port");
                    Assert.That(text,                    Does.Contain($"password  {node.GeneratedPassword}"));
                    Assert.That(text.IndexOf("First start", StringComparison.Ordinal),
                                Is.GreaterThan(text.IndexOf("could not start", StringComparison.Ordinal)),
                                "after what went wrong");
                });

            }
            finally
            {
                squatter.Stop();
            }

        }

        #endregion

        #region AStartThatFailsForAnotherReasonSaysWhyAndEndsWithOne()

        /// <summary>
        /// A node that cannot listen on its own port for another reason than
        /// the port - here a certificate it could not read.
        /// </summary>
        private sealed class NodeThatCannotListen(IPPort          Port,
                                                  String          AccountsPath,
                                                  WWCPConfigFile  ConfigFile)

            : WWCPNode(HTTPPort:        Port,
                       AccountsPath:    AccountsPath,
                       ConfigFile:      ConfigFile,
                       LogToConsole:    false,
                       BridgeDebugLog:  false)

        {

            protected override Task OnListening()
                => throw new InvalidOperationException("The charging station server's certificate could not be read.");

        }

        /// <summary>
        /// Whatever else a start fails with is said as it is, and Main returns
        /// 1 - only a port was caught, and anything else ran past Main as an
        /// unhandled exception (found by the energy meter).
        /// </summary>
        [Test]
        public async Task AStartThatFailsForAnotherReasonSaysWhyAndEndsWithOne()
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);
            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            var brief  = new StringWriter();
            var whole  = new StringWriter();

            await using var node   = new NodeThatCannotListen(IPPort.Parse(TestPorts.Free()), Path.Combine(directory, "accounts"),       new WWCPConfigFile(configuration));
            await using var again  = new NodeThatCannotListen(IPPort.Parse(TestPorts.Free()), Path.Combine(directory, "accounts-again"), new WWCPConfigFile(configuration));

            var exit     = await node. Started(Verbose: false, Error: brief);
            var verbose  = await again.Started(Verbose: true,  Error: whole);

            Assert.Multiple(() => {
                Assert.That(exit,              Is.EqualTo(1));
                Assert.That(brief.ToString(),  Does.StartWith("The WWCP node could not start: The charging station server's certificate could not be read."));
                Assert.That(brief.ToString(),  Does.Not.Contain("System.InvalidOperationException"));
                Assert.That(verbose,           Is.EqualTo(1));
                Assert.That(whole.ToString(),  Does.Contain("System.InvalidOperationException"), "the whole exception with --verbose");
            });

        }

        #endregion

        #region APortIsNamedByTheSwitchThatSetsIt()

        /// <summary>
        /// The advice names the switch that sets the port it is about: the
        /// energy meter's web interface is --http-port and its Modbus/TLS server
        /// --port, and a port below 1024 said "or pick a port above 1024" with
        /// neither (found by the energy meter). A port no switch sets is named
        /// by none.
        /// </summary>
        [Test]
        public void APortIsNamedByTheSwitchThatSetsIt()
        {

            var kind      = new NodeKind("energy meter", "meter", "ModbusTLSEnergyMeter", "Meter", "meter");
            var modbus    = new NodePort("The Modbus/TLS server");
            var switchOf  = (PortUnavailableException problem) => problem.Whose == modbus ? "--port" : "--http-port";

            PortUnavailableException Problem(UInt16 Port, SocketError Because, NodePort? Whose = null)
                => new (IPPort.Parse(Port), new SocketException((Int32) Because), Whose);

            Assert.Multiple(() => {
                Assert.That(NodeProgram.AdviceOn(kind, Problem(80,  SocketError.AccessDenied),         null, false, "/opt/meter/ModbusTLSEnergyMeterCLI", switchOf).Last(),
                            Is.EqualTo("or pick a port above 1024 with --http-port."));
                Assert.That(NodeProgram.AdviceOn(kind, Problem(802, SocketError.AccessDenied, modbus), null, false, "/opt/meter/ModbusTLSEnergyMeterCLI", switchOf).Last(),
                            Is.EqualTo("or pick a port above 1024 with --port."));
                Assert.That(NodeProgram.AdviceOn(kind, Problem(8080, SocketError.AddressAlreadyInUse), null, false, null, switchOf),
                            Is.EqualTo(new[] { "Another copy of this energy meter already running is the usual answer. Stop it, " +
                                               "or give this one another port with --http-port <number>." }));
                Assert.That(NodeProgram.AdviceOn(kind, Problem(802, SocketError.AccessDenied, modbus), null, false, "/opt/meter/ModbusTLSEnergyMeterCLI").Last(),
                            Is.EqualTo("or pick a port above 1024."), "a port no switch is known to set");
            });

        }

        #endregion

        #region SetcapIsNeverAdvisedForDotnetItself()

        /// <summary>
        /// Started as "dotnet LocalControllerCLI.dll", the program is the dotnet
        /// host, and setcap on it would give the ports below 1024 to every .NET
        /// program on the machine (found by the hub and the gateway): the right
        /// goes to a published program, or the node to a port above 1024.
        /// </summary>
        [TestCase("/usr/share/dotnet/dotnet")]
        [TestCase("/home/someone/.dotnet/dotnet")]
        public void SetcapIsNeverAdvisedForDotnetItself(String Dotnet)
        {

            var kind    = new NodeKind("test node", "test", "TestNode", "Test", "test");
            var advice  = NodeProgram.AdviceOn(kind,
                                               new PortUnavailableException(IPPort.Parse(80), new SocketException((Int32) SocketError.AccessDenied)),
                                               null,
                                               false,
                                               Dotnet).ToArray();

            Assert.Multiple(() => {
                Assert.That(advice.Where(line => line.Contains("setcap") && line.Contains(Dotnet)), Is.Empty, String.Join("\n", advice));
                Assert.That(advice, Does.Contain("  sudo setcap cap_net_bind_service=+ep <the published program>"));
                Assert.That(advice, Does.Contain("or pick a port above 1024 with --port."));
            });

        }

        #endregion

        #region ANodeThatCouldNotBeSetUpSaysWhy()

        [Test]
        public void ANodeThatCouldNotBeSetUpSaysWhy()
        {

            var kind     = new NodeKind("test node", "test", "TestNode", "Test", "test");
            var problem  = new InvalidOperationException("The configuration file is not JSON.");
            var brief    = new StringWriter();
            var whole    = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(NodeProgram.CouldNotBeSetUp(kind, problem, Verbose: false, brief), Is.EqualTo(1));
                Assert.That(brief.ToString().TrimEnd(), Is.EqualTo("The test node could not be set up: The configuration file is not JSON."));
                Assert.That(NodeProgram.CouldNotBeSetUp(kind, problem, Verbose: true,  whole), Is.EqualTo(1));
                Assert.That(whole.ToString(), Does.Contain("System.InvalidOperationException"), "the whole exception with --verbose");
            });

        }

        #endregion


        #region WhatTheCommandLineBringsGoesIntoTheStore()

        /// <summary>
        /// A certificate named on the command line is in the store before the
        /// start, named on the console with its handle, handed back to the
        /// kind - and listed with --list-certificates, the kind's word beside it.
        /// </summary>
        [Test]
        public async Task WhatTheCommandLineBringsGoesIntoTheStore()
        {

            await using var node = Node();

            var arguments = NodeArguments.Parse([ "--import-certificate", $"tlsRoot={Root("Test Root")}" ]);
            var said      = new StringWriter();
            var listed    = new StringWriter();

            Assert.Multiple(() => {
                Assert.That(node.ImportCertificates(arguments, out var imported, said, TextWriter.Null), Is.Null);
                Assert.That(imported.Select(entry => entry.Kind),   Is.EqualTo(new[] { CertificateKind.TLSRoot }));
                Assert.That(node.Certificates.Entries,               Has.Count.EqualTo(1));
                Assert.That(said.ToString().TrimEnd(),               Is.EqualTo($"  imported       Test Root as tlsRoot, handle {imported[0].Id}"));
                node.ListCertificates(entry => "<- chosen", listed);
                Assert.That(listed.ToString(), Does.Contain($"    {imported[0].Id}  on             until "));
                Assert.That(listed.ToString(), Does.Contain("Test Root"));
                Assert.That(listed.ToString(), Does.Contain("<- chosen"));
                Assert.That(listed.ToString(), Does.Contain("TLS root - what a server this WWCP node connects to may chain to"),
                            "said of the kind of node, as -h says it");
            });

        }

        #endregion

        #region WhatTheStoreDoesNotKeepOrCannotReadIsRefused()

        /// <summary>
        /// A kind of certificate this node does not keep, or a file that is not
        /// there, is refused in so many words, and Main returns 2.
        /// </summary>
        [Test]
        public async Task WhatTheStoreDoesNotKeepOrCannotReadIsRefused()
        {

            await using var node = Node(CertificateKinds: [ CertificateKind.TLSRoot ]);

            var server   = new StringWriter();
            var nowhere  = new StringWriter();
            var missing  = Path.Combine(directory, "missing.pem");

            Assert.Multiple(() => {
                Assert.That(node.ImportCertificates(NodeArguments.Parse([ "--import-certificate", $"tlsServer={Root("Server")}" ]),
                                                    out _, TextWriter.Null, server),
                            Is.EqualTo(2));
                Assert.That(server.ToString().TrimEnd(),
                            Is.EqualTo("'tlsServer' is not a kind of certificate this WWCP node keeps. Use one of tlsRoot."));
                Assert.That(node.ImportCertificates(NodeArguments.Parse([ "--import-certificate", $"tlsRoot={missing}" ]),
                                                    out _, TextWriter.Null, nowhere),
                            Is.EqualTo(2));
                Assert.That(nowhere.ToString().TrimEnd(),
                            Is.EqualTo($"--import-certificate: there is no file '{missing}'."));
            });

        }

        #endregion

        #region AnEmptyStoreSaysHowToFillIt()

        [Test]
        public async Task AnEmptyStoreSaysHowToFillIt()
        {

            await using var node = Node();

            var listed = new StringWriter();

            node.ListCertificates(Out: listed);

            Assert.That(listed.ToString(), Does.Contain("(empty - put one there with --import-certificate <kind>=<file>)"));

        }

        #endregion


        #region TheRepositoryRootIsWhereTheMarkerIs()

        /// <summary>
        /// Looked up from where the program is, the directory holding the
        /// kind's solution; where nothing leads to one, the last place looked from.
        /// </summary>
        [Test]
        public void TheRepositoryRootIsWhereTheMarkerIs()
        {

            var deep = Path.Combine(directory, "bin", "Debug", "net10.0");

            Directory.CreateDirectory(deep);
            File.WriteAllText(Path.Combine(directory, "TestNodeCLI.slnx"), "");

            Assert.Multiple(() => {
                Assert.That(NodeProgram.RepositoryRoot("TestNodeCLI.slnx",  deep, "elsewhere"), Is.EqualTo(new DirectoryInfo(directory).FullName));
                Assert.That(NodeProgram.RepositoryRoot("NoSuchCLI.slnx",    deep, "elsewhere"), Is.EqualTo("elsewhere"));
            });

        }

        #endregion

        #region ACertificatesPasswordIsReadFromTheKindsVariable()

        [Test]
        public void ACertificatesPasswordIsReadFromTheKindsVariable()

            => Assert.That(NodeProgram.CertificatePasswordVariable(new NodeKind("local controller", "lc", "LocalController", "LC", "lc")),
                           Is.EqualTo("LOCALCONTROLLER_CERT_PASSWORD"));

        #endregion

    }

}
