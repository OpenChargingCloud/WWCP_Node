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
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

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

        #region (helper) Node(Port = null, CertificateKinds = null, NameServers = null, TimeServers = null, Accounts = null, Frontend = null)

        /// <summary>
        /// A node of no particular kind in this test's directory, with no
        /// accounts yet: made, not started - and with DNS switched off, unless
        /// it is given name servers, and NTS switched off, asking the PTB's four
        /// unless it is given time servers.
        /// </summary>
        /// <param name="NameServers">The 'servers' of the file's DNS section, as JSON.</param>
        /// <param name="TimeServers">The 'servers' of the file's NTS section, as JSON.</param>
        /// <param name="Accounts">Where its accounts are, as the command line would have given it; its directory's own by default.</param>
        /// <param name="Frontend">Its web interface; none by default.</param>
        private WWCPNode Node(IPPort?                        Port              = null,
                              IEnumerable<CertificateKind>?  CertificateKinds  = null,
                              String?                        NameServers       = null,
                              String?                        TimeServers       = null,
                              String?                        Accounts          = null,
                              IStaticContentSource?          Frontend          = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            var dns = NameServers is null
                          ?    """{ "enabled": false }"""
                          : $$"""{ "enabled": true, "servers": {{NameServers}} }""";

            var nts = TimeServers is null
                          ?    """{ "enabled": false }"""
                          : $$"""{ "enabled": false, "servers": {{TimeServers}} }""";

            File.WriteAllText(configuration, $$"""{ "dns": {{dns}}, "nts": {{nts}} }""");

            return new WWCPNode(
                       HTTPPort:          Port ?? IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Accounts ?? Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       Frontend:          Frontend,
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

        #region (helper) Flat(Said)

        /// <summary>
        /// What was said, with its lines put back together: what it says,
        /// wherever it was broken.
        /// </summary>
        private static String Flat(String Said)

            => String.Join(" ", Said.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));

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
                Assert.That(banner, Has.Some.EqualTo($"  accounts       1 user(s) in {Path.TrimEndingDirectorySeparator(node.AccountsPath)}"));
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
                            Has.All.Matches<String>(line => line is not null && line[18] != ' ' && line[17] == ' '),
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

        #region EveryNameServerIsSaidOnALineOfItsOwnAsPeopleWriteIt()

        /// <summary>
        /// Every name server on a line of its own, below the first, and each as
        /// people write it: an IPv6 address in the short form of RFC 5952, as
        /// the page shows it, and a name without the root's dot. All on one line
        /// and spelled out, the name servers of a machine with IPv6 were a line
        /// of 247 characters; and a server's own timeout, after a comma among
        /// the servers, read as one more of them.
        /// </summary>
        [Test]
        public async Task EveryNameServerIsSaidOnALineOfItsOwnAsPeopleWriteIt()
        {

            await using var node = Node(NameServers: """
                                                     [ { "address": "192.0.2.53",                               "queryTimeoutSeconds": 3   },
                                                       { "address": "2001:0db8:0000:0000:0000:0000:0000:0053",  "transport": "TLS"         },
                                                       { "address": "::1",  "port": 5353,                       "queryTimeoutSeconds": 0.5 },
                                                       { "address": "dns.example",                              "transport": "TLS"         } ]
                                                     """);

            var banner  = node.Banner().ToList();
            var first   = banner.FindIndex(line => line.StartsWith("  name servers   "));

            Assert.That(first, Is.Positive, "no line of name servers");

            // Its line, and the lines below it that go on at the column.
            var said    = banner.Skip     (first + 1).
                                 TakeWhile(line => line.StartsWith(new String(' ', NodeBanner.Column))).
                                 Prepend  (banner[first]).
                                 Select   (line => line[NodeBanner.Column..]).
                                 ToList();

            Assert.That(said, Is.EquivalentTo(new[] {
                                  "udp://192.0.2.53:53, timeout: 3 sec.",
                                  "tls://[2001:db8::53]:853",
                                  "udp://[::1]:5353, timeout: 0.5 sec.",
                                  "tls://dns.example:853"
                              }));

        }

        #endregion

        #region AKindSaysANameServerAsTheBannerDoes()

        /// <summary>
        /// A kind with a banner of its own says a name server as the node's
        /// banner does. NodeBanner.NameServer was the node's alone, and the
        /// energy meter was about to keep a copy of it (asked for by the meter).
        /// </summary>
        [Test]
        public async Task AKindSaysANameServerAsTheBannerDoes()
        {

            await using var node = Node(NameServers: """
                                                     [ { "address": "2001:0db8:0000:0000:0000:0000:0000:0053",  "transport": "TLS"          },
                                                       { "address": "dns.example",                              "queryTimeoutSeconds": 0.5  } ]
                                                     """);

            Assert.That(node.DNSClient.DNSServers.Select(NodeBanner.NameServer),
                        Is.EquivalentTo(new[] {
                            "tls://[2001:db8::53]:853",
                            "udp://dns.example:53, timeout: 0.5 sec."
                        }));

        }

        #endregion

        #region ABandOfTimeServersKeepsToTheWidthOfATerminal()

        /// <summary>
        /// A band of time servers too wide for a line beside the column goes on
        /// below it, at the column, broken after a server's comma. The PTB's
        /// four, which every node asks where its file names none, made one line
        /// of 83 columns (found by the CSMS).
        /// </summary>
        [Test]
        public async Task ABandOfTimeServersKeepsToTheWidthOfATerminal()
        {

            await using var node = Node();

            var said = TimeServersSaid(node);

            Assert.Multiple(() => {
                Assert.That(said,                                                Has.Count.GreaterThan(1),  "the band on one line");
                Assert.That(said.Where(line => line.Length > NodeUsage.Width),   Is.Empty,                  "a line wider than a terminal");
                Assert.That(String.Join(" ", said.Select(line => line[NodeBanner.Column..])),
                            Is.EqualTo(String.Join(", ", NTSConfiguration.DefaultHostnames)));
            });

        }

        #endregion

        #region ABandIsOneLineAsFarAsTheLastColumn(Beside, Lines)

        /// <summary>
        /// A band is one line as far as the last column of a terminal, and two
        /// one column past it.
        /// </summary>
        [TestCase(31, 1)]
        [TestCase(32, 2)]
        public async Task ABandIsOneLineAsFarAsTheLastColumn(Int32 Beside, Int32 Lines)
        {

            // 17 columns, the first and its comma 31, a space: 49, and the second beside it.
            var first   = new String('a', 22) + ".example";
            var second  = new String('b', Beside - ".example".Length) + ".example";

            await using var node = Node(TimeServers: $$"""[ "{{first}}", "{{second}}" ]""");

            var said    = TimeServersSaid(node);

            Assert.Multiple(() => {
                Assert.That(said,                                                Has.Count.EqualTo(Lines));
                Assert.That(said.Where(line => line.Length > NodeUsage.Width),   Is.Empty,  "a line wider than a terminal");
                Assert.That(String.Join(" ", said.Select(line => line[NodeBanner.Column..])), Is.EqualTo($"{first}, {second}"));
            });

        }

        #endregion

        #region TwoBandsOfTimeServersAreALineEachWithTheirPriorities()

        /// <summary>
        /// Two bands are a line each, and each says its priority after its
        /// servers.
        /// </summary>
        [Test]
        public async Task TwoBandsOfTimeServersAreALineEachWithTheirPriorities()
        {

            await using var node = Node(TimeServers: """[ "a.example", { "hostname": "b.example", "priority": 5 } ]""");

            Assert.That(TimeServersSaid(node).Select(line => line[NodeBanner.Column..]),
                        Is.EqualTo(new[] { "a.example   (priority 0)", "b.example   (priority 5)" }));

        }

        #endregion

        #region APriorityThatWouldNotFitBesideTheLastServerHasALineOfItsOwn(Length, Said)

        /// <summary>
        /// A band's priority stays with its last server as far as the last
        /// column of a terminal, and has a line of its own past it: a name of 51
        /// characters, last of its band, and its priority made one line of 83
        /// (found by the EMSP).
        /// </summary>
        [TestCase(48, new[] { "a.example,", "{0}   (priority 0)", "b.example   (priority 5)" })]
        [TestCase(49, new[] { "a.example, {0}", "(priority 0)", "b.example   (priority 5)" })]
        public async Task APriorityThatWouldNotFitBesideTheLastServerHasALineOfItsOwn(Int32 Length, String[] Said)
        {

            var name = new String('x', Length - ".example".Length) + ".example";

            await using var node = Node(TimeServers: $$"""[ "a.example", "{{name}}", { "hostname": "b.example", "priority": 5 } ]""");

            var said = TimeServersSaid(node);

            Assert.Multiple(() => {
                Assert.That(said.Select(line => line[NodeBanner.Column..]),       Is.EqualTo(Said.Select(line => String.Format(line, name))));
                Assert.That(said.Where(line => line.Length > NodeUsage.Width),   Is.Empty,  "a line wider than a terminal");
            });

        }

        #endregion

        #region AServerWiderThanALineHasOneOfItsOwnAndNothingAfterIt()

        /// <summary>
        /// A server whose name is wider than the room beside the column has a
        /// line of its own, as a path has, and nothing is said after it where
        /// its band has no priority to say.
        /// </summary>
        [Test]
        public async Task AServerWiderThanALineHasOneOfItsOwnAndNothingAfterIt()
        {

            var name = new String('x', 56) + ".example";

            await using var node = Node(TimeServers: $$"""[ "a.example", "{{name}}" ]""");

            Assert.That(TimeServersSaid(node).Select(line => line[NodeBanner.Column..]),
                        Is.EqualTo(new[] { "a.example,", name }));

        }

        #endregion

        #region WhereTheWebInterfaceComesFromKeepsToTheWidthOfATerminal()

        /// <summary>
        /// Where the web interface comes from is broken between its words at
        /// the width of a terminal, and goes on below at the column: the
        /// resources and the assembly they are embedded in, named in full, were
        /// one line of 100 columns at the gateway and of 90 at the electric
        /// vehicle (found by the gateway and the EV).
        /// </summary>
        [Test]
        public async Task WhereTheWebInterfaceComesFromKeepsToTheWidthOfATerminal()
        {

            var bundle = new ABundle("7 embedded resources 'cloud.charging.open.protocols.WWCP.Node.Tests.HTTPRoot.*' of assembly 'WWCP_Node_Tests'");

            await using var node = Node(Frontend: bundle);

            var banner = node.Banner().ToList();
            var first  = banner.FindIndex(line => line.StartsWith("  frontend from ", StringComparison.Ordinal));

            Assert.That(first, Is.Positive, "no line of where the web interface comes from");

            var said   = banner.Skip     (first + 1).
                                TakeWhile(line => line.StartsWith(new String(' ', NodeBanner.Column), StringComparison.Ordinal)).
                                Prepend  (banner[first]).
                                ToList();

            Assert.Multiple(() => {
                Assert.That(said,                                                Has.Count.GreaterThan(1),  "on one line");
                Assert.That(said.Where(line => line.Length > NodeUsage.Width),   Is.Empty,                  "a line wider than a terminal");
                Assert.That(String.Join(" ", said.Select(line => line[NodeBanner.Column..])), Is.EqualTo(bundle.Description));
            });

        }

        /// <summary>
        /// A web interface of one page, which says what it is in whatever words
        /// it is given.
        /// </summary>
        private sealed class ABundle(String Description) : IStaticContentSource
        {

            public String   Description    { get; } = Description;

            public Boolean  IsImmutable    => true;

            public Boolean  TryGet(String RelativePath, [NotNullWhen(true)] out StaticFile? File)
            {
                File = RelativePath == WWCPNode.IndexFile
                           ? StaticFile.Create(RelativePath, "<!doctype html><title>{{NodeName}}</title>"u8.ToArray())
                           : null;
                return File is not null;
            }

        }

        #endregion

        #region TheAccountsAreSaidWhereTheyAreAsTheOtherFilesAre()

        /// <summary>
        /// Where the accounts are is said in full and as the system writes it,
        /// with no separator at the end, as the configuration, the log files and
        /// the certificates are: it was said as the command line had it, and
        /// with the separator the node puts at its end for the accounts' own
        /// use - "C:/.../accounts\" (found by the EV).
        /// </summary>
        [Test]
        public async Task TheAccountsAreSaidWhereTheyAreAsTheOtherFilesAre()
        {

            var accounts = Path.Combine(directory, "accounts");

            await using var node = Node(Accounts: accounts.Replace('\\', '/') + "/");

            var line = node.Banner().SingleOrDefault(line => line.StartsWith("  accounts ", StringComparison.Ordinal));

            Assert.That(line, Does.EndWith($" user(s) in {Path.GetFullPath(accounts)}"));

        }

        #endregion

        #region (helper) TimeServersSaid(Node)

        /// <summary>
        /// The banner's lines of time servers: the first, and those that go on
        /// below it at the column, up to how many of them must answer.
        /// </summary>
        private static List<String> TimeServersSaid(WWCPNode Node)
        {

            var banner  = Node.Banner().ToList();
            var first   = banner.FindIndex(line => line.StartsWith("  time servers ", StringComparison.Ordinal));

            Assert.That(first, Is.Positive, "no line of time servers");

            return banner.Skip     (first + 1).
                          TakeWhile(line => line.StartsWith(new String(' ', NodeBanner.Column), StringComparison.Ordinal) &&
                                           !line.TrimStart().StartsWith("at least ", StringComparison.Ordinal)).
                          Prepend  (banner[first]).
                          ToList();

        }

        #endregion

        #region AKindSaysWhatItRefusesAsTheNodeDoes()

        /// <summary>
        /// What a kind refuses of its own switches is said as the node says its
        /// own: broken between words at 80 columns, and a line that begins with
        /// a space - a command to copy - whole. NodeProgram.Say was the node's
        /// alone, and the electric vehicle kept a copy of it (asked for by the
        /// EV).
        /// </summary>
        [Test]
        public void AKindSaysWhatItRefusesAsTheNodeDoes()
        {

            var refusal  = "--contract-cert: 'nosuch' is not the handle of a certificate in the store of this electric " +
                           "vehicle, and a contract certificate has to be given by the handle the store knows it by.";
            var command  = "  sudo setcap 'cap_net_bind_service=+ep' /usr/local/share/a-kind-of-node/" + new String('x', 60);
            var said     = new StringWriter();

            NodeProgram.Say(said, refusal);
            NodeProgram.Say(said, command);

            var lines    = said.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

            Assert.Multiple(() => {
                Assert.That(lines,                                              Has.Length.GreaterThan(2),  "the refusal on one line");
                Assert.That(lines[..^1].Where(line => line.Length > NodeUsage.Width),  Is.Empty,            "a line of the refusal wider than a terminal");
                Assert.That(String.Join(" ", lines[..^1]),                      Is.EqualTo(refusal));
                Assert.That(lines[^1],                                          Is.EqualTo(command),        "the command, broken");
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
                    Assert.That(exit,                   Is.EqualTo(1));
                    Assert.That(Flat(said.ToString()),  Does.StartWith($"The WWCP node could not start: The web interface could not be given port {port}"));
                    Assert.That(Flat(said.ToString()),  Does.Contain("Another copy of this WWCP node already running is the usual answer. " +
                                                                     "Stop it, or give this one another port with --port <number>."));
                    Assert.That(said.ToString().Split(Environment.NewLine).Where(line => line.Length > NodeUsage.Width), Is.Empty,
                                "lines wider than a terminal of 80 columns");
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
                Assert.That(exit,                  Is.EqualTo(1));
                Assert.That(Flat(brief.ToString()), Does.StartWith("The WWCP node could not start: The charging station server's certificate could not be read."));
                Assert.That(brief.ToString(),      Does.Not.Contain("System.InvalidOperationException"));
                Assert.That(verbose,               Is.EqualTo(1));
                Assert.That(whole.ToString(),      Does.Contain("System.InvalidOperationException"), "the whole exception with --verbose");
            });

        }

        #endregion

        #region ACommandToCopyStaysWhole()

        /// <summary>
        /// A line of advice that begins with a space is a command to copy -
        /// setcap's - and stays as it is, however long, where every other line
        /// is broken at 80 columns: broken, or without its indent, it would be
        /// no command any more.
        /// </summary>
        [Test]
        public async Task ACommandToCopyStaysWhole()
        {

            var squatter = new TcpListener(System.Net.IPAddress.Loopback, 0);
            squatter.Start();

            try
            {

                var port     = (UInt16) ((IPEndPoint) squatter.LocalEndpoint).Port;
                var said     = new StringWriter();
                var command  = "  sudo setcap cap_net_bind_service=+ep /opt/somewhere/far/below/the/root/of/it/all/TestNodeCLI";

                await using var node = Node(IPPort.Parse(port));

                await node.Started(Verbose: false, AdviceOfTheKind: _ => command, Error: said);

                Assert.That(said.ToString().Split(Environment.NewLine), Does.Contain(command));

            }
            finally
            {
                squatter.Stop();
            }

        }

        #endregion

        #region WhyAStartFailedIsSaidInLinesOfEightyColumns()

        /// <summary>
        /// Why a start failed is broken between words at 80 columns, as the
        /// advice below it is: the EMSP's line was 115 columns wide, and a
        /// terminal of 80 broke it in the middle of "operating" (found by the
        /// EMSP).
        /// </summary>
        [Test]
        public async Task WhyAStartFailedIsSaidInLinesOfEightyColumns()
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);
            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            var said = new StringWriter();

            await using var node = new NodeThatCannotListen(IPPort.Parse(TestPorts.Free()), Path.Combine(directory, "accounts"), new WWCPConfigFile(configuration));

            await node.Started(Verbose: false, Error: said);

            Assert.Multiple(() => {
                Assert.That(said.ToString().Split(Environment.NewLine).Where(line => line.Length > NodeUsage.Width), Is.Empty,
                            "lines wider than a terminal of 80 columns");
                Assert.That(Flat(said.ToString()), Does.StartWith("The WWCP node could not start: The charging station server's certificate could not be read."),
                            "the words, however broken");
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
        /// goes to a published program, or the node to a port above 1024. And
        /// "below 1024" stays on one line: broken after "below", the next line
        /// began with the number (found by the meter).
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
                Assert.That(String.Join(" ", advice),
                            Does.Contain("Not on dotnet itself, which runs this now: that would give the ports below 1024 to every .NET program on this machine."));
                Assert.That(advice.Where(line => line.EndsWith(" below") || line.EndsWith(" above")), Is.Empty,
                            String.Join("\n", advice));
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
                Assert.That(Flat(server.ToString()),
                            Is.EqualTo("'tlsServer' is not a kind of certificate this WWCP node keeps. Use one of tlsRoot."));
                Assert.That(node.ImportCertificates(NodeArguments.Parse([ "--import-certificate", $"tlsRoot={missing}" ]),
                                                    out _, TextWriter.Null, nowhere),
                            Is.EqualTo(2));
                Assert.That(Flat(nowhere.ToString()),
                            Is.EqualTo($"--import-certificate: there is no file '{missing}'."));
                Assert.That(server. ToString().Split(Environment.NewLine).Where(line => line.Length > NodeUsage.Width), Is.Empty);
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
