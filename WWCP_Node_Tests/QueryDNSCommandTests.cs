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

using NUnit.Framework;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// queryDNS on a node's command line: a name looked up the way the node
    /// looks it up, or of one of its name servers alone - and what is said
    /// where nothing was asked.
    /// </summary>
    /// <remarks>
    /// The name server is Hermod's, authoritative for example.test, on TCP at
    /// the loopback address: nothing here leaves this machine. A second name
    /// server is configured by its name, which a node cannot ask on its own.
    /// </remarks>
    public class QueryDNSCommandTests
    {

        #region Data

        private String     directory  = "";
        private DNSServer  nameServer = null!;
        private UInt16     port;
        private WWCPNode?  node;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory   = Path.Combine(Path.GetTempPath(), "node-querydns-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            var origin  = DomainName.Parse("example.test.");

            nameServer  = new DNSServer(
                              new AuthoritativeDNSRequestHandler(
                                  new InMemoryDNSZone().
                                      AddZoneFileString("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300", Origin: origin).
                                      AddZoneFileString("csms.example.test. 300 IN A 127.0.0.42",                                                    Origin: origin).
                                      AddZoneFileString("csms.example.test. 300 IN AAAA 2001:db8::42",                                               Origin: origin).
                                      AddZoneFileString("_ntske._tcp.example.test. 300 IN SRV 0 0 4460 ntske1.example.test.",                        Origin: origin)
                              ),
                              new DNSServerOptions {
                                  EnableUDPUnicast    = false,
                                  EnableUDPMulticast  = false,
                                  EnableTCPUnicast    = true,
                                  TCPUnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Parse(0))
                              }
                          );

            await nameServer.Start();

            port = nameServer.ActiveTCPUnicastSocket!.Value.Port.ToUInt16();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (node is not null)
                await node.DisposeAsync();

            await nameServer.Stop();

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

        #region (helper) Node(DNS)

        /// <summary>
        /// A node whose "dns" section is the given one, without a legal time to
        /// look for.
        /// </summary>
        private WWCPNode Node(String DNS)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, $$"""{ "dns": {{DNS}}, "nts": { "groups": { "legal": { "enabled": false } } } }""");

            node = new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

            return node;

        }

        /// <summary>
        /// A node asking the name server of this test, as "local", and one
        /// configured by its name, as "byname".
        /// </summary>
        private WWCPNode NodeWithTheTestsNameServer()

            => Node($$"""
                      { "servers": [ { "id": "local",  "address": "127.0.0.1",        "port": {{port}}, "transport": "TCP", "queryTimeoutSeconds": 3 },
                                     { "id": "byname", "address": "resolver.example", "port": {{port}}, "transport": "TCP", "queryTimeoutSeconds": 3 } ],
                        "maxRetries": 0,
                        "useCache": false }
                      """);

        #endregion


        #region TheNodesCommandLineHasQueryDNS()

        /// <summary>
        /// Every node's command line has queryDNS, without anybody listing it.
        /// </summary>
        [Test]
        public void TheNodesCommandLineHasQueryDNS()
        {

            using var cli = new NodeCLI(Node("""{ "enabled": false }"""));

            Assert.That(cli.Commands.OfType<QueryDNSCommand>().Count(), Is.EqualTo(1));

        }

        #endregion

        #region OneServerAloneSaysWhatItAnswered()

        /// <summary>
        /// Asked of one server by its id: the question, the answer's code in
        /// the IANA registry's words, where it came from, and each record.
        /// </summary>
        [Test]
        public async Task OneServerAloneSaysWhatItAnswered()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("queryDNS csms.example.test A AAAA @local");

            Assert.Multiple(() => {
                Assert.That(said[0], Does.StartWith($"csms.example.test. A, AAAA @local -> NoError from tcp://127.0.0.1:{port} in "));
                Assert.That(said[0], Does.Contain("authoritative"));
                Assert.That(said,    Has.Some.Match(@"^  csms\.example\.test\.\s+A\s+300\s+127\.0\.0\.42$"));
                Assert.That(said,    Has.Some.Match(@"^  csms\.example\.test\.\s+AAAA\s+300\s+2001:db8::42$"));
            });

        }

        #endregion

        #region AServerIsNamedByIdPlaceOrAddress()

        /// <summary>
        /// "@local", "@1", "@127.0.0.1" and "@tcp://127.0.0.1:port" are the
        /// same server; "@2" is the one configured by name.
        /// </summary>
        [Test]
        public void AServerIsNamedByIdPlaceOrAddress()
        {

            var node = NodeWithTheTestsNameServer();

            Assert.Multiple(() => {
                Assert.That(node.DNSServerIndexOf("local"),                     Is.EqualTo(0));
                Assert.That(node.DNSServerIndexOf("LOCAL"),                     Is.EqualTo(0));
                Assert.That(node.DNSServerIndexOf("1"),                         Is.EqualTo(0));
                Assert.That(node.DNSServerIndexOf("127.0.0.1"),                 Is.EqualTo(0));
                Assert.That(node.DNSServerIndexOf($"127.0.0.1:{port}"),         Is.EqualTo(0));
                Assert.That(node.DNSServerIndexOf($"tcp://127.0.0.1:{port}"),   Is.EqualTo(0));
                Assert.That(node.DNSServerIndexOf("2"),                         Is.EqualTo(1));
                Assert.That(node.DNSServerIndexOf("resolver.example"),          Is.EqualTo(1));
                Assert.That(node.DNSServerIndexOf("3"),                         Is.Null);
                Assert.That(node.DNSServerIndexOf("0"),                         Is.Null);
                Assert.That(node.DNSServerIndexOf("192.0.2.53"),                Is.Null);
                Assert.That(node.DNSServerIndexOf(""),                          Is.Null);
            });

        }

        #endregion

        #region AServerThatIsNotConfiguredIsNotAsked()

        /// <summary>
        /// A server that is none of the node's is answered with the ones there
        /// are, and nothing is asked - not even of the configured ones.
        /// </summary>
        [Test]
        public async Task AServerThatIsNotConfiguredIsNotAsked()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var said = await cli.Execute("queryDNS csms.example.test @192.0.2.53");

            Assert.That(said, Is.EqualTo(new[] { $"'192.0.2.53' is none of this {node!.Kind.Name}'s name servers, which are local, byname." }));

        }

        #endregion

        #region AServerConfiguredByNameIsNotAskedAlone()

        /// <summary>
        /// A server configured by its name would have to be resolved before it
        /// could be asked, which is what is being tested: refused, and said so.
        /// </summary>
        [Test]
        public async Task AServerConfiguredByNameIsNotAskedAlone()
        {

            var node   = NodeWithTheTestsNameServer();
            var result = await node.ResolveAsync("csms.example.test", Server: 1);

            Assert.Multiple(() => {
                Assert.That(result.Value<Boolean>("ok"),       Is.False);
                Assert.That(result.Value<String>("refused"),   Is.EqualTo(DNSQueryRefusals.ServerByName));
                Assert.That(result.Value<String>("serverId"),  Is.EqualTo("byname"));
            });

        }

        #endregion

        #region ANameThatDoesNotExistIsNXDomain()

        /// <summary>
        /// A name the zone does not have: the server answered, with NXDomain -
        /// an answer, so not refused.
        /// </summary>
        [Test]
        public async Task ANameThatDoesNotExistIsNXDomain()
        {

            var node   = NodeWithTheTestsNameServer();
            var result = await node.ResolveAsync("missing.example.test", Server: 0);

            using var cli = new NodeCLI(node);

            var said   = await cli.Execute("queryDNS missing.example.test @local");

            Assert.Multiple(() => {
                Assert.That(result.Value<String>("responseCode"),  Is.EqualTo("NXDomain"));
                Assert.That(result.Value<String>("refused"),       Is.Null);
                Assert.That(result.Value<String>("answeredBy"),    Is.EqualTo($"tcp://127.0.0.1:{port}"));
                Assert.That(said[0],                               Does.Contain(" -> NXDomain from "));
                Assert.That(said,                                  Does.Contain("  no records"));
            });

        }

        #endregion

        #region RecordTypesByMnemonicNumberOrGenericForm()

        /// <summary>
        /// SRV by its mnemonic in any case, by its number and in the generic
        /// form of RFC 3597 - and a word that is no record type refused before
        /// anything is asked.
        /// </summary>
        [Test]
        public async Task RecordTypesByMnemonicNumberOrGenericForm()
        {

            using var cli = new NodeCLI(NodeWithTheTestsNameServer());

            var byName    = await cli.Execute("queryDNS _ntske._tcp.example.test srv @local");
            var byNumber  = await cli.Execute("queryDNS _ntske._tcp.example.test 33 @local");
            var generic   = await cli.Execute("queryDNS _ntske._tcp.example.test TYPE33 @local");
            var nonsense  = await cli.Execute("queryDNS _ntske._tcp.example.test SRVX @local");

            Assert.Multiple(() => {
                foreach (var said in new[] { byName, byNumber, generic })
                {
                    Assert.That(said[0], Does.StartWith("_ntske._tcp.example.test. SRV @local -> NoError"));
                    Assert.That(said,    Has.Some.Contains("4460"));
                }
                Assert.That(nonsense, Is.EqualTo(new[] { "'SRVX' is not a DNS resource record type." }));
            });

            Assert.Multiple(() => {
                Assert.That(WWCPNode.TryParseRecordType("aaaa",    out var aaaa),     Is.True);   Assert.That(aaaa,     Is.EqualTo(DNSResourceRecordTypes.AAAA));
                Assert.That(WWCPNode.TryParseRecordType("65",      out var https),    Is.True);   Assert.That((UInt16) https, Is.EqualTo(65));
                Assert.That(WWCPNode.TryParseRecordType("type65",  out var generic2), Is.True);   Assert.That((UInt16) generic2, Is.EqualTo(65));
                Assert.That(WWCPNode.TryParseRecordType("99999",   out _),            Is.False);
                Assert.That(WWCPNode.TryParseRecordType("-1",      out _),            Is.False);
                Assert.That(WWCPNode.TryParseRecordType("",        out _),            Is.False);
            });

        }

        #endregion

        #region TooManyRecordTypesAreRefused()

        /// <summary>
        /// Nine record types are one more than a query may ask for.
        /// </summary>
        [Test]
        public void TooManyRecordTypesAreRefused()
        {

            Assert.Multiple(() => {
                Assert.That(WWCPNode.TryParseRecordTypes([ "A", "AAAA", "MX", "NS", "TXT", "SRV", "SOA", "PTR", "CAA" ], out _, out var error, out var refused), Is.False);
                Assert.That(refused, Is.EqualTo(DNSQueryRefusals.TooManyRecordTypes));
                Assert.That(error,   Is.EqualTo($"One query may ask for at most {WWCPNode.MaxQueryRecordTypes} record types."));
                Assert.That(WWCPNode.TryParseRecordTypes([ "A", "bogus" ], out _, out _, out refused), Is.False);
                Assert.That(refused, Is.EqualTo(DNSQueryRefusals.InvalidRecordType));
                Assert.That(WWCPNode.TryParseRecordTypes([ " ", "" ], out var none, out _, out _), Is.True);
                Assert.That(none,    Is.Null, "nothing given is the default, A and AAAA");
            });

        }

        #endregion

        #region AnAddressIsTurnedAround()

        /// <summary>
        /// An address is asked for as its reverse name, and the answer says so
        /// and keeps the address it was made of.
        /// </summary>
        [Test]
        public async Task AnAddressIsTurnedAround()
        {

            var node   = NodeWithTheTestsNameServer();
            var result = await node.ResolveAsync("127.0.0.42", Server: 0);

            Assert.Multiple(() => {
                Assert.That(result.Value<String>("name"),             Is.EqualTo("42.0.0.127.in-addr.arpa."));
                Assert.That(result.Value<String>("reverseLookupOf"),  Is.EqualTo("127.0.0.42"));
                Assert.That(result["recordTypes"]?.ToObject<String[]>(), Is.EqualTo(new[] { "PTR" }));
            });

        }

        #endregion

        #region NothingIsAskedWithNameResolutionOff()

        /// <summary>
        /// With name resolution switched off, nothing is asked, and the answer
        /// says why in the reason code of QueryDNS.
        /// </summary>
        [Test]
        public async Task NothingIsAskedWithNameResolutionOff()
        {

            var node    = Node("""{ "enabled": false }""");
            var result  = await node.ResolveAsync("csms.example.test");

            using var cli = new NodeCLI(node);

            var said    = await cli.Execute("queryDNS csms.example.test");

            Assert.Multiple(() => {
                Assert.That(result.Value<String>("refused"),  Is.EqualTo(DNSQueryRefusals.Disabled));
                Assert.That(said[0],                          Does.EndWith($"failed: Name resolution is switched off on this {node.Kind.Name}."));
            });

        }

        #endregion

        #region IANANamesForResponseCodes()

        /// <summary>
        /// The registry's names, not Hermod's.
        /// </summary>
        [Test]
        public void IANANamesForResponseCodes()
        {

            Assert.Multiple(() => {
                Assert.That(WWCPNode.RCodeName(DNSResponseCodes.NoError),        Is.EqualTo("NoError"));
                Assert.That(WWCPNode.RCodeName(DNSResponseCodes.NameError),      Is.EqualTo("NXDomain"));
                Assert.That(WWCPNode.RCodeName(DNSResponseCodes.ServerFailure),  Is.EqualTo("ServFail"));
                Assert.That(WWCPNode.RCodeName(DNSResponseCodes.Refused),        Is.EqualTo("Refused"));
                Assert.That(WWCPNode.RCodeName((DNSResponseCodes) 4000),         Is.EqualTo("4000"));
            });

        }

        #endregion

    }

}
