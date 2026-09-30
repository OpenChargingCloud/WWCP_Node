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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What the "dns" section may say about the name servers - and what it may
    /// not, said as a sentence about the file rather than as an exception.
    /// </summary>
    /// <remarks>
    /// The README showed a name server as "udp://192.168.1.1:53", which is how
    /// the log names one and not a form this section has ever taken - in this
    /// node, or in the charging station and the energy meter whose sections
    /// it shares. A node given it stopped at its start with an exception out
    /// of IPAddress.TryParse. The README now shows what is read, and what is
    /// not read is refused.
    /// </remarks>
    public class DNSConfigurationTests
    {

        #region Data

        private String directory = "";

        private String ConfigurationPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-dns-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region TheREADMEsExampleIsOneNameServerOverUDP()

        /// <summary>
        /// The section as the README writes it: an address, which is a name
        /// server asked over UDP on port 53.
        /// </summary>
        [Test]
        public void TheREADMEsExampleIsOneNameServerOverUDP()
        {

            var section = JObject.Parse("""{ "enabled": true, "servers": [ "192.168.1.1" ] }""");

            Assert.That(DNSConfiguration.TryParse(section, out var read, out var error),  Is.True,  error);

            var server = read!.Servers!.Single();

            Assert.Multiple(() =>
            {
                Assert.That(read.Enabled,                  Is.True);
                Assert.That(server.IPAddress?.ToString(),  Is.EqualTo("192.168.1.1"));
                Assert.That(server.Port.ToUInt16(),        Is.EqualTo(53));
                Assert.That(server.Transport,              Is.EqualTo(DNSTransport.UDP));
            });

        }

        #endregion

        #region AnAddressIsANameServerOverUDP(Entry)

        /// <summary>
        /// An address, in either of the two forms a list takes - a string, or
        /// an object saying nothing more - is a name server asked over UDP on
        /// port 53.
        /// </summary>
        [TestCase("\"9.9.9.9\"")]
        [TestCase("""{ "address": "9.9.9.9" }""")]
        public void AnAddressIsANameServerOverUDP(String Entry)
        {

            var section = JObject.Parse($$"""{ "enabled": true, "servers": [ {{Entry}} ], "useCache": true }""");

            Assert.That(DNSConfiguration.TryParse(section, out var read, out var error),  Is.True,  error);

            var server = read!.Servers!.Single();

            Assert.Multiple(() =>
            {
                Assert.That(read.Enabled,                  Is.True);
                Assert.That(server.IPAddress?.ToString(),  Is.EqualTo("9.9.9.9"));
                Assert.That(server.Port.ToUInt16(),        Is.EqualTo(53));
                Assert.That(server.Transport,              Is.EqualTo(DNSTransport.UDP));
            });

        }

        #endregion

        #region TheLongFormIsWhatThePageWritesBack(Address, Port, Transport)

        /// <summary>
        /// The object for a server with more to say about it is read, and
        /// written back as it was - which is what makes it the form the DNS
        /// page saves the list in. The one the README shows, and one over TLS
        /// on a port of its own.
        /// </summary>
        [TestCase("192.168.1.1", 53,  "UDP")]
        [TestCase("9.9.9.9",     853, "TLS")]
        public void TheLongFormIsWhatThePageWritesBack(String  Address,
                                                       Int32   Port,
                                                       String  Transport)
        {

            var entry = new JObject(
                            new JProperty("address",              Address),
                            new JProperty("port",                 Port),
                            new JProperty("transport",            Transport),
                            new JProperty("queryTimeoutSeconds",  2)
                        );

            Assert.That(DNSConfiguration.TryParseServer(entry, out var server, out var error),  Is.True,  error);

            var written = DNSConfiguration.ServerJSON(server!);

            Assert.Multiple(() =>
            {
                Assert.That(written.Value<String>("address"),              Is.EqualTo(Address));
                Assert.That(written.Value<Int32> ("port"),                 Is.EqualTo(Port));
                Assert.That(written.Value<String>("transport"),            Is.EqualTo(Transport));
                Assert.That(written.Value<Double>("queryTimeoutSeconds"),  Is.EqualTo(2));
            });

        }

        #endregion

        #region AnIPv6NameServerIsWrittenAsPeopleWriteIt(Given, Written)

        /// <summary>
        /// An IPv6 name server is written in the short form of RFC 5952, which
        /// the page shows and the file keeps. Spelled out, it was 39 characters,
        /// cut off on the charging station's DNS page at 320 pixels; and "::1"
        /// came in brackets. Written either way, it is read back as the same
        /// server.
        /// </summary>
        [TestCase("2001:4860:4860::8888",                     "2001:4860:4860::8888")]
        [TestCase("2001:4860:4860:0000:0000:0000:0000:8888",  "2001:4860:4860::8888")]
        [TestCase("2606:4700:4700::1111",                     "2606:4700:4700::1111")]
        [TestCase("::1",                                      "::1")]
        [TestCase("[::1]",                                    "::1")]
        public void AnIPv6NameServerIsWrittenAsPeopleWriteIt(String  Given,
                                                             String  Written)
        {

            Assert.That(DNSConfiguration.TryParseServer(new JObject(new JProperty("address",    Given),
                                                                    new JProperty("transport",  "TLS")),
                                                        out var server, out var error),
                        Is.True, error);

            var json = DNSConfiguration.ServerJSON(server!);

            Assert.That(json.Value<String>("address"), Is.EqualTo(Written));

            Assert.That(DNSConfiguration.TryParseServer(json, out var reread, out var error2), Is.True, error2);

            Assert.That(reread!.IPAddress, Is.EqualTo(server!.IPAddress));

        }

        #endregion

        #region AnIPv6NameServerKeepsTheNameItIsKnownBy()

        /// <summary>
        /// The name the log and the memory of known servers give an IPv6 name
        /// server stays spelled out, as it always was: what a node knows of a
        /// server is kept under that name, and a short one would find nothing.
        /// </summary>
        [Test]
        public void AnIPv6NameServerKeepsTheNameItIsKnownBy()
        {

            Assert.That(DNSConfiguration.TryParseServer(new JObject(new JProperty("address",    "2001:4860:4860::8888"),
                                                                    new JProperty("transport",  "TLS")),
                                                        out var server, out var error),
                        Is.True, error);

            Assert.That(WWCPNode.NameOf(server!), Is.EqualTo("tls://2001:4860:4860:0000:0000:0000:0000:8888:853"));

        }

        #endregion

        #region TheFormTheLogNamesAServerInIsRefusedWithASentence(Entry)

        /// <summary>
        /// How the log names a name server, and an address with its port: not
        /// forms the section takes, so refused - as a string and as the address
        /// of an object alike, with the entry named, and not with an exception
        /// out of the parser, which is what all of them were.
        /// </summary>
        [TestCase("udp://213.133.98.98:53")]
        [TestCase("udp://[2a01:4f8:0:1::add:1010]:53")]
        [TestCase("213.133.98.98:53")]
        [TestCase("[2001:db8::1]:53")]
        public void TheFormTheLogNamesAServerInIsRefusedWithASentence(String Entry)
        {

            foreach (var server in new JToken[] { Entry, new JObject(new JProperty("address", Entry)) })
            {

                var                section  = new JObject(new JProperty("servers", new JArray(server)));
                var                parsed   = true;
                DNSConfiguration?  read     = null;
                String?            error    = null;

                Assert.That(() => parsed = DNSConfiguration.TryParse(section, out read, out error),  Throws.Nothing,  server.ToString());

                Assert.Multiple(() =>
                {
                    Assert.That(parsed,  Is.False,  server.ToString());
                    Assert.That(read,    Is.Null,   server.ToString());
                    Assert.That(error,   Does.Contain("'dns.servers'").And.Contain(Entry));
                });

            }

        }

        #endregion

        #region APortNoClientCanAskIsRefusedWithASentence(Port)

        /// <summary>
        /// A name server's port is read as every other port of the file: 0 is
        /// "any free port" to a listener and nothing at all to a client, and was
        /// kept - a name server that nothing ever answers on, which is what the
        /// DNS page sent for a port somebody emptied; one past the last port, or
        /// one below the first, threw out of the parser.
        /// </summary>
        [TestCase(0)]
        [TestCase(65536)]
        [TestCase(-1)]
        public void APortNoClientCanAskIsRefusedWithASentence(Int32 Port)
        {

            var               entry   = new JObject(
                                            new JProperty("address",  "192.0.2.53"),
                                            new JProperty("port",     Port)
                                        );

            var               parsed  = true;
            DNSServerConfig?  server  = null;
            String?           error   = null;

            Assert.That(() => parsed = DNSConfiguration.TryParseServer(entry, out server, out error),  Throws.Nothing);

            Assert.Multiple(() =>
            {
                Assert.That(parsed,  Is.False);
                Assert.That(server,  Is.Null);
                Assert.That(error,   Does.Contain("'dns.servers[].port'"));
            });

        }

        #endregion

        #region ANameWithAnAddressInItIsAName()

        /// <summary>
        /// A domain name that merely begins with an address - which is what
        /// services like nip.io hand out - is a name server named by its name,
        /// to be resolved like any other. It was an exception as well: the
        /// address was found in it, and the whole of it handed to the parser
        /// for addresses.
        /// </summary>
        [Test]
        public void ANameWithAnAddressInItIsAName()
        {

            var section = JObject.Parse("""{ "servers": [ "10.0.0.1.nip.io" ] }""");

            DNSConfiguration?  read   = null;
            String?            error  = null;

            Assert.That(() => DNSConfiguration.TryParse(section, out read, out error),  Throws.Nothing);
            Assert.That(read,  Is.Not.Null,  error);

            var server = read!.Servers!.Single();

            Assert.Multiple(() =>
            {
                Assert.That(server.IPAddress,                            Is.Null);
                Assert.That(server.DomainName?.ToString().TrimEnd('.'),  Is.EqualTo("10.0.0.1.nip.io"));
            });

        }

        #endregion

        #region ANodeWhoseFileSaysSoStopsWithASentence()

        /// <summary>
        /// And at a start: the node stops over the file the way it stops over
        /// any file it cannot read, saying what is wrong and where - rather than
        /// with an ArgumentException, which is how it stopped before.
        /// </summary>
        /// <remarks>
        /// Constructed and never started, like the nodes of the NTS tests:
        /// the constructor is what reads the file.
        /// </remarks>
        [Test]
        public void ANodeWhoseFileSaysSoStopsWithASentence()
        {

            File.WriteAllText(ConfigurationPath, """{ "dns": { "servers": [ "udp://213.133.98.98:53" ] } }""");

            var problem = Assert.Throws<InvalidOperationException>(() => new WWCPNode(
                                                                             AccountsPath:      Path.Combine(directory, "accounts"),
                                                                             ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                                                                             CertificatesPath:  Path.Combine(directory, "certificates"),
                                                                             LogToConsole:      false
                                                                         ));

            Assert.That(problem?.Message,  Does.Contain("udp://213.133.98.98:53").And.Contain(ConfigurationPath));

        }

        #endregion

        #region ANameServersOwnTimeoutChangedIsInEffectAtOnce()

        /// <summary>
        /// A name server's own timeout changed from a page: in the file, in the
        /// answer to the save, and in the client that asks it - and said in the
        /// log.
        /// </summary>
        /// <remarks>
        /// Two configurations of one server are equal without their timeouts,
        /// so the node took the list for unchanged: the file had the new one,
        /// the page was answered with the old one, and the client went on
        /// waiting as long as before until the next start.
        /// </remarks>
        [Test]
        public async Task ANameServersOwnTimeoutChangedIsInEffectAtOnce()
        {

            File.WriteAllText(ConfigurationPath, """
                                                 { "nts": { "enabled": false },
                                                   "dns": { "servers": [ { "address": "127.0.0.1", "port": 5353, "transport": "UDP", "queryTimeoutSeconds": 1 } ] } }
                                                 """);

            await using var node = new WWCPNode(
                                       AccountsPath:      Path.Combine(directory, "accounts"),
                                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                                       CertificatesPath:  Path.Combine(directory, "certificates"),
                                       LogToConsole:      false
                                   );

            var before = node.Log.LastId;

            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse("""
                            { "servers": [ { "address": "127.0.0.1", "port": 5353, "transport": "UDP", "queryTimeoutSeconds": 2 } ] }
                            """), out var error),
                        Is.True,
                        error);

            var inFile = JObject.Parse(File.ReadAllText(ConfigurationPath))["dns"]!["servers"]![0]!;

            Assert.Multiple(() => {

                Assert.That(inFile.Value<Double>("queryTimeoutSeconds"),                                           Is.EqualTo(2), "in the file");
                Assert.That(node.DNSConfigurationJSON()["servers"]![0]!.Value<Double>("queryTimeoutSeconds"),       Is.EqualTo(2), "in the answer");
                Assert.That(node.DNSClient.DNSServers.Single().QueryTimeout,                                       Is.EqualTo(TimeSpan.FromSeconds(2)), "in the client");

                Assert.That(node.Log.Recent(100, before, null).Select(entry => entry.Message),
                            Has.Some.Contains("timeout: 2 sec."),
                            "and in the log");

            });

        }

        #endregion

    }

}
