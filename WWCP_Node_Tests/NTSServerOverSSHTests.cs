/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// "ssh" in the entry of a time server: its key exchange over SSH - the
    /// subsystem "ntske/1@open.charging.cloud" of the white paper "NTS Key
    /// Establishment over SSH" - instead of TLS, the server held to its host
    /// key: NTSv4SSH of the OCPP Device Model.
    /// </summary>
    [TestFixture]
    public class NTSServerSSHConfigurationTests
    {

        private static readonly String  pinA  = "SHA256:" + new String('A', 43);
        private static readonly String  pinB  = "SHA256:" + new String('B', 43);

        private static NTSServerConfiguration Parsed(String JSON)
        {
            Assert.That(NTSServerConfiguration.TryParse(JToken.Parse(JSON), 0, out var parsed, out var error, "nts.groups.local"), Is.True, error);
            return parsed!;
        }

        private static String Refused(String JSON)
        {
            Assert.That(NTSServerConfiguration.TryParse(JToken.Parse(JSON), 0, out _, out var error, "nts.groups.local"), Is.False, "it was taken");
            return error!;
        }


        #region AnEntryOverSSHIsWrittenAndReadBack()

        /// <summary>
        /// What is not the usual is written back as it was said - a fingerprint
        /// copied with its padding without it - and what is, is left out; an
        /// entry over SSH saying nothing else is still no bare host name.
        /// </summary>
        [Test]
        public void AnEntryOverSSHIsWrittenAndReadBack()
        {

            var full  = Parsed($$"""{ "hostname": "time.lan", "ntpPort": 1123, "ssh": { "port": 2222, "user": "station", "hostKeyPins": [ "{{pinA}}=", "{{pinA}}" ], "hostCAs": [ "{{pinB}}" ], "onMismatch": "record" } }""");
            var bare  = Parsed("""{ "hostname": "time.lan", "ssh": { "user": "ntske" } }""");

            Assert.Multiple(() => {

                Assert.That(full.IsOverSSH,             Is.True);
                Assert.That(full.SSH!.PortOrDefault,    Is.EqualTo(2222));
                Assert.That(full.SSH.UserOrDefault,     Is.EqualTo("station"));
                Assert.That(full.SSH.Pins,              Is.EqualTo(new[] { pinA }), "the same pin twice, or with its padding");
                Assert.That(full.SSH.CAs,               Is.EqualTo(new[] { pinB }));
                Assert.That(full.SSH.OnMismatch,        Is.EqualTo(PinMismatch.Record));

                Assert.That(JToken.DeepEquals(full.ToJSON(), JToken.Parse($$"""{ "hostname": "time.lan.", "ntpPort": 1123, "ssh": { "port": 2222, "user": "station", "hostKeyPins": [ "{{pinA}}" ], "hostCAs": [ "{{pinB}}" ], "onMismatch": "record" } }""")),
                            Is.True, full.ToJSON().ToString());

                Assert.That(bare.SSH!.UserOrDefault,    Is.EqualTo(NTSServerSSH.DefaultUser));
                Assert.That(bare.SSH.PortOrDefault,     Is.EqualTo(NTSServerSSH.DefaultPort));
                Assert.That(JToken.DeepEquals(bare.ToJSON(), JToken.Parse("""{ "hostname": "time.lan.", "ssh": { } }""")), Is.True, bare.ToJSON().ToString());

                Assert.That(Parsed("\"time.lan\"").IsOverSSH, Is.False);

            });

        }

        #endregion

        #region AnEntryOverASharedConnectionIsWrittenAndReadBack()

        /// <summary>
        /// "connection": "shared": the key exchange as one more channel of the
        /// SSH connection the node shares with the server's host, written back
        /// as it was said; "dedicated" is the same as saying nothing. What a
        /// file written before calls it, "useOCPPConnection", is read as it was
        /// and written as it is called now.
        /// </summary>
        [Test]
        public void AnEntryOverASharedConnectionIsWrittenAndReadBack()
        {

            var shared  = Parsed("""{ "hostname": "csms.lan", "ssh": { "connection": "shared" } }""");
            var before  = Parsed("""{ "hostname": "csms.lan", "ssh": { "useOCPPConnection": true } }""");
            var both    = Parsed("""{ "hostname": "csms.lan", "ssh": { "useOCPPConnection": true, "connection": "Shared" } }""");
            var own     = Parsed("""{ "hostname": "time.lan", "ssh": { "connection": "dedicated", "port": 2222 } }""");
            var ownOld  = Parsed("""{ "hostname": "time.lan", "ssh": { "useOCPPConnection": false, "port": 2222 } }""");

            Assert.Multiple(() => {

                Assert.That(shared.IsOverSSH,                      Is.True);
                Assert.That(shared.SSH!.Connection,                Is.EqualTo(SSHConnection.Shared));
                Assert.That(shared.SSH.IsShared,                   Is.True);
                Assert.That(shared.SSH.TextFor("csms.lan"),        Is.EqualTo("the shared SSH connection to csms.lan"));

                foreach (var entry in new[] { shared, before, both })
                    Assert.That(JToken.DeepEquals(entry.ToJSON(), JToken.Parse("""{ "hostname": "csms.lan.", "ssh": { "connection": "shared" } }""")),
                                Is.True, entry.ToJSON().ToString());

                foreach (var entry in new[] { own, ownOld })
                {
                    Assert.That(entry.SSH!.IsShared,               Is.False);
                    Assert.That(JToken.DeepEquals(entry.ToJSON(), JToken.Parse("""{ "hostname": "time.lan.", "ssh": { "port": 2222 } }""")),
                                Is.True, entry.ToJSON().ToString());
                }

            });

        }

        #endregion

        #region WhatIsNoEntryOverSSHIsRefused()

        /// <summary>
        /// A fingerprint that is none, too many of them, a user name that is
        /// none, a mismatch to be used with nothing to mismatch - and anything of
        /// TLS beside SSH - are refused, saying where.
        /// </summary>
        [Test]
        public void WhatIsNoEntryOverSSHIsRefused()
        {

            var seventeen = String.Join(", ", Enumerable.Range(0, 17).Select(i => $"\"SHA256:{Convert.ToBase64String(new Byte[32] { (Byte) i, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }).TrimEnd('=')}\""));

            Assert.Multiple(() => {

                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "hostKeyPins": [ "ab:cd" ] } }"""),                 Does.Contain("nts.groups.local.servers[0].ssh.hostKeyPins").And.Contain("no SHA-256 fingerprint"));
                Assert.That(Refused($$"""{ "hostname": "time.lan", "ssh": { "hostKeyPins": [ {{seventeen}} ] } }"""),         Does.Contain("hostKeyPins"));
                Assert.That(Refused($$"""{ "hostname": "time.lan", "ssh": { "hostCAs": [ "{{pinA}}", "{{pinB}}", "{{pinA}}", "{{pinB}}", "{{pinA}}" ] } }"""), Does.Contain("hostCAs"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "user": "no one" } }"""),                            Does.Contain("is no user name"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "onMismatch": "accept" } }"""),                      Does.Contain("held to no host key and no CA"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "onMismatch": "maybe", "hostKeyPins": [ ] } }"""),   Does.Contain("is none of"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": 22 }"""),                                              Does.Contain("must be an object"));

                Assert.That(Refused($$"""{ "hostname": "time.lan", "ssh": { "connection": "shared", "port": 2222, "hostKeyPins": [ "{{pinA}}" ] } }"""),
                            Does.Contain("\"port\", \"hostKeyPins\" do not apply with \"connection\": \"shared\""));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "useOCPPConnection": true, "onMismatch": "record" } }"""),
                            Does.Contain("\"onMismatch\" does not apply"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "connection": "sometimes" } }"""),
                            Does.Contain("ssh.connection").And.Contain("neither \"dedicated\" nor \"shared\""));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "connection": "dedicated", "useOCPPConnection": true } }"""),
                            Does.Contain("say two things"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ssh": { "useOCPPConnection": "yes" } }"""),  Does.Contain("useOCPPConnection").And.Contain("must be true or false"));

                Assert.That(Refused("""{ "hostname": "time.lan", "ntsKEPort": 4461, "ssh": { } }"""),                          Does.Contain("ntsKEPort").And.Contain("do not apply"));
                Assert.That(Refused("""{ "hostname": "time.lan", "ntsKEHostname": "ke.lan", "ssh": { } }"""),                  Does.Contain("ntsKEHostname"));
                Assert.That(Refused($$"""{ "hostname": "time.lan", "certificateFingerprint": "{{new String('a', 64)}}", "ssh": { } }"""), Does.Contain("what its certificate is held to"));

            });

        }

        #endregion

        #region AHostKeyIsBelievedByItsPinOrByAHostCertificateOfItsCA()

        /// <summary>
        /// A host key is believed where it is pinned, or where it comes as a
        /// host certificate for the server's name, valid now, of one of its CAs -
        /// the certified key being the one shown - and nowhere else.
        /// </summary>
        [Test]
        public void AHostKeyIsBelievedByItsPinOrByAHostCertificateOfItsCA()
        {

            var hostKey  = SshHostKey.GenerateEd25519();
            var ca       = SshHostKey.GenerateEd25519();
            var otherCA  = SshHostKey.GenerateEd25519();
            var now      = DateTimeOffset.UtcNow;
            var keyPrint = SshFingerprint.Sha256(hostKey.PublicKeyBlob);

            Byte[] Certificate(ISshHostKey By, String Name, DateTimeOffset? Before = null)

                => new OpenSshCertificateBuilder {
                       Type         = SshCertType.Host,
                       Principals   = [ Name ],
                       ValidAfter   = now.AddDays(-1),
                       ValidBefore  = Before ?? now.AddDays(1)
                   }.Sign(hostKey.PublicKeyBlob, By).Blob;

            var pinned    = new NTSServerSSH(HostKeyPins: [ keyPrint ]);
            var byCA      = new NTSServerSSH(HostCAs:     [ SshFingerprint.Sha256(ca.PublicKeyBlob) ]);
            var nothing   = new NTSServerSSH();

            Assert.Multiple(() => {

                Assert.That(pinned. Believes(hostKey.PublicKeyBlob,                       "time.lan", now, out var shown,  out var why),    Is.True,  why);
                Assert.That(shown,                                                                                                          Is.EqualTo(keyPrint));
                Assert.That(pinned. Believes(SshHostKey.GenerateEd25519().PublicKeyBlob,  "time.lan", now, out _,          out why),        Is.False, "another key");
                Assert.That(why,                                                                                                            Does.Contain("none it is held to"));

                Assert.That(byCA.   Believes(Certificate(ca, "time.lan"),                 "time.lan", now, out shown,      out why),        Is.True,  why);
                Assert.That(shown,                                                                                                          Is.EqualTo(keyPrint), "the certificate's fingerprint, not its key's");
                Assert.That(pinned. Believes(Certificate(otherCA, "time.lan"),            "time.lan", now, out _,          out why),        Is.True,  "a pinned key, whoever certified it");
                Assert.That(byCA.   Believes(Certificate(ca, "other.lan"),                "time.lan", now, out _,          out why),        Is.False, "for another name");
                Assert.That(byCA.   Believes(Certificate(otherCA, "time.lan"),            "time.lan", now, out _,          out why),        Is.False, "of another CA");
                Assert.That(byCA.   Believes(Certificate(ca, "time.lan", now.AddHours(-1)), "time.lan", now, out _,        out why),        Is.False, "run out");
                Assert.That(byCA.   Believes(hostKey.PublicKeyBlob,                       "time.lan", now, out _,          out why),        Is.False, "a bare key, where only a CA is trusted");

                Assert.That(nothing.Believes(hostKey.PublicKeyBlob,                       "time.lan", now, out _,          out why),        Is.False, "held to nothing");
                Assert.That(why,                                                                                                            Does.Contain("held to no host key and no CA"));

            });

        }

        #endregion

    }


    /// <summary>
    /// A node whose time server makes its key exchange over SSH: a server of
    /// Norn's own with an SSH listener of its own, which lets the node's key in,
    /// on the loopback interface under a name the node's resolver knows.
    /// </summary>
    [TestFixture]
    [NonParallelizable]
    public class NTSServerOverSSHTests
    {

        #region Data

        private static readonly DomainName   timeServer  = DomainName.Parse("time-ssh.test");

        private static readonly IPPort       tlsPort     = FindFreeTCPPort();
        private static readonly IPPort       sshPort     = FindFreeTCPPort();
        private static readonly IPPort       ntpPort     = FindFreeUDPPort();

        private static readonly ISshHostKey  nodeKey     = SshHostKey.GenerateEd25519();
        private static readonly String       pinA        = "SHA256:" + new String('A', 43);
        private static readonly String       pinB        = "SHA256:" + new String('B', 43);

        private NTSServer?  server;
        private String      hostKey    = "";
        private String      directory  = "";

        #endregion

        #region OneTimeSetUp / OneTimeTearDown / Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheTimeServer()
        {

            server  = new NTSServer(
                          NTSKEPort:           tlsPort,
                          NTSPort:             ntpPort,
                          MasterKeysFilePath:  null,
                          SSHPort:             sshPort,
                          SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(nodeKey.PublicKeyBlob)
                      );

            await server.Start();

            hostKey = SshFingerprint.Sha256(server.SSHHostKeys[0].PublicKeyBlob);

        }

        [OneTimeTearDown]
        public async Task StopTheTimeServer()
        {
            if (server is not null)
                await server.ShutdownAsync();
        }

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-nts-ssh-" + Guid.NewGuid().ToString("N")[..12]);
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
            { }
        }

        #endregion

        #region (helpers) Node(SSH, WithItsKey) / TheServer(Node)

        /// <summary>
        /// A node whose legal group asks the time server alone, over SSH as
        /// given - with the key the time server lets in, unless it is to make
        /// one of its own.
        /// </summary>
        private async Task<WWCPNode> Node(String   SSH,
                                          Boolean  WithItsKey  = true,
                                          String?  Peers       = null)
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration,
                              $$"""{ "nts": { "groups": { "legal": { "servers": [ { "hostname": "{{timeServer.Trimmed}}", "ntpPort": {{ntpPort}}, "ssh": {{SSH}} } ], "minServers": 1 } } }{{(Peers is null ? "" : $", \"ssh\": {{ \"peers\": {Peers} }}")}} }""");

            // The key the node signs in with at the SSH peers of its configuration.
            if (Peers is not null)
            {
                Directory.CreateDirectory(Path.Combine(directory, WWCPNode.DefaultSSHDirectory));
                await SshKeyGenerator.WriteKeyPairAsync(nodeKey, Path.Combine(directory, WWCPNode.DefaultSSHDirectory, WWCPNode.SSHPeerClientKeyFileName));
            }

            if (WithItsKey)
            {
                Directory.CreateDirectory(Path.Combine(directory, WWCPNode.DefaultSSHDirectory));
                await SshKeyGenerator.WriteKeyPairAsync(nodeKey, Path.Combine(directory, WWCPNode.DefaultSSHDirectory, WWCPNode.NTSKEClientKeyFileName));
            }

            var dns = new DNSClient(IPv4Address.Localhost, IPPort.Parse(9), QueryTimeout: TimeSpan.FromSeconds(1));

            dns.DNSCache.Add(DNSServiceName.Parse(timeServer.ToString()), new A(timeServer, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost));
            dns.DNSCache.AddNoData(DNSServiceName.Parse(timeServer.ToString()), DNSResourceRecordTypes.AAAA, TimeSpan.FromHours(1));

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       DNSClient:         dns,
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        private static JObject TheServer(WWCPNode Node)

            => (JObject) ((JArray) Node.NTSConfigurationJSON(Node.LegalTime)["timeSources"]!)[0]!;

        #endregion


        #region ATimeServerIsAskedWithItsKeyExchangeOverSSH()

        /// <summary>
        /// Its key exchange goes over SSH, never to a port of NTS-KE over TLS,
        /// with the node's own key; the host key it showed is the pinned one,
        /// and is said with the cookies it brought.
        /// </summary>
        [Test]
        public async Task ATimeServerIsAskedWithItsKeyExchangeOverSSH()
        {

            await using var node = await Node($$"""{ "port": {{sshPort}}, "hostKeyPins": [ "{{hostKey}}" ] }""");

            var synced  = await node.SyncTimeAsync();
            var shown   = TheServer(node);

            Assert.Multiple(() => {

                Assert.That(synced.Value<Boolean>("ok"),                         Is.True,  synced.ToString());
                Assert.That(shown["cookies"]?.Value<Int32>(),                    Is.GreaterThan(0), shown.ToString());
                Assert.That(shown["sshHostKey"]?.Value<String>(),                Is.EqualTo(hostKey));
                Assert.That(shown["hostKeyJudgement"]?["matched"]?.Value<Boolean>(), Is.True);
                Assert.That(shown["hostKeyJudgement"]?["why"]?.Value<String>(),  Does.Contain("is pinned"));
                Assert.That(shown["ssh"]?["port"]?.Value<Int32>(),               Is.EqualTo(sshPort.ToUInt16()));
                Assert.That(shown["certificate"]?.Type,                          Is.EqualTo(JTokenType.Null), "a certificate, over SSH");
                Assert.That(node.NTSKEClientPublicKey,                           Does.StartWith("ssh-ed25519 " + Convert.ToBase64String(SshPublicKey.FromHostKey(nodeKey).Blob)));

            });

        }

        #endregion

        #region AHostKeyThatIsNotPinnedIsRefusedAndSaid()

        /// <summary>
        /// A host key that is none the server is held to ends the connection
        /// before any key exchange: no time, no cookies, and the page says which
        /// key it showed and why it was refused.
        /// </summary>
        [Test]
        public async Task AHostKeyThatIsNotPinnedIsRefusedAndSaid()
        {

            await using var node = await Node($$"""{ "port": {{sshPort}}, "hostKeyPins": [ "SHA256:{{new String('A', 43)}}" ] }""");

            var synced  = await node.SyncTimeAsync();
            var shown   = TheServer(node);

            Assert.Multiple(() => {
                Assert.That(synced.Value<Boolean>("ok"),                             Is.False, "a server that showed another host key was believed");
                Assert.That(shown["cookies"]?.Type,                                  Is.EqualTo(JTokenType.Null));
                Assert.That(shown["sshHostKey"]?.Value<String>(),                    Is.EqualTo(hostKey));
                Assert.That(shown["hostKeyJudgement"]?["accepted"]?.Value<Boolean>(), Is.False);
                Assert.That(shown["hostKeyJudgement"]?["why"]?.Value<String>(),      Does.Contain("none it is held to"));
            });

        }

        #endregion

        #region AMismatchThatIsRecordedIsUsed()

        /// <summary>
        /// A mismatch the entry records is used, and said as one.
        /// </summary>
        [Test]
        public async Task AMismatchThatIsRecordedIsUsed()
        {

            await using var node = await Node($$"""{ "port": {{sshPort}}, "hostKeyPins": [ "SHA256:{{new String('A', 43)}}" ], "onMismatch": "record" }""");

            var synced  = await node.SyncTimeAsync();
            var shown   = TheServer(node);

            Assert.Multiple(() => {
                Assert.That(synced.Value<Boolean>("ok"),                              Is.True,  synced.ToString());
                Assert.That(shown["hostKeyJudgement"]?["matched"]?.Value<Boolean>(),  Is.False);
                Assert.That(shown["hostKeyJudgement"]?["accepted"]?.Value<Boolean>(), Is.True);
            });

        }

        #endregion

        #region AKeyTheServerDoesNotKnowIsNoTime()

        /// <summary>
        /// A node that makes a key of its own - which the time server does not
        /// know yet - is not let in; and keeps that key for the next start, so
        /// that what was entered at the server once stays good.
        /// </summary>
        [Test]
        public async Task AKeyTheServerDoesNotKnowIsNoTimeAndIsKept()
        {

            String? made;

            await using (var node = await Node($$"""{ "port": {{sshPort}}, "hostKeyPins": [ "{{hostKey}}" ] }""", WithItsKey: false))
            {

                var synced = await node.SyncTimeAsync();

                made = node.NTSKEClientPublicKey;

                Assert.Multiple(() => {
                    Assert.That(synced.Value<Boolean>("ok"),                  Is.False, "a key the server does not know was let in");
                    Assert.That(made,                                         Does.StartWith("ssh-ed25519 "));
                    Assert.That(File.Exists(node.NTSKEClientKeyPath),         Is.True);
                    Assert.That(File.Exists(node.NTSKEClientKeyPath + ".pub"), Is.True);
                });

            }

            await using var again = await Node($$"""{ "port": {{sshPort}}, "hostKeyPins": [ "{{hostKey}}" ] }""", WithItsKey: false);

            Assert.That(again.NTSKEClientPublicKey, Is.EqualTo(made), "a new key at the next start");

        }

        #endregion

        #region AKeyExchangeSharesTheConnectionToAnSSHPeer()

        /// <summary>
        /// "connection": "shared": the key exchange is one more channel of the
        /// SSH connection the node keeps to the SSH peer the server's host is -
        /// with the login of that connection, and the host key it is held to,
        /// not judged again. Nothing made that connection before: the key
        /// exchange is the first to need it, and has it made. It leaves it
        /// open, and so does the test of the server, which goes over the same
        /// one. No key of the node's own is made for it.
        /// </summary>
        [Test]
        public async Task AKeyExchangeSharesTheConnectionToAnSSHPeer()
        {

            var serversKey = server!.SSHHostKeys[0].PublicKeyBlob;

            await using var connection = new SshSharedConnection("127.0.0.1",
                                                                 sshPort.ToUInt16(),
                                                                 new SshClientOptions {
                                                                     Username       = "ntske",
                                                                     Credentials    = [ nodeKey ],
                                                                     VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(serversKey)
                                                                 });

            await using var node = await Node("""{ "connection": "shared" }""", WithItsKey: false);

            var askedFor = new List<String>();
            var peer     = new SSHPeer(timeServer,
                                       sshPort.ToUInt16(),
                                       connection,
                                       WhyNot: subsystem => { askedFor.Add(subsystem); return null; });

            var before  = node.AddSSHPeer(peer);
            var unmade  = connection.Current;

            var synced  = await node.SyncTimeAsync();
            var made    = connection.Current;
            var shown   = TheServer(node);
            var tested  = await node.TestTimeServerAsync(timeServer.Trimmed);
            var said    = String.Join(" | ", ((JArray) tested["steps"]!).Select(step => step["text"]!.Value<String>()));

            Assert.Multiple(() => {

                Assert.That(before,                                     Is.Null);
                Assert.That(node.SSHPeerTo(timeServer),                 Is.SameAs(peer));
                Assert.That(unmade,                                     Is.Null,  "a connection before anything needed one");

                Assert.That(synced.Value<Boolean>("ok"),                Is.True,  synced.ToString());
                Assert.That(shown["cookies"]?.Value<Int32>(),           Is.GreaterThan(0), shown.ToString());
                Assert.That(shown["sshHostKey"]?.Value<String>(),       Is.EqualTo(hostKey));
                Assert.That(shown["hostKeyJudgement"]?.Type ?? JTokenType.Null, Is.EqualTo(JTokenType.Null), "the shared connection's host key was judged again");
                Assert.That(shown["ssh"]?["connection"]?.Value<String>(), Is.EqualTo("shared"));

                Assert.That(tested.Value<Boolean>("ok"),                Is.True,  said);
                Assert.That(said,                                       Does.Contain("the shared SSH connection to " + timeServer.Trimmed));
                Assert.That(said,                                       Does.Contain($"It shows the SSH host key {hostKey}, which the shared connection is held to"));

                Assert.That(askedFor,                                   Is.Not.Empty);
                Assert.That(askedFor,                                   Has.All.EqualTo(NTSKE_SSH.SubsystemName));
                Assert.That(made,                                       Is.Not.Null, "the key exchange did not have the connection made");
                Assert.That(connection.Current,                         Is.SameAs(made), "the shared connection was closed, or made again");
                Assert.That(connection.Made,                            Is.EqualTo(1));
                Assert.That(File.Exists(node.NTSKEClientKeyPath),       Is.False, "a key of the node's own was made");

            });

        }

        #endregion

        #region WithoutAnSSHPeerThereIsNoKeyExchange()

        /// <summary>
        /// Where the server's host is no SSH peer of the node - or its
        /// connection may not carry the key exchange now - there is no key
        /// exchange, and no other way is tried: not a connection of the node's
        /// own, not TLS. A peer that says no is not even dialled.
        /// </summary>
        [Test]
        public async Task WithoutAnSSHPeerThereIsNoKeyExchange()
        {

            await using var node = await Node("""{ "connection": "shared" }""");

            var noPeer  = await node.SyncTimeAsync();
            var tested  = await node.TestTimeServerAsync(timeServer.Trimmed);
            var said    = String.Join(" | ", ((JArray) tested["steps"]!).Select(step => step["text"]!.Value<String>()));

            var dials   = 0;

            await using var connection = new SshSharedConnection(ct => { dials++; return ValueTask.FromException<SshClient>(new InvalidOperationException("dialled")); });

            var peer    = new SSHPeer(timeServer, sshPort.ToUInt16(), connection, WhyNot: subsystem => "its host key is on probation.");

            node.AddSSHPeer(peer);

            var refused = await node.SyncTimeAsync();
            var again   = await node.TestTimeServerAsync(timeServer.Trimmed);
            var saidNow = String.Join(" | ", ((JArray) again["steps"]!).Select(step => step["text"]!.Value<String>()));

            var removed = node.RemoveSSHPeer(peer);

            Assert.Multiple(() => {
                Assert.That(noPeer. Value<Boolean>("ok"),               Is.False, "a key exchange without an SSH peer");
                Assert.That(refused.Value<Boolean>("ok"),               Is.False, "a key exchange over a connection that may not carry it");
                Assert.That(TheServer(node)["cookies"]?.Type ?? JTokenType.Null, Is.EqualTo(JTokenType.Null));
                Assert.That(tested.Value<Boolean>("ok"),                Is.False);
                Assert.That(said,                                       Does.Contain($"{timeServer.Trimmed} is no SSH peer of this"));
                Assert.That(said,                                       Does.Not.Contain("over TLS"));
                Assert.That(again.Value<Boolean>("ok"),                 Is.False);
                Assert.That(saidNow,                                    Does.Contain("its host key is on probation."));
                Assert.That(dials,                                      Is.Zero,  "a peer that may not carry the key exchange was dialled for it");
                Assert.That(removed,                                    Is.True);
                Assert.That(node.SSHPeerTo(timeServer),                 Is.Null);
            });

        }

        #endregion

        #region AKeyExchangeGoesOverAPeerOfTheConfigurationWithoutOCPP()

        /// <summary>
        /// An SSH peer the configuration file names, under "ssh.peers": a host
        /// the node keeps one SSH connection to with nothing of OCPP about it.
        /// A time server there with "connection": "shared" makes its key
        /// exchange as a channel of it - the node signed in with the key it has
        /// for its peers, the host believed by the pin of the peer's entry, and
        /// the one connection made by the key exchange and left to the next.
        /// </summary>
        [Test]
        public async Task AKeyExchangeGoesOverAPeerOfTheConfigurationWithoutOCPP()
        {

            await using var node = await Node("""{ "connection": "shared" }""",
                                              WithItsKey:  false,
                                              Peers:       $$"""[ { "id": "time", "address": "{{timeServer.Trimmed}}", "port": {{sshPort}}, "user": "ntske", "hostKeyPins": [ "{{hostKey}}" ] } ]""");

            var peer    = node.SSHPeerTo(timeServer);
            var unmade  = peer?.Connection.Current;

            var synced  = await node.SyncTimeAsync();
            var again   = await node.SyncTimeAsync();
            var shown   = (JObject) node.SSHPeersJSON().Single();

            Assert.Multiple(() => {

                Assert.That(node.ConfiguredSSHPeers.Select(configured => configured.Id), Is.EqualTo(new[] { "time" }));
                Assert.That(peer,                                        Is.Not.Null, "the host of the configuration is no SSH peer");
                Assert.That(peer?.Port,                                  Is.EqualTo(sshPort.ToUInt16()));
                Assert.That(unmade,                                      Is.Null,  "a connection before anything needed one");

                Assert.That(synced.Value<Boolean>("ok"),                 Is.True,  synced.ToString());
                Assert.That(again. Value<Boolean>("ok"),                 Is.True,  again.ToString());
                Assert.That(TheServer(node)["cookies"]?.Value<Int32>(),  Is.GreaterThan(0));
                Assert.That(peer?.Connection.Made,                       Is.EqualTo(1), "more than the one connection was made");

                Assert.That(node.SSHPeerHostKeyJudgementOf("time")?.Matched,  Is.True);
                Assert.That(node.SSHPeerHostKeyJudgementOf("time")?.Shown,    Is.EqualTo(hostKey));
                Assert.That(shown.Value<Boolean>("connected"),           Is.True,  shown.ToString());
                Assert.That(shown.Value<String>("id"),                   Is.EqualTo("time"));
                Assert.That(peer?.PublicKey?.Invoke(),                   Does.StartWith("ssh-ed25519 " + Convert.ToBase64String(SshPublicKey.FromHostKey(nodeKey).Blob)));

                Assert.That(File.Exists(node.NTSKEClientKeyPath),        Is.False, "a key for time servers of their own was made");

            });

        }

        #endregion

        #region APeerOfTheConfigurationThatShowsAnotherKeyIsRefused()

        /// <summary>
        /// A configured peer is believed by what its entry holds it to, and by
        /// nothing else: one that shows another host key is refused, and said
        /// so, and the key exchange that wanted its connection fails.
        /// </summary>
        [Test]
        public async Task APeerOfTheConfigurationThatShowsAnotherKeyIsRefused()
        {

            await using var node = await Node("""{ "connection": "shared" }""",
                                              WithItsKey:  false,
                                              Peers:       $$"""[ { "id": "time", "address": "{{timeServer.Trimmed}}", "port": {{sshPort}}, "user": "ntske", "hostKeyPins": [ "{{pinB}}" ] } ]""");

            var synced = await node.SyncTimeAsync();

            Assert.Multiple(() => {
                Assert.That(synced.Value<Boolean>("ok"),                          Is.False, "a key exchange over a peer that showed a key it is not held to");
                Assert.That(node.SSHPeerHostKeyJudgementOf("time")?.Matched,      Is.False);
                Assert.That(node.SSHPeerHostKeyJudgementOf("time")?.Accepted,     Is.False);
                Assert.That(node.SSHPeerHostKeyJudgementOf("time")?.Shown,        Is.EqualTo(hostKey));
                Assert.That(node.SSHPeerTo(timeServer)?.Connection.Current,       Is.Null);
            });

        }

        #endregion

        #region APeerTakenOutOfTheConfigurationIsNoPeerAnyMore()

        /// <summary>
        /// The peers are what the configuration says now: one that is taken out
        /// is no peer any more, its connection is closed for whatever shared
        /// it, and the time server that shared it has no key exchange - the
        /// cookies it has keep NTP going. Put back,
        /// it is a peer again, with a connection made anew.
        /// </summary>
        [Test]
        public async Task APeerTakenOutOfTheConfigurationIsNoPeerAnyMore()
        {

            var peers = $$"""[ { "id": "time", "address": "{{timeServer.Trimmed}}", "port": {{sshPort}}, "user": "ntske", "hostKeyPins": [ "{{hostKey}}" ] } ]""";

            await using var node = await Node("""{ "connection": "shared" }""", WithItsKey: false, Peers: peers);

            var with      = await node.SyncTimeAsync();
            var first     = node.SSHPeerTo(timeServer);
            var itsSsh    = first?.Connection.Current;

            var takenOut  = await node.TryUpdateSSHConfiguration(new JObject { ["peers"] = new JArray() });

            if (itsSsh is not null)
                await itsSsh.Closed.WaitAsync(TimeSpan.FromSeconds(10));

            // The cookies it has keep NTP going; a key exchange is what needs
            // the connection, and the test of the server makes one.
            var tested    = await node.TestTimeServerAsync(timeServer.Trimmed);
            var said      = String.Join(" | ", ((JArray) tested["steps"]!).Select(step => step["text"]!.Value<String>()));

            var putBack   = await node.TryUpdateSSHConfiguration(new JObject { ["peers"] = JArray.Parse(peers) });
            var back      = await node.SyncTimeAsync();

            Assert.Multiple(() => {
                Assert.That(with.Value<Boolean>("ok"),                   Is.True,  with.ToString());
                Assert.That(takenOut.Error,                              Is.Null);
                Assert.That(itsSsh?.Closed.IsCompleted,                  Is.True,  "the connection to a peer that is none any more stayed open");
                Assert.That(tested.Value<Boolean>("ok"),                 Is.False, "a key exchange over a peer that was taken out");
                Assert.That(said,                                        Does.Contain($"{timeServer.Trimmed} is no SSH peer of this"));
                Assert.That(putBack.Error,                               Is.Null);
                Assert.That(back.Value<Boolean>("ok"),                   Is.True,  back.ToString());
                Assert.That(node.SSHPeerTo(timeServer),                  Is.Not.Null.And.Not.SameAs(first));
                Assert.That(node.SSHConfigurationJSON()["configured"]?["peers"]?.Count(), Is.EqualTo(1));
            });

        }

        #endregion

        #region ThePeersOfTheConfigurationAreReadAndWrittenBack()

        /// <summary>
        /// "ssh.peers": a name and an address each, and a host key or a CA to
        /// hold it to. What is none of that is refused, saying where.
        /// </summary>
        [Test]
        public void ThePeersOfTheConfigurationAreReadAndWrittenBack()
        {

            static String Refusal(String Peers)
                => SSHConfiguration.TryParse(JObject.Parse($$"""{ "peers": {{Peers}} }"""), out _, out var error) ? "" : error!;

            var read = SSHConfiguration.TryParse(JObject.Parse($$"""{ "peers": [ { "id": "lc", "address": "LC.example", "hostKeyPins": [ "{{pinA}}=" ] }, { "id": "time", "address": "10.10.0.7", "port": 2222, "user": "cs001", "hostCAs": [ "{{pinB}}" ], "onMismatch": "record" } ] }"""),
                                                 out var parsed, out var problem);

            Assert.Multiple(() => {

                Assert.That(read, Is.True, problem);

                Assert.That(parsed!.Peers!.Select(peer => peer.Id),             Is.EqualTo(new[] { "lc", "time" }));
                Assert.That(parsed.Peers![0].Port,                               Is.EqualTo(22));
                Assert.That(parsed.Peers![0].User,                               Is.Null);
                Assert.That(parsed.Peers![1].Port,                               Is.EqualTo(2222));
                Assert.That(parsed.Peers![1].User,                               Is.EqualTo("cs001"));
                Assert.That(parsed.Peers![1].Trust.OnMismatch,                   Is.EqualTo(PinMismatch.Record));

                Assert.That(JToken.DeepEquals(parsed.ToJSON()["peers"],
                                              JToken.Parse($$"""[ { "id": "lc", "address": "LC.example", "hostKeyPins": [ "{{pinA}}" ] }, { "id": "time", "address": "10.10.0.7", "user": "cs001", "port": 2222, "hostCAs": [ "{{pinB}}" ], "onMismatch": "record" } ]""")),
                            Is.True, parsed.ToJSON().ToString());

                Assert.That(Refusal($$"""[ { "id": "lc", "address": "lc.example" } ]"""),                                       Does.Contain("ssh.peers[0]").And.Contain("held to no host key and no CA"));
                Assert.That(Refusal($$"""[ { "address": "lc.example", "hostKeyPins": [ "{{pinA}}" ] } ]"""),                    Does.Contain("ssh.peers[0].id"));
                Assert.That(Refusal($$"""[ { "id": "l c", "address": "lc.example", "hostKeyPins": [ "{{pinA}}" ] } ]"""),       Does.Contain("is no name of a peer"));
                Assert.That(Refusal($$"""[ { "id": "lc", "hostKeyPins": [ "{{pinA}}" ] } ]"""),                                 Does.Contain("ssh.peers[0].address"));
                Assert.That(Refusal($$"""[ { "id": "lc", "address": "lc.example", "user": "no one", "hostKeyPins": [ "{{pinA}}" ] } ]"""), Does.Contain("is no user name"));
                Assert.That(Refusal($$"""[ { "id": "lc", "address": "lc.example", "hostKeyPins": [ "ab:cd" ] } ]"""),           Does.Contain("no SHA-256 fingerprint"));
                Assert.That(Refusal($$"""[ { "id": "a", "address": "lc.example", "hostKeyPins": [ "{{pinA}}" ] }, { "id": "A", "address": "other.example", "hostKeyPins": [ "{{pinA}}" ] } ]"""),
                            Does.Contain("ssh.peers[1].id").And.Contain("already"));
                Assert.That(Refusal($$"""[ { "id": "a", "address": "lc.example", "hostKeyPins": [ "{{pinA}}" ] }, { "id": "b", "address": "LC.example.", "hostKeyPins": [ "{{pinA}}" ] } ]"""),
                            Does.Contain("ssh.peers[1].address").And.Contain("one connection to a host"));
                Assert.That(Refusal("""{ "id": "lc" }"""),                                                                     Does.Contain("must be a list"));

            });

        }

        #endregion

        #region TheTestOfATimeServerGoesOverSSH()

        /// <summary>
        /// The test of one server, as the page and the command line start it,
        /// makes its key exchange as every round does: over SSH.
        /// </summary>
        [Test]
        public async Task TheTestOfATimeServerGoesOverSSH()
        {

            await using var node = await Node($$"""{ "port": {{sshPort}}, "hostKeyPins": [ "{{hostKey}}" ] }""");

            var tested  = await node.TestTimeServerAsync(timeServer.Trimmed);
            var said    = String.Join(" | ", ((JArray) tested["steps"]!).Select(step => step["text"]!.Value<String>()));

            Assert.Multiple(() => {
                Assert.That(tested.Value<Boolean>("ok"),  Is.True,  said);
                Assert.That(said,                         Does.Contain("Key exchange over SSH"));
                Assert.That(said,                         Does.Contain($"It showed the SSH host key {hostKey}"));
                Assert.That(said,                         Does.Not.Contain("over TLS"));
            });

        }

        #endregion


        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {
            using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            return IPPort.Parse(((IPEndPoint) listener.LocalEndpoint).Port);
        }

        private static IPPort FindFreeUDPPort()
        {
            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);
        }

        #endregion

    }

}
