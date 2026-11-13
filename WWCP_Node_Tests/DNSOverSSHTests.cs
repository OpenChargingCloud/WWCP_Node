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

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// "transport": "SSH" in the entry of a name server, and "ssh" beside it:
    /// asked over the subsystem "dns@open.charging.cloud" of the white paper
    /// "DNS over SSH", the server held to its host key - as the file says it,
    /// reads it and writes it back.
    /// </summary>
    [TestFixture]
    public class DNSServerSSHConfigurationTests
    {

        private static readonly String  pinA  = "SHA256:" + new String('A', 43);
        private static readonly String  pinB  = "SHA256:" + new String('B', 43);

        private static DNSConfiguration Parsed(String Servers, String More = "")
        {
            Assert.That(DNSConfiguration.TryParse(JObject.Parse($$"""{ "servers": [ {{Servers}} ] {{More}} }"""), out var parsed, out var error), Is.True, error);
            return parsed!;
        }

        private static String Refused(String Servers)
        {
            Assert.That(DNSConfiguration.TryParse(JObject.Parse($$"""{ "servers": [ {{Servers}} ] }"""), out _, out var error), Is.False, "it was taken: " + Servers);
            return error!;
        }


        #region AServerOverSSHIsWrittenAndReadBack()

        /// <summary>
        /// What is not the usual is written back as it was said - a fingerprint
        /// copied with its padding without it, the port once, as the server's -
        /// and what is, is left out. The login is kept as it was said, also
        /// where it is the one a time server leaves out: a name server's usual
        /// login is the node's own name, which no file knows.
        /// </summary>
        [Test]
        public void AServerOverSSHIsWrittenAndReadBack()
        {

            var full    = Parsed($$"""{ "id": "cpo-1", "address": "192.0.2.53", "transport": "SSH", "ssh": { "port": 2222, "user": "ntske", "hostKeyPins": [ "{{pinA}}=", "{{pinA}}" ], "hostCAs": [ "{{pinB}}" ], "onMismatch": "record" } }""");
            var bare    = Parsed($$"""{ "address": "ns.example", "transport": "ssh", "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }""");
            var server  = full.Servers![0];
            var ssh     = full.SSH![server];

            Assert.Multiple(() => {

                Assert.That(server.Transport,                 Is.EqualTo(DNSTransport.SSH));
                Assert.That(server.Port.ToUInt16(),           Is.EqualTo(2222), "the SSH port is the server's port");
                Assert.That(server.SSH,                       Is.Null,          "the file says what a server is held to; the node says how it is asked");
                Assert.That(ssh.Port,                         Is.Null,          "the port, said twice");
                Assert.That(ssh.User,                         Is.EqualTo("ntske"));
                Assert.That(ssh.Pins,                         Is.EqualTo(new[] { pinA }), "the same pin twice, or with its padding");
                Assert.That(ssh.CAs,                          Is.EqualTo(new[] { pinB }));
                Assert.That(ssh.OnMismatch,                   Is.EqualTo(PinMismatch.Record));
                Assert.That(ssh.IsShared,                     Is.False);
                Assert.That(full.Pins,                        Is.Empty,         "a certificate pin, over SSH");

                Assert.That(JToken.DeepEquals(full.ToJSON()["servers"]![0],
                                              JToken.Parse($$"""{ "id": "cpo-1", "address": "192.0.2.53", "port": 2222, "transport": "SSH", "queryTimeoutSeconds": null, "ssh": { "user": "ntske", "hostKeyPins": [ "{{pinA}}" ], "hostCAs": [ "{{pinB}}" ], "onMismatch": "record" } }""")),
                            Is.True, full.ToJSON().ToString());

                Assert.That(bare.Servers![0].Port.ToUInt16(), Is.EqualTo(22));
                Assert.That(bare.SSH![bare.Servers[0]].User,  Is.Null);
                Assert.That(JToken.DeepEquals(bare.ToJSON()["servers"]![0],
                                              JToken.Parse($$"""{ "address": "ns.example.", "port": 22, "transport": "SSH", "queryTimeoutSeconds": null, "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }""")),
                            Is.True, bare.ToJSON().ToString());

                // Read again, it is what it was.
                Assert.That(DNSConfiguration.TryParse(full.ToJSON(), out var again, out var error), Is.True, error);
                Assert.That(again!.ToJSON().ToString(),       Is.EqualTo(full.ToJSON().ToString()));

                // The port as the server's own, as every other transport has it.
                Assert.That(Parsed($$"""{ "address": "192.0.2.53", "port": 2222, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }""").Servers![0].Port.ToUInt16(),
                            Is.EqualTo(2222));
                Assert.That(Parsed($$"""{ "address": "192.0.2.53", "port": 2222, "transport": "SSH", "ssh": { "port": 2222, "hostKeyPins": [ "{{pinA}}" ] } }""").Servers![0].Port.ToUInt16(),
                            Is.EqualTo(2222));

            });

        }

        #endregion

        #region AServerOnASharedConnectionIsWrittenAndReadBack()

        /// <summary>
        /// "connection": "shared": the queries as one more channel of the SSH
        /// connection the node keeps to the SSH peer the address is - with
        /// nothing of its own, not even a port.
        /// </summary>
        [Test]
        public void AServerOnASharedConnectionIsWrittenAndReadBack()
        {

            var shared  = Parsed("""{ "id": "lc", "address": "10.10.0.1", "transport": "SSH", "ssh": { "connection": "shared" } }""");
            var written = Parsed("""{ "id": "lc", "address": "10.10.0.1", "port": 22, "transport": "SSH", "ssh": { "connection": "Shared" } }""");

            Assert.Multiple(() => {

                foreach (var entry in new[] { shared, written })
                {
                    Assert.That(entry.SSH![entry.Servers![0]].IsShared,  Is.True);
                    Assert.That(entry.SSH [entry.Servers [0]].IsPinned,  Is.False);
                    Assert.That(JToken.DeepEquals(entry.ToJSON()["servers"]![0],
                                                  JToken.Parse("""{ "id": "lc", "address": "10.10.0.1", "transport": "SSH", "queryTimeoutSeconds": null, "ssh": { "connection": "shared" } }""")),
                                Is.True, entry.ToJSON().ToString());
                }

            });

        }

        #endregion

        #region WhatIsNoServerOverSSHIsRefused()

        /// <summary>
        /// A server over SSH that nobody could believe - no host key, no CA, no
        /// shared connection - is never stored (section 7.2 of the white
        /// paper); nor is "ssh" on a server that is not asked over SSH, a
        /// certificate pin on one that is, anything of its own on a shared
        /// connection, or two ports.
        /// </summary>
        [Test]
        public void WhatIsNoServerOverSSHIsRefused()
        {

            var certificate = new String('a', 64);

            Assert.Multiple(() => {

                // The positive control: the same entry with a pin is taken.
                Assert.That(Parsed($$"""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }""").Servers, Has.Count.EqualTo(1));
                Assert.That(Parsed($$"""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "hostCAs": [ "{{pinA}}" ] } }""").Servers,     Has.Count.EqualTo(1));

                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH" }"""),
                            Does.Contain("dns.servers[0]").And.Contain("held to no host key and no CA").And.Contain("never stored"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { } }"""),
                            Does.Contain("held to no host key and no CA"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "connection": "dedicated", "user": "cs001" } }"""),
                            Does.Contain("held to no host key and no CA"));
                Assert.That(Refused("\"192.0.2.1\", " + """{ "address": "192.0.2.53", "transport": "SSH" }"""),
                            Does.Contain("dns.servers[1]"));

                Assert.That(Refused($$"""{ "address": "192.0.2.53", "transport": "TLS", "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }"""),
                            Does.Contain("dns.servers[0].ssh").And.Contain("asked over TLS"));
                Assert.That(Refused($$"""{ "address": "192.0.2.53", "ssh": { "connection": "shared" } }"""),
                            Does.Contain("dns.servers[0].ssh").And.Contain("asked over UDP"));

                Assert.That(Refused($$"""{ "address": "192.0.2.53", "transport": "SSH", "certificateFingerprint": "{{certificate}}", "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }"""),
                            Does.Contain("held to a certificate and asked over SSH, which shows none"));

                Assert.That(Refused($$"""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "connection": "shared", "hostKeyPins": [ "{{pinA}}" ] } }"""),
                            Does.Contain("\"hostKeyPins\" does not apply with \"connection\": \"shared\"").And.Contain("name resolution goes over the SSH connection"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "connection": "shared", "user": "cs001" } }"""),
                            Does.Contain("\"user\" does not apply"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "port": 2222, "transport": "SSH", "ssh": { "connection": "shared" } }"""),
                            Does.Contain("dns.servers[0].port").And.Contain("does not apply with \"connection\": \"shared\""));

                Assert.That(Refused($$"""{ "address": "192.0.2.53", "port": 2222, "transport": "SSH", "ssh": { "port": 22, "hostKeyPins": [ "{{pinA}}" ] } }"""),
                            Does.Contain("one port"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "hostKeyPins": [ "ab:cd:ef" ] } }"""),
                            Does.Contain("dns.servers[0].ssh.hostKeyPins").And.Contain("no SHA-256 fingerprint"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH", "ssh": { "onMismatch": "accept" } }"""),
                            Does.Contain("held to no host key and no CA"));
                Assert.That(Refused("""{ "address": "192.0.2.53", "transport": "SSH", "ssh": 22 }"""),
                            Does.Contain("must be an object"));

            });

        }

        #endregion

        #region SSHCountsAsEncrypted()

        /// <summary>
        /// A server asked over SSH is none in clear text: where only encrypted
        /// servers are asked, it is one of them (section 7.1). It shows no
        /// certificate all the same.
        /// </summary>
        [Test]
        public void SSHCountsAsEncrypted()
        {

            var servers = Parsed($$"""{ "address": "192.0.2.1" }, { "address": "192.0.2.2", "transport": "TLS" }, { "address": "192.0.2.3", "transport": "SSH", "ssh": { "hostKeyPins": [ "{{pinA}}" ] } }""",
                                 """, "encryptedOnly": true""");

            Assert.Multiple(() => {
                Assert.That(DNSConfiguration.IsEncrypted     (DNSTransport.SSH),  Is.True);
                Assert.That(DNSConfiguration.ShowsCertificate(DNSTransport.SSH),  Is.False);
                Assert.That(DNSConfiguration.IsEncrypted     (DNSTransport.TCP),  Is.False);
                Assert.That(DNSConfiguration.ShowsCertificate(DNSTransport.TLS),  Is.True);
                Assert.That(DNSConfiguration.InClearText(servers.Servers!).Select(server => server.Transport), Is.EqualTo(new[] { DNSTransport.UDP }));
            });

        }

        #endregion

    }


    /// <summary>
    /// A node with a name server over SSH: an SSH server on the loopback
    /// interface that hands the subsystem "dns@open.charging.cloud" to a DNS
    /// server without a listener of its own, as a resolver behind OpenSSH
    /// would (white paper "DNS over SSH", chapter 11: T5, T6, T7, T9, T11, T12,
    /// T13, T18, T21).
    /// </summary>
    /// <remarks>
    /// Whatever is said not to have happened here is said beside something
    /// that shows the server was reached - or was there to be reached, and was
    /// not: the SSH server's own account of its connections, logins and
    /// subsystems, and what the DNS server behind it was asked.
    /// </remarks>
    [TestFixture]
    [NonParallelizable]
    public class DNSOverSSHTests
    {

        #region Data

        private const String Echo      = "echo@test.open.charging.cloud";

        /// <summary>
        /// A login the SSH server lets in, and does not offer the DNS subsystem to.
        /// </summary>
        private const String OCPPOnly  = "ocpp-only";

        private static readonly ISshHostKey  nodeKey   = SshHostKey.GenerateEd25519();
        private static readonly ISshHostKey  hostKey1  = SshHostKey.GenerateEd25519();
        private static readonly ISshHostKey  hostKey2  = SshHostKey.GenerateEd25519();
        private static readonly String       print1    = SshFingerprint.Sha256(hostKey1.PublicKeyBlob);
        private static readonly String       print2    = SshFingerprint.Sha256(hostKey2.PublicKeyBlob);
        private static readonly String       notShown  = "SHA256:" + new String('A', 43);

        private String directory = "";

        private readonly List<Running> servers = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-dns-ssh-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var server in servers)
                await server.DisposeAsync();

            servers.Clear();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion

        #region (helpers) The name server behind an SSH server

        private sealed class Running(DNSServer DNS, SshServer SSH, CollectingAuditSink Audit) : IAsyncDisposable
        {

            private Int32 channels;
            private Int32 channelsEnded;
            private Int32 stopped;

            public CollectingAuditSink         Audit     { get; } = Audit;
            public UInt16                      Port      => (UInt16) SSH.LocalEndPoint.Port.ToInt32();

            /// <summary>
            /// What the DNS server was asked.
            /// </summary>
            public ConcurrentQueue<DNSPacket>  Requests  { get; } = new();

            /// <summary>
            /// How many channels the DNS subsystem was served on so far, and
            /// how many of them ended.
            /// </summary>
            public Int32  Channels       => Volatile.Read(ref channels);
            public Int32  ChannelsEnded  => Volatile.Read(ref channelsEnded);

            public Int32 ChannelOpened()  => Interlocked.Increment(ref channels);
            public Int32 ChannelEnded()   => Interlocked.Increment(ref channelsEnded);

            public Int32 Count<TEvent>(Func<TEvent, Boolean>? Which = null) where TEvent : SshAuditEvent
                => Audit.Events.OfType<TEvent>().Count(audited => Which?.Invoke(audited) ?? true);

            public async ValueTask DisposeAsync()
            {

                if (Interlocked.Exchange(ref stopped, 1) != 0)
                    return;

                await SSH.DisposeAsync();
                await DNS.Stop();

            }

        }

        private static InMemoryDNSZone Zone()
        {

            var zone = new InMemoryDNSZone().
                           Add(new SOA(
                                   DomainName.        Parse("example.org."),
                                   DNSQueryClasses.IN,
                                   TimeSpan.          FromSeconds(300),
                                   DomainName.        Parse("ns.example.org."),
                                   SimpleEMailAddress.Parse("hostmaster@example.org"),
                                   1,
                                   TimeSpan.          FromSeconds(3600),
                                   TimeSpan.          FromSeconds(600),
                                   TimeSpan.          FromSeconds(86400),
                                   TimeSpan.          FromSeconds(300)
                               ));

            // A name for every question of a test, so that no answer is one
            // the node remembered.
            for (var i = 0; i < 16; i++)
                zone.Add(new A(
                             DomainName. Parse($"host{i:D2}.example.org."),
                             DNSQueryClasses.IN,
                             TimeSpan.   FromSeconds(300),
                             IPv4Address.Parse($"192.0.2.{100 + i}")
                         ));

            return zone;

        }

        /// <summary>
        /// An SSH server that shows the given host key, lets the given keys in
        /// under any login, and hands the DNS subsystem to a DNS server without
        /// a listener of its own - to every login but <see cref="OCPPOnly"/>.
        /// </summary>
        /// <param name="HostKey">The host key it shows: a key, or a key with its host certificate.</param>
        /// <param name="Port">The port it listens on, where it takes the place of a server before it.</param>
        /// <param name="LetIn">The keys it lets in; the node's by default.</param>
        private async Task<Running> NameServer(ISshHostKey      HostKey,
                                               UInt16?          Port    = null,
                                               params Byte[][]  LetIn)
        {

            var dns      = new DNSServer(
                               new AuthoritativeDNSRequestHandler(Zone()),
                               new DNSServerOptions {
                                   EnableUDPUnicast    = false,
                                   EnableUDPMulticast  = false,
                                   EnableTCPUnicast    = false
                               }
                           );

            var audit    = new CollectingAuditSink();
            Running? running = null;

            dns.OnDNSRequestReceived += (timestamp, server, serverType, request, ct) => {
                running!.Requests.Enqueue(request);
                return Task.CompletedTask;
            };

            var ssh      = new SshServer(new SshServerOptions {
                               HostKeys       = [ HostKey ],
                               Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(LetIn.Length > 0 ? LetIn : [ nodeKey.PublicKeyBlob ]),
                               AuditSink      = audit,
                               Subsystems     = (session, name, ct) => ValueTask.FromResult<SshSubsystemHandler?>(name switch {

                                                    DNSServer.SSHSubsystemName when session.Username != OCPPOnly
                                                        => async (context, token) => {

                                                               running!.ChannelOpened();

                                                               try
                                                               {
                                                                   await dns.ServeSSHSubsystemAsync(context, token);
                                                               }
                                                               catch (OperationCanceledException)
                                                               { }
                                                               finally
                                                               {
                                                                   running.ChannelEnded();
                                                               }

                                                           },

                                                    Echo
                                                        => async (context, token) => {
                                                               await context.Channel.SendDataAsync("echo\n"u8.ToArray(), token);
                                                           },

                                                    _   => null

                                                })
                           });

            running = new Running(dns, ssh, audit);

            await ssh.StartAsync(new IPSocket(IPv4Address.Localhost, Port.HasValue ? IPPort.Parse(Port.Value) : IPPort.Auto));

            servers.Add(running);

            return running;

        }

        #endregion

        #region (helpers) Node(Servers, ...) / TheServer(Node) / Ask(Node, Name) / Eventually(Holds, What)

        /// <summary>
        /// A node with the given name servers and nothing else to ask - with
        /// the key the name server lets in as its key for name servers, unless
        /// it is to make one of its own.
        /// </summary>
        private async Task<WWCPNode> Node(String         Servers,
                                          String?        Peers        = null,
                                          Boolean        WithItsKey   = true,
                                          TimeProvider?  Clock        = null,
                                          String         More         = "")
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration,
                              $$"""{ "nts": { "groups": { "legal": { "enabled": false } } }, "dns": { "servers": [ {{Servers}} ], "queryTimeoutSeconds": 5, "maxRetries": 0 {{More}} }{{(Peers is null ? "" : $", \"ssh\": {{ \"peers\": {Peers} }}")}} }""");

            Directory.CreateDirectory(Path.Combine(directory, WWCPNode.DefaultSSHDirectory));

            // The key the node signs in with at the SSH peers of its configuration.
            if (Peers is not null)
                await SshKeyGenerator.WriteKeyPairAsync(nodeKey, Path.Combine(directory, WWCPNode.DefaultSSHDirectory, WWCPNode.SSHPeerClientKeyFileName));

            if (WithItsKey)
                await SshKeyGenerator.WriteKeyPairAsync(nodeKey, Path.Combine(directory, WWCPNode.DefaultSSHDirectory, WWCPNode.DNSSSHClientKeyFileName));

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false,
                       TimeProvider:      Clock
                   );

        }

        private static JObject TheServer(WWCPNode Node, Int32 Index = 0)

            => (JObject) ((JArray) Node.DNSConfigurationJSON()["servers"]!)[Index]!;

        /// <summary>
        /// The addresses the node resolves a name of the zone to: none where
        /// nobody answered.
        /// </summary>
        private static async Task<String[]> Ask(WWCPNode Node, Int32 Host)
        {

            var answer = await Node.ResolveAsync($"host{Host:D2}.example.org", [ DNSResourceRecordTypes.A ]);

            return [.. (answer["answers"] as JArray ?? []).Select(record => record["value"]!.Value<String>()!)];

        }

        private static String AddressOf(Int32 Host)
            => $"192.0.2.{100 + Host}";

        private static async Task Eventually(Func<Boolean> Holds, String What)
        {

            var since = Stopwatch.GetTimestamp();

            while (!Holds())
            {

                if (Stopwatch.GetElapsedTime(since) > TimeSpan.FromSeconds(10))
                    Assert.Fail($"{What} did not happen within 10 s.");

                await Task.Delay(20);

            }

        }

        private static List<(String Server, NameServerSSHState State, NameServerSSHNews News)> NewsOf(WWCPNode Node)
        {

            var news = new List<(String, NameServerSSHState, NameServerSSHNews)>();

            Node.OnNameServerSSHNews += (server, state, which) => {
                lock (news)
                    news.Add((WWCPNode.NameOf(server), state, which));
            };

            return news;

        }

        /// <summary>
        /// A clock that stands still at a time of the test's choosing.
        /// </summary>
        private sealed class ClockAt(DateTimeOffset Now) : TimeProvider
        {
            public override DateTimeOffset GetUtcNow() => Now;
        }

        #endregion


        #region ANameServerIsAskedOverSSH()

        /// <summary>
        /// A server whose host key is pinned is asked over its own SSH
        /// connection, signed in with the node's key for name servers under
        /// the node's own name: the answer of the zone, SSHStatus Accepted, the
        /// host key it showed, and since when it is believed with it.
        /// </summary>
        [Test]
        public async Task ANameServerIsAskedOverSSH()
        {

            var server = await NameServer(hostKey1);

            await using var node = await Node($$"""{ "id": "cpo-1", "address": "127.0.0.1", "transport": "SSH", "ssh": { "port": {{server.Port}}, "hostKeyPins": [ "{{print1}}" ] } }""");

            var news     = NewsOf(node);
            var before   = TheServer(node);
            var answer   = await Ask(node, 0);
            var shown    = TheServer(node);

            Assert.Multiple(() => {

                Assert.That(before["sshStatus"]?.Value<String>(),                   Is.Null, "a verdict before the first attempt");
                Assert.That(before["transport"]?.Value<String>(),                   Is.EqualTo("SSH"));

                Assert.That(answer,                                                 Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(server.Requests,                                        Has.Count.EqualTo(1));
                Assert.That(server.Count<AuthenticationSucceededEvent>(login => login.Username == node.Kind.Tag), Is.EqualTo(1), "the login is the node's own name");

                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("Accepted"));
                Assert.That(shown["sshHostKey"]?.Value<String>(),                   Is.EqualTo(print1));
                Assert.That(shown["sshJudgement"]?["matched"]?.Value<Boolean>(),    Is.True);
                Assert.That(shown["sshJudgement"]?["why"]?.Value<String>(),         Does.Contain("is pinned"));
                Assert.That(shown["known"]?["certificate"]?.Value<String>(),        Is.EqualTo(print1));
                Assert.That(shown["known"]?["since"]?.Value<String>(),              Is.Not.Empty);
                Assert.That(shown["judgement"]?.Type ?? JTokenType.Null,            Is.EqualTo(JTokenType.Null), "a certificate, over SSH");
                Assert.That(shown["sshClientPublicKey"]?.Value<String>(),           Does.StartWith("ssh-ed25519 " + Convert.ToBase64String(SshPublicKey.FromHostKey(nodeKey).Blob)));
                Assert.That(node.DNSSSHClientPublicKey,                             Is.EqualTo(shown["sshClientPublicKey"]?.Value<String>()));

                Assert.That(news,                                                   Is.Empty, "a server that is believed is no news");

            });

        }

        #endregion

        #region T5_AHostKeyThatIsNotPinnedIsNotUsed()

        /// <summary>
        /// T5: a host key that is not pinned. Not used; SSHStatus PinMismatch,
        /// said once however often it is tried; and no query to that server
        /// any other way - nothing over UDP to its port, and nothing over TCP
        /// that is not SSH.
        /// </summary>
        [Test]
        public async Task T5_AHostKeyThatIsNotPinnedIsNotUsed()
        {

            // Where a query over UDP to that server would arrive: the port of
            // its number. A number has to be had over UDP and over TCP, and the
            // ports the system hands out by itself come from a range where
            // Windows keeps whole blocks for one of the two only - so it is a
            // number of the test's choosing, from below that range, until one
            // is free both ways.
            UdpClient?  listening  = null;
            Running?    started    = null;

            for (var attempt = 1; started is null; attempt++)
            {

                var port = (UInt16) Random.Shared.Next(20000, 45000);

                try
                {
                    listening = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, port));
                    started   = await NameServer(hostKey1, port);
                }
                catch (SocketException) when (attempt < 50)
                {
                    listening?.Dispose();
                    listening = null;
                }

            }

            using var overUDP = listening!;
            var server        = started;

            await using var node = await Node($$"""{ "id": "cpo-1", "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{notShown}}" ] } }""");

            var news     = NewsOf(node);
            var first    = await Ask(node, 0);
            var second   = await Ask(node, 1);
            var shown    = TheServer(node);

            // The control: the listener over UDP hears what is sent to it.
            using (var sender = new UdpClient())
                await sender.SendAsync(new Byte[] { 1, 2, 3 }, new IPEndPoint(System.Net.IPAddress.Loopback, server.Port));

            using var soon   = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var heard        = await overUDP.ReceiveAsync(soon.Token);

            Assert.Multiple(() => {

                Assert.That(first,                                                  Is.Empty, "a server that showed another host key was asked");
                Assert.That(second,                                                 Is.Empty);

                // It was reached, once for each question - a connection more
                // would be a question put another way, over TCP - and that
                // is as far as it went: the node ended both handshakes, and
                // never tried to sign in.
                Assert.That(server.Count<ConnectionOpenedEvent>(),                  Is.EqualTo(2), "the server was not reached once per question");
                Assert.That(server.Count<KexCompletedEvent>(),                      Is.Zero, "a handshake the node went on with");
                Assert.That(server.Count<AuthMethodFailedEvent>() +
                            server.Count<AuthenticationSucceededEvent>(),           Is.Zero, "the node tried to sign in at a server it does not believe");
                Assert.That(server.Requests,                                        Is.Empty);

                // And nothing came over UDP.
                Assert.That(heard.Buffer,                                           Is.EqualTo(new Byte[] { 1, 2, 3 }), "something else came over UDP first");

                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("PinMismatch"));
                Assert.That(shown["sshHostKey"]?.Value<String>(),                   Is.EqualTo(print1));
                Assert.That(shown["sshJudgement"]?["accepted"]?.Value<Boolean>(),   Is.False);
                Assert.That(shown["sshJudgement"]?["why"]?.Value<String>(),         Does.Contain("none it is held to"));
                Assert.That(shown["known"]?.Type ?? JTokenType.Null,                Is.EqualTo(JTokenType.Null), "a key that was refused is remembered");

                Assert.That(news.Select(said => said.News),                         Is.EqualTo(new[] { NameServerSSHNews.HostKeyRefused }), "once per change of the verdict");
                Assert.That(news[0].Server,                                         Is.EqualTo($"ssh://127.0.0.1:{server.Port}"));
                Assert.That(news[0].State.HostKey,                                  Is.EqualTo(print1));

            });

        }

        #endregion

        #region AMismatchThatIsRecordedIsUsedAndSaid()

        /// <summary>
        /// OnPinMismatch applies to host keys (decision 3): a mismatch the
        /// entry records is used - and said, once, as a host key that nothing
        /// vouches for.
        /// </summary>
        [Test]
        public async Task AMismatchThatIsRecordedIsUsedAndSaid()
        {

            var server = await NameServer(hostKey1);

            await using var node = await Node($$"""{ "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{notShown}}" ], "onMismatch": "record" } }""");

            var news     = NewsOf(node);
            var first    = await Ask(node, 0);
            var second   = await Ask(node, 1);
            var shown    = TheServer(node);

            Assert.Multiple(() => {
                Assert.That(first,                                                  Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(second,                                                 Is.EqualTo(new[] { AddressOf(1) }));
                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("Accepted"));
                Assert.That(shown["sshJudgement"]?["matched"]?.Value<Boolean>(),    Is.False);
                Assert.That(shown["known"]?.Type ?? JTokenType.Null,                Is.EqualTo(JTokenType.Null), "a key nothing vouches for is remembered as believed");
                Assert.That(news.Select(said => said.News),                         Is.EqualTo(new[] { NameServerSSHNews.HostKeyTolerated }));
            });

        }

        #endregion

        #region T6_TheServerChangesToTheSecondKeyOfItsPinSet()

        /// <summary>
        /// T6: the server changes to the second key of its pin set. Used; said
        /// as a host key that changed, with the key before; and believed with
        /// the new one since then.
        /// </summary>
        [Test]
        public async Task T6_TheServerChangesToTheSecondKeyOfItsPinSet()
        {

            var first  = await NameServer(hostKey1);
            var port   = first.Port;

            await using var node = await Node($$"""{ "address": "127.0.0.1", "port": {{port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{print1}}", "{{print2}}" ] } }""");

            var news     = NewsOf(node);
            var before   = await Ask(node, 0);
            var known1   = TheServer(node)["known"]!;

            await first.DisposeAsync();
            await Task.Delay(50);

            var second   = await NameServer(hostKey2, port);
            var after    = await Ask(node, 1);
            var shown    = TheServer(node);

            Assert.Multiple(() => {

                Assert.That(before,                                                 Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(known1["certificate"]?.Value<String>(),                 Is.EqualTo(print1));

                Assert.That(after,                                                  Is.EqualTo(new[] { AddressOf(1) }), "the second key of its pin set was not used");
                Assert.That(second.Requests,                                        Has.Count.EqualTo(1));
                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("Accepted"));
                Assert.That(shown["sshHostKey"]?.Value<String>(),                   Is.EqualTo(print2));
                Assert.That(shown["known"]?["certificate"]?.Value<String>(),        Is.EqualTo(print2));
                Assert.That(DateTimeOffset.Parse(shown["known"]!["since"]!.Value<String>()!),
                            Is.GreaterThan(DateTimeOffset.Parse(known1["since"]!.Value<String>()!)), "KnownSince was not updated");

                Assert.That(news.Select(said => said.News),                         Is.EqualTo(new[] { NameServerSSHNews.HostKeyChanged }));
                Assert.That(news[0].State.Previously,                               Is.EqualTo(print1));
                Assert.That(news[0].State.HostKey,                                  Is.EqualTo(print2));

            });

        }

        #endregion

        #region T7_AHostCertificateOfItsCAForTheAddressDialled_AndForAnother()

        /// <summary>
        /// T7: a host certificate of a CA in "hostCAs", for the address
        /// dialled: used. Then one of the same CA for another address: not
        /// used, SSHStatus Untrusted - and not PinMismatch, which is a key no
        /// CA of its vouches for at all.
        /// </summary>
        [Test]
        public async Task T7_AHostCertificateOfItsCAForTheAddressDialled_AndForAnother()
        {

            var ca       = SshHostKey.GenerateEd25519();
            var otherCA  = SshHostKey.GenerateEd25519();
            var now      = DateTimeOffset.UtcNow;

            ISshHostKey Certified(ISshHostKey By, String Name)

                => new CertifiedKey(hostKey1,
                                    new OpenSshCertificateBuilder {
                                        Type         = SshCertType.Host,
                                        Principals   = [ Name ],
                                        ValidAfter   = now.AddDays(-1),
                                        ValidBefore  = now.AddDays(1)
                                    }.Sign(hostKey1.PublicKeyBlob, By));

            var forIt    = await NameServer(Certified(ca,      "127.0.0.1"));
            var forOther = await NameServer(Certified(ca,      "192.0.2.53"));
            var ofOther  = await NameServer(Certified(otherCA, "127.0.0.1"));

            String Entry(String Id, Running Server)
                => $$"""{ "id": "{{Id}}", "address": "127.0.0.1", "port": {{Server.Port}}, "transport": "SSH", "ssh": { "hostCAs": [ "{{SshFingerprint.Sha256(ca.PublicKeyBlob)}}" ] } }""";

            await using var node = await Node(Entry("for-it", forIt));

            var news     = NewsOf(node);
            var used     = await Ask(node, 0);
            var believed = TheServer(node);

            // The same node, given the two others instead.
            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""{ "servers": [ {{Entry("for-other", forOther)}}, {{Entry("of-other", ofOther)}} ] }"""), out var error), Is.True, error);

            var notUsed  = await Ask(node, 1);
            var another  = TheServer(node, 0);
            var unknown  = TheServer(node, 1);

            Assert.Multiple(() => {

                Assert.That(used,                                                   Is.EqualTo(new[] { AddressOf(0) }), "a host certificate of its CA for its address was not used");
                Assert.That(believed["sshStatus"]?.Value<String>(),                 Is.EqualTo("Accepted"));
                Assert.That(believed["sshHostKey"]?.Value<String>(),                Is.EqualTo(print1), "the certified key's fingerprint");
                Assert.That(believed["sshJudgement"]?["why"]?.Value<String>(),      Does.Contain("was signed by its CA"));

                Assert.That(notUsed,                                                Is.Empty);
                Assert.That(forOther.Count<ConnectionOpenedEvent>(),                Is.GreaterThanOrEqualTo(1), "the server was not reached");
                Assert.That(forOther.Count<KexCompletedEvent>(),                    Is.Zero, "a handshake the node went on with");
                Assert.That(forOther.Requests,                                      Is.Empty);
                Assert.That(another["sshStatus"]?.Value<String>(),                  Is.EqualTo("Untrusted"));
                Assert.That(another["sshJudgement"]?["why"]?.Value<String>(),       Does.Contain("not valid for 127.0.0.1"));

                Assert.That(ofOther.Count<ConnectionOpenedEvent>(),                 Is.GreaterThanOrEqualTo(1), "the server was not reached");
                Assert.That(ofOther.Requests,                                       Is.Empty);
                Assert.That(unknown["sshStatus"]?.Value<String>(),                  Is.EqualTo("PinMismatch"));

                Assert.That(news.Select(said => said.News),                         Is.All.EqualTo(NameServerSSHNews.HostKeyRefused));
                Assert.That(news,                                                   Has.Count.EqualTo(2));

            });

        }

        #endregion

        #region T9_TheServerDoesNotKnowTheNodesKey()

        /// <summary>
        /// T9: the server does not know the node's key. SSHStatus
        /// AuthenticationFailed, said once; the node offered its key, and no
        /// password. The key it made is kept for the next start, so that what
        /// is entered at the server once stays good.
        /// </summary>
        [Test]
        public async Task T9_TheServerDoesNotKnowTheNodesKey()
        {

            var server = await NameServer(hostKey1);
            var entry  = $$"""{ "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "user": "cs001", "hostKeyPins": [ "{{print1}}" ] } }""";

            String? itsKey;

            await using (var node = await Node(entry, WithItsKey: false))
            {

                var news     = NewsOf(node);
                var first    = await Ask(node, 0);
                var second   = await Ask(node, 1);
                var shown    = TheServer(node);

                itsKey       = node.DNSSSHClientPublicKey;

                Assert.Multiple(() => {

                    Assert.That(first,                                              Is.Empty, "a node the server does not know was answered");
                    Assert.That(second,                                             Is.Empty);
                    Assert.That(server.Requests,                                    Is.Empty);

                    // It was reached, believed, and offered the node's key - and nothing else.
                    Assert.That(server.Count<KexCompletedEvent>(),                  Is.GreaterThanOrEqualTo(1), "the server was not believed");
                    Assert.That(server.Count<AuthMethodFailedEvent>(attempt => attempt.Method == "publickey" && attempt.Username == "cs001"), Is.GreaterThanOrEqualTo(1), "the node did not offer its key");
                    Assert.That(server.Count<AuthMethodFailedEvent>(attempt => attempt.Method != "publickey" && attempt.Method != "none"),    Is.Zero, "the node tried something else than its key: a password, say");
                    Assert.That(server.Count<AuthenticationSucceededEvent>(),       Is.Zero);

                    Assert.That(shown["sshStatus"]?.Value<String>(),                Is.EqualTo("AuthenticationFailed"));
                    Assert.That(shown["sshHostKey"]?.Value<String>(),               Is.EqualTo(print1));
                    Assert.That(news.Select(said => said.News),                     Is.EqualTo(new[] { NameServerSSHNews.AuthenticationFailed }), "once per change of the verdict");

                    Assert.That(File.Exists(node.DNSSSHClientKeyPath),              Is.True, "the key was not kept");
                    Assert.That(itsKey,                                             Does.StartWith("ssh-ed25519 "));
                    Assert.That(itsKey,                                             Does.Not.Contain(Convert.ToBase64String(SshPublicKey.FromHostKey(nodeKey).Blob)));

                });

            }

            await using var again = await Node(entry, WithItsKey: false);

            Assert.That(again.DNSSSHClientPublicKey, Is.EqualTo(itsKey), "another key after a restart");

        }

        #endregion

        #region T11_ALoginWithoutTheSubsystemIsRefused()

        /// <summary>
        /// T11: a login that is admitted, and not for names, opens the
        /// subsystem: SSH_MSG_CHANNEL_FAILURE, and SSHStatus SubsystemRefused.
        /// The node was let in and asked for the subsystem; no query was sent.
        /// </summary>
        [Test]
        public async Task T11_ALoginWithoutTheSubsystemIsRefused()
        {

            var server = await NameServer(hostKey1);

            await using var node = await Node($$"""{ "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "user": "{{OCPPOnly}}", "hostKeyPins": [ "{{print1}}" ] } }""");

            var news     = NewsOf(node);
            var first    = await Ask(node, 0);
            var second   = await Ask(node, 1);
            var shown    = TheServer(node);

            Assert.Multiple(() => {

                Assert.That(first,                                                  Is.Empty);
                Assert.That(second,                                                 Is.Empty);

                Assert.That(server.Count<AuthenticationSucceededEvent>(login => login.Username == OCPPOnly), Is.EqualTo(1), "the node was not let in, or signed in again for the second question");
                Assert.That(server.Count<ChannelOpenedEvent>(opened => opened.ChannelType == "session"), Is.GreaterThanOrEqualTo(1), "no channel was opened to ask for the subsystem on");
                Assert.That(server.Channels,                                        Is.Zero);
                Assert.That(server.Requests,                                        Is.Empty);

                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("SubsystemRefused"));
                Assert.That(shown["sshHostKey"]?.Value<String>(),                   Is.EqualTo(print1));
                Assert.That(news,                                                   Is.Empty, "no security event is of a refused subsystem");

            });

        }

        #endregion

        #region T12_ASharedConnectionIsMadeByTheFirstQuery_AndGoesOnAfterTheChannelEnds()

        /// <summary>
        /// T12: "connection": "shared". A query before anything else went to
        /// that SSH peer has the connection made; what else goes there goes
        /// over the same one, with one SSH authentication for both; and the
        /// connection goes on after the DNS channel ends, as does what else
        /// goes over it. No key of the node's own for name servers is made.
        /// </summary>
        [Test]
        public async Task T12_ASharedConnectionIsMadeByTheFirstQuery_AndGoesOnAfterTheChannelEnds()
        {

            var server = await NameServer(hostKey1);
            var host   = DomainName.Parse("127.0.0.1");

            await using var node = await Node("""{ "id": "lc", "address": "127.0.0.1", "transport": "SSH", "ssh": { "connection": "shared" } }""",
                                              Peers:       $$"""[ { "id": "lc", "address": "127.0.0.1", "port": {{server.Port}}, "user": "cs001", "hostKeyPins": [ "{{print1}}" ] } ]""",
                                              WithItsKey:  false);

            async Task<String> EchoOverThePeer()
            {

                var channel = await (await node.SharedSSHConnectionTo(host, Echo)).OpenSubsystemAsync(Echo);

                using var within = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var said         = new MemoryStream();

                await channel.Input.CopyToAsync(said, within.Token);

                return System.Text.Encoding.UTF8.GetString(said.ToArray());

            }

            var news     = NewsOf(node);
            var peer     = node.SSHPeerTo(host);
            var unmade   = peer?.Connection.Current;

            var answer   = await Ask(node, 0);
            var made     = peer?.Connection.Current;
            var shown    = TheServer(node);

            // What else goes to that peer, after the names.
            var echoed   = await EchoOverThePeer();

            // The DNS channel ends: the client lets go of its connection to the server.
            var channels = server.Channels;
            var closed   = node.DNSClient.CloseConnection(new DNSServerConfig(IPv4Address.Localhost, IPPort.SSH, DNSTransport.SSH));

            await Eventually(() => server.ChannelsEnded == channels, "The end of the DNS channels");

            var echoed2  = await EchoOverThePeer();
            var answer2  = await Ask(node, 1);

            Assert.Multiple(() => {

                Assert.That(peer,                                                   Is.Not.Null);
                Assert.That(unmade,                                                 Is.Null,  "a connection before anything needed one");

                Assert.That(answer,                                                 Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(made,                                                   Is.Not.Null, "the query did not have the connection made");
                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("Accepted"));
                Assert.That(shown["sshHostKey"]?.Value<String>(),                   Is.EqualTo(print1));
                Assert.That(shown["port"],                                          Is.Null, "a port of its own, on a shared connection");
                Assert.That(shown["sshClientPublicKey"]?.Value<String>(),           Is.EqualTo(node.SSHPeerClientPublicKey), "the key of the connection to that SSH peer");

                Assert.That(echoed,                                                 Is.EqualTo("echo\n"));
                Assert.That(closed,                                                 Is.True,  "there was no connection of the DNS client to close");
                Assert.That(channels,                                               Is.GreaterThanOrEqualTo(1));
                Assert.That(echoed2,                                                Is.EqualTo("echo\n"), "what else goes over the connection did not go on");
                Assert.That(answer2,                                                Is.EqualTo(new[] { AddressOf(1) }), "the next query did not get a new channel");
                Assert.That(server.Requests,                                        Has.Count.EqualTo(2));

                // One connection, and one login, for all of it.
                Assert.That(peer!.Connection.Current,                               Is.SameAs(made), "the shared connection was closed, or made again");
                Assert.That(peer.Connection.Made,                                   Is.EqualTo(1));
                Assert.That(server.Count<AuthenticationSucceededEvent>(),           Is.EqualTo(1), "one SSH authentication for both");
                Assert.That(server.Count<AuthenticationSucceededEvent>(login => login.Username == "cs001"), Is.EqualTo(1));

                Assert.That(File.Exists(node.DNSSSHClientKeyPath),                  Is.False, "a key of the node's own for name servers was made");
                Assert.That(news,                                                   Is.Empty);

            });

        }

        #endregion

        #region T13_ASharedConnectionToAnAddressThatIsNoSSHPeerIsNotAsked()

        /// <summary>
        /// T13: "connection": "shared" to an address that is no SSH peer of
        /// the node. The server is not asked - not even dialled, though it is
        /// there - and SSHStatus says NoSSHPeer.
        /// </summary>
        [Test]
        public async Task T13_ASharedConnectionToAnAddressThatIsNoSSHPeerIsNotAsked()
        {

            var server = await NameServer(hostKey1);

            // An SSH peer, and another host than the name server's.
            await using var node = await Node("""{ "id": "lc", "address": "127.0.0.1", "transport": "SSH", "ssh": { "connection": "shared" } }""",
                                              Peers:       $$"""[ { "id": "elsewhere", "address": "192.0.2.77", "port": {{server.Port}}, "hostKeyPins": [ "{{print1}}" ] } ]""",
                                              WithItsKey:  false);

            var answer   = await Ask(node, 0);
            var shown    = TheServer(node);
            var reached  = server.Count<ConnectionOpenedEvent>();

            // The control: the server is there, and says so when somebody comes.
            using (var somebody = new TcpClient())
                await somebody.ConnectAsync(System.Net.IPAddress.Loopback, server.Port);

            await Eventually(() => server.Count<ConnectionOpenedEvent>() == 1, "The connection of the control");

            Assert.Multiple(() => {
                Assert.That(answer,                                                 Is.Empty);
                Assert.That(reached,                                                Is.Zero, "the server was dialled");
                Assert.That(server.Requests,                                        Is.Empty);
                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("NoSSHPeer"));
                Assert.That(shown["sshJudgement"]?["why"]?.Value<String>(),         Does.Contain("127.0.0.1 is no SSH peer"));
                Assert.That(shown["sshClientPublicKey"]?.Value<String>(),           Is.Null);
                Assert.That(File.Exists(node.DNSSSHClientKeyPath),                  Is.False, "a key of the node's own for name servers was made");
            });

        }

        #endregion

        #region T18_NamesResolveWithTheClockAt1970()

        /// <summary>
        /// T18: a cold start with the clock at 1970, a name server over SSH
        /// with a pinned host key. Names resolve before the time is
        /// synchronized: a pinned key has no validity period to be outside of.
        /// </summary>
        [Test]
        public async Task T18_NamesResolveWithTheClockAt1970()
        {

            var server = await NameServer(hostKey1);

            await using var node = await Node($$"""{ "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{print1}}" ] } }""",
                                              Clock:  new ClockAt(new DateTimeOffset(1970, 1, 1, 0, 0, 42, TimeSpan.Zero)),
                                              More:   """, "encryptedOnly": true""");

            var answer   = await Ask(node, 0);
            var shown    = TheServer(node);

            Assert.Multiple(() => {
                Assert.That(answer,                                                 Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(shown["sshStatus"]?.Value<String>(),                    Is.EqualTo("Accepted"));
                // The control: it is 1970 to the node.
                Assert.That(node.TimeProvider.GetUtcNow().Year,                     Is.EqualTo(1970));
                Assert.That(shown["sshJudgement"]?["at"]?.Value<String>(),          Does.StartWith("1970-01-01T00:00:42"));
                Assert.That(shown["known"]?["since"]?.Value<String>(),              Does.StartWith("1970-01-01T00:00:42"));
                // And only encrypted servers are asked: SSH is one.
                Assert.That(node.DNSEncryptedOnly,                                  Is.True);
            });

        }

        #endregion

        #region T21_ThePinsOfAServerChangeWhileItsChannelIsOpen()

        /// <summary>
        /// T21: the pins of a server change while its channel is open. The
        /// connection is closed, and the next query makes a new handshake
        /// judged by the new pins: refused by a pin the server does not show,
        /// and used again by the one it does.
        /// </summary>
        [Test]
        public async Task T21_ThePinsOfAServerChangeWhileItsChannelIsOpen()
        {

            var server = await NameServer(hostKey1);

            String Entry(String Pin)
                => $$"""{ "id": "cpo-1", "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{Pin}}" ] } }""";

            await using var node = await Node(Entry(print1));

            var changes  = new List<String>();
            node.OnDNSConfigurationChanged += (changed, origin) => changes.AddRange(changed);

            var before   = await Ask(node, 0);
            var open     = server.Count<ConnectionOpenedEvent>() - server.Count<ConnectionClosedEvent>();

            // Another pin: its connection goes.
            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""{ "servers": [ {{Entry(notShown)}} ] }"""), out var error), Is.True, error);

            await Eventually(() => server.Count<ConnectionClosedEvent>() == 1, "The end of the connection that was believed by the old pin");

            var unjudged = TheServer(node);
            var refused  = await Ask(node, 1);
            var judged   = TheServer(node);
            var handshakes = server.Count<ConnectionOpenedEvent>();

            // And the pin it shows again.
            Assert.That(node.TryUpdateDNSConfiguration(JObject.Parse($$"""{ "servers": [ {{Entry(print1)}} ] }"""), out error), Is.True, error);

            var after    = await Ask(node, 2);

            Assert.Multiple(() => {

                Assert.That(before,                                                 Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(open,                                                   Is.EqualTo(1), "the connection was not open when its pins changed");

                Assert.That(unjudged["sshStatus"]?.Value<String>(),                 Is.Null, "the verdict of the old pins outlived them");
                Assert.That(refused,                                                Is.Empty, "the server was asked over a connection its old pin believed");
                Assert.That(handshakes,                                             Is.GreaterThanOrEqualTo(2), "there was no new handshake");
                Assert.That(judged["sshStatus"]?.Value<String>(),                   Is.EqualTo("PinMismatch"));
                Assert.That(server.Requests.Count,                                  Is.EqualTo(2), "one query before, one after, and none in between");

                Assert.That(after,                                                  Is.EqualTo(new[] { AddressOf(2) }));
                Assert.That(TheServer(node)["sshStatus"]?.Value<String>(),          Is.EqualTo("Accepted"));

                Assert.That(changes,                                                Has.Some.Contains($"ssh://127.0.0.1:{server.Port} signed in under its own name, held to {notShown}"));

            });

        }

        #endregion

        #region ASaveThatSaysTheSameAgainKeepsTheConnectionAndItsVerdict()

        /// <summary>
        /// A save that says of a server over SSH what was in effect already -
        /// a page sending the list back as it was shown, beside a change of
        /// something else - is no change of it: its connection stays, and so
        /// does what its last attempt came to. The positive control for T21,
        /// where another pin ends both.
        /// </summary>
        [Test]
        public async Task ASaveThatSaysTheSameAgainKeepsTheConnectionAndItsVerdict()
        {

            var server = await NameServer(hostKey1);

            await using var node = await Node($$"""{ "id": "cpo-1", "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{print1}}" ] } }""");

            var before   = await Ask(node, 0);

            // The list as the node shows it, with everything it shows beside it.
            var shown    = node.DNSConfigurationJSON();

            Assert.That(node.TryUpdateDNSConfiguration(new JObject(new JProperty("servers", shown["servers"]!.DeepClone()), new JProperty("maxRetries", 1)), out var error), Is.True, error);

            var verdict  = TheServer(node);
            var after    = await Ask(node, 1);

            Assert.Multiple(() => {
                Assert.That(before,                                                 Is.EqualTo(new[] { AddressOf(0) }));
                Assert.That(verdict["sshStatus"]?.Value<String>(),                  Is.EqualTo("Accepted"), "the verdict went with a save that changed nothing of the server");
                Assert.That(verdict["sshHostKey"]?.Value<String>(),                 Is.EqualTo(print1));
                Assert.That(after,                                                  Is.EqualTo(new[] { AddressOf(1) }));
                Assert.That(server.Count<ConnectionOpenedEvent>(),                  Is.EqualTo(1), "the connection was made again");
                Assert.That(server.Count<ConnectionClosedEvent>(),                  Is.Zero);
                Assert.That(node.DNSClient.MaxRetries,                              Is.EqualTo(1));
            });

        }

        #endregion

        #region ADryRunAsksAServerOverSSH_AndTellsNothing()

        /// <summary>
        /// A dry run of a configuration asks a server over SSH by what that
        /// configuration holds it to - so a CSMS learns before the change
        /// whether its names would still resolve - and nothing of it is in
        /// effect, kept or news afterwards. What a save would refuse, it
        /// refuses in the same words.
        /// </summary>
        [Test]
        public async Task ADryRunAsksAServerOverSSH_AndTellsNothing()
        {

            var server = await NameServer(hostKey1);

            await using var node = await Node("\"192.0.2.1\"");

            var news     = NewsOf(node);

            String Change(String Pin)
                => $$"""{ "servers": [ { "id": "cpo-1", "address": "127.0.0.1", "port": {{server.Port}}, "transport": "SSH", "ssh": { "hostKeyPins": [ "{{Pin}}" ] } } ] }""";

            var believed = await node.ResolveWithAsync(JObject.Parse(Change(print1)),   [ "host00.example.org" ], TimeSpan.FromSeconds(10));
            var refused  = await node.ResolveWithAsync(JObject.Parse(Change(notShown)), [ "host01.example.org" ], TimeSpan.FromSeconds(10));
            var unsaved  = await node.ResolveWithAsync(JObject.Parse("""{ "servers": [ { "address": "127.0.0.1", "transport": "SSH" } ] }"""), [ "host02.example.org" ], TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {

                Assert.That(believed.Error,                                         Is.Null);
                Assert.That(believed.Resolves("host00.example.org"),                Is.True,  "the dry run did not ask the server over SSH");
                Assert.That(refused. Resolves("host01.example.org"),                Is.False, "the dry run believed a host key the change does not pin");
                Assert.That(server.Requests.Select(request => request.Questions.First().DomainName.ToString().TrimEnd('.')),
                            Is.All.EqualTo("host00.example.org"));
                Assert.That(server.Requests,                                        Is.Not.Empty);
                Assert.That(server.Count<ConnectionOpenedEvent>(),                  Is.GreaterThanOrEqualTo(2), "the server was not reached by the second dry run");
                Assert.That(unsaved.Error,                                          Does.Contain("held to no host key and no CA"));

                // Nothing of it is in effect, or news.
                Assert.That(((JArray) node.DNSConfigurationJSON()["servers"]!).Count, Is.EqualTo(1));
                Assert.That(TheServer(node)["transport"]?.Value<String>(),          Is.EqualTo("UDP"));
                Assert.That(node.KnownServers.All,                                  Is.Empty);
                Assert.That(news,                                                   Is.Empty);

            });

        }

        #endregion

        #region ASharedServerIsNotAskedForTheNameOfItsOwnConnection()

        /// <summary>
        /// A server on a shared connection does not count for resolving the
        /// name that connection is dialled by (section 7.2): a dry run does
        /// not ask it for that name, and asks it for every other.
        /// </summary>
        [Test]
        public async Task ASharedServerIsNotAskedForTheNameOfItsOwnConnection()
        {

            var server = await NameServer(hostKey1);
            var host   = DomainName.Parse("host03.example.org");

            await using var node = await Node("\"192.0.2.1\"");

            // The node's connection to the SSH peer "host03.example.org".
            await using var connection = new SshSharedConnection("127.0.0.1",
                                                                 server.Port,
                                                                 new SshClientOptions {
                                                                     Username       = "cs001",
                                                                     Credentials    = [ nodeKey ],
                                                                     VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey1.PublicKeyBlob)
                                                                 });

            node.AddSSHPeer(new SSHPeer(host, server.Port, connection));

            var change   = JObject.Parse("""{ "servers": [ { "id": "lc", "address": "host03.example.org", "transport": "SSH", "ssh": { "connection": "shared" } } ] }""");
            var dryRun   = await node.ResolveWithAsync(change, [ "host03.example.org", "host04.example.org" ], TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {
                Assert.That(dryRun.Error,                                           Is.Null);
                Assert.That(dryRun.Resolves("host04.example.org"),                  Is.True,  "the shared server was not asked at all");
                Assert.That(dryRun.Resolves("host03.example.org"),                  Is.False, "the name of the connection resolved through that connection");
                Assert.That(server.Requests.Select(request => request.Questions.First().DomainName.ToString().TrimEnd('.')),
                            Has.None.EqualTo("host03.example.org"));
                Assert.That(connection.Made,                                        Is.EqualTo(1));
            });

        }

        #endregion

    }

}
