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

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Whether a node asks if the certificate of a server it connects to is
    /// revoked, and what it makes of the answer - or of no answer: asked of
    /// the judgement directly, with the chain a handshake hands over.
    /// </summary>
    /// <remarks>
    /// The certificates name revocation lists served here, on the loopback,
    /// and signed by CAs of the test's own. A chain "the machine trusts" is
    /// made as a handshake that checks no revocation hands it over: built
    /// against the test's root without asking, and without errors. A root of
    /// the node's own is the same kind of root, imported into its store.
    /// </remarks>
    public class ServerRevocationTests
    {

        #region Data

        private const String  Server  = "dns.example.org";

        private String  directory  = "";
        private Lists   lists      = default!;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory  = Path.Combine(Path.GetTempPath(), "node-revocation-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

            lists      = new Lists();

        }

        [TearDown]
        public void TearDown()
        {

            lists.Dispose();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (class) Lists

        /// <summary>
        /// Revocation lists over HTTP on the loopback, each at a URL of its own,
        /// so that no cache of the machine answers for another test. A URL is
        /// handed out first, for a certificate to name, and given its list once
        /// the certificate the list names exists; until then it is not found.
        /// </summary>
        private sealed class Lists : IDisposable
        {

            private readonly TcpListener                          listener;
            private readonly CancellationTokenSource              stop     = new ();
            private readonly ConcurrentDictionary<String, Byte[]> served   = new ();
            private readonly ConcurrentDictionary<String, Byte>   hanging  = new ();

            public Int32  Port  { get; }

            public Lists()
            {

                listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();

                Port     = ((IPEndPoint) listener.LocalEndpoint).Port;

                _ = Task.Run(Accept);

            }

            /// <summary>
            /// A URL of its own, not found until a list is put there.
            /// </summary>
            public String NewURL()

                => $"http://127.0.0.1:{Port}/{Guid.NewGuid():N}.crl";

            /// <summary>
            /// Serve the list at the URL from now on.
            /// </summary>
            public void Put(String URL, Byte[] List)

                => served[new Uri(URL).AbsolutePath] = List;

            /// <summary>
            /// Accept a request for the URL from now on, and never answer it.
            /// </summary>
            public void Hang(String URL)

                => hanging[new Uri(URL).AbsolutePath] = 0;

            /// <summary>
            /// A URL on a port nobody listens at.
            /// </summary>
            public static String OutOfReach()
            {

                var closed = new TcpListener(IPAddress.Loopback, 0);
                closed.Start();
                var port   = ((IPEndPoint) closed.LocalEndpoint).Port;
                closed.Stop();

                return $"http://127.0.0.1:{port}/{Guid.NewGuid():N}.crl";

            }

            private async Task Accept()
            {
                while (!stop.IsCancellationRequested)
                {

                    TcpClient client;

                    try
                    {
                        client = await listener.AcceptTcpClientAsync(stop.Token);
                    }
                    catch
                    {
                        return;
                    }

                    _ = Task.Run(() => Answer(client));

                }
            }

            private async Task Answer(TcpClient Client)
            {
                using (Client)
                {
                    try
                    {

                        var stream   = Client.GetStream();
                        var request  = new StringBuilder();
                        var buffer   = new Byte[1024];

                        while (!request.ToString().Contains("\r\n\r\n"))
                        {
                            var read = await stream.ReadAsync(buffer, stop.Token);
                            if (read == 0)
                                return;
                            request.Append(Encoding.ASCII.GetString(buffer, 0, read));
                        }

                        var path = request.ToString().Split(' ', 3) is [ _, var target, _ ]
                                       ? new Uri(new Uri("http://127.0.0.1/"), target).AbsolutePath
                                       : "";

                        if (hanging.ContainsKey(path))
                        {
                            await Task.Delay(Timeout.Infinite, stop.Token);
                            return;
                        }

                        var body   = served.GetValueOrDefault(path);
                        var head   = body is null
                                         ? "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                         : $"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n";

                        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), stop.Token);

                        if (body is not null)
                            await stream.WriteAsync(body, stop.Token);

                    }
                    catch
                    { }
                }
            }

            public void Dispose()
            {
                stop.Cancel();
                listener.Stop();
            }

        }

        #endregion

        #region (helpers) CA(Name, Issuer, List) / Leaf(Issuer, List) / ListOf(Issuer, Revoked)

        /// <summary>
        /// A CA, with its key: a root where no issuer is given, and otherwise
        /// one below the issuer, naming the issuer's list at the given URL.
        /// </summary>
        private static X509Certificate2 CA(String             Name,
                                          X509Certificate2?  Issuer  = null,
                                          String?            List    = null)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            if (Issuer is null)
                return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Issuer, true, false));

            if (List is not null)
                request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([ List ]));

            using var issued = request.Create(Issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(180), Guid.NewGuid().ToByteArray());

            return issued.CopyWithPrivateKey(key);

        }

        /// <summary>
        /// The server's certificate, naming its issuer's list at the given URL
        /// where one is given.
        /// </summary>
        private static X509Certificate2 Leaf(X509Certificate2  Issuer,
                                            String?           List)
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Server}", key, HashAlgorithmName.SHA256);
            var names   = new SubjectAlternativeNameBuilder();

            names.AddDnsName(Server);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Issuer, true, false));

            if (List is not null)
                request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([ List ]));

            return request.Create(Issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), Guid.NewGuid().ToByteArray());

        }

        /// <summary>
        /// The issuer's revocation list, naming the given certificates.
        /// </summary>
        private static Byte[] ListOf(X509Certificate2           Issuer,
                                     params X509Certificate2[]  Revoked)
        {

            var builder = new CertificateRevocationListBuilder();

            foreach (var certificate in Revoked)
                builder.AddEntry(certificate, DateTimeOffset.UtcNow.AddHours(-1), X509RevocationReason.KeyCompromise);

            return builder.Build(Issuer,
                                 BigInteger.One,
                                 DateTimeOffset.UtcNow.AddDays(1),
                                 HashAlgorithmName.SHA256,
                                 thisUpdate: DateTimeOffset.UtcNow.AddHours(-1));

        }

        private static Byte[] Pem(X509Certificate2 Certificate)

            => Encoding.ASCII.GetBytes(Certificate.ExportCertificatePem());

        #endregion

        #region (helpers) Node() / Machine(Leaf, Root, Intermediates) / Unknown(Leaf) / Judge(...) / Texts(Judgement)

        private WWCPNode Node()
        {

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, "{ }");

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        /// <summary>
        /// What a TLS handshake that checks no revocation hands over for a
        /// certificate whose root the machine trusts - the given one.
        /// </summary>
        private static X509Chain Machine(X509Certificate2           Leaf,
                                         X509Certificate2           Root,
                                         params X509Certificate2[]  Intermediates)
        {

            var chain = new X509Chain();

            chain.ChainPolicy.TrustMode       = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode  = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(Root);
            chain.ChainPolicy.ExtraStore.AddRange(Intermediates);

            Assert.That(chain.Build(Leaf), Is.True, "the test's own chain did not build");

            return chain;

        }

        /// <summary>
        /// What a handshake hands over for a certificate whose root the machine
        /// does not know.
        /// </summary>
        private static (X509Chain Chain, SslPolicyErrors Errors) Unknown(X509Certificate2 Leaf)
        {

            var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            return (chain, chain.Build(Leaf) ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors);

        }

        private static ServerJudgement Judge(WWCPNode          Node,
                                             X509Certificate2  Leaf,
                                             X509Chain         Chain,
                                             SslPolicyErrors   Errors = SslPolicyErrors.None)

            => Node.JudgeServer(CertificateUsages.DNS,
                                Server,
                                null,
                                Leaf,
                                Chain,
                                Errors,
                                Evidence:  false,
                                Learn:     null,
                                Remember:  false);

        private static String[] Texts(ServerJudgement Judgement)

            => [.. Judgement.Steps.Select(step => step.Text)];

        private const String NotAsked = "Whether its chain is revoked could not be asked, which is not held against it.";

        #endregion


        #region ACertificateTheMachineTrustsAndItsCARevokedIsRefused()

        /// <summary>
        /// A handshake that checks no revocation - a name server's - hands over
        /// a chain the machine trusts, and the node asks: the certificate is on
        /// its CA's list, so the server is refused, as untrusted, and the
        /// judgement says which certificate is revoked.
        /// </summary>
        [Test]
        public async Task ACertificateTheMachineTrustsAndItsCARevokedIsRefused()
        {

            using var root   = CA("Machine Root");
            var       url    = lists.NewURL();
            using var leaf   = Leaf(root, url);

            lists.Put(url, ListOf(root, leaf));

            await using var node   = Node();
            using var       chain  = Machine(leaf, root);

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.False);
                Assert.That(judgement.Outcome,   Is.EqualTo("untrusted"));
                Assert.That(Texts(judgement),    Has.Some.EqualTo($"Refused: its certificate {CertificateEntry.ThumbprintOf(leaf)} is revoked."));
            });

        }

        #endregion

        #region ACertificateTheMachineTrustsAndNoListNamesIsBelieved()

        /// <summary>
        /// The same, with a list that names nothing: the server is believed,
        /// and nothing is said of revocation.
        /// </summary>
        [Test]
        public async Task ACertificateTheMachineTrustsAndNoListNamesIsBelieved()
        {

            using var root   = CA("Machine Root");
            var       url    = lists.NewURL();
            using var leaf   = Leaf(root, url);

            lists.Put(url, ListOf(root));

            await using var node   = Node();
            using var       chain  = Machine(leaf, root);

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.True);
                Assert.That(judgement.Outcome,   Is.EqualTo("accepted"));
                Assert.That(Texts(judgement),    Has.None.Contains("revoked"));
            });

        }

        #endregion

        #region ARevokedCAInTheChainIsNamed()

        /// <summary>
        /// Not the server's certificate but the CA that issued it is on the
        /// root's list: refused, naming that CA.
        /// </summary>
        [Test]
        public async Task ARevokedCAInTheChainIsNamed()
        {

            using var root          = CA("Machine Root");
            var       rootList      = lists.NewURL();
            using var intermediate  = CA("Some Issuing CA", root, rootList);
            var       ownList       = lists.NewURL();
            using var leaf          = Leaf(intermediate, ownList);

            lists.Put(rootList, ListOf(root, intermediate));
            lists.Put(ownList,  ListOf(intermediate));

            await using var node   = Node();
            using var       chain  = Machine(leaf, root, intermediate);

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.False);
                Assert.That(judgement.Outcome,   Is.EqualTo("untrusted"));
                Assert.That(Texts(judgement),    Has.Some.EqualTo("Refused: the certificate of 'Some Issuing CA' in its chain is revoked."));
            });

        }

        #endregion

        #region AListOutOfReachIsNotHeldAgainstTheCertificate()

        /// <summary>
        /// The list cannot be fetched: the server is believed all the same, and
        /// the judgement says that its revocation could not be asked.
        /// </summary>
        [Test]
        public async Task AListOutOfReachIsNotHeldAgainstTheCertificate()
        {

            using var root   = CA("Machine Root");
            using var leaf   = Leaf(root, Lists.OutOfReach());

            await using var node   = Node();
            using var       chain  = Machine(leaf, root);

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.True);
                Assert.That(judgement.Outcome,   Is.EqualTo("accepted"));
                Assert.That(Texts(judgement),    Has.Some.EqualTo(NotAsked));
            });

        }

        #endregion

        #region AListThatIsNeverSentHoldsTheJudgementUpNoLongerThanTheWait()

        /// <summary>
        /// The list's server takes the request and never answers: the judgement
        /// - which a handshake waits for - goes ahead after the node's wait, and
        /// believes the server.
        /// </summary>
        [Test]
        public async Task AListThatIsNeverSentHoldsTheJudgementUpNoLongerThanTheWait()
        {

            using var root   = CA("Machine Root");
            var       url    = lists.NewURL();
            using var leaf   = Leaf(root, url);

            lists.Hang(url);

            await using var node   = Node();
            using var       chain  = Machine(leaf, root);

            var watch     = Stopwatch.StartNew();
            var judgement = Judge(node, leaf, chain);
            watch.Stop();

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.True);
                Assert.That(Texts(judgement),    Has.Some.EqualTo(NotAsked));
                Assert.That(watch.Elapsed,       Is.LessThan(WWCPNode.RevocationWait + TimeSpan.FromSeconds(4)));
            });

        }

        #endregion

        #region ACertificateThatNamesNoListIsNotAsked()

        /// <summary>
        /// A certificate that names nowhere to ask is not asked of, and nothing
        /// is said of it: a missing answer is no news where nobody was there to
        /// give one.
        /// </summary>
        [Test]
        public async Task ACertificateThatNamesNoListIsNotAsked()
        {

            using var root   = CA("Machine Root");
            using var leaf   = Leaf(root, null);

            await using var node   = Node();
            using var       chain  = Machine(leaf, root);

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.True);
                Assert.That(Texts(judgement),    Has.None.Contains("revoked"));
            });

        }

        #endregion

        #region AChainTheHandshakeBuiltOnlineIsNotAskedAgain()

        /// <summary>
        /// A key exchange builds its chain online itself, and what is revoked
        /// then never reaches the judgement without chain errors: a chain that
        /// was asked about already is not asked about again.
        /// </summary>
        [Test]
        public async Task AChainTheHandshakeBuiltOnlineIsNotAskedAgain()
        {

            using var root   = CA("Machine Root");
            using var leaf   = Leaf(root, Lists.OutOfReach());

            await using var node  = Node();
            using var       chain = new X509Chain();

            chain.ChainPolicy.TrustMode            = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode       = X509RevocationMode.Online;
            chain.ChainPolicy.UrlRetrievalTimeout  = TimeSpan.FromSeconds(1);
            chain.ChainPolicy.VerificationFlags    = X509VerificationFlags.IgnoreEndRevocationUnknown |
                                                     X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                                     X509VerificationFlags.IgnoreRootRevocationUnknown;
            chain.ChainPolicy.CustomTrustStore.Add(root);

            Assert.That(chain.Build(leaf), Is.True, "the test's own chain did not build");

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.True);
                Assert.That(Texts(judgement),    Has.None.Contains("revoked"));
            });

        }

        #endregion

        #region ARevokedCertificateUnderARootOfTheNodesOwnIsSaidToBeRevoked()

        /// <summary>
        /// A root of the node's own store anchors a chain the machine does not
        /// trust, and the certificate is on that root's list: refused, and the
        /// judgement says it is revoked rather than that it chains to no root.
        /// </summary>
        [Test]
        public async Task ARevokedCertificateUnderARootOfTheNodesOwnIsSaidToBeRevoked()
        {

            using var root   = CA("Our Root");
            var       url    = lists.NewURL();
            using var leaf   = Leaf(root, url);

            lists.Put(url, ListOf(root, leaf));

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(root), CertificateKind.TLSRoot, null, null, out _, out var error),  Is.True,  error);

            var (chain, errors) = Unknown(leaf);

            using (chain)
            {

                var judgement = Judge(node, leaf, chain, errors);

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,  Is.False);
                    Assert.That(judgement.Outcome,   Is.EqualTo("untrusted"));
                    Assert.That(Texts(judgement),    Has.Some.EqualTo($"Refused: its certificate {CertificateEntry.ThumbprintOf(leaf)} is revoked."));
                    Assert.That(Texts(judgement),    Has.None.Contains("chain ends at no root"));
                });

            }

        }

        #endregion

        #region AListThatIsNeverSentHoldsTheNodesOwnRootsUpNoLongerThanTheWait()

        /// <summary>
        /// The same wait where a root of the node's own anchors the chain: the
        /// server is believed after it, and the judgement says so.
        /// </summary>
        [Test]
        public async Task AListThatIsNeverSentHoldsTheNodesOwnRootsUpNoLongerThanTheWait()
        {

            using var root   = CA("Our Root");
            var       url    = lists.NewURL();
            using var leaf   = Leaf(root, url);

            lists.Hang(url);

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(root), CertificateKind.TLSRoot, null, null, out _, out var error),  Is.True,  error);

            var (chain, errors) = Unknown(leaf);

            using (chain)
            {

                var watch     = Stopwatch.StartNew();
                var judgement = Judge(node, leaf, chain, errors);
                watch.Stop();

                Assert.Multiple(() => {
                    Assert.That(judgement.Accepted,  Is.True);
                    Assert.That(judgement.AnchoredBy, Is.Not.Null);
                    Assert.That(Texts(judgement),    Has.Some.EqualTo(NotAsked));
                    Assert.That(watch.Elapsed,       Is.LessThan(WWCPNode.RevocationWait + TimeSpan.FromSeconds(4)));
                });

            }

        }

        #endregion

        #region AnOCSPResponderOutOfReachIsNotHeldAgainstTheCertificate()

        /// <summary>
        /// A certificate that names an OCSP responder instead of a list is asked
        /// of as well: the responder cannot be reached, so the server is
        /// believed, and the judgement says that its revocation could not be
        /// asked.
        /// </summary>
        [Test]
        public async Task AnOCSPResponderOutOfReachIsNotHeldAgainstTheCertificate()
        {

            using var root   = CA("Machine Root");
            using var key    = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request = new CertificateRequest($"CN={Server}", key, HashAlgorithmName.SHA256);
            var names   = new SubjectAlternativeNameBuilder();

            names.AddDnsName(Server);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
            request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([ Lists.OutOfReach() ], null));

            using var leaf = request.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), Guid.NewGuid().ToByteArray());

            await using var node   = Node();
            using var       chain  = Machine(leaf, root);

            var judgement = Judge(node, leaf, chain);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.True);
                Assert.That(Texts(judgement),    Has.Some.EqualTo(NotAsked));
            });

        }

        #endregion

        #region ACertificateOnTheListOfARootNobodyTrustsIsNotSaidToBeRevoked()

        /// <summary>
        /// The server sends a root along that neither the machine nor the node
        /// trusts, and that root's list names the certificate: what is wrong is
        /// the root, and the judgement says so - a list nobody here vouches for
        /// says nothing.
        /// </summary>
        [Test]
        public async Task ACertificateOnTheListOfARootNobodyTrustsIsNotSaidToBeRevoked()
        {

            using var ours     = CA("Our Root");
            using var stranger = CA("Some Stranger's Root");
            var       url      = lists.NewURL();
            using var leaf     = Leaf(stranger, url);

            lists.Put(url, ListOf(stranger, leaf));

            await using var node = Node();

            Assert.That(node.Certificates.Import(Pem(ours), CertificateKind.TLSRoot, null, null, out _, out var error),  Is.True,  error);

            using var chain  = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.ExtraStore.Add(stranger);

            var errors = chain.Build(leaf) ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors;

            var judgement = Judge(node, leaf, chain, errors);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,  Is.False);
                Assert.That(judgement.Outcome,   Is.EqualTo("untrusted"));
                Assert.That(Texts(judgement),    Has.Some.Contains("ends at no root"));
                Assert.That(Texts(judgement),    Has.None.Contains("is revoked"));
            });

        }

        #endregion

    }

}
