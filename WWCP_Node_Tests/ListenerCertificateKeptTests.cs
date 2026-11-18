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
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a server keeps of the certificate a listener showed it - a TLS
    /// context built once per certificate, as Hermod's Modbus TLS front end
    /// builds one while the node is still starting - goes on working while
    /// the store changes around it.
    /// </summary>
    [TestFixture]
    public class ListenerCertificateKeptTests
    {

        #region Data

        private const String      Listener   = "ocpp";

        private String            directory  = "";
        private EventLog          log        = new ();
        private TestClock         clock      = TestClock.At(2026, 11, 18);
        private CertificateStore  store      = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeAStore()
        {

            directory  = Path.Combine(Path.GetTempPath(), "node-listener-kept-" + Guid.NewGuid().ToString("N")[..12]);
            log        = new EventLog();
            clock      = TestClock.At(2026, 11, 18);
            store      = new CertificateStore(directory,
                                              log,
                                              [ CertificateKind.TLSRoot, CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ],
                                              "gateway",
                                              Listeners:  [ "web" ],
                                              Clock:      clock);

            store.Reload();

        }

        [TearDown]
        public void TakeItAwayAgain()
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


        #region AContextKeptByAServer_OutlivesThreeRootsTakenIn()

        /// <summary>
        /// The Energy Meter session's reproduction: a TLS context built once
        /// from what the listener shows, then three TLS roots taken into the
        /// store - three changes, none of them about the server identity - and
        /// the kept certificate is still readable and the kept context still
        /// gets a client through a handshake.
        /// </summary>
        [Test]
        public async Task AContextKeptByAServer_OutlivesThreeRootsTakenIn()
        {

            using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {

                var request        = new CertificateRequest("CN=shown.example.org", key, HashAlgorithmName.SHA256);
                using var identity = request.CreateSelfSigned(clock.Now.AddDays(-1), clock.Now.AddDays(30));

                Assert.That(store.Import(identity.Export(X509ContentType.Pkcs12)!, CertificateKind.TLSServerIdentity, null, "shown", [ Listener ], out _, out var error),
                            Is.True, error);

            }

            using var chooser = new ListenerCertificate(store, Listener, log);

            var kept    = chooser.Current;

            Assert.That(kept, Is.Not.Null);

            var context = SslStreamCertificateContext.Create(kept!.Certificate, null);

            for (var i = 1; i <= 3; i++)
            {

                using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var rootRequest   = new CertificateRequest($"CN=Root {i}", rootKey, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

                using var root    = rootRequest.CreateSelfSigned(clock.Now.AddDays(-1), clock.Now.AddYears(10));

                Assert.That(store.Import(root.Export(X509ContentType.Cert), CertificateKind.TLSRoot, null, $"root-{i}", out _, out var error),
                            Is.True, error);

            }

            Assert.That(() => kept.Certificate.Subject, Is.EqualTo("CN=shown.example.org"), "the kept certificate was let go of underneath its holder");

            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            try
            {

                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                var serving = Task.Run(async () => {
                                  using var accepted = await listener.AcceptTcpClientAsync(deadline.Token);
                                  using var tls      = new SslStream(accepted.GetStream(), false);
                                  await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificateContext = context }, deadline.Token);
                              });

                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint) listener.LocalEndpoint).Port, deadline.Token);

                using var tls    = new SslStream(client.GetStream(), false, (sender, certificate, chain, errors) => true);

                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "shown.example.org" }, deadline.Token);

                await serving;

                Assert.That(tls.RemoteCertificate?.Subject, Is.EqualTo("CN=shown.example.org"));

            }
            finally
            {
                listener.Stop();
            }

        }

        #endregion

    }

}
