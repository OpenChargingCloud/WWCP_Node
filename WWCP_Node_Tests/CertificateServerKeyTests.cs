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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The server keys of a node's listeners, in its certificate store: a key
    /// its clients may pin, shown in a carrier certificate made from it, one
    /// current and perhaps one announced as the next - and the store's clock,
    /// which decides what has run out.
    /// </summary>
    /// <remarks>
    /// What the station port's own store promised, asked of the node's store
    /// it moves into: the carrier's dates, a next key that never takes over
    /// by itself, a switch only to the key that was handed out, the current
    /// key kept from being deleted, and all of it there again after a restart.
    /// </remarks>
    [TestFixture]
    public class CertificateServerKeyTests
    {

        #region Data

        private const String      Listener   = "ocpp";

        private String            directory  = "";
        private EventLog          log        = new ();
        private TestClock         clock      = TestClock.At(2026, 11, 18);
        private CertificateStore  store      = default!;

        #endregion

        #region SetUp / TearDown

        private CertificateStore AStore()
        {

            var made = new CertificateStore(directory,
                                            log,
                                            [ CertificateKind.TLSRoot, CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ],
                                            "gateway",
                                            Listeners:     [ "web" ],
                                            RequestKinds:  [ CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ],
                                            Clock:         clock);

            made.Reload();

            return made;

        }

        [SetUp]
        public void MakeAStore()
        {
            directory  = Path.Combine(Path.GetTempPath(), "node-server-keys-" + Guid.NewGuid().ToString("N")[..12]);
            log        = new EventLog();
            clock      = TestClock.At(2026, 11, 18);
            store      = AStore();
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

        #region (private) Helpers

        private ServerKey AServerKey(Boolean AsNext = false)
        {

            Assert.That(store.TryCreateServerKey(Listener, null, AsNext, out var key, out var error),
                        Is.True, error);

            return key!;

        }

        /// <summary>
        /// What a certificate authority would issue for a key it was shown the
        /// public half of, and its own certificate after it - as PEM, the way
        /// it is uploaded.
        /// </summary>
        private String ACertificateFor(CertificateEntry  Carrier,
                                       DateTimeOffset?   NotBefore  = null,
                                       DateTimeOffset?   NotAfter   = null)
        {

            Assert.That(store.TryLoad(Carrier, out var carrier, out var error), Is.True, error);

            using (carrier)
            {

                using var caKey  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var caRequest    = new CertificateRequest("CN=Test CSMS CA", caKey, HashAlgorithmName.SHA256);
                caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

                using var ca     = caRequest.CreateSelfSigned(clock.Now.AddDays(-2), clock.Now.AddYears(10));

                var request      = new CertificateRequest(new X500DistinguishedName("CN=gateway.example.org"), carrier!.PublicKey, HashAlgorithmName.SHA256);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));

                using var issued = request.Create(ca.SubjectName,
                                                  X509SignatureGenerator.CreateForECDsa(caKey),
                                                  NotBefore ?? clock.Now.AddDays(-1),
                                                  NotAfter  ?? clock.Now.AddDays(365),
                                                  Guid.NewGuid().ToByteArray());

                return issued.ExportCertificatePem() + "\n" + ca.ExportCertificatePem() + "\n";

            }

        }

        private JObject Index()
            => JObject.Parse(File.ReadAllText(Path.Combine(directory, CertificateStore.IndexFileName)));

        /// <summary>
        /// A TLS server identity with its key, valid from yesterday for the
        /// given number of days by the test's clock, told the given listeners.
        /// </summary>
        private CertificateEntry AnIdentity(String     Name,
                                            Int32      Days,
                                            String[]?  Listeners  = null,
                                            Int32      Since      = -1)
        {

            using var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request        = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);
            using var identity = request.CreateSelfSigned(clock.Now.AddDays(Since), clock.Now.AddDays(Days));

            Assert.That(store.Import(identity.Export(X509ContentType.Pkcs12)!, CertificateKind.TLSServerIdentity, null, Name, Listeners, out var entry, out var error),
                        Is.True, error);

            return entry!;

        }

        /// <summary>
        /// A clock a test moves, whose timers fire when the test says so.
        /// </summary>
        private sealed class ClockWithTimersByHand(DateTimeOffset Start) : TimeProvider
        {

            public DateTimeOffset        Now     { get; set; } = Start;
            public List<TimerCallback>   Timers  { get; }      = [];

            public override DateTimeOffset GetUtcNow()
                => Now;

            public override ITimer CreateTimer(TimerCallback Callback, Object? State, TimeSpan DueTime, TimeSpan Period)
            {
                Timers.Add(Callback);
                return new ByHand(() => Timers.Remove(Callback));
            }

            public void Fire()
            {
                foreach (var timer in Timers.ToList())
                    timer(null);
            }

            private sealed class ByHand(Action Gone) : ITimer
            {
                public Boolean    Change(TimeSpan DueTime, TimeSpan Period)  => true;
                public void       Dispose()                                    => Gone();
                public ValueTask  DisposeAsync()                               { Gone(); return ValueTask.CompletedTask; }
            }

        }

        #endregion


        #region TheCarrier_IsDatedFrom1970To9999_AndToldItsListener()

        /// <summary>
        /// A carrier is valid from 1970 to the last second of 9999, to the
        /// second - not an hour short, as .NET reads that end east of
        /// Greenwich - carries its key, is told the listener, and the index
        /// carries the key under its key pin.
        /// </summary>
        [Test]
        public void TheCarrier_IsDatedFrom1970To9999_AndToldItsListener()
        {

            var key      = AServerKey();
            var carrier  = store.CarrierOf(key);

            Assert.That(carrier, Is.Not.Null);

            Assert.Multiple(() => {

                Assert.That(carrier!.NotBefore,                                Is.EqualTo(CertificateStore.CarrierNotBefore));
                Assert.That(carrier. NotAfter,                                 Is.EqualTo(CertificateStore.CarrierNotAfter));
                Assert.That(carrier. HasPrivateKey,                            Is.True);
                Assert.That(carrier. KeyPin,                                   Is.EqualTo(key.KeyPin));
                Assert.That(carrier. Subject,                                  Does.Contain(CertificateStore.CarrierMark));
                Assert.That(carrier. Usages?.Select(usage => usage.ToString()), Is.EqualTo(new[] { Listener }));
                Assert.That(carrier. IsFor("web"),                             Is.False, "A carrier of the station port was offered to the web interface.");

                Assert.That(key.Id,            Is.EqualTo(key.KeyPin.ToHex()[..16]));
                Assert.That(key.IsNext,        Is.False);
                Assert.That(key.CurrentSince,  Is.EqualTo(clock.Now));

                var index = Index();

                Assert.That(index["serverKeys"]?[key.KeyPin.ToHex()]?["carrier"]?.Value<String>(),  Is.EqualTo(carrier.Id));
                Assert.That(index["serverKeys"]?[key.KeyPin.ToHex()]?["listener"]?.Value<String>(), Is.EqualTo(Listener));
                Assert.That((index["certificates"] as JArray)?.Any(entry => entry["keyPin"]?.Value<String>() == key.KeyPin.ToHex()),
                            Is.True, "The index does not say the carrier's key pin.");

            });

        }

        #endregion

        #region ANewKey_NeverTakesOverByItself()

        /// <summary>
        /// Nothing shown: a next key has nothing to be announced after. A
        /// current key: another one is announced as the next, never made in
        /// its place - and only one next key at a time.
        /// </summary>
        [Test]
        public void ANewKey_NeverTakesOverByItself()
        {

            Assert.That(store.TryCreateServerKey(Listener, null, AsNext: true, out _, out var error), Is.False);
            Assert.That(error, Does.Contain("nothing to announce"));

            var current = AServerKey();

            Assert.That(store.TryCreateServerKey(Listener, null, AsNext: false, out _, out error), Is.False);
            Assert.That(error, Does.Contain("does not take its place by itself"));

            var next = AServerKey(AsNext: true);

            Assert.That(store.TryCreateServerKey(Listener, null, AsNext: true, out _, out error), Is.False);
            Assert.That(error, Does.Contain("already"));

            Assert.That(store.GetCurrentAndNextKey(Listener, out var announced)?.KeyPin, Is.EqualTo(current.KeyPin));
            Assert.That(announced?.KeyPin,                                                Is.EqualTo(next.KeyPin));
            Assert.That(announced?.CurrentSince,                                          Is.Null);

        }

        #endregion

        #region AnIdentityForEveryListener_CountsAsShown()

        /// <summary>
        /// An identity told nothing may be shown on every listener, the station
        /// port among them: a server key does not take its place by itself.
        /// </summary>
        [Test]
        public void AnIdentityForEveryListener_CountsAsShown()
        {

            using var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request        = new CertificateRequest("CN=gateway.example.org", key, HashAlgorithmName.SHA256);
            using var identity = request.CreateSelfSigned(clock.Now.AddDays(-1), clock.Now.AddDays(90));

            Assert.That(store.Import(identity.Export(X509ContentType.Pkcs12)!, CertificateKind.TLSServerIdentity, null, null, out _, out var error),
                        Is.True, error);

            Assert.That(store.TryCreateServerKey(Listener, null, AsNext: false, out _, out error), Is.False);
            Assert.That(store.TryCreateServerKey(Listener, null, AsNext: true,  out _, out error), Is.True, error);

        }

        #endregion

        #region TheSwitch_MakesTheNextKeyCurrent_AndSaysWhoWasBefore()

        /// <summary>
        /// The next key is current from the switch on, the one before is
        /// current no more, and whoever follows is told both key pins.
        /// </summary>
        [Test]
        public void TheSwitch_MakesTheNextKeyCurrent_AndSaysWhoWasBefore()
        {

            var current  = AServerKey();
            var next     = AServerKey(AsNext: true);

            (CertificateUsage Listener, KeyPin? Before, KeyPin After)? told = null;

            store.OnServerKeySwitched += (listener, before, after) => told = (listener, before, after);

            clock.Advance(TimeSpan.FromHours(1));

            Assert.That(store.TrySwitchToNextKey(Listener, next.KeyPin, out var switched, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(switched?.KeyPin,                                        Is.EqualTo(next.KeyPin));
                Assert.That(switched?.CurrentSince,                                  Is.EqualTo(clock.Now));
                Assert.That(store.GetCurrentAndNextKey(Listener, out var announced)?.KeyPin, Is.EqualTo(next.KeyPin));
                Assert.That(announced,                                               Is.Null);
                Assert.That(told?.Listener.ToString(),                               Is.EqualTo(Listener));
                Assert.That(told?.Before,                                            Is.EqualTo(current.KeyPin));
                Assert.That(told?.After,                                             Is.EqualTo(next.KeyPin));
                Assert.That(store.CarrierOf(current),                                Is.Not.Null, "The key before was thrown away by the switch.");
            });

            Assert.That(store.TrySwitchToNextKey(Listener, null, out _, out error), Is.False);
            Assert.That(error, Does.Contain("nothing to switch to"));

        }

        #endregion

        #region ASwitch_ToAKeyNobodyHandedOut_IsRefused()

        /// <summary>
        /// Whoever names the key pin it handed out gets that key or nothing.
        /// </summary>
        [Test]
        public void ASwitch_ToAKeyNobodyHandedOut_IsRefused()
        {

            var current  = AServerKey();
            var next     = AServerKey(AsNext: true);

            var other    = KeyPin.FromSHA256(SHA256.HashData("somebody else's key"u8));

            Assert.That(store.TrySwitchToNextKey(Listener, other, out _, out var error), Is.False);
            Assert.That(error, Does.Contain(next.KeyPin.ToHex()));

            Assert.That(store.GetCurrentAndNextKey(Listener, out var announced)?.KeyPin, Is.EqualTo(current.KeyPin));
            Assert.That(announced?.KeyPin,                                                Is.EqualTo(next.KeyPin));

        }

        #endregion

        #region TheCurrentKey_AndWhatIsShown_CannotBeDeleted()

        /// <summary>
        /// The carrier of the current key stays; the next key may go, and with
        /// its carrier goes the announcement. What a listener is showing stays
        /// whatever it is.
        /// </summary>
        [Test]
        public void TheCurrentKey_AndWhatIsShown_CannotBeDeleted()
        {

            var current  = AServerKey();
            var next     = AServerKey(AsNext: true);

            Assert.That(store.Remove(current.CarrierId, out var error), Is.False);
            Assert.That(error, Does.Contain("current server key"));
            Assert.That(store.CarrierOf(current), Is.Not.Null);

            Assert.That(store.Remove(next.CarrierId, out error), Is.True, error);
            Assert.That(store.GetCurrentAndNextKey(Listener, out var announced), Is.Not.Null);
            Assert.That(announced,                                                Is.Null);
            Assert.That(Index()["serverKeys"]?[next.KeyPin.ToHex()],              Is.Null);

            Assert.That(store.TryAnswerRequest(ACertificateFor(store.CarrierOf(current)!), out var issued, out _, out _, out error, out _),
                        Is.True, error);

            store.Serving(Listener, issued!.Id);

            Assert.That(store.Remove(issued.Id, out error), Is.False);
            Assert.That(error, Does.Contain("showing right now"));

            store.Serving(Listener, current.CarrierId);

            Assert.That(store.Remove(issued.Id, out error), Is.True, error);

        }

        #endregion

        #region ACertificateIssuedForAServerKey_IsThatKeys_AndTheCarrierIsKept()

        /// <summary>
        /// A certificate issued for a server key is taken in as a renewal that
        /// kept its key: beside the carrier, told the same listener, and found
        /// as the key's by its key pin.
        /// </summary>
        [Test]
        public void ACertificateIssuedForAServerKey_IsThatKeys_AndTheCarrierIsKept()
        {

            var key      = AServerKey();
            var carrier  = store.CarrierOf(key)!;

            Assert.That(store.TryAnswerRequest(ACertificateFor(carrier), out var issued, out var answered, out _, out var error, out _),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(answered,                                                 Is.Null);
                Assert.That(issued!.KeyPin,                                           Is.EqualTo(key.KeyPin));
                Assert.That(issued. HasPrivateKey,                                    Is.True);
                Assert.That(issued. Usages?.Select(usage => usage.ToString()),       Is.EqualTo(new[] { Listener }));
                Assert.That(store.IssuedFor(key).Select(entry => entry.Id),           Is.EqualTo(new[] { issued.Id }));
                Assert.That(store.ServerKeyOf(issued)?.KeyPin,                        Is.EqualTo(key.KeyPin));
                Assert.That(store.CarrierOf(key)?.Id,                                 Is.EqualTo(carrier.Id));
                Assert.That(store.GetCurrentAndNextKey(Listener, out _)?.KeyPin,      Is.EqualTo(key.KeyPin));
            });

        }

        #endregion

        #region ServerKeys_SurviveARestart()

        /// <summary>
        /// A store made again over the same directory knows the same keys as
        /// current and next, and switches to the same one.
        /// </summary>
        [Test]
        public void ServerKeys_SurviveARestart()
        {

            var current  = AServerKey();
            var next     = AServerKey(AsNext: true);

            var again    = AStore();

            Assert.That(again.GetCurrentAndNextKey(Listener, out var announced)?.KeyPin, Is.EqualTo(current.KeyPin));
            Assert.That(announced?.KeyPin,                                                Is.EqualTo(next.KeyPin));
            Assert.That(again.ServerKeys(Listener),                                       Has.Count.EqualTo(2));

            clock.Advance(TimeSpan.FromMinutes(5));

            Assert.That(again.TrySwitchToNextKey(Listener, next.KeyPin, out _, out var error), Is.True, error);

            var thrice = AStore();

            Assert.That(thrice.GetCurrentAndNextKey(Listener, out announced)?.KeyPin, Is.EqualTo(next.KeyPin));
            Assert.That(announced,                                                     Is.Null);

        }

        #endregion

        #region ALostIndex_CostsWhichKeyWasCurrent_AndNoMore()

        /// <summary>
        /// Without its index, a store takes its carriers back as server keys of
        /// the listener their subjects name, told that listener again - the one
        /// key of a listener as its current key, several as none.
        /// </summary>
        [Test]
        public void ALostIndex_CostsWhichKeyWasCurrent_AndNoMore()
        {

            var current = AServerKey();

            File.Delete(Path.Combine(directory, CertificateStore.IndexFileName));

            var again   = AStore();
            var carrier = again.CarrierOf(again.GetCurrentAndNextKey(Listener, out _)!);

            Assert.That(again.GetCurrentAndNextKey(Listener, out _)?.KeyPin,     Is.EqualTo(current.KeyPin));
            Assert.That(carrier?.Usages?.Select(usage => usage.ToString()),      Is.EqualTo(new[] { Listener }));
            Assert.That(carrier?.IsFor("web"),                                   Is.False);

            Assert.That(again.TryCreateServerKey(Listener, null, AsNext: true, out _, out var error), Is.True, error);

            File.Delete(Path.Combine(directory, CertificateStore.IndexFileName));

            var thrice  = AStore();

            Assert.That(thrice.ServerKeys(Listener),                             Has.Count.EqualTo(2));
            Assert.That(thrice.GetCurrentAndNextKey(Listener, out var next),     Is.Null);
            Assert.That(next,                                                    Is.Null);

        }

        #endregion

        #region TheStoresClock_DecidesWhatHasRunOut()

        /// <summary>
        /// Whether a certificate is usable is the store's clock's to say, not
        /// the system's: moved past a certificate's end, it is not usable any
        /// more - while the carrier, valid until 9999, still is.
        /// </summary>
        [Test]
        public void TheStoresClock_DecidesWhatHasRunOut()
        {

            var key      = AServerKey();

            Assert.That(store.TryAnswerRequest(ACertificateFor(store.CarrierOf(key)!), out var issued, out _, out _, out var error, out _),
                        Is.True, error);

            Assert.That(store.UsableFor(CertificateKind.TLSServerIdentity, Listener).Select(entry => entry.Id),
                        Is.EquivalentTo(new[] { key.CarrierId, issued!.Id }));

            clock.Advance(TimeSpan.FromDays(400));

            Assert.Multiple(() => {
                Assert.That(store.UsableFor(CertificateKind.TLSServerIdentity, Listener).Select(entry => entry.Id),
                            Is.EquivalentTo(new[] { key.CarrierId }));
                Assert.That(issued.IsExpiredAt(clock.Now),                          Is.True);
                Assert.That(issued.IsUsableAt (clock.Now),                          Is.False);
                Assert.That(issued.ToJSON(WithDiagnostics: true, clock.Now)["expired"]?.Value<Boolean>(), Is.True);
                Assert.That(store.CarrierOf(key)!.IsUsableAt(clock.Now),            Is.True);
            });

        }

        #endregion


        #region AGenericChoice_ShowsNoNextOrFormerKey()

        /// <summary>
        /// What chooses by the store's usable identities - the web interface,
        /// a kind of node's own listener - is never handed the carrier of an
        /// announced next key, or of one that was current once: it would switch
        /// the clients over before anybody asked for it. The carriers stay
        /// switched on all the same.
        /// </summary>
        [Test]
        public void AGenericChoice_ShowsNoNextOrFormerKey()
        {

            var current  = AServerKey();
            var next     = AServerKey(AsNext: true);

            Assert.That(store.UsableFor   (CertificateKind.TLSServerIdentity, Listener).Select(entry => entry.Id), Is.EqualTo(new[] { current.CarrierId }));
            Assert.That(store.UsableByKind(CertificateKind.TLSServerIdentity).          Select(entry => entry.Id), Is.EqualTo(new[] { current.CarrierId }));
            Assert.That(store.CarrierOf(next)!.IsActive, Is.True);

            Assert.That(store.TrySwitchToNextKey(Listener, next.KeyPin, out _, out var error), Is.True, error);

            Assert.That(store.UsableFor(CertificateKind.TLSServerIdentity, Listener).Select(entry => entry.Id), Is.EqualTo(new[] { next.CarrierId }));

        }

        #endregion

        #region TheCurrentCarrier_IsNotSwitchedOff_ToldAway_OrMoved()

        /// <summary>
        /// Switching the carrier of the current key off, telling it another
        /// listener or every one, or moving it to another kind would take the
        /// current key from its listener as removing it would: refused, or left
        /// where it is. The next key's carrier may go.
        /// </summary>
        [Test]
        public void TheCurrentCarrier_IsNotSwitchedOff_ToldAway_OrMoved()
        {

            var current  = AServerKey();
            var next     = AServerKey(AsNext: true);

            Assert.That(store.SetActive(current.CarrierId, false, out _, out var error), Is.False);
            Assert.That(error, Does.Contain("not switched off"));

            Assert.That(store.SetUsages(current.CarrierId, [ "web" ], out _, out error), Is.False);
            Assert.That(error, Does.Contain("carries the server key"));

            Assert.That(store.SetUsages(current.CarrierId, null, out _, out error), Is.False);
            Assert.That(error, Does.Contain("every listener"));

            Assert.That(store.SetUsages(next.CarrierId, [ "web" ], out _, out error), Is.False, "the next key's carrier was told another listener");

            Assert.That(store.MoveKind(CertificateKind.TLSServerIdentity, CertificateKind.TLSIdentity, out var moved, out error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(moved,                                                                   Is.EqualTo(1), "the next key's carrier was not moved");
                Assert.That(store.Get(current.CarrierId, CertificateKind.TLSServerIdentity),        Is.Not.Null, "the current key's carrier was moved");
                Assert.That(store.GetCurrentAndNextKey(Listener, out var announced)?.KeyPin,         Is.EqualTo(current.KeyPin));
                Assert.That(announced,                                                               Is.Null, "the next key is announced without its carrier");
                Assert.That(log.Recent(200).Any(entry => entry.Message.Contains("left where it is") && entry.Message.Contains("not moved")),
                            Is.True, "it is not said why the carrier stayed");
            });

            Assert.That(store.SetActive(current.CarrierId, true, out _, out error), Is.True, error);

        }

        #endregion

        #region WhatAListenerShows_IsNotSwitchedOffOrToldAway()

        /// <summary>
        /// What a listener is showing right now is not switched off, nor told a
        /// list of listeners without that one; told one more, it may be.
        /// </summary>
        [Test]
        public void WhatAListenerShows_IsNotSwitchedOffOrToldAway()
        {

            var shown = AnIdentity("gateway.example.org", 90, [ Listener ]);

            store.Serving(Listener, shown.Id);

            Assert.That(store.SetActive(shown.Id, false, out _, out var error), Is.False);
            Assert.That(error, Does.Contain("showing right now"));

            Assert.That(store.SetUsages(shown.Id, [ "web" ], out _, out error), Is.False);
            Assert.That(error, Does.Contain("showing right now"));

            Assert.That(store.SetUsages(shown.Id, [ Listener, "web" ], out _, out error), Is.True, error);
            Assert.That(store.SetUsages(shown.Id, null,                out _, out error), Is.True, error);

            store.Serving(Listener, null);

            Assert.That(store.SetActive(shown.Id, false, out _, out error), Is.True, error);

        }

        #endregion

        #region TheChooser_ShowsTheIssuedCertificate_ThenTheCarrier()

        /// <summary>
        /// A listener with a current key shows the newest certificate issued for
        /// it while that is valid, and the key's carrier once it has run out -
        /// never an identity of no key, however valid.
        /// </summary>
        [Test]
        public void TheChooser_ShowsTheIssuedCertificate_ThenTheCarrier()
        {

            var key     = AServerKey();

            AnIdentity("somebody-else.example.org", 900, [ Listener ]);

            Assert.That(store.TryAnswerRequest(ACertificateFor(store.CarrierOf(key)!), out var issued, out _, out _, out var error, out _),
                        Is.True, error);

            using var chooser = new ListenerCertificate(store, Listener, log);

            var shown = chooser.Choose();

            Assert.That(shown?.Entry.Id,    Is.EqualTo(issued!.Id));
            Assert.That(shown?.IsCarrier,   Is.False);
            Assert.That(shown?.PresentedAs, Is.EqualTo("certificate"));

            clock.Advance(TimeSpan.FromDays(400));

            shown = chooser.Choose();

            Assert.That(shown?.Entry.Id,    Is.EqualTo(key.CarrierId));
            Assert.That(shown?.IsCarrier,   Is.True);
            Assert.That(shown?.PresentedAs, Is.EqualTo("carrier"));
            Assert.That(shown?.Chain.Certificate.HasPrivateKey, Is.True);

        }

        #endregion

        #region TheChooser_ReadsACertificateOnce_UntilTheStoreChanges()

        /// <summary>
        /// The certificate a listener shows is read once and handed out at every
        /// handshake - a new key in the user's key store at each would be one
        /// more left there on Windows - until the store changes, when it is read
        /// again.
        /// </summary>
        [Test]
        public void TheChooser_ReadsACertificateOnce_UntilTheStoreChanges()
        {

            AServerKey();

            using var chooser = new ListenerCertificate(store, Listener, log);

            var first   = chooser.Current;
            var again   = chooser.Current;

            Assert.That(first,  Is.Not.Null);
            Assert.That(again,  Is.SameAs(first));

            AnIdentity("unrelated.example.org", 30, [ "web" ]);

            var after   = chooser.Current;

            Assert.That(after,  Is.Not.SameAs(first), "the store changed and the certificate was not read again");
            Assert.That(CertificateEntry.ThumbprintOf(after!.Certificate), Is.EqualTo(CertificateEntry.ThumbprintOf(first!.Certificate)));

        }

        #endregion

        #region WithoutAKey_OnlyAListenerThatKeepsServingTheLast_ShowsWhatRanOut()

        /// <summary>
        /// Without a server key a listener chooses as the web interface always
        /// has: the newest valid identity for it. Once that has run out, a web
        /// interface shows nothing - and a listener that keeps serving the last
        /// shows it all the same, and says so.
        /// </summary>
        [Test]
        public void WithoutAKey_OnlyAListenerThatKeepsServingTheLast_ShowsWhatRanOut()
        {

            var older   = AnIdentity("older.example.org", 20, [ Listener ], Since: -10);
            var newer   = AnIdentity("newer.example.org", 10, [ Listener ], Since: -1);

            using var web     = new ListenerCertificate(store, Listener, log);
            using var station = new ListenerCertificate(store, Listener, log, KeepServingLast: true);

            Assert.That(web.    Choose()?.Entry.Id, Is.EqualTo(newer.Id), "not the identity whose validity began last");
            Assert.That(station.Choose()?.Entry.Id, Is.EqualTo(newer.Id));

            clock.Advance(TimeSpan.FromDays(30));

            var kept = station.Choose();

            Assert.Multiple(() => {
                Assert.That(web.Choose(),     Is.Null, "a listener that does not keep serving the last shows what ran out");
                Assert.That(kept?.Entry.Id,   Is.EqualTo(newer.Id), "not the one shown last");
                Assert.That(kept?.IsKeptOn,   Is.True);
            });

            using var fresh   = new ListenerCertificate(store, Listener, log, KeepServingLast: true);

            Assert.That(fresh.Choose()?.Entry.Id, Is.EqualTo(older.Id), "a fresh start does not take the one that lasted longest");

        }

        #endregion

        #region TheClock_NoticesWhatRunsOut_AndTellsWhoFollows()

        /// <summary>
        /// The node's clock looks at the store: a certificate issued for the
        /// current key that runs out is said in the log, and whoever follows
        /// what the listener shows - an HTTP/3 listener, which takes its
        /// certificate when it starts - is told that it shows the carrier now.
        /// </summary>
        [Test]
        public void TheClock_NoticesWhatRunsOut_AndTellsWhoFollows()
        {

            var byHand  = new ClockWithTimersByHand(clock.Now);

            store       = new CertificateStore(directory,
                                               log,
                                               [ CertificateKind.TLSRoot, CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ],
                                               "gateway",
                                               Listeners:     [ "web" ],
                                               RequestKinds:  [ CertificateKind.TLSIdentity, CertificateKind.TLSServerIdentity ],
                                               Clock:         byHand);
            store.Reload();

            var key     = AServerKey();

            Assert.That(store.TryAnswerRequest(ACertificateFor(store.CarrierOf(key)!, byHand.Now.AddDays(-1), byHand.Now.AddDays(30)), out var issued, out _, out _, out var error, out _),
                        Is.True, error);

            using var listeners = new ListenerCertificates(store, byHand, log, TimeSpan.FromMinutes(1));

            var told    = new List<(String Listener, String? Before, String? After)>();

            listeners.OnShownChanged += (listener, before, after) => told.Add((listener.ToString(), before?.Id, after?.Id));

            Assert.That(listeners.For(Listener).Entry?.Id, Is.EqualTo(issued!.Id));

            listeners.StartChecking();

            Assert.That(byHand.Timers, Has.Count.EqualTo(1), "nothing looks at the store by the clock");

            byHand.Fire();

            Assert.That(told, Is.Empty, "a change was told where nothing changed");

            byHand.Now = byHand.Now.AddDays(31);
            byHand.Fire();

            Assert.Multiple(() => {
                Assert.That(told, Is.EqualTo(new[] { (Listener, (String?) issued.Id, (String?) key.CarrierId) }));
                Assert.That(log.Recent(200).Any(entry => entry.Message.Contains(issued.Id) && entry.Message.Contains("ran out")), Is.True, "that it ran out is not said");
                Assert.That(log.Recent(200).Any(entry => entry.Message.Contains($"the listener '{Listener}' shows") && entry.Message.Contains("carrier")), Is.True);
            });

            listeners.StopChecking();

            Assert.That(byHand.Timers, Is.Empty, "the clock goes on looking after it was stopped");

        }

        #endregion

        #region AnAnswer_IsJudgedByTheStoresClock()

        /// <summary>
        /// Whether a certificate brought for a key has run out is the store's
        /// clock's to say: valid by the system's clock, and two years past its
        /// end by the node's, it is refused.
        /// </summary>
        [Test]
        public void AnAnswer_IsJudgedByTheStoresClock()
        {

            clock       = new TestClock(DateTimeOffset.UtcNow.AddYears(2));
            store       = AStore();

            var key     = AServerKey();
            var real    = DateTimeOffset.UtcNow;

            Assert.That(store.TryAnswerRequest(ACertificateFor(store.CarrierOf(key)!, real.AddDays(-1), real.AddDays(365)), out _, out _, out _, out var error, out _),
                        Is.False, "a certificate that ran out by the node's clock was taken in");

            Assert.That(error, Does.Contain("expired"));

        }

        #endregion

    }

}
