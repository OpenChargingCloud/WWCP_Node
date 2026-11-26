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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.KeyPins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Trust on first use by asking (mDNS-Concept.md, B.4): "Ask" for ssh:// and
    /// wss://, what a connection to a host under ".local" does where it says
    /// nothing (Q2), the key written down and not believed, another key in its
    /// place (Q7), confirmed by an admin - pinned, with who and when (Q6) - or
    /// turned down.
    /// </summary>
    public class KeyConfirmationTests
    {

        #region Data

        private String           directory  = "";
        private ConnectionStore  store      = default!;

        private const String KeyA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        private const String KeyB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-ask-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void TearDown()
        {

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            { }

        }

        private ConnectionStore Node()
        {
            store = new ConnectionStore(Path.Combine(directory, "conn"));
            return store;
        }

        private String Add(String URL, String? SshTrust = null, String? KeyTrust = null, String? HostKey = null)
        {

            Assert.That(store.TryAddConnection(I18NString.Create("The local controller"), org.GraphDefined.Vanaheimr.Hermod.HTTP.URL.Parse(URL), "CSMS", false, null, null,
                                                           out var id, out var error,
                                                           SshHostKey:   HostKey,
                                                           SshTrust:     SshTrust is not null ? new SshTrustSettings(SshTrust, null, null)        : null,
                                                           KeyPinTrust:  KeyTrust is not null ? new ServerKeyPinSettings(null, KeyTrust, null)    : null),
                        Is.True, error);

            return id!;

        }

        private ConnectionEntry Entry(String Id)
            => store.Connections.Single(entry => entry.Id == Id);

        #endregion


        #region AskIsWhatALocalHostDoesWhereItSaysNothing()

        /// <summary>
        /// Q2: ssh:// and wss:// to a host under ".local" without a pin and
        /// without a word of trust on first use ask; the same to another host do
        /// not, nor one under ".local" that pins a key or says otherwise. A
        /// wss:// one to ".local" is key-pinned for it: never believed by a CA
        /// alone.
        /// </summary>
        [Test]
        public void AskIsWhatALocalHostDoesWhereItSaysNothing()
        {

            Node();

            var sshLocal   = Add("ssh://cs001@lc1.local:2222");
            var sshOther   = Add("ssh://cs001@lc1.example.org:2222", SshTrust: "HostKey");
            var sshPinned  = Add("ssh://cs001@lc2.local:2222", HostKey: KeyA);
            var sshSays    = Add("ssh://cs001@lc3.local:2222", SshTrust: "HostKey");
            var wssLocal   = Add("wss://lc1.local:443/ocpp");
            var wssOther   = Add("wss://csms.example.org:443/ocpp");
            var wssAsks    = Add("wss://csms.example.org:443/ocpp2", KeyTrust: "Ask");

            Assert.Multiple(() => {
                Assert.That(Entry(sshLocal). EffectiveSshTrustOnFirstUse,  Is.EqualTo(SshTrustOnFirstUse.Ask));
                Assert.That(Entry(sshOther). EffectiveSshTrustOnFirstUse,  Is.EqualTo(SshTrustOnFirstUse.HostKey));
                Assert.That(Entry(sshPinned).EffectiveSshTrustOnFirstUse,  Is.EqualTo(SshTrustOnFirstUse.None));
                Assert.That(Entry(sshSays).  EffectiveSshTrustOnFirstUse,  Is.EqualTo(SshTrustOnFirstUse.HostKey));
                Assert.That(Entry(wssLocal). EffectiveTrustOnFirstUse,     Is.EqualTo(KeyTrustOnFirstUse.Ask));
                Assert.That(Entry(wssLocal). IsKeyPinned,                  Is.True, "A host under .local was left to its CA.");
                Assert.That(Entry(wssOther). EffectiveTrustOnFirstUse,     Is.EqualTo(KeyTrustOnFirstUse.None));
                Assert.That(Entry(wssOther). IsKeyPinned,                  Is.False);
                Assert.That(Entry(wssAsks).  EffectiveTrustOnFirstUse,     Is.EqualTo(KeyTrustOnFirstUse.Ask));
                Assert.That(Entry(wssAsks).  IsKeyPinned,                  Is.True);
            });

        }

        #endregion

        #region TheTrustWritesTheKeyDownAndBelievesNothing()

        /// <summary>
        /// The trust of an ssh:// connection that asks: the key shown is not
        /// believed and not refused - it waits; the same key again is not new;
        /// another one takes its place and names the one before (Q7); a signed
        /// pin set ends the waiting.
        /// </summary>
        [Test]
        public void TheTrustWritesTheKeyDownAndBelievesNothing()
        {

            var keyA     = SshHostKey.GenerateEd25519().PublicKeyBlob;
            var keyB     = SshHostKey.GenerateEd25519().PublicKeyBlob;
            var trust    = new SshHostKeyTrust([], null, SshTrustOnFirstUse.Ask, SshOnPinMismatch.Refuse, false, "lc1.local", IPPort.Parse(22));
            var awaited  = new List<(String Shown, String? Before, Boolean IsNew)>();
            var refused  = 0;

            trust.OnAwaiting += (shown, before, isNew) => awaited.Add((shown, before, isNew));
            trust.OnRefused  += _ => refused++;

            var first    = trust.Verify(keyA);
            var again    = trust.Verify(keyA);
            var other    = trust.Verify(keyB);

            Assert.Multiple(() => {
                Assert.That(first || again || other,  Is.False, "A key was believed before an admin confirmed it.");
                Assert.That(refused,                  Is.Zero,  "Waiting was taken for a refusal of the server.");
                Assert.That(trust.IsAwaiting,         Is.True);
                Assert.That(trust.Awaiting,           Is.EqualTo(SshFingerprint.Sha256(keyB)));
                Assert.That(awaited,                  Is.EqualTo(new[] {
                                                          (SshFingerprint.Sha256(keyA), (String?) null,                      true),
                                                          (SshFingerprint.Sha256(keyA), (String?) null,                      false),
                                                          (SshFingerprint.Sha256(keyB), (String?) SshFingerprint.Sha256(keyA), true)
                                                      }));
                Assert.That(trust.WhyRefused(),       Does.Contain("waits for an admin to confirm it"));
            });

            trust.TakePins([ SshFingerprint.Sha256(keyB) ]);

            Assert.Multiple(() => {
                Assert.That(trust.Awaiting,      Is.Null);
                Assert.That(trust.Verify(keyB),  Is.True, "The key pinned since was not believed.");
            });

        }

        #endregion

        #region AnAdminConfirmsTheKeyThatWaits()

        /// <summary>
        /// The key that waits is confirmed: pinned from now on, with who and
        /// when, and the connection made again - its revision moves. One that
        /// waits in place of the one shown to the admin is not confirmed unseen.
        /// </summary>
        [Test]
        public void AnAdminConfirmsTheKeyThatWaits()
        {

            Node();

            var id    = Add("ssh://cs001@lc1.local:2222");
            var url   = Entry(id).URL;

            Assert.That(store.TryAwaitHostKey(id, url, KeyA, out var error), Is.True, error);
            Assert.That(store.TryAwaitHostKey(id, url, KeyA, out error),     Is.False, "The same key was written down again.");
            Assert.That(store.TryAwaitHostKey(id, url, KeyB, out error),     Is.True, error);

            var revision = store.ConnectionRevisionOf(id);

            Assert.That(store.TryConfirmKey(id, "alice", KeyA, out _, out var stale), Is.False);
            Assert.That(stale, Does.Contain($"The host key that waits now is {KeyB}"));

            Assert.That(store.TryConfirmKey(id, "alice", KeyB, out var confirmed, out error), Is.True, error);

            var entry   = Entry(id);
            var written = File.ReadAllText(Directory.GetFiles(directory, "peers.json", SearchOption.AllDirectories).Single());

            Assert.Multiple(() => {
                Assert.That(confirmed,                                    Is.EqualTo(KeyB));
                Assert.That(entry.SshHostKey,                             Is.EqualTo(KeyB));
                Assert.That(entry.SshAwaitingHostKey,                     Is.Null);
                Assert.That(entry.KeyConfirmedBy,                         Is.EqualTo("alice"));
                Assert.That(entry.KeyConfirmedAt,                         Is.Not.Null);
                Assert.That(entry.EffectiveSshTrustOnFirstUse,            Is.EqualTo(SshTrustOnFirstUse.None), "A pinned key still asks.");
                Assert.That(store.ConnectionRevisionOf(id),    Is.GreaterThan(revision), "The connection is not made again with the key.");
                Assert.That(written,                                      Does.Contain("\"keyConfirmedBy\": \"alice\""));
                Assert.That(store.TryConfirmKey(id, "alice", null, out _, out error), Is.False, "Nothing waits any more, and something was confirmed.");
            });

        }

        #endregion

        #region AnAdminTurnsTheKeyDown_AndASaveAsksAnew()

        /// <summary>
        /// The key that waits is turned down: forgotten, and the connection
        /// held off with who did it - until somebody saves it again.
        /// </summary>
        [Test]
        public void AnAdminTurnsTheKeyDown_AndASaveAsksAnew()
        {

            Node();

            var id = Add("wss://lc1.local:443/ocpp");
            var pin = KeyPin.Parse(new String('a', 64));

            Assert.That(store.TryAwaitServerKeyPin(id, Entry(id).URL, pin, out var notWritten), Is.True, notWritten);
            Assert.That(store.TryRejectKey(id, "bob", out var rejected, out var error), Is.True, error);

            var entry = Entry(id);

            Assert.Multiple(() => {
                Assert.That(rejected,                    Is.EqualTo(pin.ToString()));
                Assert.That(entry.ServerKeyPinAwaiting,  Is.Null);
                Assert.That(entry.KeyRejected,           Is.EqualTo(pin.ToString()));
                Assert.That(entry.KeyRejectedBy,         Is.EqualTo("bob"));
                Assert.That(entry.ServerKeyPins,         Is.Empty);
            });

            Assert.That(store.TryUpdateConnection(id, entry.Description, entry.URL, "CSMS", false, null, null, out error),
                        Is.True, error);

            Assert.That(Entry(id).KeyRejected, Is.Null, "A save left the key turned down.");

        }

        #endregion

        #region AskIsReadAndWrittenWithWhatWaits()

        /// <summary>
        /// "Ask" written into the file and read back, with the key that waits,
        /// and an unknown value refused with the three there are.
        /// </summary>
        [Test]
        public void AskIsReadAndWrittenWithWhatWaits()
        {

            Node();

            var id = Add("ssh://cs001@lc9.example.org:2222", SshTrust: "Ask");

            Assert.That(store.TryAwaitHostKey(id, Entry(id).URL, KeyA, out var error), Is.True, error);

            var json = Entry(id).ToJSON();

            Assert.Multiple(() => {
                Assert.That(json["sshTrustOnFirstUse"]?.Value<String>(),  Is.EqualTo("Ask"));
                Assert.That(json["sshAwaitingHostKey"]?.Value<String>(),  Is.EqualTo(KeyA));
                Assert.That(ConnectionEntry.ValidateSshTrust("Maybe", null, null, out _, out _, out _, out var wrong), Is.False);
                Assert.That(wrong, Does.Contain("'None', 'HostKey' or 'Ask'"));
            });

        }

        #endregion

    }

}
