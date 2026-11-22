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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using IPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The sign-in brake every node has for the logins of its kind: five
    /// wrong sign-ins of one address within a minute, where the file says
    /// nothing, then that address is told no without a look - until the
    /// minute is over. Said in the section "signIns", and braking the logins
    /// of a kind over SSH as at the station port.
    /// </summary>
    [TestFixture]
    public class SignInBrakeTests
    {

        #region Data

        private          String          directory  = "";
        private readonly List<WWCPNode>  nodes      = [];

        private const    String          Guesser    = "192.0.2.7";
        private const    String          Neighbour  = "192.0.2.8";

        #endregion

        #region (class) Stations

        /// <summary>
        /// The logins of a kind, signing in over SSH with a password.
        /// </summary>
        private sealed class Stations(User_Id TheLogin, String ThePassword) : ISSHSignIns
        {

            public String PrincipalKind
                => "station";

            public Boolean Knows(User_Id Username)
                => Username == TheLogin;

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(false);

            public Boolean TakesPasswords
                => true;

            public ValueTask<Boolean> AuthorizePasswordAsync(User_Id Username, String Password, IPAddress? Client, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(Username == TheLogin && Password == ThePassword);

            public IReadOnlySet<String> SubsystemsFor(User_Id Username)
                => new HashSet<String>(StringComparer.Ordinal);

            public IReadOnlyList<String> GroupsOf(User_Id Username)
                => [];

            public String? WhyNoLongerIn(SshSessionInfo Session)
                => null;

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = TestNodes.TemporaryDirectory("signInBrake");
        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var node in nodes)
            {
                try
                {
                    await node.DisposeAsync();
                }
                catch (Exception)
                { }
            }

            nodes.Clear();

            TestNodes.Remove(directory);

        }

        #endregion

        #region (private) Node(SignIns)

        /// <summary>
        /// A node, built and not started, whose file says the given section "signIns", or none.
        /// </summary>
        private WWCPNode Node(JObject? SignIns = null)
        {

            var configuration = TestNodes.Offline;

            if (SignIns is not null)
                configuration.Add(SignInsConfiguration.SectionName, SignIns);

            var node = TestNodes.New(Path.Combine(directory, "node" + nodes.Count), configuration);

            nodes.Add(node);

            return node;

        }

        #endregion


        #region FiveWrongSignInsHoldAnAddressBack_ForAMinute()

        /// <summary>
        /// Five wrong sign-ins hold an address back - not its neighbour - and
        /// a minute after the first of them it is let through again.
        /// </summary>
        [Test]
        public void FiveWrongSignInsHoldAnAddressBack_ForAMinute()
        {

            var clock  = TestClock.At(2026, 11, 20);
            var brake  = new SignInBrake(clock);

            for (var guess = 1; guess < SignInBrake.DefaultMaxFailedPerMinute; guess++)
            {
                brake.CountFailed(Guesser);
                Assert.That(brake.IsHeldBack(Guesser), Is.False, $"held back after {guess} wrong sign-ins");
            }

            brake.CountFailed(Guesser);

            Assert.Multiple(() => {
                Assert.That(brake.IsHeldBack(Guesser),    Is.True,  "five wrong sign-ins hold nothing back");
                Assert.That(brake.IsHeldBack(Neighbour),  Is.False, "another address is held back as well");
                Assert.That(brake.IsHeldBack(null),       Is.False, "an address nobody can tell is held back");
            });

            clock.Advance(TimeSpan.FromSeconds(59));
            Assert.That(brake.IsHeldBack(Guesser), Is.True, "let through before the minute is over");

            clock.Advance(TimeSpan.FromSeconds(2));
            Assert.That(brake.IsHeldBack(Guesser), Is.False, "still held back after the minute");

        }

        #endregion

        #region NoBrake_HoldsNothingBack()

        /// <summary>
        /// 0 is no brake at all: however often an address signs in wrong.
        /// </summary>
        [Test]
        public void NoBrake_HoldsNothingBack()
        {

            var brake = new SignInBrake(TestClock.At(2026, 11, 20)) { MaxFailedPerMinute = 0 };

            for (var guess = 0; guess < 100; guess++)
                brake.CountFailed(Guesser);

            Assert.Multiple(() => {
                Assert.That(brake.IsOn,                Is.False);
                Assert.That(brake.IsHeldBack(Guesser), Is.False);
            });

        }

        #endregion

        #region TheSectionSaysHowManyAndTravelsInTheWholeDocument()

        /// <summary>
        /// "signIns": { "maxFailedPerMinute": … } in the file is what the
        /// node brakes with, 0 to 10000; written back as it was read.
        /// </summary>
        [Test]
        public void TheSectionSaysHowManyAndTravelsInTheWholeDocument()
        {

            var document = new WWCPConfiguration(SignIns: new SignInsConfiguration(3)).ToJSON();

            Assert.That(document[SignInsConfiguration.SectionName]?["maxFailedPerMinute"]?.Value<UInt32>(), Is.EqualTo(3));

            Assert.That(WWCPConfiguration.TryParse(document, out var read, out var error), Is.True, error);
            Assert.That(read!.SignIns?.MaxFailedPerMinute, Is.EqualTo(3));

            Assert.That(WWCPConfiguration.TryParse(new JObject(new JProperty(SignInsConfiguration.SectionName,
                                                                            new JObject(new JProperty("maxFailedPerMinute", 10001)))),
                                                   out _, out error),
                        Is.False, "more than 10000 wrong sign-ins a minute were taken");

            Assert.That(error, Does.Contain("maxFailedPerMinute"));

        }

        #endregion

        #region ANodeBrakesAsItsFileSays_FiveOtherwise()

        [Test]
        public void ANodeBrakesAsItsFileSays_FiveOtherwise()
        {

            Assert.Multiple(() => {
                Assert.That(Node().                                                        SignInBrake.MaxFailedPerMinute, Is.EqualTo(5));
                Assert.That(Node(new JObject(new JProperty("maxFailedPerMinute", 3))).     SignInBrake.MaxFailedPerMinute, Is.EqualTo(3));
                Assert.That(Node(new JObject(new JProperty("maxFailedPerMinute", 0))).     SignInBrake.IsOn,               Is.False);
            });

        }

        #endregion

        #region ALoginOfTheKind_IsBrakedOverSSH_AnAccountIsNot()

        /// <summary>
        /// A login of the node's kind that signs in over SSH with a password
        /// is braked as at the station port: five wrong passwords from one
        /// address, and the right one opens nothing from there for now - from
        /// another address it does. An account's wrong passwords are not
        /// counted here: they are rationed with the web interface's sign-in.
        /// </summary>
        [Test]
        public async Task ALoginOfTheKind_IsBrakedOverSSH_AnAccountIsNot()
        {

            var node           = Node();
            node.AddSSHSignIns(new Stations(User_Id.Parse("cs001"), "The-Right-Password"));

            var authenticator  = new NodeSSHAuthenticator(node, Passwords: true);
            var guesser        = IPAddress.Parse(Guesser);

            // An account's wrong password: no guess at a login of the kind.
            Assert.That(await authenticator.AuthorizePasswordAsync(User_Id.Parse("nobody"), "Not-The-Password", guesser), Is.False);
            Assert.That(await authenticator.AuthorizePasswordAsync(User_Id.Parse("cs001"),  "The-Right-Password", guesser), Is.True, "an account's wrong password braked a login of the kind");

            for (var guess = 1; guess <= SignInBrake.DefaultMaxFailedPerMinute; guess++)
                Assert.That(await authenticator.AuthorizePasswordAsync(User_Id.Parse("cs001"), $"Not-The-Password-{guess}", guesser), Is.False);

            var fromTheGuesser    = await authenticator.AuthorizePasswordAsync(User_Id.Parse("cs001"), "The-Right-Password", guesser);
            var fromTheNeighbour  = await authenticator.AuthorizePasswordAsync(User_Id.Parse("cs001"), "The-Right-Password", IPAddress.Parse(Neighbour));

            Assert.Multiple(() => {
                Assert.That(fromTheGuesser,    Is.False, "the guesser's address may guess no more");
                Assert.That(fromTheNeighbour,  Is.True,  "another address signs in");
            });

        }

        #endregion

    }

}
