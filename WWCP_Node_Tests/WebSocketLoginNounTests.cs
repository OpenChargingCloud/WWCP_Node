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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Who a WebSocket login is, in what its store says.
    /// </summary>
    /// <remarks>
    /// The logins of a WebSocket port are charging stations at a CSMS or a
    /// local controller, and local controllers at a grid operator: what the
    /// log and a refusal say names them as the node told the store - and as
    /// a charging station where nothing was told, word for word what it has
    /// always said.
    /// </remarks>
    public class WebSocketLoginNounTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void SetUp()
        {
            directory = Path.Combine(Path.GetTempPath(), $"wwcp-login-noun-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void TearDown()
        {
            try { Directory.Delete(directory, true); } catch { }
        }

        #endregion


        #region (private) Said(Logins, Do)

        private static List<String> Said(WebSocketLogins Logins, Action Do)
        {

            var said = new List<String>();

            Logins.OnNotice += (level, message) => said.Add(message);

            Do();

            return said;

        }

        #endregion


        #region ALocalControllerIsCalledOne

        [Test]
        public void ALocalControllerIsCalledOne()
        {

            var logins = new WebSocketLogins(Path.Combine(directory, "websocket-logins.json"),
                                             NodeNoun:   "grid operator",
                                             LoginNoun:  "local controller");

            Assert.That(logins.TryLoad(out var error), Is.True, error);

            var said = Said(logins, () =>
                           Assert.That(logins.TrySetPasswordAuthentication(User_Id.Parse("lc-1"), "a-password-long-enough", null, null, out var refused), Is.True, refused));

            Assert.That(said, Has.Some.EqualTo("The local controller 'lc-1' may now sign in to this grid operator."));
            Assert.That(said, Has.None.Contains("charging station"));

            Assert.That(logins.TrySetPasswordAuthentication(User_Id.Parse("lc-2"), "short", null, null, out var tooShort), Is.False);
            Assert.That(tooShort, Does.StartWith("A local controller password must be at least"));
            Assert.That(tooShort, Does.Not.Contain("OCPP"));

            Assert.That(logins.TryRemoveSSHKey(User_Id.Parse("lc-3"), "SHA256:none", out var unheardOf, out _), Is.False);
            Assert.That(unheardOf, Is.EqualTo("This grid operator has never heard of a local controller called 'lc-3'."));

        }

        #endregion

        #region AChargingStationWhereNothingIsSaid

        [Test]
        public void AChargingStationWhereNothingIsSaid()
        {

            var logins = new WebSocketLogins(Path.Combine(directory, "websocket-logins.json"),
                                             NodeNoun:  "local controller");

            Assert.That(logins.LoginNoun, Is.EqualTo(WebSocketLogins.DefaultLoginNoun));
            Assert.That(logins.TryLoad(out var error), Is.True, error);

            var said = Said(logins, () =>
                           Assert.That(logins.TrySetPasswordAuthentication(User_Id.Parse("cs001"), "a-password-long-enough", null, null, out var refused), Is.True, refused));

            Assert.That(said, Has.Some.EqualTo("The charging station 'cs001' may now sign in to this local controller."));

            Assert.That(logins.TrySetPasswordAuthentication(User_Id.Parse("cs002"), "short", null, null, out var tooShort), Is.False);
            Assert.That(tooShort, Does.EndWith("characters long; OCPP asks for that much."));

        }

        #endregion

    }

}
