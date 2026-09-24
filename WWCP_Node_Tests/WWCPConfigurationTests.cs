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

using cloud.charging.open.protocols.WWCP.node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.node.Tests
{

    /// <summary>
    /// The whole document: the sections every node reads from its
    /// configuration file, and what it does with the ones it does not know.
    /// </summary>
    public class WWCPConfigurationTests
    {

        #region TheCertificatesSectionTravelsInTheWholeDocument()

        [Test]
        public void TheCertificatesSectionTravelsInTheWholeDocument()
        {

            var document = new WWCPConfiguration(
                               Certificates: new CertificatesConfiguration("certificates")
                           ).ToJSON();

            Assert.That(WWCPConfiguration.TryParse(document, out var read, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(read!.Certificates,            Is.Not.Null);
                Assert.That(read!.Certificates!.Directory, Is.EqualTo("certificates"));
                Assert.That(read!.IsEmpty,                 Is.False);
            });

        }

        #endregion

        #region ASectionOfTheWrongKindIsRefused()

        [Test]
        public void ASectionOfTheWrongKindIsRefused()
        {

            // '"certificates": "somewhere"' is a file whose author believed they
            // had configured something.
            Assert.That(WWCPConfiguration.TryParse(
                            new JObject(new JProperty(CertificatesConfiguration.SectionName, "somewhere")),
                            out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("JSON object"));

        }

        #endregion

        #region ASectionNobodyHereKnowsIsPassedOver()

        /// <summary>
        /// A vehicle's sections in the file a node reads: not its business,
        /// and not a fault. This is what lets one file carry the sections of
        /// the node and of the kind of node it is, each read by its own
        /// reader.
        /// </summary>
        [Test]
        public void ASectionNobodyHereKnowsIsPassedOver()
        {

            var document = new JObject(
                               new JProperty("vehicle", new JObject(
                                   new JProperty("name", "Test vehicle")
                               ))
                           );

            Assert.That(WWCPConfiguration.TryParse(document, out var read, out var error), Is.True, error);

            Assert.That(read!.IsEmpty, Is.True, "nothing of the node's was in it");

        }

        #endregion

    }

}
