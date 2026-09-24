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
    /// What the "certificates" section may say, and what it may not.
    /// </summary>
    public class CertificatesConfigurationTests
    {

        #region AnEmptySectionSaysNothing()

        [Test]
        public void AnEmptySectionSaysNothing()
        {

            Assert.That(CertificatesConfiguration.TryParse([], out var configuration, out var error), Is.True, error);

            Assert.That(configuration!.Directory, Is.Null,
                        "an absent directory is 'the file has no opinion', not 'nowhere'");

        }

        #endregion

        #region WhatIsWrittenComesBack()

        [Test]
        public void WhatIsWrittenComesBack()
        {

            var written = new CertificatesConfiguration("/var/lib/ev/certificates").ToJSON();

            Assert.That(CertificatesConfiguration.TryParse(written, out var read, out var error), Is.True, error);

            Assert.That(read!.Directory, Is.EqualTo("/var/lib/ev/certificates"));

        }

        #endregion

        #region ADirectoryOfTheWrongKindIsRefused()

        [Test]
        public void ADirectoryOfTheWrongKindIsRefused()
        {

            Assert.That(CertificatesConfiguration.TryParse(
                            new JObject(new JProperty("directory", 42)),
                            out _, out var error),
                        Is.False);

            Assert.That(error, Does.Contain("string"));

        }

        #endregion

        #region TheInventoryIsNotInTheConfigurationFile()

        [Test]
        public void TheInventoryIsNotInTheConfigurationFile()
        {

            // The point of the section being one field: what is in the store is
            // the content of a directory and is described by that directory's own
            // index, so a store copied to another machine arrives complete.
            var written = new CertificatesConfiguration("certificates").ToJSON();

            Assert.That(written.Properties().Count(), Is.EqualTo(1));

        }

        #endregion

    }

}
