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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What every node has to pass, asked of a node whose store keeps the
    /// identities its listeners show and none of a client's - as a meter's
    /// does: the checks of an identity's key, switch, name and deletion are
    /// asked of its server identities, where they had been skipped for want of
    /// a client's (found by the meter).
    /// </summary>
    public class ServerIdentityNodeConformance : PlainNodeConformance
    {

        #region (protected override) NewNode(Directory, Configuration)

        protected override WWCPNode NewNode(String   Directory,
                                            JObject  Configuration)
        {

            var configuration = Path.Combine(Directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, Configuration.ToString());

            var node = new WWCPNode(
                           HTTPPort:              IPPort.Parse(TestPorts.Free()),
                           AccountsPath:          Path.Combine(Directory, "accounts"),
                           ConfigFile:            new WWCPConfigFile(configuration),
                           Frontend:              new FileSystemContentSource(AFrontendIn(Directory)),
                           CertificatesPath:      Path.Combine(Directory, "certificates"),
                           LogToConsole:          false,
                           BridgeDebugLog:        false,
                           CertificateKinds:      [ CertificateKind.TLSRoot, CertificateKind.ClientRoot, CertificateKind.TLSServer, CertificateKind.TLSServerIdentity ],
                           CertificateListeners:  [ "modbus", "web" ]
                       );

            _ = new NodeHTTPAPI(node.HTTPServer, node, node.ExtAPI, node.Log);

            return node;

        }

        #endregion

    }

}
