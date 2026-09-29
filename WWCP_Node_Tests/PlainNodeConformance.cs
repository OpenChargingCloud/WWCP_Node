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

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What every node has to pass, asked of a node of no particular kind:
    /// the node itself with the JSON API every kind derives its own from, and
    /// nothing on top - so that WWCP_Node's own suite says what every kind's
    /// suite then asks of that kind.
    /// </summary>
    public class PlainNodeConformance : NodeConformanceTests
    {

        #region (protected override) NewNode(Directory, Configuration)

        protected override WWCPNode NewNode(String   Directory,
                                            JObject  Configuration)
        {

            var configuration = Path.Combine(Directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, Configuration.ToString());

            var node = new WWCPNode(
                           HTTPPort:          IPPort.Parse(TestPorts.Free()),
                           AccountsPath:      Path.Combine(Directory, "accounts"),
                           ConfigFile:        new WWCPConfigFile(configuration),
                           Frontend:          new FileSystemContentSource(AFrontendIn(Directory)),
                           CertificatesPath:  Path.Combine(Directory, "certificates"),
                           LogToConsole:      false,
                           BridgeDebugLog:    false
                       );

            _ = new NodeHTTPAPI(node.HTTPServer, node, node.ExtAPI, node.Log);

            return node;

        }

        #endregion

        #region (private static) AFrontendIn(Directory)

        /// <summary>
        /// The least of a web interface a kind of node is built with: the
        /// stub with the placeholders the node fills in, a bundle it references
        /// relatively, and the icon /favicon.ico is pointed at.
        /// </summary>
        private static String AFrontendIn(String Directory)
        {

            var frontend = Path.Combine(Directory, "frontend");

            System.IO.Directory.CreateDirectory(Path.Combine(frontend, "assets"));

            File.WriteAllText(Path.Combine(frontend, WWCPNode.IndexFile),
                              """
                              <!DOCTYPE html>
                              <html lang="en">
                              <head>
                                  <base href="{{BasePath}}/" />
                                  <meta name="server-version" content="{{ServerVersion}}" />
                                  <meta name="node-name" content="{{NodeName}}" />
                                  <script defer src="assets/main.test.js"></script>
                              </head>
                              <body><div id="app"></div></body>
                              </html>
                              """);

            File.WriteAllText(Path.Combine(frontend, "assets", "main.test.js"),
                              "document.getElementById('app').textContent = 'a node of no particular kind';");

            File.WriteAllText(Path.Combine(frontend, WWCPNode.FaviconSVG),
                              """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>""");

            return frontend;

        }

        #endregion

    }

}
