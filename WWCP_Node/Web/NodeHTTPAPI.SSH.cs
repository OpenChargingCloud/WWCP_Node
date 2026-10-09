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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The part of the JSON API that is about the SSH server the command line
    /// is served over.
    /// </summary>
    public partial class NodeHTTPAPI
    {

        #region (private) RegisterSSHRoutes()

        private void RegisterSSHRoutes()
        {

            AddHandler(HTTPPath.Root + "v1/configuration/ssh",  GetSSHConfiguration,  HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/ssh",  PutSSHConfiguration,  HTTPMethod.PUT);

        }

        #endregion


        #region (private) GetSSHConfiguration(Request) / PutSSHConfiguration(Request)

        /// <summary>
        /// GET /api/v1/configuration/ssh: the SSH server - whether it runs,
        /// where, its host key, what it offers, who is connected, and which
        /// keys every account may sign in with.
        /// </summary>
        private Task<HTTPResponse> GetSSHConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.SSH), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.SSHConfigurationJSON(Request.Host.Name))
                   );

        }

        /// <summary>
        /// PUT /api/v1/configuration/ssh with {"enabled", "port", "passwords"}:
        /// save them and make them at once. Answers with the SSH server as it
        /// now stands, and a "notice" where a switch on the command line wins
        /// over what was saved.
        /// </summary>
        /// <remarks>
        /// A port that is taken is a 409, and the server goes on where it was;
        /// who changed it is in the log, as for every other setting.
        /// </remarks>
        private async Task<HTTPResponse> PutSSHConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.SSH), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var change = await Node.TryUpdateSSHConfiguration(json);

            if (!change.IsChanged)
                return NotChanged(Request,
                                  change.PortTaken ? HTTPStatusCode.Conflict : HTTPStatusCode.BadRequest,
                                  change.Error ?? "The SSH server was not changed.",
                                  change.NotSaved);

            Log.Notice($"'{user.Id}' changed the SSH server of this {Node.Kind.Name}: {(Node.SSHEnabled ? $"on port {Node.SSHPort}{(Node.SSHPasswords ? ", passwords open it" : ", keys alone")}" : "off")}.",
                       "ssh", "web", "security");

            var answer = Node.SSHConfigurationJSON(Request.Host.Name);

            if (change.Notice is String notice)
                answer.Add("notice", notice);

            return JSONResponse(Request, HTTPStatusCode.OK, answer);

        }

        #endregion

    }

}
