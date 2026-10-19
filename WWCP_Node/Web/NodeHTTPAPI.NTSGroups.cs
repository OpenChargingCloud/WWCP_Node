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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Web
{

    /// <summary>
    /// The groups of time servers, one by one: listed, made, read, changed,
    /// asked and tested, and taken away.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Below /api/v1/configuration/nts/groups, each group at its name. The
    /// routes from before there were groups - /nts, /nts/sync, /nts/test - are
    /// the legal group's, answer as they always did, and say 404 where the node
    /// has no legal group.
    /// </para>
    /// <para>
    /// At the permissions of the NTS client: reading at read, making, changing
    /// and taking away at edit, asking and testing at run. Who did it is in the
    /// log, as for every other change of the time source.
    /// </para>
    /// </remarks>
    public partial class NodeHTTPAPI
    {

        #region (private) RegisterNTSGroupRoutes()

        private void RegisterNTSGroupRoutes()
        {

            var groups = HTTPPath.Root + "v1/configuration/nts/groups";

            AddHandler(groups,                 GetNTSGroups,       HTTPMethod.GET);
            AddHandler(groups,                 PostNTSGroup,       HTTPMethod.POST);
            AddHandler(groups + "/{id}",       GetNTSGroup,        HTTPMethod.GET);
            AddHandler(groups + "/{id}",       PutNTSGroup,        HTTPMethod.PUT);
            AddHandler(groups + "/{id}",       DeleteNTSGroup,     HTTPMethod.DELETE);
            AddHandler(groups + "/{id}/sync",  PostNTSGroupSync,   HTTPMethod.POST);
            AddHandler(groups + "/{id}/test",  PostNTSGroupTest,   HTTPMethod.POST);

        }

        #endregion


        #region (private) GetNTSGroups(Request) / PostNTSGroup(Request)

        /// <summary>
        /// GET /api/v1/configuration/nts/groups: every group of time servers,
        /// and the names a page may suggest for one more.
        /// </summary>
        private Task<HTTPResponse> GetNTSGroups(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.NTS), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.NTSGroupsJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/configuration/nts/groups with {"id"} and an optional
        /// {"displayName"}: make a group, switched off and naming no server.
        /// </summary>
        /// <remarks>
        /// 201 with the group as GET answers for it; 409 where the node has a
        /// group of that name already, 400 for a name that cannot be a group's
        /// or a display name in no language, and 500 where only the file
        /// refused.
        /// </remarks>
        private Task<HTTPResponse> PostNTSGroup(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.NTS), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (json["id"] is not JValue { Type: JTokenType.String } idToken)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'id' must be the name of the group, e.g. \"local\"."));

            var id = idToken.Value<String>()!.Trim();

            if (Node.NTSGroupOf(id) is not null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, $"This {Node.Kind.Name} has an NTS group '{id}' already."));

            if (!NTSConfiguration.TryReadDisplayName(json, NTSSection.IsGroupId(id) ? NTSSection.PathOf(id) : $"{NTSConfiguration.SectionName}.{NTSSection.GroupsKey}", out var displayName, out var nameError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, nameError));

            if (!Node.TryAddNTSGroup(id, displayName, out var group, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request,
                                                  Node.NTSGroupOf(id) is not null ? HTTPStatusCode.Conflict : HTTPStatusCode.BadRequest,
                                                  error,
                                                  notSaved));

            Log.Notice($"'{user.Id}' added the NTS group '{id}' to this {Node.Kind.Name}.", "nts", "config", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.Created, Node.NTSConfigurationJSON(group))
                   );

        }

        #endregion

        #region (private) GetNTSGroup(Request) / PutNTSGroup(Request) / DeleteNTSGroup(Request)

        /// <summary>
        /// GET /api/v1/configuration/nts/groups/{id}: where a group gets the
        /// time from - as /nts says it of the legal group.
        /// </summary>
        private Task<HTTPResponse> GetNTSGroup(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.NTS), false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryGetNTSGroup(Request, GroupIdOf(Request), out var group, out var notFound))
                return Task.FromResult(notFound);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, Node.NTSConfigurationJSON(group))
                   );

        }

        /// <summary>
        /// PUT /api/v1/configuration/nts/groups/{id}: change what may be
        /// changed about a group, switching it on and off among it.
        /// </summary>
        private Task<HTTPResponse> PutNTSGroup(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.NTS), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetNTSGroup(Request, GroupIdOf(Request), out var group, out var notFound))
                return Task.FromResult(notFound);

            return Task.FromResult(ChangeNTSGroup(Request, user, group));

        }

        /// <summary>
        /// DELETE /api/v1/configuration/nts/groups/{id}: take a group away,
        /// while it is switched off.
        /// </summary>
        /// <remarks>
        /// 200 with every group that is left, as GET /groups answers; 409 while
        /// the group is switched on, and 500 where only the file refused. It
        /// answers once everything that ran for the group has ended.
        /// </remarks>
        private async Task<HTTPResponse> DeleteNTSGroup(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.NTS), true, out var user, out var refused))
                return refused;

            if (!TryGetNTSGroup(Request, GroupIdOf(Request), out var group, out var notFound))
                return notFound;

            var (removed, error, notSaved) = await Node.TryRemoveNTSGroupAsync(group.Id);

            if (!removed)
                return NotChanged(Request,
                                  Node.NTSGroupOf(group.Id) is NTSGroup still && still.Enabled ? HTTPStatusCode.Conflict
                                      : Node.NTSGroupOf(group.Id) is null                    ? HTTPStatusCode.NotFound
                                      : HTTPStatusCode.BadRequest,
                                  error ?? "Nothing was changed.",
                                  notSaved);

            Log.Notice($"'{user.Id}' removed the NTS group '{group.Id}' from this {Node.Kind.Name}.", "nts", "config", "web");

            return JSONResponse(Request, HTTPStatusCode.OK, Node.NTSGroupsJSON());

        }

        #endregion

        #region (private) PostNTSGroupSync(Request) / PostNTSGroupTest(Request)

        /// <summary>
        /// POST /api/v1/configuration/nts/groups/{id}/sync: ask a group what
        /// the time is - as /nts/sync asks the legal group.
        /// </summary>
        private async Task<HTTPResponse> PostNTSGroupSync(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run (NodeResources.NTS), true, out var user, out var refused))
                return refused;

            if (!TryGetNTSGroup(Request, GroupIdOf(Request), out var group, out var notFound))
                return notFound;

            return await SyncNTSGroup(Request, user, group);

        }

        /// <summary>
        /// POST /api/v1/configuration/nts/groups/{id}/test with an optional
        /// {"host"}: ask one time server of a group everything there is to ask
        /// - as /nts/test asks one of the legal group.
        /// </summary>
        private async Task<HTTPResponse> PostNTSGroupTest(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run (NodeResources.NTS), true, out var user, out var refused))
                return refused;

            if (!TryGetNTSGroup(Request, GroupIdOf(Request), out var group, out var notFound))
                return notFound;

            return await TestNTSGroup(Request, user, group);

        }

        #endregion


        #region (private) ChangeNTSGroup(Request, User, Group)

        /// <summary>
        /// What changing a group is, by whichever route: the body put into
        /// effect, and the group as it then stands.
        /// </summary>
        private HTTPResponse ChangeNTSGroup(HTTPRequest  Request,
                                            IUser        User,
                                            NTSGroup     Group)
        {

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (!Node.TryUpdateNTSConfiguration(Group, json, out var error, out var notSaved))
                return NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved);

            Log.Notice(Group.IsLegal
                           ? $"'{User.Id}' changed the time source of this {Node.Kind.Name}."
                           : $"'{User.Id}' changed the NTS group '{Group.Id}' of this {Node.Kind.Name}.",
                       "nts", "web");

            return JSONResponse(Request, HTTPStatusCode.OK, Node.NTSConfigurationJSON(Group));

        }

        #endregion

        #region (private) SyncNTSGroup(Request, User, Group)

        /// <summary>
        /// What asking a group is, by whichever route.
        /// </summary>
        /// <remarks>
        /// Answers with the whole group and not only with the result, because
        /// an exchange moves the cookie pool, the key material and the record of
        /// the last exchange - all of which the page is showing while it waits.
        /// </remarks>
        private async Task<HTTPResponse> SyncNTSGroup(HTTPRequest  Request,
                                                      IUser        User,
                                                      NTSGroup     Group)
        {

            // A notice rather than information: a request about the clock that
            // everything this node writes down is stamped with wants somebody's
            // attention - the energy meter's users asked for it, and it is the
            // same request on every kind.
            Log.Notice(Group.IsLegal
                           ? $"'{User.Id}' asked this {Node.Kind.Name} to synchronise its time."
                           : $"'{User.Id}' asked this {Node.Kind.Name} to check its time against the NTS group '{Group.Id}'.",
                       "nts", "test", "web");

            var result     = await Node.SyncTimeAsync(Group, Request.CancellationToken);

            var json       = Node.NTSConfigurationJSON(Group);

            json["result"] = result;

            return JSONResponse(Request, HTTPStatusCode.OK, json);

        }

        #endregion

        #region (private) TestNTSGroup(Request, User, Group)

        /// <summary>
        /// What testing one server of a group is, by whichever route.
        /// </summary>
        /// <remarks>
        /// The host is optional and names the server to ask; left out, or
        /// empty, it is the one the group's client was made for. A host that is
        /// not a string is refused here, rather than thrown out of as a 500.
        /// </remarks>
        private async Task<HTTPResponse> TestNTSGroup(HTTPRequest  Request,
                                                      IUser        User,
                                                      NTSGroup     Group)
        {

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (json["host"] is JToken hostToken && hostToken.Type is not (JTokenType.String or JTokenType.Null))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "'host' must be the name or the address of a time server.");

            var host = json.Value<String>("host")?.Trim();

            if (host?.Length == 0)
                host = null;

            Log.Info($"'{User.Id}' asked this {Node.Kind.Name} to test {(host is null ? "its time server" : $"the time server '{host}'")}" +
                     (Group.IsLegal ? "." : $" of the NTS group '{Group.Id}'."),
                     "nts", "test", "web");

            return JSONResponse(
                       Request,
                       HTTPStatusCode.OK,
                       await Node.TestTimeServerAsync(Group, host, Request.CancellationToken)
                   );

        }

        #endregion

        #region (private) TryGetNTSGroup(Request, Id, out Group, out NotFound)

        /// <summary>
        /// The group of the given name, or the 404 that says this node has none.
        /// </summary>
        private Boolean TryGetNTSGroup(HTTPRequest                             Request,
                                       String                                  Id,
                                       [NotNullWhen(true)]  out NTSGroup?      Group,
                                       [NotNullWhen(false)] out HTTPResponse?  NotFound)
        {

            Group     = Node.NTSGroupOf(Id);
            NotFound  = Group is null
                            ? ErrorJSON(Request, HTTPStatusCode.NotFound, $"This {Node.Kind.Name} has no NTS group '{Id}'.")
                            : null;

            return Group is not null;

        }

        #endregion

        #region (private static) GroupIdOf(Request)

        /// <summary>
        /// The name of the group out of the request's path, as it was written:
        /// a group's name is in lower case, and one asked for otherwise is not
        /// that group.
        /// </summary>
        private static String GroupIdOf(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? Request.ParsedURLParameters[0].Trim()
                   : "";

        #endregion

    }

}
