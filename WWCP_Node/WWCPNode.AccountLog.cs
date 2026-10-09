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

using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What is changed of an account on the web interface - on its own page,
    /// through the HTTPExt API's routes below /ext/users/{UserId} - in the
    /// log, as the command line's sshKeys and apiKeys say what they change:
    /// who changed what of which account, tagged "web" where the command line
    /// says "cli". The routes are Hermod's and say nothing to this log; what
    /// they answered is read here, from the responses this node's HTTP server
    /// sends, so that only what was done is said, and nothing twice - the
    /// command line does not go through HTTP.
    /// </summary>
    /// <remarks>
    /// An API key is the account to whoever has it: neither these lines nor
    /// the line every request writes say more of one than its beginning, as
    /// a list shows it.
    /// </remarks>
    public partial class WWCPNode
    {

        #region Data

        /// <summary>
        /// How much of an API key the log says: as much as a list shows.
        /// </summary>
        public const Int32 APIKeyShownInTheLog = 8;

        /// <summary>
        /// An account as it was when a request to save it came in, to say
        /// what the save changed once it is answered.
        /// </summary>
        private readonly ConditionalWeakTable<HTTPRequest, JObject> accountsBeforeSaving = [];

        /// <summary>
        /// An API key in a path: what follows "/APIKeys/".
        /// </summary>
        private static readonly Regex APIKeyInAPath = new ("(/APIKeys/)([^/?#]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>
        /// What the log calls the fields of an account; one not named here is
        /// called what the JSON calls it.
        /// </summary>
        private static readonly Dictionary<String, String> AccountFieldNames = new () {
            [ "name"          ] = "name",
            [ "description"   ] = "description",
            [ "email"         ] = "e-mail address",
            [ "telephone"     ] = "telephone",
            [ "mobilePhone"   ] = "mobile phone",
            [ "homepage"      ] = "homepage",
            [ "telegram"      ] = "Telegram",
            [ "language"      ] = "language",
            [ "privacyLevel"  ] = "privacy level",
            [ "isDisabled"    ] = "whether it is switched off"
        };

        /// <summary>
        /// What an account's JSON has that is no field of it to change.
        /// </summary>
        private static readonly HashSet<String> NotAccountFields = [ "@id", "@context", "lastChange", "createdAt", "lastLoginAt", "youCanEdit" ];

        #endregion


        #region (static) PathForTheLog(Path)

        /// <summary>
        /// A request's path as the log may say it: an API key in it cut to its
        /// beginning.
        /// </summary>
        /// <param name="Path">A request's path.</param>
        public static String PathForTheLog(String Path)

            => APIKeyInAPath.Replace(Path, match => match.Groups[1].Value + BeginningOfAnAPIKey(Uri.UnescapeDataString(match.Groups[2].Value)));

        #endregion

        #region (static) BeginningOfAnAPIKey(Key)

        /// <summary>
        /// The beginning of an API key, as a list shows it.
        /// </summary>
        public static String BeginningOfAnAPIKey(String Key)

            => Key.Length > APIKeyShownInTheLog
                   ? Key[..APIKeyShownInTheLog] + "..."
                   : Key;

        #endregion


        #region (private) AccountRequest(Request)

        /// <summary>
        /// What a request to the HTTPExt API does to an account, where it does:
        /// the account's id and the rest of the path below it - "", "password",
        /// "APIKeys", "APIKeys/{key}", "SSHKeys" or "SSHKeys/{fingerprint}".
        /// </summary>
        private (String Account, String[] Below)? AccountRequest(HTTPRequest Request)
        {

            if (Request.HTTPMethod != HTTPMethod.SET &&
                Request.HTTPMethod != HTTPMethod.ADD &&
                Request.HTTPMethod != HTTPMethod.DELETE)
            {
                return null;
            }

            var below = ExtAPI.RootPath.ToString().TrimEnd('/') + "/users/";
            var path  = Request.Path.ToString();

            if (!ReferenceEquals(ExtAPI.HTTPServer, HTTPServer) ||
                !path.StartsWith(below, StringComparison.Ordinal))
            {
                return null;
            }

            var segments = path[below.Length..].Split('/', StringSplitOptions.RemoveEmptyEntries);

            if (segments.Length == 0 || segments.Length > 3)
                return null;

            return (Uri.UnescapeDataString(segments[0]), segments[1..]);

        }

        #endregion

        #region (private) BeforeAccountChange(Request)

        /// <summary>
        /// Keep the account a SET of it is about to change, to say afterwards
        /// what changed.
        /// </summary>
        private void BeforeAccountChange(HTTPRequest Request)
        {

            if (Request.HTTPMethod == HTTPMethod.SET &&
                AccountRequest(Request) is { Below.Length: 0 } account &&
                User_Id.TryParse(account.Account) is User_Id userId &&
                ExtAPI.TryGetUser(userId, out var user) &&
                user is not null)
            {
                accountsBeforeSaving.AddOrUpdate(Request, user.ToJSON());
            }

        }

        #endregion

        #region (private) AfterAccountChange(Request, Response)

        /// <summary>
        /// Say in the log what a request that was answered 200 changed of an
        /// account: its details, an API key or an SSH key.
        /// </summary>
        private void AfterAccountChange(HTTPRequest   Request,
                                        HTTPResponse  Response)
        {

            if (Response.HTTPStatusCode.Code != 200 ||
                AccountRequest(Request) is not { } account)
            {
                return;
            }

            var who      = ExtAPI.TryGetHTTPUser(Request, out var asker) && asker is not null
                               ? $"'{asker.Id}'"
                               : "Somebody";

            var whose    = asker?.Id.ToString() == account.Account
                               ? "their account"
                               : $"the account '{account.Account}'";

            JObject? answer = null;

            try
            {
                answer = Response.HTTPBodyAsJSONObject;
            }
            catch (Exception)
            { }

            switch (account.Below)
            {

                case []:

                    accountsBeforeSaving.TryGetValue(Request, out var before);
                    accountsBeforeSaving.Remove(Request);

                    // The account as it is kept now, written as it was written
                    // before: read back from the answer, a date in it would be
                    // a date where it was a text, and say it changed.
                    var changed = ChangedFields(before,
                                                User_Id.TryParse(account.Account) is User_Id savedId &&
                                                ExtAPI.TryGetUser(savedId, out var saved) && saved is not null
                                                    ? saved.ToJSON()
                                                    : null);

                    Log.Notice(
                        changed.Count > 0
                            ? $"{who} changed {whose} on the web interface: {String.Join(", ", changed)}."
                            : $"{who} saved {whose} on the web interface, changing nothing.",
                        "auth", "web"
                    );

                    return;

                // Only the account itself may, and only with its current
                // password: answered 200, it was the account. Nothing of
                // what was sent is said.
                case [ "password" ] when Request.HTTPMethod == HTTPMethod.SET:

                    Log.Notice(
                        asker is null || asker.Id.ToString() == account.Account
                            ? $"'{account.Account}' changed their password on the web interface."
                            : $"{who} changed the password of '{account.Account}' on the web interface.",
                        "auth", "security", "web"
                    );

                    return;

                case [ "APIKeys" ] when Request.HTTPMethod == HTTPMethod.ADD:

                    Log.Notice(
                        $"{who} gave '{account.Account}' the API key {BeginningOfAnAPIKey(answer?["@id"]?.Value<String>() ?? "")} " +
                        $"({answer?["accessRights"]?.Value<String>() ?? "readOnly"}) on the web interface.",
                        "api", "auth", "security", "web"
                    );

                    return;

                case [ "APIKeys", var key ] when Request.HTTPMethod == HTTPMethod.SET:

                    Log.Notice(
                        answer?["isDisabled"]?.Value<Boolean>() == true
                            ? $"{who} switched off the API key {BeginningOfAnAPIKey(Uri.UnescapeDataString(key))} of '{account.Account}' on the web interface: it opens nothing until it is switched on again."
                            : $"{who} switched on the API key {BeginningOfAnAPIKey(Uri.UnescapeDataString(key))} of '{account.Account}' on the web interface: it opens the door again.",
                        "api", "auth", "security", "web"
                    );

                    return;

                case [ "APIKeys", var key ] when Request.HTTPMethod == HTTPMethod.DELETE:

                    Log.Notice(
                        $"{who} took the API key {BeginningOfAnAPIKey(Uri.UnescapeDataString(key))} from '{account.Account}' on the web interface: it opens nothing from now on.",
                        "api", "auth", "security", "web"
                    );

                    return;

                case [ "SSHKeys" ] when Request.HTTPMethod == HTTPMethod.ADD:

                    Log.Notice(
                        $"{who} let '{account.Account}' in over SSH with the key {answer?["fingerprint"]?.Value<String>()} on the web interface.",
                        "ssh", "auth", "security", "web"
                    );

                    return;

                case [ "SSHKeys", _ ] when Request.HTTPMethod == HTTPMethod.SET:

                    Log.Notice(
                        answer?["isDisabled"]?.Value<Boolean>() == true
                            ? $"{who} switched off the key {answer?["fingerprint"]?.Value<String>()} of '{account.Account}' on the web interface: it lets nobody in until it is switched on again."
                            : $"{who} switched on the key {answer?["fingerprint"]?.Value<String>()} of '{account.Account}' on the web interface: it lets '{account.Account}' in again.",
                        "ssh", "auth", "security", "web"
                    );

                    return;

                case [ "SSHKeys", _ ] when Request.HTTPMethod == HTTPMethod.DELETE:

                    Log.Notice(
                        $"{who} took the key {answer?["fingerprint"]?.Value<String>()} from '{account.Account}' on the web interface: it lets nobody in from now on.",
                        "ssh", "auth", "security", "web"
                    );

                    return;

            }

        }

        #endregion

        #region (private static) ChangedFields(Before, After)

        /// <summary>
        /// The fields of an account that are not what they were, as the log
        /// calls them, in the order of the account's JSON.
        /// </summary>
        private static List<String> ChangedFields(JObject?  Before,
                                                  JObject?  After)
        {

            if (Before is null || After is null)
                return [];

            return [ .. Before.Properties().Select(property => property.Name).
                            Union(After.Properties().Select(property => property.Name)).
                            Where (name => !NotAccountFields.Contains(name)).
                            Where (name => !JToken.DeepEquals(Before[name], After[name])).
                            Select(name => AccountFieldNames.TryGetValue(name, out var called) ? called : name) ];

        }

        #endregion

    }

}
