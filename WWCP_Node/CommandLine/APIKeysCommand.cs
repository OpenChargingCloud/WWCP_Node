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

using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The API keys of an account: listed, made, and taken back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// apiKeys [&lt;account&gt;] lists them; apiKeys [&lt;account&gt;] add
    /// [readOnly | readWrite] [&lt;description&gt;] makes one - read-only unless
    /// it is said otherwise - and apiKeys [&lt;account&gt;] remove &lt;key&gt;
    /// takes one back: nobody is signed in with it from that moment on.
    /// </para>
    /// <para>
    /// An API key is its own secret: whoever has it is signed in as its
    /// account. So a list shows only the beginning of each key, enough to tell
    /// them apart and to name one to remove; the whole key is shown once, when
    /// it is made, and never again.
    /// </para>
    /// <para>
    /// Whose keys are whose to manage is decided as for the SSH keys: an
    /// account its own, another's where the HTTPExt API lets it act for it, and
    /// the console everybody's.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class APIKeysCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                               ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const   String  CommandName  = "apiKeys";

        /// <summary>
        /// How much of a key a list shows.
        /// </summary>
        public const   Int32   Shown        = 8;

        /// <summary>
        /// How long a key made here is: 40 characters of 62, some 238 bits.
        /// </summary>
        public const   Int32   KeyLength    = 40;

        private const  String  KeyCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                           : [];

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            var rest = Arguments.Skip(1).ToArray();

            #region Whose keys

            IUser? account;

            if (rest.Length == 0 || IsVerb(rest[0]))
            {

                if (cli.Caller.Account is not { } own)
                    return [ $"At the console, name the account: {Help()}" ];

                account = own;

            }

            else
            {

                if (User_Id.TryParse(rest[0]) is not User_Id userId ||
                    !cli.Node.ExtAPI.TryGetUser(userId, out account) ||
                    account is null)
                {
                    return [ $"'{rest[0]}' is no account of this {cli.Node.Kind.Name}." ];
                }

                rest = rest[1..];

            }

            if (!cli.MayActFor(account, CommandName, out var refused))
                return [ refused ];

            #endregion

            if (rest.Length == 0)
                return Listed(account);

            switch (rest[0].ToLowerInvariant())
            {

                case "add":
                    return await Add(account, rest[1..]);

                case "remove":
                    return rest.Length == 2
                               ? await Remove(account, rest[1])
                               : [ $"Usage: {Help()}" ];

                default:
                    return [ $"Usage: {Help()}" ];

            }

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [<account>] [add [readOnly | readWrite] [<description>] | remove <key>] - the API keys of an account";

        #endregion


        #region (private) Listed(Account)

        private String[] Listed(IUser Account)
        {

            var keys = cli.Node.ExtAPI.GetAPIKeysForUser(Account).
                           OrderBy(key => key.Created).
                           ToArray();

            if (keys.Length == 0)
                return [ $"'{Account.Id}' has no API key." ];

            return [ .. keys.Select(key => $"{Beginning(key)}  {key.AccessRights}" +
                                           $"  made {key.Created.ToLocalTime():yyyy-MM-dd HH:mm}" +
                                           (key.NotAfter.HasValue ? $", valid until {key.NotAfter.Value.ToLocalTime():yyyy-MM-dd HH:mm}" : "") +
                                           (key.IsDisabled ? ", switched off" : "") +
                                           (key.Description.IsNotNullOrEmpty() ? $"  {key.Description.FirstText()}" : "")) ];

        }

        private static String Beginning(APIKey Key)
        {
            var text = Key.Id.ToString();
            return text.Length > Shown ? text[..Shown] + "..." : text;
        }

        #endregion

        #region (private) Add(Account, Words)

        private async Task<String[]> Add(IUser     Account,
                                         String[]  Words)
        {

            var rights = APIKeyRights.ReadOnly;

            if (Words.Length > 0 && Enum.TryParse<APIKeyRights>(Words[0], ignoreCase: true, out var said) &&
                said is APIKeyRights.ReadOnly or APIKeyRights.ReadWrite)
            {
                rights = said;
                Words  = Words[1..];
            }

            var description = String.Join(" ", Words).Trim();
            var secret      = RandomNumberGenerator.GetString(KeyCharacters, KeyLength);

            var added = await cli.Node.ExtAPI.AddAPIKey(
                                  new APIKey(APIKey_Id.Parse(secret),
                                             Account.Id,
                                             Description:   description.Length > 0 ? I18NString.Create(description) : null,
                                             AccessRights:  rights,
                                             Created:       Timestamp.Now),
                                  CurrentUserId: cli.Caller.Account?.Id
                              );

            if (added.Result != CommandResult.Success)
                return [ $"No API key was made: {added.Description?.FirstText() ?? added.Result.ToString()}" ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} gave '{Account.Id}' the API key {secret[..Shown]}... ({rights}).",
                cli.Caller.Tags("api", "auth", "security")
            );

            return [
                $"'{Account.Id}' has a new API key, {rights}. It is shown here once, and never again:",
                secret
            ];

        }

        #endregion

        #region (private) Remove(Account, Key)

        private async Task<String[]> Remove(IUser   Account,
                                            String  Key)
        {

            var matching = cli.Node.ExtAPI.GetAPIKeysForUser(Account).
                               Where(key => key.Id.ToString().StartsWith(Key.TrimEnd('.'), StringComparison.Ordinal)).
                               ToArray();

            if (matching.Length == 0)
                return [ $"'{Account.Id}' has no API key that begins with '{Key}'." ];

            if (matching.Length > 1)
                return [ $"'{Key}' is the beginning of {matching.Length} API keys of '{Account.Id}': give more of it." ];

            var removed = await cli.Node.ExtAPI.RemoveAPIKey(matching[0], CurrentUserId: cli.Caller.Account?.Id);

            if (removed.Result != CommandResult.Success)
                return [ $"The API key {Beginning(matching[0])} was not taken back: {removed.Description?.FirstText() ?? removed.Result.ToString()}" ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} took the API key {Beginning(matching[0])} from '{Account.Id}': nobody is signed in with it from now on.",
                cli.Caller.Tags("api", "auth", "security")
            );

            return [ $"The API key {Beginning(matching[0])} signs '{Account.Id}' in no more." ];

        }

        #endregion

        #region (private static) IsVerb(Word)

        private static Boolean IsVerb(String Word)

            => Word.Equals("add",    StringComparison.OrdinalIgnoreCase) ||
               Word.Equals("remove", StringComparison.OrdinalIgnoreCase);

        #endregion

    }

}
