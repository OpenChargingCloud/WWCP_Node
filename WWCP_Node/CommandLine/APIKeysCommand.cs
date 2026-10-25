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
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
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
    /// [readOnly | readWrite] [key &lt;key&gt;] [from &lt;address&gt;[,&lt;address&gt;]]
    /// [&lt;description&gt;] makes one - read-only unless it is said otherwise,
    /// the key given or else made here, opening the door from anywhere unless
    /// it is bound to addresses - and apiKeys [&lt;account&gt;] remove &lt;key&gt;
    /// takes one back: nobody is signed in with it from that moment on.
    /// </para>
    /// <para>
    /// A key bound to addresses opens the door only from them, as the HTTPExt
    /// API compares them: one by one, so no network, and without a zone.
    /// Behind a reverse proxy it is the client the "web" section of the
    /// configuration file believes the proxy about.
    /// </para>
    /// <para>
    /// An API key is a secret the account shares with its programs, and the
    /// list shows each whole: it is shown to the account itself, or to whoever
    /// may act for it. The log, which others read, names a key by its
    /// beginning only.
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
        /// How much of a key the log shows.
        /// </summary>
        public const   Int32   ShownInTheLog  = 8;

        /// <summary>
        /// How long a key made here is: 40 characters of 62, some 238 bits.
        /// </summary>
        public const   Int32   KeyLength    = 40;

        private const  String  KeyCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        /// <summary>
        /// The characters a key given may have besides letters and digits:
        /// with them, it goes into an API-Key header and into the path of
        /// .../APIKeys/{key} as it is.
        /// </summary>
        public const   String  OtherKeyCharacters = "._~-";

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

            => $"{CommandName} [<account>] [add [readOnly | readWrite] [key <key>] [from <address>[,<address>]] [<description>] | remove <key>] - the API keys of an account";

        #endregion


        #region (private) Listed(Account)

        private String[] Listed(IUser Account)
        {

            var keys = cli.Node.ExtAPI.GetAPIKeysForUser(Account).
                           OrderBy(key => key.Created).
                           ToArray();

            if (keys.Length == 0)
                return [ $"'{Account.Id}' has no API key." ];

            return [ .. keys.Select(key => $"{key.Id}  {key.AccessRights}" +
                                           $"  made {key.Created.ToLocalTime():yyyy-MM-dd HH:mm}" +
                                           (key.NotAfter.HasValue ? $", valid until {key.NotAfter.Value.ToLocalTime():yyyy-MM-dd HH:mm}" : "") +
                                           OnlyFrom(key.ValidRemoteIPAddresses) +
                                           (key.IsDisabled ? ", switched off" : "") +
                                           (key.Description.IsNotNullOrEmpty() ? $"  {key.Description.FirstText()}" : "")) ];

        }

        private static String ForTheLog(APIKey Key)
        {
            var text = Key.Id.ToString();
            return text.Length > ShownInTheLog ? text[..ShownInTheLog] + "..." : text;
        }

        /// <summary>
        /// ", only from 192.0.2.7, 2001:db8::7" for a key bound to addresses, nothing for one that is not.
        /// </summary>
        private static String OnlyFrom(IEnumerable<IIPAddress> Addresses)

            => Addresses.Any()
                   ? $", only from {String.Join(", ", Addresses.Select(Shown))}"
                   : "";

        /// <summary>
        /// An address as people write it: Hermod writes an IPv6 address with
        /// every one of its zeros, and some in brackets - "2001:0db8:0000:...",
        /// "[::1]" - where 2001:db8::7 and ::1 are what was typed.
        /// </summary>
        private static String Shown(IIPAddress Address)
        {
            var text = Address.ToString() ?? "";
            return System.Net.IPAddress.TryParse(text.Trim('[', ']'), out var parsed)
                       ? parsed.ToString()
                       : text;
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

            String?            given  = null;
            List<IIPAddress>?  from   = null;

            // "key" and "from", each at most once and in either order, before
            // the description - which may say "key" or "from" itself further on.
            while (Words.Length > 0)
            {

                if (given is null && Words[0].Equals("key", StringComparison.OrdinalIgnoreCase))
                {

                    if (Words.Length < 2)
                        return [ $"Usage: {Help()}" ];

                    given = Words[1];
                    Words = Words[2..];

                    if (!given.All(c => Char.IsAsciiLetterOrDigit(c) || OtherKeyCharacters.Contains(c)))
                        return [ $"No API key was made: an API key is letters, digits and {String.Join(" ", OtherKeyCharacters.ToCharArray())} only." ];

                    if (given.Length < cli.Node.ExtAPI.MinAPIKeyLength)
                        return [ $"No API key was made: an API key has at least {cli.Node.ExtAPI.MinAPIKeyLength} characters; this one has {given.Length}." ];

                }

                else if (from is null && Words[0].Equals("from", StringComparison.OrdinalIgnoreCase))
                {

                    if (Words.Length < 2)
                        return [ $"Usage: {Help()}" ];

                    if (!TryParseAddresses(Words[1], out from, out var problem))
                        return [ $"No API key was made: {problem}" ];

                    Words = Words[2..];

                }

                else
                    break;

            }

            var description = String.Join(" ", Words).Trim();
            var secret      = given ?? RandomNumberGenerator.GetString(KeyCharacters, KeyLength);

            var added = await cli.Node.ExtAPI.AddAPIKey(
                                  new APIKey(APIKey_Id.Parse(secret),
                                             Account.Id,
                                             Description:   description.Length > 0 ? I18NString.Create(description) : null,
                                             AccessRights:  rights,
                                             Created:       Timestamp.Now,
                                             ValidRemoteIPAddresses:  from),
                                  CurrentUserId: cli.Caller.Account?.Id
                              );

            if (added.Result != CommandResult.Success)
                return [ $"No API key was made: {added.Description?.FirstText() ?? added.Result.ToString()}" ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} gave '{Account.Id}' the API key {secret[..ShownInTheLog]}... ({rights}{OnlyFrom(from ?? [])}).",
                cli.Caller.Tags("api", "auth", "security")
            );

            return [
                $"'{Account.Id}' has a new API key, {rights}{OnlyFrom(from ?? [])}:",
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
                return [ $"The API key {matching[0].Id} was not taken back: {removed.Description?.FirstText() ?? removed.Result.ToString()}" ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} took the API key {ForTheLog(matching[0])} from '{Account.Id}': nobody is signed in with it from now on.",
                cli.Caller.Tags("api", "auth", "security")
            );

            return [ $"The API key {matching[0].Id} signs '{Account.Id}' in no more." ];

        }

        #endregion

        #region (static) TryParseAddresses(Text, out Addresses, out Problem)

        /// <summary>
        /// The addresses an API key is to be bound to, separated by commas,
        /// each once - or what is wrong with one of them, as the account page
        /// says it.
        /// </summary>
        /// <remarks>
        /// Addresses one by one, as the HTTPExt API compares them: a network
        /// would never be matched, and a zone is left out of the comparison.
        /// Hermod's IPAddress.TryParse takes an IPv4 address in its four parts
        /// only - not "192.7", which System.Net's takes for 192.0.0.7.
        /// </remarks>
        public static Boolean TryParseAddresses(String                                      Text,
                                                [NotNullWhen(true)]  out List<IIPAddress>?  Addresses,
                                                [NotNullWhen(false)] out String?            Problem)
        {

            Addresses  = [];
            Problem    = null;

            foreach (var address in Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {

                if (address.Contains('/'))
                    Problem = $"'{address}' is a network; an API key is bound to addresses, one by one.";

                else if (address.Contains('%'))
                    Problem = $"'{address}' names a zone; an API key is bound to the address without it.";

                else if (!IPAddress.TryParse(address, out var bound))
                    Problem = $"'{address}' is no IP address.";

                else
                {
                    if (!Addresses.Contains(bound))
                        Addresses.Add(bound);
                    continue;
                }

                Addresses = null;
                return false;

            }

            if (Addresses.Count == 0)
            {
                Addresses  = null;
                Problem    = "'from' names no address.";
                return false;
            }

            return true;

        }

        #endregion

        #region (private static) IsVerb(Word)

        private static Boolean IsVerb(String Word)

            => Word.Equals("add",    StringComparison.OrdinalIgnoreCase) ||
               Word.Equals("remove", StringComparison.OrdinalIgnoreCase);

        #endregion

    }

}
