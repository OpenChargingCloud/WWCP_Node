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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// The SSH keys of an account: listed, let in, and taken out.
    /// </summary>
    /// <remarks>
    /// <para>
    /// sshKeys [&lt;account&gt;] lists them; sshKeys [&lt;account&gt;] add
    /// &lt;authorized_keys line&gt; lets a key in - with its options, from= and
    /// expiry-time= among them, which hold as in OpenSSH's authorized_keys - and
    /// sshKeys [&lt;account&gt;] remove &lt;fingerprint&gt; takes one out: nobody
    /// signs in with it from that moment on. A fingerprint may be written as
    /// OpenSSH writes it, "SHA256:...", or by enough of its beginning to be
    /// only one key's.
    /// </para>
    /// <para>
    /// Over SSH the account may be left out, and is then the one signed in. The
    /// keys of another account are managed by whoever the HTTPExt API lets act
    /// for it - as its routes below /ext do for the same keys. The console names
    /// the account, and may do everything.
    /// </para>
    /// <para>
    /// Every key let in or taken out is written down twice: in the database of
    /// the accounts, with who did it, as a link of its hash chain; and in the
    /// log, as the web interface writes what somebody did there.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class SSHKeysCommand(NodeCLI CLI) : ACLICommand<NodeCLI>(CLI),
                                               ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "sshKeys";

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
                {

                    // The console has no account of its own: without one named,
                    // every account's keys - and an add or remove needs a name.
                    if (rest.Length == 0)
                        return EveryAccountsKeys();

                    return [ $"At the console, name the account: {Help()}" ];

                }

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
                    return await Add(account, String.Join(" ", rest[1..]));

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

            => $"{CommandName} [<account>] [add <authorized_keys line> | remove <fingerprint>] - the SSH keys an account signs in with";

        #endregion


        #region (private) Listed(Account)

        private String[] Listed(IUser Account)
        {

            var keys = cli.Node.ExtAPI.GetSSHKeys(Account.Id);

            if (keys.Count == 0)
                return [ $"'{Account.Id}' has no SSH key." ];

            return [ .. keys.Select(Line) ];

        }

        private String[] EveryAccountsKeys()
        {

            var lines = new List<String>();

            foreach (var name in cli.Node.AccountsWithSSHKeys())
            {
                lines.Add($"{name}:");
                lines.AddRange(cli.Node.ExtAPI.GetSSHKeys(User_Id.Parse(name)).Select(key => "  " + Line(key)));
            }

            return lines.Count > 0
                       ? [ .. lines ]
                       : [ $"No account of this {cli.Node.Kind.Name} has an SSH key." ];

        }

        /// <summary>
        /// One key, as a line: its fingerprint, when and by whom it was let in,
        /// the options in front of it, and what it is called.
        /// </summary>
        private static String Line(UserSSHKey Key)
        {

            var options  = Key.Key.Options.Count > 0
                               ? "  " + String.Join(",", Key.Key.Options)
                               : "";

            var called   = Key.Label ?? (Key.Key.PublicKey.Comment is { Length: > 0 } comment ? comment : null);

            return $"{Key.Fingerprint}  {Key.Created.ToLocalTime():yyyy-MM-dd HH:mm}" +
                   (Key.CreatedBy is not null ? $" by {Key.CreatedBy}" : "") +
                   options +
                   (Key.IsDisabled ? ", switched off" : "") +
                   (called is not null ? $"  {called}" : "");

        }

        #endregion

        #region (private) Add(Account, Line)

        private async Task<String[]> Add(IUser   Account,
                                         String  Line)
        {

            if (Line.Trim().Length == 0)
                return [ $"Usage: {Help()}" ];

            var added = await cli.Node.ExtAPI.AddSSHKey(Account,
                                                       Line,
                                                       CurrentUserId:  cli.Caller.Account?.Id,
                                                       CreatedBy:      cli.Caller.Account is null ? "the console" : null);

            switch (added.Outcome)
            {

                case AddSSHKeyOutcome.Added:

                    cli.Node.Log.Notice(
                        $"{cli.Caller.Asker} let '{Account.Id}' in over SSH with the key {added.SSHKey!.Fingerprint}.",
                        cli.Caller.Tags("ssh", "auth", "security")
                    );

                    return [ $"'{Account.Id}' signs in with the key {added.SSHKey.Fingerprint} now." ];

                case AddSSHKeyOutcome.AlreadyThere:
                    return [ $"'{Account.Id}' has the key {added.SSHKey!.Fingerprint} already." ];

                default:
                    return [ $"The key was not let in: {added.Reason}" ];

            }

        }

        #endregion

        #region (private) Remove(Account, Fingerprint)

        private async Task<String[]> Remove(IUser   Account,
                                            String  Fingerprint)
        {

            var wanted   = UserSSHKey.FingerprintFromURL(Fingerprint)["SHA256:".Length..];
            var matching = cli.Node.ExtAPI.GetSSHKeys(Account.Id).
                               Where(key => key.Fingerprint["SHA256:".Length..].StartsWith(wanted, StringComparison.Ordinal)).
                               ToArray();

            if (matching.Length == 0)
                return [ $"'{Account.Id}' has no key {Fingerprint}." ];

            if (matching.Length > 1 && !matching.Any(key => key.Fingerprint == "SHA256:" + wanted))
                return [ $"'{Fingerprint}' is the beginning of {matching.Length} keys of '{Account.Id}': {String.Join(", ", matching.Select(key => key.Fingerprint))}." ];

            var key = matching.FirstOrDefault(key => key.Fingerprint == "SHA256:" + wanted) ?? matching[0];

            if (!await cli.Node.ExtAPI.RemoveSSHKey(Account.Id, key.Fingerprint, CurrentUserId: cli.Caller.Account?.Id))
                return [ $"'{Account.Id}' has no key {key.Fingerprint} any more." ];

            cli.Node.Log.Notice(
                $"{cli.Caller.Asker} took the key {key.Fingerprint} from '{Account.Id}': it lets nobody in from now on.",
                cli.Caller.Tags("ssh", "auth", "security")
            );

            return [ $"The key {key.Fingerprint} lets '{Account.Id}' in no more." ];

        }

        #endregion

        #region (private static) IsVerb(Word)

        private static Boolean IsVerb(String Word)

            => Word.Equals("add",    StringComparison.OrdinalIgnoreCase) ||
               Word.Equals("remove", StringComparison.OrdinalIgnoreCase);

        #endregion

    }

}
