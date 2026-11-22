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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// Who may sign in to a node over SSH: an account of the node, under its
    /// name, with one of its keys - or its password, where the node says so;
    /// and the logins a kind of node lets in besides, with what the kind says
    /// (see <see cref="ISSHSignIns"/>), confined to their subsystems.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The accounts are the web interface's, and what an account may do once it
    /// is in is what its roles let it do there. So an account that is switched
    /// off is refused here as it is there, and so is an account that holds none
    /// of this node's roles: it could not do anything, and being let in to be
    /// refused everything is no way to be told so.
    /// </para>
    /// <para>
    /// Every question is asked again at every sign-in - the account, its roles,
    /// its keys, which the HTTPExt API keeps with it - and nothing is
    /// remembered between two of them: a key removed lets nobody in from that
    /// moment on. And asked again of a session while it lasts, see
    /// <see cref="WhyNoLongerIn(SshSessionInfo)"/>: an account switched off,
    /// or a key taken out, ends the sessions it let in, as it ends the
    /// account's sessions on the web interface.
    /// </para>
    /// <para>
    /// A password opens nothing unless the node says it may, and never an
    /// account that signs in to the web interface with a second factor: SSH
    /// would be the way around it.
    /// </para>
    /// <para>
    /// A one-time password bound to the session (totp@open.charging.cloud)
    /// opens the logins of a kind that says it takes one, and nothing else:
    /// no account, and no login of a kind that does not. Unbound, a one-time
    /// password is a password.
    /// </para>
    /// <para>
    /// A password opens a login of a kind where the kind says it takes
    /// passwords - asked of the kind, whatever the node says of its accounts -,
    /// and never an account then: a name is one or the other.
    /// </para>
    /// </remarks>
    public sealed class NodeSSHAuthenticator : ISshUserAuthenticator
    {

        #region Data

        private readonly WWCPNode  node;
        private readonly Boolean   passwords;

        #endregion

        #region Properties

        /// <summary>
        /// "publickey"; "totp@open.charging.cloud" where a kind lets logins in that sign in with a
        /// one-time password bound to the session; and "password" where the node says so of its
        /// accounts, or a kind of its logins. Asked at every attempt: a kind may add its logins while
        /// the server runs.
        /// </summary>
        public IReadOnlyList<String> OfferedMethods
        {
            get
            {

                var boundTotp      = false;
                var kindPasswords  = false;

                try
                {
                    boundTotp      = node.SSHSignIns.Any(signIns => signIns.TakesSessionBoundTotp);
                    kindPasswords  = node.SSHSignIns.Any(signIns => signIns.TakesPasswords);
                }
                catch (Exception)
                {
                    // What can not be told is not offered.
                }

                return (boundTotp, passwords || kindPasswords) switch {
                           (true,  true)  => [ "publickey", UserAuthentication.SessionBoundTotpMethod, "password" ],
                           (true,  false) => [ "publickey", UserAuthentication.SessionBoundTotpMethod ],
                           (false, true)  => [ "publickey", "password" ],
                           _              => [ "publickey" ]
                       };

            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Who may sign in to the given node, with the keys its accounts keep.
        /// </summary>
        /// <param name="Node">The node whose accounts these are.</param>
        /// <param name="Passwords">Whether an account's password opens it as well.</param>
        public NodeSSHAuthenticator(WWCPNode  Node,
                                    Boolean   Passwords)
        {

            this.node       = Node;
            this.passwords  = Passwords;

        }

        #endregion


        #region AuthorizePublicKeyAsync(Request, CancellationToken)

        /// <summary>
        /// Whether the given key lets the given name in: one of the account's keys - or, for a login a
        /// kind of node lets in besides (see <see cref="ISSHSignIns"/>), what the kind says. A name that
        /// is both is let in as neither.
        /// </summary>
        public async ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest  Request,
                                                                CancellationToken        CancellationToken = default)
        {

            var (signIns, clash) = node.SSHLoginOf(Request.Username);

            if (clash is not null)
            {
                node.WarnOfSSHClash(Request.Username, clash);
                return false;
            }

            if (signIns is not null)
                return await signIns.AuthorizePublicKeyAsync(Request, CancellationToken);

            return AccountMaySignIn(Request.Username) is IUser user &&
                   node.ExtAPI.FindSSHKey(user.Id, Request.PublicKeyBlob, node.TimeProvider.GetUtcNow()) is not null;

        }

        #endregion

        #region GetRestrictionsAsync(Request, CancellationToken)

        /// <summary>
        /// What the authorized_keys line of the key that let the account in
        /// confines the session to: where it may come from, and whether it gets
        /// a terminal. A login a kind of node lets in is confined besides to
        /// the subsystems it may use - no terminal, no forwarding, no command
        /// line, no SFTP - whatever the kind's own entry says.
        /// </summary>
        public async ValueTask<SshSessionRestrictions> GetRestrictionsAsync(SshPublicKeyAuthRequest  Request,
                                                                            CancellationToken        CancellationToken = default)
        {

            var (signIns, clash) = node.SSHLoginOf(Request.Username);

            // Not let in, and so not asked - but where it is: nothing at all.
            if (clash is not null)
                return WWCPNode.SSHConfinementOf(null, Request.Username);

            if (signIns is not null)
                return (await signIns.GetRestrictionsAsync(Request, CancellationToken)).
                           And(WWCPNode.SSHConfinementOf(signIns, Request.Username, node.GetsSftp(Request.Username)));

            return node.ExtAPI.FindSSHKey(Request.Username, Request.PublicKeyBlob, node.TimeProvider.GetUtcNow())?.Key.Restrictions
                       ?? SshSessionRestrictions.None;

        }

        #endregion

        #region AuthorizePasswordAsync(Username, Password, CancellationToken)

        /// <summary>
        /// Whether the given password opens the given account, guessed from an
        /// address nobody said: counted against the one ration of every such guess.
        /// </summary>
        public ValueTask<Boolean> AuthorizePasswordAsync(User_Id            Username,
                                                         String             Password,
                                                         CancellationToken  CancellationToken = default)

            => AuthorizePasswordAsync(Username, Password, null, CancellationToken);

        #endregion

        #region AuthorizePasswordAsync(Username, Password, Client, CancellationToken)

        /// <summary>
        /// Whether the given password opens the given account, guessed from the
        /// given address.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Asked as the web interface's sign-in asks it, and counted against the
        /// same ration of guesses, per client and per account, and with one of
        /// the HTTPExt API's few password verifiers - so that SSH is
        /// neither a faster way to guess a password nor a way to keep everybody's
        /// sign-in waiting. One ration for both doors rather than one each: both
        /// guess at the same password, and two rations would be twice the guesses.
        /// </para>
        /// <para>
        /// A name that opens nothing - no such account, one switched off or
        /// without a role here, one with a second factor - costs a hash all the
        /// same, so that how long the answer takes does not say which it is.
        /// </para>
        /// </remarks>
        /// <param name="Username">The account's name.</param>
        /// <param name="Password">The password guessed.</param>
        /// <param name="Client">The address of the client, or null where it can not be told.</param>
        /// <param name="CancellationToken">An optional token to cancel the wait for a password verifier.</param>
        public async ValueTask<Boolean> AuthorizePasswordAsync(User_Id                Username,
                                                               String                 Password,
                                                               System.Net.IPAddress?  Client,
                                                               CancellationToken      CancellationToken = default)
        {

            var (signIns, clash) = node.SSHLoginOf(Username);

            // A kind's login with its password, where the kind takes passwords: the kind decides -
            // braked by the node's sign-in brake, as at the station port.
            if (clash is null && signIns is not null && signIns.TakesPasswords)
                return await Braked(Client, () => signIns.AuthorizePasswordAsync(Username, Password, Client, CancellationToken));

            if (!passwords)
                return false;

            // A kind's login that takes no password opens with nothing here - and a name that is an
            // account and such a login as well, with nothing: neither costs less than a password that
            // opens nothing.
            var user = (signIns, clash) is (null, null)
                           ? AccountMaySignIn(Username)
                           : null;

            return await node.ExtAPI.VerifySignInPassword(
                             Client,
                             Username.ToString(),
                             user is not null && user.Use2AuthFactor == Use2AuthFactor.None
                                 ? user.Id
                                 : null,
                             Password,
                             CancellationToken
                         );

        }

        #endregion

        #region AuthorizeSessionBoundTotpAsync(Username, Totp, SessionId, Client, CancellationToken)

        /// <summary>
        /// Whether the given one-time password, bound to the session with the given identifier, lets
        /// the given name in: a login of a kind that takes one, as the kind says. No account - an
        /// account signs in with its keys, or its password where the node says so - and no name that
        /// is both.
        /// </summary>
        public async ValueTask<Boolean> AuthorizeSessionBoundTotpAsync(User_Id                Username,
                                                                       String                 Totp,
                                                                       ReadOnlyMemory<Byte>   SessionId,
                                                                       System.Net.IPAddress?  Client,
                                                                       CancellationToken      CancellationToken = default)
        {

            var (signIns, clash) = node.SSHLoginOf(Username);

            if (clash is not null)
            {
                node.WarnOfSSHClash(Username, clash);
                return false;
            }

            if (signIns is null || !signIns.TakesSessionBoundTotp)
                return false;

            // Braked by the node's sign-in brake, as at the station port.
            return await Braked(Client, () => signIns.AuthorizeSessionBoundTotpAsync(Username, Totp, SessionId, Client, CancellationToken));

        }

        #endregion

        #region (private) Braked(Client, Check)

        /// <summary>
        /// What a kind's login says to what was brought, behind the node's
        /// sign-in brake: an address that guessed too often is told no without
        /// a look, and what opens nothing is counted against it. An account is
        /// not braked here: its password is rationed with the sign-in of the
        /// web interface.
        /// </summary>
        private async ValueTask<Boolean> Braked(System.Net.IPAddress?     Client,
                                                Func<ValueTask<Boolean>>  Check)
        {

            if (node.SignInBrake.IsHeldBack(Client?.ToString()))
                return false;

            var opens = await Check();

            if (!opens)
                node.SignInBrake.CountFailed(Client?.ToString());

            return opens;

        }

        #endregion

        #region GetRestrictionsAsync(Username, Method, CancellationToken)

        /// <summary>
        /// What a session is confined to that no key let in: a login of a kind to the subsystems it may
        /// use - no terminal, no forwarding, no command line, no SFTP - as one a key let in; an account
        /// to nothing here, what it may do is what its roles say.
        /// </summary>
        public ValueTask<SshSessionRestrictions> GetRestrictionsAsync(User_Id            Username,
                                                                      String             Method,
                                                                      CancellationToken  CancellationToken = default)
        {

            var (signIns, clash) = node.SSHLoginOf(Username);

            return ValueTask.FromResult(
                       clash   is not null ? WWCPNode.SSHConfinementOf(null,    Username)
                     : signIns is not null ? WWCPNode.SSHConfinementOf(signIns, Username, node.GetsSftp(Username))
                     :                       SshSessionRestrictions.None
                   );

        }

        #endregion


        #region WhyNoLongerIn(Session)

        /// <summary>
        /// Why the given session may not go on, or null where it may: what let
        /// it in, asked again now - the account still there, not switched off
        /// and holding a role of this node, and the key it signed in with still
        /// one of the account's, switched on and valid; or, where its password
        /// let it in, a password still opening the account over SSH.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        public String? WhyNoLongerIn(SshSessionInfo Session)
        {

            var signedInAs        = node.SSHSignInsOf(Session);
            var (now, clash)      = node.SSHLoginOf(Session.Username);

            if (clash is not null)
                return clash;

            // One of the logins a kind lets in: still one of them, and still let in, as the kind says.
            if (signedInAs is not null)
            {

                if (!ReferenceEquals(now, signedInAs))
                    return $"'{Session.Username}' is no {signedInAs.PrincipalKind} of this {node.Kind.Name} any more";

                try
                {
                    return signedInAs.WhyNoLongerIn(Session);
                }
                catch (Exception problem)
                {
                    // What can not be asked is not a pass.
                    return $"whether the {signedInAs.PrincipalKind} '{Session.Username}' may go on could not be asked: {problem.Message}";
                }

            }

            // Signed in as an account, and the name is a kind's login now.
            if (now is not null)
                return $"'{Session.Username}' is a {now.PrincipalKind} of this {node.Kind.Name} now, and no account";

            if (!node.ExtAPI.TryGetUser(Session.Username, out var user) ||
                user is null)
            {
                return $"there is no account '{Session.Username}' any more";
            }

            if (user.IsDisabled)
                return $"the account '{user.Id}' was switched off";

            if (node.RolesOf(user).Count == 0)
                return $"the account '{user.Id}' holds no role of this {node.Kind.Name} any more";

            if (Session.PublicKeyBlob is Byte[] key)
                return node.ExtAPI.FindSSHKey(user.Id, key, node.TimeProvider.GetUtcNow()) is null
                           ? $"the key {Session.PublicKeyFingerprint} is no longer one '{user.Id}' signs in with - taken out, switched off or expired"
                           : null;

            return passwords && user.Use2AuthFactor == Use2AuthFactor.None
                       ? null
                       : $"a password no longer opens the account '{user.Id}' over SSH";

        }

        #endregion

        #region (private) AccountMaySignIn(Username)

        /// <summary>
        /// The account the given name signs in as, where it may sign in at all:
        /// it is there, it is not switched off, and it holds a role of this node.
        /// </summary>
        private IUser? AccountMaySignIn(User_Id Username)
        {

            if (!AuthorizedKeysStore.IsAccountName(Username.ToString()) ||
                !node.ExtAPI.TryGetUser(Username, out var user) ||
                user is null ||
                user.IsDisabled ||
                node.RolesOf(user).Count == 0)
            {
                return null;
            }

            return user;

        }

        #endregion

    }

}
