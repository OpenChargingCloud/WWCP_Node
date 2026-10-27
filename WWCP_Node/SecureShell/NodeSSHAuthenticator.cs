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

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// Who may sign in to a node over SSH: an account of the node, under its
    /// name, with one of its keys - or its password, where the node says so.
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
    /// moment on.
    /// </para>
    /// <para>
    /// A password opens nothing unless the node says it may, and never an
    /// account that signs in to the web interface with a second factor: SSH
    /// would be the way around it.
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
        /// "publickey", and "password" where the node says so.
        /// </summary>
        public IReadOnlyList<String> OfferedMethods { get; }

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

            this.OfferedMethods = Passwords
                                      ? [ "publickey", "password" ]
                                      : [ "publickey" ];

        }

        #endregion


        #region AuthorizePublicKeyAsync(Request, CancellationToken)

        /// <inheritdoc />
        public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest  Request,
                                                          CancellationToken        CancellationToken = default)

            => ValueTask.FromResult(
                   AccountMaySignIn(Request.Username) is IUser user &&
                   node.ExtAPI.FindSSHKey(user.Id, Request.PublicKeyBlob, node.TimeProvider.GetUtcNow()) is not null
               );

        #endregion

        #region GetRestrictionsAsync(Request, CancellationToken)

        /// <summary>
        /// What the authorized_keys line of the key that let the account in
        /// confines the session to: where it may come from, and whether it gets
        /// a terminal.
        /// </summary>
        public ValueTask<SshSessionRestrictions> GetRestrictionsAsync(SshPublicKeyAuthRequest  Request,
                                                                      CancellationToken        CancellationToken = default)

            => ValueTask.FromResult(
                   (User_Id.TryParse(Request.Username) is User_Id userId
                        ? node.ExtAPI.FindSSHKey(userId, Request.PublicKeyBlob, node.TimeProvider.GetUtcNow())?.Key.Restrictions
                        : null)
                       ?? SshSessionRestrictions.None
               );

        #endregion

        #region AuthorizePasswordAsync(Username, Password, CancellationToken)

        /// <summary>
        /// Whether the given password opens the given account, guessed from an
        /// address nobody said: counted against the one ration of every such guess.
        /// </summary>
        public ValueTask<Boolean> AuthorizePasswordAsync(String             Username,
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
        public async ValueTask<Boolean> AuthorizePasswordAsync(String                 Username,
                                                               String                 Password,
                                                               System.Net.IPAddress?  Client,
                                                               CancellationToken      CancellationToken = default)
        {

            if (!passwords)
                return false;

            var user = AccountMaySignIn(Username);

            return await node.ExtAPI.VerifySignInPassword(
                             Client,
                             Username,
                             user is not null && user.Use2AuthFactor == Use2AuthFactor.None
                                 ? user.Id
                                 : null,
                             Password,
                             CancellationToken
                         );

        }

        #endregion


        #region (private) AccountMaySignIn(Username)

        /// <summary>
        /// The account the given name signs in as, where it may sign in at all:
        /// it is there, it is not switched off, and it holds a role of this node.
        /// </summary>
        private IUser? AccountMaySignIn(String Username)
        {

            if (!AuthorizedKeysStore.IsAccountName(Username) ||
                User_Id.TryParse(Username) is not User_Id userId ||
                !node.ExtAPI.TryGetUser(userId, out var user) ||
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
