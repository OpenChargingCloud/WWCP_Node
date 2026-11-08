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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// The SSH access rules: who may sign in over SSH from where and to where, and use what - restricting
    /// what the node lets in anyway, and never more than that.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rules are the "ssh" section's "accessRules" - see <see cref="SSHAccessRules"/>. They are asked
    /// three times: once a client has signed in (<see cref="SSHAccessRules.ForSignIn"/>, with the address
    /// it came from and the address of this node it came to); before every service it asks for - the
    /// command line ("shell"), SFTP ("sftp"), a subsystem a kind serves ("subsystem:&lt;name&gt;"); and
    /// every few seconds while a session lasts, so that rules changed end the sessions they now refuse.
    /// </para>
    /// <para>
    /// A client refused is told no more than "not permitted": the rule that refused it is in the log, and
    /// for whoever may read the rules, not for whoever ran into them.
    /// </para>
    /// </remarks>
    public partial class WWCPNode
    {

        #region SSHAccessRules

        /// <summary>
        /// The SSH access rules in effect: the "ssh" section's, as it stands.
        /// </summary>
        public SSHAccessRules SSHAccessRules
            => sshFile?.AccessRules ?? SSHAccessRules.None;

        #endregion

        #region (protected virtual) SSHPrincipalOf(Session)

        /// <summary>
        /// Who a session is, as the rules see it: an account of the node, with its roles as its groups -
        /// or one of the logins a kind of node lets in besides (a local controller its charging stations,
        /// see <see cref="AddSSHSignIns"/>), with the groups the kind says.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        protected virtual SSHPrincipal SSHPrincipalOf(SshSessionInfo Session)
        {

            if (SSHSignInsOf(Session) is ISSHSignIns signIns)
            {

                IReadOnlyList<String> groups;

                try
                {
                    groups = signIns.GroupsOf(Session.Username);
                }
                catch (Exception)
                {
                    groups = [];
                }

                return new SSHPrincipal(signIns.PrincipalKind, Session.Username, groups);

            }

            return User_Id.TryParse(Session.Username) is User_Id userId && ExtAPI.TryGetUser(userId, out var user) && user is not null
                       ? new SSHPrincipal(SSHPrincipal.Account, user.Id.ToString(), [ .. RolesOf(user).Select(role => role.Name) ])
                       : new SSHPrincipal("unknown", Session.Username, []);

        }

        #endregion

        #region SSHAccessFor(Session, Service)

        /// <summary>
        /// What the rules say of the given session, signing in (no service) or asking for a service.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        /// <param name="Service">"shell", "sftp", "subsystem:&lt;name&gt;" - or null, signing in.</param>
        public SSHAccessDecision SSHAccessFor(SshSessionInfo  Session,
                                              String?         Service)
        {

            var request = new SSHAccessRequest(SSHPrincipalOf(Session),
                                               Service,
                                               Session.Peer ?.IPAddress.ToDotNet(),
                                               Session.Local?.IPAddress.ToDotNet(),
                                               Session.Method);

            return SSHAccessRules.For(request);

        }

        #endregion

        #region SSHAccessRefusal(Session, Service)

        /// <summary>
        /// Why the rules refuse the given session, signing in or asking for the given service - or null
        /// where they do not.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        /// <param name="Service">"shell", "sftp", "subsystem:&lt;name&gt;" - or null, signing in.</param>
        public String? SSHAccessRefusal(SshSessionInfo  Session,
                                        String?         Service)
        {

            var decision = SSHAccessFor(Session, Service);

            return decision.Allowed
                       ? null
                       : $"SSH access {decision} refuses {SSHPrincipalOf(Session)} " +
                         (Service is null ? "" : $"{Service} ") +
                         $"from {Session.Peer?.IPAddress.ToString() ?? "an address not known"} on {Session.Local?.IPAddress.ToString() ?? "an address not known"}";

        }

        #endregion

        #region (private) WhySSHSessionMayNotGoOn(Session, Service)

        /// <summary>
        /// Why a session open now may not go on - its account, role or key gone, or the rules refusing it
        /// now - or null where it may.
        /// </summary>
        private String? WhySSHSessionMayNotGoOn(SshSessionInfo  Session,
                                                String          Service)

            => sshAuthenticator?.WhyNoLongerIn(Session) ??
               SSHAccessRefusal(Session, Service);

        #endregion

        #region (private) AuthorizeSSHSession(Session, CancellationToken)

        /// <summary>
        /// Asked by the SSH server once a client has signed in: refused where the rules refuse it at the
        /// door, or where its kind has as many connections open as it may - and said in the log, which the
        /// server's audit then does not say again.
        /// </summary>
        private ValueTask<String?> AuthorizeSSHSession(SshSessionInfo     Session,
                                                       CancellationToken  CancellationToken)
        {

            // As whom it signed in, from here on - a name that is let in as nothing is refused.
            var refusal = RememberSSHSignIn(Session) ??
                          SSHAccessRefusal(Session, null);

            if (refusal is not null)
            {

                Log.Notice($"'{Session.Username}' signed in over SSH from {Session.Peer?.ToString() ?? "somewhere"}, and was refused: {refusal}.",
                           "ssh", "auth", "security");

                return ValueTask.FromResult<String?>(refusal);

            }

            // Counted in its kind until its connection closes - or refused, its kind full.
            var full = AdmitSSHConnection(Session, out var kind);

            if (full is not null)
                SayFullSSHKind(kind, Session, full);

            return ValueTask.FromResult(full);

        }

        #endregion

        #region TryUpdateSSHAccessRules(Rules)

        /// <summary>
        /// Replace the SSH access rules: saved in the "ssh" section of the configuration file, in effect
        /// at once - and every session open now asked again, so that one the new rules refuse ends now.
        /// </summary>
        /// <param name="Rules">The rules, in order.</param>
        public Task<SSHConfigurationChange> TryUpdateSSHAccessRules(SSHAccessRules Rules)

            => TryUpdateSSHConfiguration(new JObject { ["accessRules"] = Rules.ToJSON() });

        #endregion

    }

}
