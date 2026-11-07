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

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// Who a kind of node lets sign in over SSH besides its accounts - a local controller its charging
    /// stations: under their own names, with their own keys, to the subsystems they may use and to
    /// nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Whatever a kind answers here, the node confines such a login: no terminal, no forwarding, and of
    /// the subsystems only those <see cref="SubsystemsFor"/> names - never the command line, never a
    /// command, never SFTP. A kind can narrow that with <see cref="GetRestrictionsAsync"/>, not widen it.
    /// </para>
    /// <para>
    /// A name that is an account of the node as well is let in as neither: which of the two a key was
    /// meant for is not for the node to guess. The log says so, at the start and at every attempt.
    /// </para>
    /// </remarks>
    public interface ISSHSignIns
    {

        /// <summary>
        /// What these logins are, as the access rules and the log write it: "station" for
        /// "station:cs001". Not "account", which the node's accounts are.
        /// </summary>
        String                 PrincipalKind     { get; }

        /// <summary>
        /// Whether the given name is one of these logins - let in or not, switched on or off: a name the
        /// node must not take for one of its accounts.
        /// </summary>
        /// <param name="Username">The login name, as the client sent it.</param>
        Boolean                Knows(String Username);

        /// <summary>
        /// Whether the given key lets the given login in now - asked before and after the signature is
        /// checked, as Hermod asks an authenticator.
        /// </summary>
        ValueTask<Boolean>     AuthorizePublicKeyAsync(SshPublicKeyAuthRequest  Request,
                                                       CancellationToken        CancellationToken = default);

        /// <summary>
        /// What the entry that let the key in confines the session to besides - its authorized_keys
        /// options, say. The node's own confinement applies in any case; this only narrows it.
        /// </summary>
        ValueTask<SshSessionRestrictions> GetRestrictionsAsync(SshPublicKeyAuthRequest  Request,
                                                               CancellationToken        CancellationToken = default)

            => ValueTask.FromResult(SshSessionRestrictions.None);

        /// <summary>
        /// The subsystems the given login may use, by name - and nothing else is served to it. Empty
        /// where it may use none, which leaves it nothing to do once in.
        /// </summary>
        /// <param name="Username">The login name.</param>
        IReadOnlySet<String>   SubsystemsFor(String Username);

        /// <summary>
        /// The groups the given login is in, as the access rules' "group:" matches them - a station's
        /// login group, say.
        /// </summary>
        /// <param name="Username">The login name.</param>
        IReadOnlyList<String>  GroupsOf(String Username);

        /// <summary>
        /// Why the given session may not go on - the login gone or switched off, the key it came with
        /// taken out - or null where it may. Asked before every subsystem and every few seconds while a
        /// session lasts.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        String?                WhyNoLongerIn(SshSessionInfo Session);

    }

}
