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
using org.GraphDefined.Vanaheimr.Illias;

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
        Boolean                Knows(User_Id Username);

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
        /// Whether these logins can sign in with a one-time password bound to the SSH session
        /// (<c>totp@open.charging.cloud</c>, white paper "SSH Authentication Extensions for OCPP"): the
        /// node offers the method where a kind says so, and not otherwise. Default: no.
        /// </summary>
        Boolean                TakesSessionBoundTotp

            => false;

        /// <summary>
        /// Whether the given one-time password lets the given login in, in the connection with the given
        /// exporter material - checked with <see cref="SshSessionBoundTotp.Verify"/> against the secret the
        /// kind keeps for the login. A login let in so is confined as one a key let in. Default: no.
        /// </summary>
        /// <remarks>
        /// A one-time password that is not bound to the session is a password, and opens a login of a
        /// kind only as its password does - see <see cref="AuthorizePasswordAsync"/>.
        /// </remarks>
        /// <param name="Username">The login name, as the client sent it.</param>
        /// <param name="Totp">The one-time password as it was sent.</param>
        /// <param name="Binding">The exporter material of the connection it has to be bound with (<see cref="SshSessionBoundTotp.BindingOf"/>).</param>
        /// <param name="Client">The address of the client, or null where it can not be told.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        ValueTask<Boolean>     AuthorizeSessionBoundTotpAsync(User_Id                Username,
                                                              String                 Totp,
                                                              ReadOnlyMemory<Byte>   Binding,
                                                              System.Net.IPAddress?  Client,
                                                              CancellationToken      CancellationToken = default)

            => ValueTask.FromResult(false);

        /// <summary>
        /// Whether these logins can sign in with a password: the node offers the method "password"
        /// where a kind says so, as it does where its accounts may. Default: no.
        /// </summary>
        Boolean                TakesPasswords

            => false;

        /// <summary>
        /// Whether the given password lets the given login in now. A login let in so is confined as one
        /// a key let in. Default: no.
        /// </summary>
        /// <remarks>
        /// The password goes through the encrypted SSH connection, to the server whose host key the
        /// client checked - as a password over TLS does. A kind decides, as it does on its other doors,
        /// whether a login may use one.
        /// </remarks>
        /// <param name="Username">The login name, as the client sent it.</param>
        /// <param name="Password">The password as it was sent.</param>
        /// <param name="Client">The address of the client, or null where it can not be told.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        ValueTask<Boolean>     AuthorizePasswordAsync(User_Id                Username,
                                                      String                 Password,
                                                      System.Net.IPAddress?  Client,
                                                      CancellationToken      CancellationToken = default)

            => ValueTask.FromResult(false);

        /// <summary>
        /// The subsystems the given login may use, by name - and nothing else is served to it. Empty
        /// where it may use none, which leaves it nothing to do once in.
        /// </summary>
        /// <param name="Username">The login name.</param>
        IReadOnlySet<String>   SubsystemsFor(User_Id Username);

        /// <summary>
        /// The groups the given login is in, as the access rules' "group:" matches them - a station's
        /// login group, say.
        /// </summary>
        /// <param name="Username">The login name.</param>
        IReadOnlyList<String>  GroupsOf(User_Id Username);

        /// <summary>
        /// Why the given session may not go on - the login gone or switched off, the key it came with
        /// taken out, the secret of the one-time password it came with (no key, and the method
        /// <c>totp@open.charging.cloud</c>) changed, the password it came with (the method
        /// <c>password</c>) changed - or null where it may. Asked before every subsystem and every few seconds while a
        /// session lasts.
        /// </summary>
        /// <param name="Session">The session, as it signed in.</param>
        String?                WhyNoLongerIn(SshSessionInfo Session);

    }

}
