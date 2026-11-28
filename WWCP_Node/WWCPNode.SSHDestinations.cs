/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP_Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// SSH that goes elsewhere than this node's own shell, SFTP and subsystems:
    /// destinations of a kind's own that an account reaches through this node with
    /// <c>ssh -J</c>, and this node's SSH server served over a connection it opens
    /// itself.
    /// </summary>
    public partial class WWCPNode
    {

        #region SSHServerIsRunning

        /// <summary>
        /// Whether the SSH server of this node is running now.
        /// </summary>
        public Boolean SSHServerIsRunning
            => sshServer is not null;

        #endregion

        #region ConnectSSHOut(WebSocket, CancellationToken = default)

        /// <summary>
        /// Serve this node's SSH server over a WebSocket this node opens itself -
        /// SSH over WebSocket, where nothing reaches this node from outside: the
        /// same host key, sign-ins, access rules, limits and audit as on its port.
        /// Returns once that connection has ended.
        /// </summary>
        /// <param name="WebSocket">The WebSocket client to connect out with.</param>
        /// <param name="CancellationToken">Ends the connection.</param>
        /// <exception cref="InvalidOperationException">The SSH server of this node is not running.</exception>
        public Task ConnectSSHOut(SshWebSocketClient  WebSocket,
                                  CancellationToken   CancellationToken   = default)

            => sshServer is SshServer server
                   ? server.ConnectOut(WebSocket, CancellationToken)
                   : throw new InvalidOperationException($"The SSH server of this {Kind.Name} is not running.");

        #endregion


        #region (protected virtual) SSHDestinationFor(Session, Host, Port, CancellationToken)

        /// <summary>
        /// A destination of this kind's own that the given session asks to reach
        /// through this node with <c>ssh -J</c> or <c>ssh -W</c> - a charging station
        /// behind its tunnel, say: how to serve it, or null where the host is none of
        /// this kind's. What it throws refuses the channel, and says why. None by
        /// default: this node forwards no ports, so a destination answered null for
        /// is refused.
        /// </summary>
        /// <param name="Session">Who signed in.</param>
        /// <param name="Host">The host asked for, as the client named it.</param>
        /// <param name="Port">The port asked for.</param>
        /// <param name="CancellationToken">Fires after five seconds, or when the connection ends.</param>
        protected virtual ValueTask<SshDestinationHandler?> SSHDestinationFor(SshSessionInfo     Session,
                                                                              String             Host,
                                                                              IPPort             Port,
                                                                              CancellationToken  CancellationToken)

            => ValueTask.FromResult<SshDestinationHandler?>(null);

        #endregion

        #region (protected) WhySSHAccountMayNot(Session, Needed, What, Service)

        /// <summary>
        /// Why the given session may not do what needs the given permission, or null
        /// where it may: an account of this node that holds it, signed in still, and
        /// let through by the access rules for the given service. A login a kind adds -
        /// a station's, say - is no account, and may not.
        /// </summary>
        /// <param name="Session">Who signed in.</param>
        /// <param name="Needed">What it takes.</param>
        /// <param name="What">What it is, for the reason: "a tunnel to 'CP001'".</param>
        /// <param name="Service">The service the access rules are asked for: "destination:CP001".</param>
        protected String? WhySSHAccountMayNot(SshSessionInfo  Session,
                                              Permission      Needed,
                                              String          What,
                                              String          Service)
        {

            try
            {

                if (sshAuthenticator is not NodeSSHAuthenticator authenticator)
                    return $"the SSH server of this {Kind.Name} is not running";

                if (authenticator.WhyNoLongerIn(Session) is String notIn)
                    return notIn;

                if (SSHSignInsOf(Session) is ISSHSignIns signIns)
                    return $"the {signIns.PrincipalKind} '{Session.Username}' is no account of this {Kind.Name}, and may not open {What}";

                if (!ExtAPI.TryGetUser(Session.Username, out var account) || account is null)
                    return $"there is no account '{Session.Username}' on this {Kind.Name}";

                if (!IsAllowed(account, [ Needed ]))
                    return $"'{account.Id}' may not open {What}: that takes {Needed}";

                return SSHAccessRefusal(Session, Service);

            }
            catch (Exception problem)
            {
                // What can not be asked is not a pass.
                return $"whether '{Session.Username}' may open {What} could not be asked: {problem.Message}";
            }

        }

        #endregion

    }

}
