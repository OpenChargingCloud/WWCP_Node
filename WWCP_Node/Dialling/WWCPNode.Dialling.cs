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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node
{

    /// <summary>
    /// What a node dials, and the keys it signs in with where it gets there:
    /// its connections over WebSockets and over SSH. A node that dials
    /// sets its connection store when it is made; one that does not has none.
    /// </summary>
    public partial class WWCPNode
    {

        #region Data

        // The trust each connection over SSH was dialled with last: what its
        // server showed, and where a signed pin set puts its pins at once.
        protected readonly ConcurrentDictionary<String, SshHostKeyTrust>  sshTrusts  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// The places this node dials, and the credentials it proves itself
        /// with when it gets there.
        /// </summary>
        public ConnectionStore         Connections           { get; protected set; } = default!;

        /// <summary>
        /// The key this node signs in with when it dials an ssh://
        /// connection - made the first time one needs it.
        /// </summary>
        public SshClientKey            SshKey                { get; protected set; } = default!;

        private SshClientKeys? sshKeys;

        /// <summary>
        /// Every key this node signs in with over SSH: its own, and the ones
        /// somebody made beside it - for one server and not the next, or to
        /// follow another at a time its server was told.
        /// </summary>
        public SshClientKeys           SshKeys
        {
            get
            {

                if (sshKeys is SshClientKeys kept)
                    return kept;

                var keys = new SshClientKeys(SshKey,
                                             $"This {NodeWording.Noun}'s own key",
                                             SshKey.Comment,
                                             TimeProvider);

                keys.OnNotice += (level, message) => Log.Log(level, message, "ocpp", "connections", "ssh", "security");

                if (Interlocked.CompareExchange(ref sshKeys, keys, null) is SshClientKeys before)
                    return before;

                // What an ssh:// connection may name, asked whenever one is
                // written down: a key removed next door is gone from it too.
                Connections.KnownSshKeyIds ??= () => keys.Ids;

                return keys;

            }
        }

        #endregion

        #region (internal) SshSecurityEvent(Connection, Type, TechInfo)

        /// <summary>
        /// Report a security event of the white paper "OCPP over SSH" (section 9.4) through the networking node
        /// of the connection's version - or of every one, where it is the node's own.
        /// </summary>
        public void SshSecurityEvent(ConnectionEntry?  Connection,
                                       String            Type,
                                       String            TechInfo)
        {

            try
            {

                if (Connection is null || Connection.OCPPVersion == OCPPVersion.OCPP2_1)
                    QueueSecurityEvent(OCPPVersion.OCPP2_1, Type, TechInfo.Length > 255 ? TechInfo[..255] : TechInfo);

                if (Connection is null || Connection.OCPPVersion == OCPPVersion.OCPP1_6)
                    QueueSecurityEvent(OCPPVersion.OCPP1_6, Type, TechInfo.Length > 255 ? TechInfo[..255] : TechInfo);

            }
            catch (Exception e)
            {
                Log.Warning($"The security event '{Type}' could not be queued: {e.Message}", "ocpp", "ssh", "security");
            }

        }

        #endregion

    }

}
