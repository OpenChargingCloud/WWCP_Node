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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.CommandLine
{

    /// <summary>
    /// Who is typing at a command line: whoever is at the node's own console,
    /// or an account signed in over SSH.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The console of the process is whoever started it, and has the process:
    /// it may do everything, and the node cannot tell who it is - which is why
    /// what it asks for is written down as asked by "somebody at the command
    /// line". Over SSH it is an account, signed in with a key of its own, and
    /// may do what its roles let it do on the web interface: the same question,
    /// asked of the same node, with the same answer.
    /// </para>
    /// <para>
    /// The log says it as the web interface says it: the account by its name,
    /// and the door it came through as a tag - "web" there, "cli" here, and
    /// "ssh" beside it for a command line that is not the console's.
    /// </para>
    /// </remarks>
    public sealed class CLICaller
    {

        #region Properties

        /// <summary>
        /// Whoever is at the node's own console.
        /// </summary>
        public static CLICaller  Console     { get; } = new ();

        /// <summary>
        /// The account signed in over SSH; null at the console.
        /// </summary>
        public IUser?            Account     { get; }

        /// <summary>
        /// The SSH session it signed in with - from where, with which key; null at the console.
        /// </summary>
        public SshSessionInfo?   Session     { get; }

        /// <summary>
        /// Whether this is the node's own console.
        /// </summary>
        public Boolean           AtTheConsole
            => Account is null;

        /// <summary>
        /// Who asked, as the log's sentences begin: "Somebody at the command
        /// line", or "'root' at the command line over SSH".
        /// </summary>
        public String            Asker
            => Account is null
                   ? "Somebody at the command line"
                   : $"'{Account.Id}' at the command line over SSH";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The given account, signed in over SSH in the given session.
        /// </summary>
        /// <param name="Account">The account.</param>
        /// <param name="Session">The SSH session.</param>
        public CLICaller(IUser           Account,
                         SshSessionInfo  Session)
        {
            this.Account  = Account;
            this.Session  = Session;
        }

        /// <summary>
        /// Whoever is at the node's console.
        /// </summary>
        private CLICaller()
        { }

        #endregion


        #region Tags(Before)

        /// <summary>
        /// The tags of a log entry about something asked at this command line:
        /// those given, "cli", and "ssh" where it is not the console.
        /// </summary>
        /// <param name="Before">What the entry is about: "nts", "test", ...</param>
        public String[] Tags(params String[] Before)

            => Account is null
                   ? [ .. Before, "cli" ]
                   : [ .. Before, "cli", "ssh" ];

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Account is null
                   ? "the console"
                   : $"'{Account.Id}' from {Session?.Peer?.ToString() ?? "somewhere"}";

        #endregion

    }

}
