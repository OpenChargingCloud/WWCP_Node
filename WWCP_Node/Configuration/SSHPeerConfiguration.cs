/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
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

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Configuration
{

    /// <summary>
    /// An SSH peer of the node, as the "ssh" section of the configuration file
    /// has it under "peers": a host the node keeps one SSH connection to, which
    /// everything that goes to that host over SSH and says "connection":
    /// "shared" is a channel of - the key exchange of a time server, name
    /// resolution, OCPP. An instance of SSHPeerController in the OCPP Device
    /// Model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// { "id", "address", "port", "user", "hostKeyPins", "hostCAs",
    /// "onMismatch" }: "id" and "address" always, and a host key or a CA it is
    /// held to - a peer nobody could believe is never stored. The rest is
    /// optional.
    /// </para>
    /// <para>
    /// A peer needs no OCPP: a node that speaks OCPP over a WebSocket, or none
    /// at all, has its time and its names over the connection to a peer all the
    /// same.
    /// </para>
    /// </remarks>
    /// <param name="Id">What the peer is called: the instance of SSHPeerController.</param>
    /// <param name="Address">Its host name or address, as the entries that share its connection name it.</param>
    /// <param name="User">The user name to sign in under, or null for the node's own.</param>
    /// <param name="Trust">Its port, and the host keys and CAs it is held to, with what a host key that is none of them comes to.</param>
    public sealed record SSHPeerConfiguration(String        Id,
                                              DomainName    Address,
                                              String?       User,
                                              NTSServerSSH  Trust)
    {

        #region Data

        /// <summary>
        /// How many SSH peers a node may have.
        /// </summary>
        public const Int32  MaxPeers     = 16;

        /// <summary>
        /// How long the name of a peer may be.
        /// </summary>
        public const Int32  MaxIdLength  = 32;

        private static readonly Regex  id        = new ("^[A-Za-z0-9][A-Za-z0-9._-]*$",        RegexOptions.CultureInvariant);
        private static readonly Regex  userName  = new ("^[A-Za-z0-9._][A-Za-z0-9._@-]*$",     RegexOptions.CultureInvariant);

        #endregion

        #region Properties

        /// <summary>
        /// The SSH port it is dialled at.
        /// </summary>
        public UInt16 Port
            => Trust.PortOrDefault;

        #endregion


        #region (static) TryParse(JSON, Path, out Peer, out Error)

        /// <summary>
        /// Read one entry of "peers".
        /// </summary>
        /// <param name="JSON">The entry.</param>
        /// <param name="Path">Where it is in the file: "ssh.peers[0]".</param>
        public static Boolean TryParse(JToken                                         JSON,
                                       String                                         Path,
                                       [NotNullWhen(true)]  out SSHPeerConfiguration?  Peer,
                                       [NotNullWhen(false)] out String?                Error)
        {

            Peer = null;

            if (JSON is not JObject json)
            {
                Error = $"'{Path}' must be an object: {{ \"id\", \"address\", \"port\", \"user\", \"hostKeyPins\", \"hostCAs\", \"onMismatch\" }}.";
                return false;
            }

            if (!ConfigurationReader.TryReadString(json, "id",      Path, MaxIdLength,                 out var name,    out Error) ||
                !ConfigurationReader.TryReadString(json, "address", Path, 253,                         out var address, out Error) ||
                !ConfigurationReader.TryReadString(json, "user",    Path, NTSServerSSH.MaxUserLength,  out var user,    out Error))
            {
                return false;
            }

            if (name is null || !id.IsMatch(name))
            {
                Error = $"'{Path}.id': {(name is null ? "a peer has a name" : $"'{name}' is no name of a peer")}: letters, digits, '.', '_' and '-', and at most {MaxIdLength} of them.";
                return false;
            }

            if (address is null || !DomainName.TryParse(address.Trim(), out var host, out var problem) || host is null)
            {
                Error = $"'{Path}.address': {(address is null ? "a peer has a host name or an address" : $"'{address}' is no host name or address")}.";
                return false;
            }

            if (user is not null && !userName.IsMatch(user))
            {
                Error = $"'{Path}.user': '{user}' is no user name: letters, digits, '.', '_', '-' and '@', and at most {NTSServerSSH.MaxUserLength} of them.";
                return false;
            }

            // What a peer is held to is read as a time server's "ssh" is: the
            // same pins, the same CAs, the same words.
            var trust = new JObject();

            foreach (var key in new[] { "port", "hostKeyPins", "hostCAs", "onMismatch" })
                if (json[key] is JToken value && value.Type != JTokenType.Null)
                    trust[key] = value;

            if (!NTSServerSSH.TryParse(trust, Path, out var held, out Error))
                return false;

            if (!held.IsPinned)
            {
                Error = $"'{Path}': the peer '{name}' is held to no host key and no CA: say which in \"hostKeyPins\" or \"hostCAs\". A peer nobody could believe is never stored.";
                return false;
            }

            Peer = new SSHPeerConfiguration(name, host, user, held);

            return true;

        }

        #endregion

        #region (static) TryParseAll(JSON, Path, out Peers, out Error)

        /// <summary>
        /// Read "peers": a list of entries, each name and each address once.
        /// </summary>
        public static Boolean TryParseAll(JToken                                                        JSON,
                                          String                                                        Path,
                                          [NotNullWhen(true)]  out IReadOnlyList<SSHPeerConfiguration>?  Peers,
                                          [NotNullWhen(false)] out String?                               Error)
        {

            Peers = null;

            if (JSON is not JArray array)
            {
                Error = $"'{Path}' must be a list of SSH peers.";
                return false;
            }

            if (array.Count > MaxPeers)
            {
                Error = $"'{Path}' names {array.Count} SSH peers, and a node may have {MaxPeers}.";
                return false;
            }

            var peers = new List<SSHPeerConfiguration>();

            for (var i = 0; i < array.Count; i++)
            {

                if (!TryParse(array[i], $"{Path}[{i}]", out var peer, out Error))
                    return false;

                if (peers.Any(other => String.Equals(other.Id, peer.Id, StringComparison.OrdinalIgnoreCase)))
                {
                    Error = $"'{Path}[{i}].id': there is a peer '{peer.Id}' already.";
                    return false;
                }

                if (peers.FirstOrDefault(other => other.Address.Equals(peer.Address)) is SSHPeerConfiguration same)
                {
                    Error = $"'{Path}[{i}].address': {peer.Address.Trimmed} is the peer '{same.Id}' already, and a node keeps one connection to a host.";
                    return false;
                }

                peers.Add(peer);

            }

            Peers  = peers;
            Error  = null;

            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The entry as it is written to the file, with the usual left out.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("id",       Id),
                           new JProperty("address",  Address.Trimmed)
                       );

            if (User is not null)
                json.Add("user", User);

            foreach (var property in Trust.ToJSON().Properties())
                json.Add(property.Name, property.Value);

            return json;

        }

        #endregion

    }

}
