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

using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// The command line over SSH, as every kind of node has to serve it: to its
    /// first account, with a key of its own, as the console's command line -
    /// and nothing else.
    /// </summary>
    /// <remarks>
    /// Over the network and with Hermod's own client, as PuTTY or ssh would
    /// come: a host key to verify, a key to sign in with, a terminal asked for,
    /// keys typed and a screen read back.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region (private) SignInOverSSH() / ReadUntil(Shell, Received, What)

        /// <summary>
        /// The first account, let in with a key of its own, signed in.
        /// </summary>
        private async Task<SshClient> SignInOverSSH()
        {

            var key = SshHostKey.GenerateEd25519();

            var added = await Node.AuthorizeSSHKey(AdminLogin, SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine());

            Assert.That(added.IsAdded, Is.True, added.Reason);

            return await SshClient.ConnectAsync("127.0.0.1",
                                                Node.SSHPort!.Value.ToUInt16(),
                                                new SshClientOptions {
                                                    Username       = AdminLogin,
                                                    VerifyHostKey  = blob => Node.SSHHostKey == $"ssh-ed25519 {SshFingerprint.Sha256(blob)}",
                                                    Credentials    = [ key ]
                                                });

        }

        /// <summary>
        /// Read what the shell writes into the given builder until it holds the
        /// given text, for ten seconds at most.
        /// </summary>
        private static async Task ReadUntil(SshClientShell Shell, StringBuilder Received, String What)
        {

            using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var buffer       = new Byte[4096];

            try
            {
                while (!Received.ToString().Contains(What, StringComparison.Ordinal))
                {
                    var read = await Shell.Output.ReadAsync(buffer, cancel.Token);
                    if (read == 0)
                        break;
                    Received.Append(Encoding.UTF8.GetString(buffer, 0, read));
                }
            }
            catch (OperationCanceledException)
            { }

            Assert.That(Received.ToString(), Does.Contain(What), "the session never said it");

        }

        #endregion


        #region TheCommandLineIsServedOverSSHToAnAccountWithItsKey

        /// <summary>
        /// The first account signs in with a key of its own, is greeted as who it
        /// is, gets the node's prompt, and the node's commands answer it - as
        /// syncNTS does, which every node has.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SSH)]
        public async Task TheCommandLineIsServedOverSSHToAnAccountWithItsKey()
        {

            await using var client  = await SignInOverSSH();
            await using var shell   = await client.OpenShellAsync(new SshPty("xterm", new SshWindowSize(120, 40), new Dictionary<Byte, UInt32>()));

            var received            = new StringBuilder();

            await ReadUntil(shell, received, "> ");

            Assert.That(received.ToString(), Does.Contain($"signed in as '{AdminLogin}'"));

            await shell.WriteAsync("syncNTS nowhere.example\r");

            await ReadUntil(shell, received, $"is none of this {Node.Kind.Name}'s time servers");

        }

        #endregion

        #region QuitOverSSHLeavesTheNodeRunning

        /// <summary>
        /// 'quit' over SSH ends the session and nothing else: the node goes on
        /// answering.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SSH)]
        public async Task QuitOverSSHLeavesTheNodeRunning()
        {

            await using var client  = await SignInOverSSH();
            await using var shell   = await client.OpenShellAsync(new SshPty("xterm", new SshWindowSize(80, 24), new Dictionary<Byte, UInt32>()));

            await ReadUntil(shell, new StringBuilder(), "> ");

            await shell.WriteAsync("quit\r");

            Assert.That(await shell.ExitStatus.WaitAsync(TimeSpan.FromSeconds(10)), Is.EqualTo(0));

            Assert.That(Node.HTTPServer.IsRunning, Is.True, $"quit over SSH stopped the {Node.Kind.Name}");

        }

        #endregion

        #region NothingButTheCommandLineIsServedOverSSH

        /// <summary>
        /// No exec, no SFTP, no tunnel: a node serves its command line over SSH
        /// and nothing of the machine it runs on.
        /// </summary>
        [Test]
        [WithNode(NodeSetup.SSH)]
        public async Task NothingButTheCommandLineIsServedOverSSH()
        {

            await using var client = await SignInOverSSH();

            var exec = await client.Multiplexer.OpenChannelAsync("session");
            var sftp = await client.Multiplexer.OpenChannelAsync("session");

            Assert.Multiple(() => {
                Assert.That(exec.SendRequestAsync("exec",      true, SshSessionChannel.EncodeString("id")).AsTask().Result,    Is.False, "exec");
                Assert.That(sftp.SendRequestAsync("subsystem", true, SshSessionChannel.EncodeString("sftp")).AsTask().Result,  Is.False, "sftp");
            });

            Assert.That(async () => await client.OpenTcpStreamAsync("127.0.0.1", Node.HTTPPort.ToUInt16()),
                        Throws.TypeOf<SshChannelOpenException>(), "a tunnel");

        }

        #endregion

    }

}
