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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The command line every node has: its commands, found without being
    /// listed - the node's in this library and a kind's in its own - and
    /// syncNTS, which every kind had a copy of, as what it answers without
    /// asking anybody anything; and its console where nobody can type at it,
    /// which runs until a task it was given ends.
    /// </summary>
    [TestFixture]
    public class NodeCLITests
    {

        #region Data

        private String    directory  = default!;
        private WWCPNode  node       = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeTheNode()
        {

            directory = Path.Combine(Path.GetTempPath(), $"node-cli-{Guid.NewGuid().ToString("N")[..12]}");
            Directory.CreateDirectory(directory);

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "dns": { "enabled": false }, "nts": { "enabled": false } }""");

            node = new WWCPNode(
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configuration),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false,
                       BridgeDebugLog:    false
                   );

        }

        [TearDown]
        public async Task LetTheNodeGo()
        {

            await node.DisposeAsync();

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // A file let go of a moment too late; the temporary directory
                // is the system's to clear.
            }

        }

        #endregion


        #region EveryNodeCanBeToldToSyncItsTime()

        /// <summary>
        /// The node's command line has syncNTS without anybody listing it, and
        /// Styx's own - help and quit - beside it.
        /// </summary>
        [Test]
        public void EveryNodeCanBeToldToSyncItsTime()
        {

            var cli = new NodeCLI(node);

            Assert.Multiple(() => {
                Assert.That(cli.Commands.OfType<SyncNTSCommand>().Count(),  Is.EqualTo(1));
                Assert.That(cli.Commands.Select(command => command.GetType().Name),
                            Does.Contain("HelpCommand").And.Contain("QuitCommand"));
            });

        }

        #endregion

        #region AKindsCommandLineHasTheNodesCommandsAndItsOwn()

        /// <summary>
        /// A kind of node derives its command line from the node's and registers
        /// its type: its own commands are found in its assembly, the node's in
        /// this library - and each of them once.
        /// </summary>
        [Test]
        public async Task AKindsCommandLineHasTheNodesCommandsAndItsOwn()
        {

            var cli = new KindCLI(node);

            Assert.Multiple(() => {
                Assert.That(cli.Commands.OfType<SyncNTSCommand>().Count(),  Is.EqualTo(1), "the node's command, once");
                Assert.That(cli.Commands.OfType<KindCommand>().   Count(),  Is.EqualTo(1), "the kind's own");
            });

            Assert.That(await cli.Execute("kindOnly"), Is.EqualTo(new[] { "the kind's own" }));

        }

        #endregion

        #region ATimeServerThatIsNoneOfTheNodesIsNotAsked()

        /// <summary>
        /// A name that is none of the node's time servers is answered with the
        /// servers there are, in the kind's words, and nobody is asked anything
        /// - a mistyped name would otherwise be a key exchange with whoever
        /// answers to it. Not written to the log either, which is a book of
        /// what was asked.
        /// </summary>
        [Test]
        public async Task ATimeServerThatIsNoneOfTheNodesIsNotAsked()
        {

            var cli    = new NodeCLI(node);
            var said   = new List<String>();

            node.Log.OnLogged += logged => said.Add(logged.Message);

            var answer = await cli.Execute("syncNTS nowhere.example");
            var first  = node.TimeSources.Sources.First().Hostname.Trimmed;

            Assert.Multiple(() => {
                Assert.That(answer,  Has.Length.EqualTo(1));
                Assert.That(answer[0], Does.StartWith($"'nowhere.example' is none of this {node.Kind.Name}'s time servers, which are "));
                Assert.That(answer[0], Does.Contain(first));
                Assert.That(said,    Has.None.Contains("asked this"), "something was asked, and written down");
            });

        }

        #endregion

        #region TheTimeServersAreOfferedOnceTheCommandIsWhole()

        /// <summary>
        /// Tab after the whole command offers the node's time servers, which is
        /// what the local controller's older copy of the command did not.
        /// </summary>
        [Test]
        public async Task TheTimeServersAreOfferedOnceTheCommandIsWhole()
        {

            var cli          = new NodeCLI(node);
            var suggestions  = await cli.Suggest("syncNTS");
            var servers      = node.TimeSources.Sources.Select(source => $"syncNTS {source.Hostname.Trimmed}").ToArray();

            Assert.That(servers, Is.Not.Empty, "a node with no time servers to offer says nothing here");

            Assert.That(suggestions.Select(suggestion => suggestion.Suggestion), Is.SupersetOf(servers));

        }

        #endregion

        #region TheBannerSaysWhichRepositoryIsWhich()

        /// <summary>
        /// The banner's lines: the first labelled, every value where the other
        /// lines of the banner have theirs, the names padded to the longest -
        /// and where two repositories share a name, the assembly beside it, as
        /// five kinds said it and three did not.
        /// </summary>
        [Test]
        public void TheBannerSaysWhichRepositoryIsWhich()
        {

            var lines = BuiltFrom.BannerLinesOf([
                            new LoadedAssembly("Hermod",                   "1.0", "Hermod",                "1111111111111111111111111111111111111111"),
                            new LoadedAssembly("ModbusTLSEnergyMeter",     "1.0", "ModbusTLSEnergyMeter",  "2222222222222222222222222222222222222222"),
                            new LoadedAssembly("ModbusTLSEnergyMeterCLI",  "1.0", "ModbusTLSEnergyMeter",  "3333333333333333333333333333333333333333")
                        ]).ToArray();

            Assert.That(lines, Is.EqualTo(new[] {
                "  built from     Hermod                                          1111111111111111111111111111111111111111",
                "                 ModbusTLSEnergyMeter (ModbusTLSEnergyMeter)     2222222222222222222222222222222222222222",
                "                 ModbusTLSEnergyMeter (ModbusTLSEnergyMeterCLI)  3333333333333333333333333333333333333333"
            }));

        }

        #endregion

        #region ANodeStopsWhenTheTaskItWasGivenEnds(Ending)

        /// <summary>
        /// Where nobody can type - under a service manager, in CI, in this test
        /// host - the console only waits, and a task it was given stops it as
        /// Ctrl+C does: the energy meter's Modbus server's, however that ends,
        /// for a server that failed is as gone as one that finished. Not
        /// before, though: a console that returned at once would stop the node
        /// right after its banner.
        /// </summary>
        [TestCase("finished")]
        [TestCase("failed")]
        [TestCase("cancelled")]
        public async Task ANodeStopsWhenTheTaskItWasGivenEnds(String Ending)
        {

            Assume.That(Console.IsInputRedirected || Console.IsOutputRedirected, Is.True,
                        "a terminal on both ends, where the console would wait for keys instead");

            var server   = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var running  = new NodeCLI(node).RunUntilStopped(server.Task);

            Assert.That(await Task.WhenAny(running, Task.Delay(300)), Is.Not.SameAs(running),
                        "the console returned before the task ended");

            switch (Ending)
            {
                case "finished":  server.SetResult();                                                  break;
                case "failed":    server.SetException(new IOException("The Modbus server stopped."));  break;
                default:          server.SetCanceled();                                                break;
            }

            Assert.That(await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(5))), Is.SameAs(running),
                        $"the console still ran 5 s after the task {Ending}");

            Assert.That(running.IsCompletedSuccessfully, Is.True,
                        "a task that ended is the node being stopped, not the console failing");

        }

        #endregion


        #region (class) KindCLI, KindCommand

        /// <summary>
        /// The command line of a kind of node, as a kind derives it.
        /// </summary>
        public class KindCLI : NodeCLI
        {
            public KindCLI(WWCPNode Node)
                : base(Node)
            {
                RegisterCLIType(typeof(KindCLI));
            }
        }

        /// <summary>
        /// A command only that kind has.
        /// </summary>
        public class KindCommand(KindCLI CLI) : ACLICommand<KindCLI>(CLI),
                                                ICLICommand
        {

            public static readonly String CommandName = "kindOnly";

            public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

                => Arguments.Length == 1 && CommandName.StartsWith(Arguments[0], StringComparison.CurrentCultureIgnoreCase)
                       ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                       : [];

            public override Task<String[]> Execute(String[]           Arguments,
                                                   CancellationToken  CancellationToken)

                => Task.FromResult<String[]>([ "the kind's own" ]);

            public override String Help()
                => $"{CommandName} - a command only this kind has";

        }

        #endregion

    }

}
