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

using System.Diagnostics;
using System.Net.Security;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// A dry run of a configuration of name resolution: names resolved as they
    /// would be with it, and nothing about it remembered, learned or put into
    /// effect.
    /// </summary>
    public abstract partial class NodeConformanceTests
    {

        #region ADryRunJudgesACertificateAndRemembersNothing()

        /// <summary>
        /// A certificate judged without being remembered is judged as at every
        /// handshake, but learns no pin, is not the server's last judgement, and
        /// is not what the server is believed with.
        /// </summary>
        [Test, WithNode(NodeSetup.ServersToLearnFrom)]
        public void ADryRunJudgesACertificateAndRemembersNothing()
        {

            Assert.That(DNSConfiguration.TryParseServer(NameServerToLearn, out var nameServer, out var problem), Is.True, problem);

            using var ca     = CA("Name Server CA");
            using var leaf   = ServerCertificate("127.0.0.1", ca);

            var learning     = false;
            var news         = new List<ServerNews>();
            ServerJudgement judgement;

            Node.OnServerNews += (_, said) => news.Add(said);

            using (var chain = Trusted(leaf, ca))
                judgement    = Node.JudgeServer(CertificateUsages.DNS,
                                                WWCPNode.NameOf(nameServer!),
                                                Node.PinsOf(nameServer!),
                                                leaf,
                                                chain,
                                                SslPolicyErrors.None,
                                                Evidence:  false,
                                                Learn:     (_, _) => learning = true,
                                                Remember:  false);

            Assert.Multiple(() => {
                Assert.That(judgement.Accepted,                                                       Is.True,  String.Join(" ", judgement.Steps.Select(step => step.Text)));
                Assert.That(judgement.Learned,                                                        Is.EqualTo(TrustOnFirstUse.None));
                Assert.That(learning,                                                                 Is.False, "nothing is learned in a dry run");
                Assert.That(news,                                                                     Is.Empty, "nor told as news, which learning would be");
                Assert.That(Node.LastJudgementOf(nameServer!),                                        Is.Null,  "nor kept as the server's last judgement");
                Assert.That(Node.KnownServers.Get(CertificateUsages.DNS, WWCPNode.NameOf(nameServer!)), Is.Null,  "nor as what it is believed with");
                Assert.That(Node.PinsOf(nameServer!)?.Roots ?? [],                                    Is.Empty);
            });

        }

        #endregion

        #region ADryRunOfResolutionSwitchedOffResolvesNothing()

        /// <summary>
        /// With name resolution switched off nothing resolves, and the node
        /// itself still resolves names.
        /// </summary>
        [Test, WithNode(NodeSetup.ServersToLearnFrom)]
        public async Task ADryRunOfResolutionSwitchedOffResolvesNothing()
        {

            var preflight = await Node.ResolveWithAsync(new JObject(new JProperty("enabled", false)),
                                                        [ "csms.example.org" ],
                                                        TimeSpan.FromSeconds(1));

            Assert.Multiple(() => {
                Assert.That(preflight.Error,                                  Is.Null);
                Assert.That(preflight.Resolved.Keys,                          Is.EqualTo(new[] { "csms.example.org" }));
                Assert.That(preflight.Resolves("CSMS.example.org"),           Is.False);
                Assert.That(preflight.Judgements,                             Is.Empty);
                Assert.That(Node.DNSConfigurationJSON()["enabled"]?.Value<Boolean>(), Is.True, "nothing was put into effect");
            });

        }

        #endregion

        #region ADryRunOfASectionThatCannotBeSavedSaysWhy()

        /// <summary>
        /// A section the node would refuse to save is not asked at all, and says
        /// why in the words a save would have said it.
        /// </summary>
        [Test, WithNode(NodeSetup.ServersToLearnFrom)]
        public async Task ADryRunOfASectionThatCannotBeSavedSaysWhy()
        {

            var preflight = await Node.ResolveWithAsync(new JObject(new JProperty("servers", new JArray(new JObject(new JProperty("address", "not an address!"))))),
                                                        [ "csms.example.org" ],
                                                        TimeSpan.FromSeconds(1));

            Assert.Multiple(() => {
                Assert.That(preflight.Error,                                  Does.Contain("dns.servers"));
                Assert.That(preflight.Resolved,                               Is.Empty);
                Assert.That((Node.DNSConfigurationJSON()["servers"] as JArray)?.Count, Is.EqualTo(2), "nothing was put into effect");
            });

        }

        #endregion

        #region ADryRunAsksTheServersOfTheChangeWithinItsTime()

        /// <summary>
        /// The servers of the section are asked, not the node's: one that never
        /// answers resolves nothing, within the time given, and the node keeps
        /// its own servers.
        /// </summary>
        [Test, WithNode(NodeSetup.ServersToLearnFrom)]
        public async Task ADryRunAsksTheServersOfTheChangeWithinItsTime()
        {

            using var nowhere = new ClosedPort();

            // By address and port: what was made of a server's certificate in
            // the meantime is the node's own, not the dry run's.
            String[] ServersNow()
                => [.. Node.DNSConfigurationJSON()["servers"]!.Children<JObject>().Select(server => $"{server["address"]}:{server["port"]}")];

            var before    = ServersNow();
            var watch     = Stopwatch.StartNew();

            var preflight = await Node.ResolveWithAsync(new JObject(new JProperty("servers", new JArray(new JObject(
                                                            new JProperty("address",              "127.0.0.1"),
                                                            new JProperty("port",                 nowhere.Number.ToUInt16()),
                                                            new JProperty("transport",            "UDP"),
                                                            new JProperty("queryTimeoutSeconds",  1)
                                                        )))),
                                                        [ "csms.example.org" ],
                                                        TimeSpan.FromSeconds(3));

            watch.Stop();

            Assert.Multiple(() => {
                Assert.That(preflight.Error,                                  Is.Null);
                Assert.That(preflight.Resolves("csms.example.org"),           Is.False);
                Assert.That(watch.Elapsed,                                    Is.LessThan(TimeSpan.FromSeconds(10)));
                Assert.That(ServersNow(),                                     Is.EqualTo(before), "the node keeps its own servers");
            });

        }

        #endregion

    }

}
