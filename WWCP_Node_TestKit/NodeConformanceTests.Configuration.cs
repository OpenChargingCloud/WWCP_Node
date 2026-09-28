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

using System.Net;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// What the node says it is, what time it thinks it is, and what happens
    /// when somebody tells it to resolve names or keep time otherwise.
    /// </summary>
    public abstract partial class NodeConformanceTests
    {

        #region TheStatusSaysWhatIsRunning()

        [Test]
        public async Task TheStatusSaysWhatIsRunning()
        {

            using var http = await SignedIn();

            var status = await GetJSON(http, "api/v1/status");

            Assert.Multiple(() => {
                Assert.That(status.Value<String>("service"),           Is.EqualTo(Node.Kind.Product));
                Assert.That(status.Value<String>("version"),           Is.EqualTo(Node.JSONAPI?.Version ?? Node.Version));
                Assert.That(status.Value<String>("hermod"),            Is.Not.Null.And.Not.Empty);
                Assert.That(status.Value<Int32> ("sessions"),          Is.EqualTo(1), "the one this test signed in with");
                Assert.That(status["log"]?.Value<Int32>("capacity"),   Is.GreaterThan(0));
                Assert.That(status.Properties().Select(property => property.Name).Take(2),
                            Is.EqualTo(new[] { "service", "version" }),
                            "what the kind adds comes after the version");
            });

        }

        #endregion

        #region TheClockIsAtClock()

        /// <summary>
        /// At api/v1/clock on every node, and nowhere else: it was at
        /// v1/configuration/time on five kinds of node and at v1/clock on
        /// three, and the old place is a JSON 404 now, like any path the API
        /// does not have.
        /// </summary>
        [Test]
        public async Task TheClockIsAtClock()
        {

            using var http      = await SignedIn();
            using var nobody    = Anonymous();

            var clock           = await GetJSON(http, "api/v1/clock");
            var signedOut       = await nobody.GetAsync("api/v1/clock");
            var (old, oldSaid)  = await Send(http, HttpMethod.Get, "api/v1/configuration/time");

            Assert.Multiple(() => {
                Assert.That(clock.Value<String>("now"),        Is.Not.Null, "the clock says what time it is");
                Assert.That(signedOut.StatusCode,              Is.EqualTo(HttpStatusCode.Unauthorized));
                Assert.That(old,                               Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(oldSaid.Value<String>("error"),    Is.EqualTo("Unknown API path"));
            });

        }

        #endregion

        #region TheConfigurationNamesEveryNodesSection()

        /// <summary>
        /// The Configuration page renders whatever the node sends rather than a
        /// list of its own, so a section going missing is not a broken page -
        /// it is a page that quietly stops mentioning something. These are the
        /// sections every node has; a kind adds its own.
        /// </summary>
        [Test]
        public async Task TheConfigurationNamesEveryNodesSection()
        {

            using var http = await SignedIn();

            var configuration = await GetJSON(http, "api/v1/configuration");

            Assert.Multiple(() => {
                foreach (var section in new[] { "http", "web", "log", "time" })
                    Assert.That(configuration[section], Is.TypeOf<JObject>(), $"the '{section}' section");
            });

        }

        #endregion

        #region TheConfigurationNeverCarriesThePassword()

        /// <summary>
        /// The web login appears in the configuration with its username and the
        /// path of its file, and never with anything about its password -
        /// neither the password nor its hash.
        /// </summary>
        [Test]
        public async Task TheConfigurationNeverCarriesThePassword()
        {

            using var http = await SignedIn();

            var configuration = (await GetJSON(http, "api/v1/configuration")).ToString();

            Assert.Multiple(() => {
                Assert.That(configuration.Contains(Password, StringComparison.Ordinal),   Is.False,
                            "The configuration carries the password in the clear.");
                Assert.That(configuration.Contains("$pbkdf2", StringComparison.Ordinal),  Is.False,
                            "The configuration carries the password hash, which is worth a dictionary attack.");
            });

        }

        #endregion


        #region TheDNSConfigurationIsReadable()

        [Test]
        public async Task TheDNSConfigurationIsReadable()
        {

            using var http = await SignedIn();

            var dns = await GetJSON(http, "api/v1/configuration/dns");

            Assert.Multiple(() => {
                Assert.That(dns.Value<Boolean>("enabled"),                Is.EqualTo(Node.DNSEnabled));
                Assert.That(dns["servers"],                               Is.TypeOf<JArray>());
                Assert.That(dns["settings"],                              Is.Not.Null);
                Assert.That(dns["limits"]?.Value<Int32>("maxServers"),    Is.GreaterThan(0));
                Assert.That(dns.Value<String>("file"),                    Is.EqualTo(Node.ConfigFile.Path));
            });

        }

        #endregion

        #region ChangingTheDNSSettingsReachesTheClientAndTheFile()

        /// <summary>
        /// Every change takes effect at once and is written down, in that order
        /// of importance: a change that was applied but not written down
        /// disappears at the next start without anybody noticing.
        /// </summary>
        [Test]
        public async Task ChangingTheDNSSettingsReachesTheClientAndTheFile()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync(
                                     "api/v1/configuration/dns",
                                     JSONBody(
                                         new JProperty("useCache",    false),
                                         new JProperty("maxRetries",  4),
                                         new JProperty("servers",     new JArray(
                                             new JObject(
                                                 new JProperty("address",    "9.9.9.9"),
                                                 new JProperty("port",       853),
                                                 new JProperty("transport",  "TLS")
                                             )
                                         ))
                                     )
                                 );

            var answered = JObject.Parse(await response.Content.ReadAsStringAsync());
            var onDisk   = JObject.Parse(File.ReadAllText(Node.ConfigFile.Path));

            Assert.Multiple(() => {

                Assert.That(response.IsSuccessStatusCode, Is.True, answered.ToString());

                // What the node answers is the whole configuration as it now
                // stands, so the page shows what was taken rather than what was
                // sent.
                Assert.That(answered["settings"]?.Value<Boolean>("useCache"),    Is.False);
                Assert.That(answered["settings"]?.Value<Int32>  ("maxRetries"),  Is.EqualTo(4));
                Assert.That((answered["servers"] as JArray)?.Count,              Is.EqualTo(1));

                // In the client everything below this node was handed, and not
                // in a copy of it.
                Assert.That(Node.DNSClient.UseCache,    Is.False);
                Assert.That(Node.DNSClient.MaxRetries,  Is.EqualTo(4));

                // And in the file, for the next start.
                Assert.That(onDisk["dns"]?.Value<Int32>("maxRetries"),  Is.EqualTo(4));

            });

        }

        #endregion

        #region WhatAChangeDoesNotMentionIsLeftAlone()

        /// <summary>
        /// A page that only offers the checkboxes must be able to send only the
        /// checkboxes without taking the name servers with it.
        /// </summary>
        [Test]
        public async Task WhatAChangeDoesNotMentionIsLeftAlone()
        {

            using var http = await SignedIn();

            var before  = await GetJSON(http, "api/v1/configuration/dns");
            var servers = (before["servers"] as JArray)?.Count ?? 0;

            await http.PutAsync("api/v1/configuration/dns",
                                JSONBody(new JProperty("dnssecOK", true)));

            var after   = await GetJSON(http, "api/v1/configuration/dns");

            Assert.Multiple(() => {
                Assert.That(after["settings"]?.Value<Boolean>("dnssecOK"),  Is.True);
                Assert.That((after["servers"] as JArray)?.Count,            Is.EqualTo(servers),
                            "A change that said nothing about the name servers took them away.");
            });

        }

        #endregion

        #region EmptyingTheNameServersIsRefused()

        /// <summary>
        /// Switching name resolution off is a thing somebody means; a list of
        /// no name servers is a thing nobody means.
        /// </summary>
        [Test]
        public async Task EmptyingTheNameServersIsRefused()
        {

            using var http = await SignedIn();

            var serversBefore = Node.DNSClient.DNSServers.Count();

            var response = await http.PutAsync("api/v1/configuration/dns",
                                               JSONBody(new JProperty("servers", new JArray())));

            var error    = JObject.Parse(await response.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                      Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(error.Value<String>("error"),             Does.Contain("Switch name resolution off"));
                Assert.That(Node.DNSClient.DNSServers.Count(),        Is.EqualTo(serversBefore),
                            "The refused request emptied the list anyway.");
            });

        }

        #endregion

        #region SwitchingNameResolutionOffTakesTheServersAway()

        /// <summary>
        /// Off means off for everything that was handed this client, not only
        /// for the parts of the node that would have remembered to check a flag
        /// first.
        /// </summary>
        [Test]
        public async Task SwitchingNameResolutionOffTakesTheServersAway()
        {

            using var http = await SignedIn();

            await http.PutAsync("api/v1/configuration/dns",
                                JSONBody(new JProperty("enabled", false)));

            Assert.Multiple(() => {
                Assert.That(Node.DNSEnabled,                   Is.False);
                Assert.That(Node.DNSClient.DNSServers.Any(),   Is.False,
                            "Name resolution is off, but the client still holds servers to ask.");
            });

        }

        #endregion

        #region AFieldOfTheWrongKindIsRefused()

        /// <summary>
        /// Present but of the wrong kind is an error and never a silent null:
        /// somebody wrote it and deserves to be told, rather than watching the
        /// setting quietly not happen - named by its path in the document,
        /// because "must be a port number" over a form with three ports on it
        /// has said nothing.
        /// </summary>
        [Test]
        public async Task AFieldOfTheWrongKindIsRefused()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync("api/v1/configuration/nts",
                                               JSONBody(new JProperty("ntpPort", "onetwothree")));

            var error    = JObject.Parse(await response.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,           Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(error.Value<String>("error"),  Does.Contain("nts.ntpPort"));
            });

        }

        #endregion


        #region TheNTSConfigurationIsReadable()

        [Test]
        public async Task TheNTSConfigurationIsReadable()
        {

            using var http = await SignedIn();

            var nts = await GetJSON(http, "api/v1/configuration/nts");

            Assert.Multiple(() => {

                // Switched off by the fixture, so that no test reaches the
                // network - the servers it would ask are still named.
                Assert.That(nts.Value<Boolean>("enabled"),                        Is.False);
                Assert.That(nts.Value<String>("file"),                            Is.EqualTo(Node.ConfigFile.Path));

                // What the page draws its list of time servers from. A node
                // nobody has configured asks the PTB's four, so the list has
                // four to draw rather than nothing.
                Assert.That(nts["timeSources"],                                   Is.Not.Null.And.Count.EqualTo(4));
                Assert.That(nts["timeSources"]?[0]?.Value<String>("hostname"),    Is.EqualTo(Node.NTSClient.Hostname.ToString()));
                Assert.That(nts["group"]?.Value<String>("name"),                  Is.EqualTo("legal"));
                Assert.That(nts["group"]?.Value<Byte>  ("minServers"),            Is.EqualTo(2));

            });

        }

        #endregion

        #region PointingTheNodeAtAnotherTimeServerReplacesTheClient()

        /// <summary>
        /// An NTS client is bound to its host at construction, and the cookies
        /// and keys it holds belong to that host and to no other - so being
        /// pointed elsewhere builds a new one rather than reconfiguring this
        /// one.
        /// </summary>
        [Test]
        public async Task PointingTheNodeAtAnotherTimeServerReplacesTheClient()
        {

            using var http = await SignedIn();

            var before   = Node.NTSClient;

            var response = await http.PutAsync(
                                     "api/v1/configuration/nts",
                                     JSONBody(
                                         new JProperty("hostname",   "ptbtime2.ptb.de"),
                                         new JProperty("ntsKEPort",  4460),
                                         new JProperty("ntpPort",    123)
                                     )
                                 );

            var onDisk   = JObject.Parse(File.ReadAllText(Node.ConfigFile.Path));

            Assert.Multiple(() => {

                Assert.That(response.IsSuccessStatusCode,              Is.True);
                Assert.That(Node.NTSClient.Hostname.ToString(),        Does.StartWith("ptbtime2.ptb.de"));

                Assert.That(Node.NTSClient,                            Is.Not.SameAs(before),
                            "The host changed and the client did not, so it still holds the cookies of the old one.");

                // Written as the domain name it was parsed into, which is the
                // absolute form with the root label on the end - so this is
                // what a name looks like on its way back out of the file, and
                // not a stray character.
                Assert.That(onDisk["nts"]?.Value<String>("hostname"),  Is.EqualTo(Node.NTSClient.Hostname.ToString()));

            });

        }

        #endregion

    }

}
