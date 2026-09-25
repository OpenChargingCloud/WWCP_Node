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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// What a node makes of an "nts" section: the section put into effect
    /// on top of the group of time servers it already has.
    /// </summary>
    /// <remarks>
    /// Beside the tests of the section on its own, because the rule that
    /// matters here - what a section does not mention is left as it is - can
    /// only be seen against something that is already there.
    ///
    /// The nodes are constructed and never started. The constructor is what
    /// applies the file, and starting would open a port and make up an account
    /// for nothing.
    /// </remarks>
    public class NTSGroupInEffectTests
    {

        #region Data

        private String directory = "";

        private String ConfigurationPath
            => Path.Combine(directory, WWCPConfigFile.DefaultFileName);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "node-nts-group-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helper) Node(Configuration = null)

        /// <summary>
        /// A node as it stands after reading this configuration file, or
        /// after reading none.
        /// </summary>
        private WWCPNode Node(String? Configuration = null)
        {

            if (Configuration is not null)
                File.WriteAllText(ConfigurationPath, Configuration);

            return new WWCPNode(
                       AccountsPath:      Path.Combine(directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                       CertificatesPath:  Path.Combine(directory, "certificates"),
                       LogToConsole:      false
                   );

        }

        #endregion


        #region AQuorumOnItsOwnHoldsTheServersInEffectToIt()

        /// <summary>
        /// "minServers" without a list is about the servers the node has.
        /// </summary>
        /// <remarks>
        /// It used to count only beside a list or a hostname: the file was read,
        /// the start reported NTS configuration, and the default four went on
        /// being held to two.
        /// </remarks>
        [Test]
        public async Task AQuorumOnItsOwnHoldsTheServersInEffectToIt()
        {

            await using var node = Node("""{ "nts": { "minServers": 3 } }""");

            Assert.Multiple(() =>
            {
                Assert.That(node.TimeSources.Sources.Count(),  Is.EqualTo(4),  "the servers were not mentioned, so they are the default four");
                Assert.That(node.TimeSources.MinServers,       Is.EqualTo(3),  "the quorum was read and changed nothing");
            });

        }

        #endregion

        #region ADeviationOnItsOwnAppliesToTheServersInEffect()

        [Test]
        public async Task ADeviationOnItsOwnAppliesToTheServersInEffect()
        {

            await using var node = Node("""{ "nts": { "maxDeviationSeconds": 0.5 } }""");

            Assert.Multiple(() =>
            {
                Assert.That(node.TimeSources.Sources.Count(),  Is.EqualTo(4));
                Assert.That(node.TimeSources.MinServers,       Is.EqualTo(2));
                Assert.That(node.TimeSources.MaxDeviation,     Is.EqualTo(TimeSpan.FromSeconds(0.5)),  "the deviation was read and changed nothing");
            });

        }

        #endregion

        #region AQuorumTheServersInEffectCannotReachStopsTheStart()

        /// <summary>
        /// Five of four is refused while the file is read, as five of a list of
        /// four always was.
        /// </summary>
        [Test]
        public void AQuorumTheServersInEffectCannotReachStopsTheStart()
        {

            var problem = Assert.Throws<InvalidOperationException>(() => Node("""{ "nts": { "minServers": 5 } }"""));

            Assert.That(problem?.Message,  Does.Contain("minServers").And.Contain(ConfigurationPath));

        }

        #endregion

        #region AQuorumOnItsOwnIsRefusedBeforeItIsWrittenDown()

        /// <summary>
        /// And the same from the page: refused, and the file left as it was, so
        /// that the next start does not stop over what was refused.
        /// </summary>
        [Test]
        public async Task AQuorumOnItsOwnIsRefusedBeforeItIsWrittenDown()
        {

            await using var node = Node();

            Assert.Multiple(() =>
            {

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "minServers": 5 }"""), out var error),  Is.False);
                Assert.That(error,                                                                                   Does.Contain("minServers"));

                Assert.That(!File.Exists(ConfigurationPath) || !File.ReadAllText(ConfigurationPath).Contains("minServers"),
                            Is.True,
                            "a refused quorum was written down all the same");

                Assert.That(node.TimeSources.MinServers,  Is.EqualTo(2));

            });

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "minServers": 3 }"""), out var unexpected),  Is.True,  unexpected);
            Assert.That(node.TimeSources.MinServers,                                                                  Is.EqualTo(3));

        }

        #endregion

        #region AListAfterALoneHostnameIsHeldToTheQuorumAgain()

        /// <summary>
        /// The quorum a group of one has to settle for is not carried over to
        /// the four that come after it.
        /// </summary>
        /// <remarks>
        /// Read from the file at the next start, the same section holds the four
        /// to two. A running node that held them to one would be a different
        /// node from the one that file describes.
        /// </remarks>
        [Test]
        public async Task AListAfterALoneHostnameIsHeldToTheQuorumAgain()
        {

            await using var node = Node();

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "hostname": "ptbtime1.ptb.de" }"""), out var error),  Is.True,  error);
            Assert.That(node.TimeSources.MinServers,                                                                          Is.EqualTo(1),  "one server cannot be held to two");

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""
                            {
                                "servers": [ "ptbtime1.ptb.de", "ptbtime2.ptb.de",
                                             "ptbtime3.ptb.de", "ptbtime4.ptb.de" ]
                            }
                            """), out error),  Is.True,  error);

            Assert.That(node.TimeSources.MinServers,  Is.EqualTo(2),  "the group of one's quorum was carried over to four");

        }

        #endregion

        #region ASaveOfPartOfTheSectionLeavesTheRestInEffect()

        /// <summary>
        /// The switch on the page sends "enabled" and nothing else, and the
        /// rest of what the file said stays in effect.
        /// </summary>
        /// <remarks>
        /// It used to be replaced by what was sent: how often to check and who
        /// stands behind the time went back to their defaults, and came back
        /// only when the next start read the file again.
        /// </remarks>
        [Test]
        public async Task ASaveOfPartOfTheSectionLeavesTheRestInEffect()
        {

            await using var node = Node("""{ "nts": { "checkEverySeconds": 600, "legalTimeAuthority": "PTB" } }""");

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "enabled": true }"""), out var error),  Is.True,  error);

            Assert.Multiple(() =>
            {
                Assert.That(node.TimeCheckEvery,      Is.EqualTo(TimeSpan.FromSeconds(600)),  "the interval went back to its default");
                Assert.That(node.LegalTimeAuthority,  Is.EqualTo("PTB"),                      "the authority was forgotten");
            });

            // And the other way round, as the meter's page does: saving the
            // legal time's settings leaves the interval as it was.
            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "legalTimeToleranceSeconds": 0.5 }"""), out error),  Is.True,  error);

            Assert.Multiple(() =>
            {
                Assert.That(node.TimeCheckEvery,      Is.EqualTo(TimeSpan.FromSeconds(600)),  "the interval went back to its default");
                Assert.That(node.LegalTimeAuthority,  Is.EqualTo("PTB"),                      "the authority was forgotten");
                Assert.That(node.LegalTimeTolerance,  Is.EqualTo(TimeSpan.FromSeconds(0.5)));
            });

        }

        #endregion

        #region ALoneHostnameReplacesTheListHereAndInTheFile()

        /// <summary>
        /// A save naming a lone hostname and no list makes the group that one
        /// server - now, and at the next start.
        /// </summary>
        /// <remarks>
        /// The file kept its list beside the hostname, and the next start made
        /// the list again: a node ran with one server until it was restarted
        /// and with three after it, nobody having changed anything in between.
        /// The Modbus/TLS energy meter found it, from its NTS page's form, and
        /// had this before it was a node.
        /// </remarks>
        [Test]
        public async Task ALoneHostnameReplacesTheListHereAndInTheFile()
        {

            await using (var node = Node("""{ "nts": { "servers": [ "a.example", "b.example", "c.example" ] } }"""))
            {

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "hostname": "d.example" }"""), out var error),  Is.True,  error);

                Assert.That(node.TimeSources.Sources.Select(source => source.Hostname.Trimmed),  Is.EqualTo(new[] { "d.example" }));

            }

            Assert.That(JObject.Parse(File.ReadAllText(ConfigurationPath))["nts"]?["servers"],  Is.Null,
                        "the file still has its list beside the hostname");

            await using var restarted = Node();

            Assert.That(restarted.TimeSources.Sources.Select(source => source.Hostname.Trimmed),  Is.EqualTo(new[] { "d.example" }),
                        "the next start made the list again");

        }

        #endregion

        #region AnAuthorityTakenAwayStaysAway()

        /// <summary>
        /// The legal time's authority is taken away by sending it as null - or
        /// as nothing between the quotes, which is what a page sends for an
        /// emptied field - and it stays away, here and in the file.
        /// </summary>
        /// <remarks>
        /// A null in a section otherwise means "the file does not say", and the
        /// file kept what it said: the authority was gone until the next start,
        /// and back after it, with nobody having put it back.
        /// </remarks>
        [Test]
        [TestCase("null")]
        [TestCase("\"\"")]
        public async Task AnAuthorityTakenAwayStaysAway(String TakenAwayAs)
        {

            await using (var node = Node("""{ "nts": { "checkEverySeconds": 600, "legalTimeAuthority": "PTB" } }"""))
            {

                var before = node.Log.LastId;

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse($$"""{ "legalTimeAuthority": {{TakenAwayAs}} }"""), out var error),  Is.True,  error);

                var said = node.Log.Recent(100, before, null).ToArray();

                Assert.Multiple(() =>
                {
                    Assert.That(node.LegalTimeAuthority,  Is.Null,                                "still vouched for");
                    Assert.That(node.TimeCheckEvery,      Is.EqualTo(TimeSpan.FromSeconds(600)),  "the rest went with it");
                    Assert.That(said.Where(entry => entry.Metrological).Select(entry => entry.Message),
                                Has.Some.Contains("no legal time authority"),
                                "a change to who stands behind the time is not in the metrological log");
                });

            }

            Assert.That(File.ReadAllText(ConfigurationPath),  Does.Not.Contain("legalTimeAuthority"),
                        "the file still names the authority, and the next start brings it back");

            await using var restarted = Node();

            Assert.That(restarted.LegalTimeAuthority,  Is.Null,  "the authority came back at the next start");

        }

        #endregion

        #region WhatLegalTimeRestsOnIsShownAndItsChangesWrittenDown()

        /// <summary>
        /// The NTS answer carries what legal time rests on and the limits a page
        /// checks it against, and a change to either bound is written into the
        /// metrological log.
        /// </summary>
        [Test]
        public async Task WhatLegalTimeRestsOnIsShownAndItsChangesWrittenDown()
        {

            await using var node = Node("""{ "nts": { "legalTimeAuthority": "PTB", "legalTimeToleranceSeconds": 0.25 } }""");

            var json     = node.NTSConfigurationJSON();
            var settings = json["settings"] as JObject;
            var limits   = json["limits"]   as JObject;

            Assert.Multiple(() =>
            {
                Assert.That(settings?.Value<String>("legalTimeAuthority"),         Is.EqualTo("PTB"));
                Assert.That(settings?.Value<Double>("legalTimeToleranceSeconds"),  Is.EqualTo(0.25));
                Assert.That(settings?.Value<Double>("legalTimeMaxAgeSeconds"),     Is.EqualTo(NTSConfiguration.DefaultLegalMaxAge.TotalSeconds));
                Assert.That(limits?.  Value<Double>("minTolerance"),               Is.EqualTo(NTSConfiguration.MinToleranceSeconds));
                Assert.That(limits?.  Value<Double>("maxMaxAge"),                  Is.EqualTo(NTSConfiguration.MaxMaxAgeSeconds));
                Assert.That(limits?.  Value<Int32> ("maxAuthorityLength"),         Is.EqualTo(NTSConfiguration.MaxAuthorityLength));
            });

            var before = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "legalTimeToleranceSeconds": 0.5, "legalTimeMaxAgeSeconds": 600 }"""), out var error),  Is.True,  error);

            var said = node.Log.Recent(100, before, null).Where(entry => entry.Metrological).Select(entry => entry.Message).ToArray();

            Assert.That(said,  Has.Some.Contains("legal time tolerance = 0.5 s").And.Contains("legal time max age = 600 s"),  String.Join(" | ", said));

        }

        #endregion

        #region AListShorterThanTheQuorumIsRefusedAndNotWritten()

        /// <summary>
        /// A server deleted or switched off below the quorum the file holds is
        /// refused, and the file is left as it was.
        /// </summary>
        /// <remarks>
        /// Each half was fine on its own - the quorum in the file, the list that
        /// was sent - and merged they made a section the next start refuses. A
        /// save that is accepted and then stops the node is the one thing
        /// worse than a save that is refused.
        /// </remarks>
        [Test]
        public async Task AListShorterThanTheQuorumIsRefusedAndNotWritten()
        {

            await using var node = Node("""
                                          { "nts": { "servers": [ "a.example", "b.example", "c.example" ], "minServers": 3 } }
                                          """);

            var before = File.ReadAllText(ConfigurationPath);

            Assert.Multiple(() =>
            {

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out var deleted),
                            Is.False,
                            "a server was deleted below the quorum");

                Assert.That(deleted,  Does.Contain("minServers"));

                Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""
                                { "servers": [ "a.example", "b.example", { "hostname": "c.example", "enabled": false } ] }
                                """), out _),
                            Is.False,
                            "a server was switched off below the quorum");

                Assert.That(File.ReadAllText(ConfigurationPath),         Is.EqualTo(before),  "a refused save was written down");
                Assert.That(node.TimeSources.Sources.Count(),          Is.EqualTo(3));

            });

        }

        #endregion

        #region EveryServerIsListedWithItsPorts()

        /// <summary>
        /// The list the page edits and sends back whole has every server in it,
        /// the switched-off ones included, with the ports each is asked on.
        /// </summary>
        /// <remarks>
        /// It used to list the bands, which have only the servers switched on:
        /// a page sending back what it was shown would have deleted every
        /// server that was switched off.
        /// </remarks>
        [Test]
        public async Task EveryServerIsListedWithItsPorts()
        {

            await using var node = Node("""
                                          { "nts": { "servers": [ "a.example",
                                                                  { "hostname": "b.example", "ntsKEPort": 4461, "enabled": false } ] } }
                                          """);

            var listed = node.NTSConfigurationJSON()["timeSources"] as JArray;

            Assert.Multiple(() =>
            {
                Assert.That(listed,                                      Has.Count.EqualTo(2),  "the switched-off server is missing");
                Assert.That(listed?[1]?.Value<String>("hostname"),       Is.EqualTo("b.example."));
                Assert.That(listed?[1]?.Value<Boolean>("enabled"),       Is.False);
                Assert.That(listed?[1]?.Value<Int32>("ntsKEPort"),       Is.EqualTo(4461));
                Assert.That(listed?[0]?.Value<Int32>("ntpPort"),         Is.EqualTo(123));

                // There and empty until a key exchange has shown a chain.
                Assert.That(listed?[0]?["rootCA"]?.Type,                 Is.EqualTo(JTokenType.Null));
            });

        }

        #endregion

        #region TheQuorumWantedAndTheQuorumHeldAreBothShown()

        /// <summary>
        /// A lone hostname holds the group to one, and the page shows both that
        /// and the two that is wanted, which the next list is held to.
        /// </summary>
        [Test]
        public async Task TheQuorumWantedAndTheQuorumHeldAreBothShown()
        {

            await using var node = Node("""{ "nts": { "hostname": "a.example" } }""");

            var shown = node.NTSConfigurationJSON();

            Assert.Multiple(() =>
            {
                Assert.That(shown["settings"]?.Value<Int32>("minServers"),  Is.EqualTo(2),  "the quorum wanted");
                Assert.That(shown["group"]?.   Value<Int32>("minServers"),  Is.EqualTo(1),  "the quorum one server can be held to");
            });

        }

        #endregion

        #region AChangeToOneServerIsWrittenDown()

        /// <summary>
        /// A server given another priority or a port of its own is a change to
        /// the group, and the log book hears of it.
        /// </summary>
        /// <remarks>
        /// The log compared the names of the servers switched on, in the order
        /// they are asked. A priority that put a server into a band of its own
        /// at the end, and a port of its own, left those just as they were -
        /// and so the group changed without a line saying so.
        /// </remarks>
        [Test]
        public async Task AChangeToOneServerIsWrittenDown()
        {

            await using var node = Node("""{ "nts": { "servers": [ "a.example", "b.example" ] } }""");

            var before = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""
                            { "servers": [ "a.example", { "hostname": "b.example", "priority": 5, "ntsKEPort": 4461 } ] }
                            """), out var error),
                        Is.True,
                        error);

            var said = node.Log.Recent(50, before, null).Select(entry => entry.Message).ToArray();

            Assert.That(said,  Has.Some.Contains("time servers = a.example, b.example (priority 5, NTS-KE port 4461)"),
                        String.Join(" | ", said));

        }

        #endregion

        #region AnotherServerIsWrittenIntoTheLogAsItIsRead()

        /// <summary>
        /// The line a change of the one server writes. What goes into the file
        /// keeps its root dot; only the sentence drops it, as every other
        /// sentence of the node does.
        /// </summary>
        /// <remarks>
        /// "server = time.example.org.:4460 (NTS-KE)" is what it said: the one
        /// sentence of a change that still carried the dot. The roaming hub's
        /// tests caught it, which had it without the dot before the hub was a
        /// node.
        /// </remarks>
        [Test]
        public async Task AnotherServerIsWrittenIntoTheLogAsItIsRead()
        {

            await using var node = Node();

            var before = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "hostname": "time.example.org" }"""), out var error),
                        Is.True,
                        error);

            var said = node.Log.Recent(50, before, null).
                                Select(entry => entry.Message).
                                Where (message => message.StartsWith("NTS configuration changed", StringComparison.Ordinal)).
                                ToArray();

            Assert.Multiple(() => {
                Assert.That(said,  Has.Some.Contains("server = time.example.org:4460 (NTS-KE), :123 (NTP)"),  String.Join(" | ", said));
                Assert.That(said,  Has.None.Contains("time.example.org."),                                    String.Join(" | ", said));
            });

        }

        #endregion

        #region TheOverviewNamesTheGroupAndNotTheTestClient()

        /// <summary>
        /// The Configuration page's time card names the servers the clock is
        /// set by - all of them, the one switched off as well - and not the
        /// host of the single client the detailed test starts from.
        /// </summary>
        /// <remarks>
        /// It led with "NTS: ptbtime1.ptb.de." above the servers switched on:
        /// one server, which was the test's, above the group that was asked.
        /// The NTS answer carried the same client as "server", "cookies" and
        /// "keyExchange", and does not any more either.
        /// </remarks>
        [Test]
        public async Task TheOverviewNamesTheGroupAndNotTheTestClient()
        {

            await using var node = Node("""
                                          { "nts": { "servers": [ "a.example",
                                                                  { "hostname": "b.example", "priority": 5 },
                                                                  { "hostname": "c.example", "enabled": false } ] } }
                                          """);

            var time  = node.ConfigurationJSON()["time"] as JObject;
            var nts   = node.NTSConfigurationJSON();

            Assert.Multiple(() =>
            {

                Assert.That(time?.Value<String>("timeServers"),  Is.EqualTo("a.example, b.example (priority 5), c.example (switched off)"));
                Assert.That(time?.Value<Boolean>("ntsEnabled"),  Is.True);
                Assert.That(time?.ContainsKey("nts"),            Is.False,  "the test client's host is named again");

                // There and empty while nothing has been synchronised, so that
                // the card says "-" rather than leaving the line out.
                Assert.That(time?["lastSync"]?.      Type,       Is.EqualTo(JTokenType.Null));
                Assert.That(time?["lastSyncResult"]?.Type,       Is.EqualTo(JTokenType.Null));

                Assert.That(nts.ContainsKey("server"),           Is.False);
                Assert.That(nts.ContainsKey("cookies"),          Is.False);
                Assert.That(nts.ContainsKey("keyExchange"),      Is.False);

            });

        }

        #endregion

        #region ADeviationStaysWhenTheServersChange()

        /// <summary>
        /// What a section does not mention is left as it is - the deviation
        /// too, when the servers are replaced.
        /// </summary>
        [Test]
        public async Task ADeviationStaysWhenTheServersChange()
        {

            await using var node = Node("""{ "nts": { "maxDeviationSeconds": 0.5 } }""");

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out var error),  Is.True,  error);

            Assert.That(node.TimeSources.MaxDeviation,  Is.EqualTo(TimeSpan.FromSeconds(0.5)));

        }

        #endregion

        #region TheClockIsCheckedAgainstTheGroupAndNotTheTestClient()

        /// <summary>
        /// Against whom the clock is checked, as its JSON says it: the group,
        /// its servers switched on in the order they are asked, and how many of
        /// them have to answer.
        /// </summary>
        /// <remarks>
        /// It used to say "server", with the host of the single client that is
        /// only there for a server's detailed test - one name, the default, for
        /// a check that asks whatever group the file names. "server" is there
        /// again, and names the one server of a group of one only - see below.
        /// </remarks>
        [Test]
        public async Task TheClockIsCheckedAgainstTheGroupAndNotTheTestClient()
        {

            await using var node = Node("""
                                          { "nts": { "servers": [ { "hostname": "b.example", "priority": 5 },
                                                                  "a.example",
                                                                  { "hostname": "c.example", "enabled": false } ] } }
                                          """);

            var nts = (JObject) node.ClockJSON()["nts"]!;

            Assert.Multiple(() =>
            {

                Assert.That(nts.Value<String>("group"),        Is.EqualTo("legal"));

                Assert.That(nts["servers"]!.Values<String>(),  Is.EqualTo(new[] { "a.example", "b.example" }),
                            "switched on, in the order their bands are asked, and without the root's dot");

                Assert.That(nts.Value<Int32>("minServers"),    Is.EqualTo(2));

                Assert.That(nts["server"]?.Type,               Is.EqualTo(JTokenType.Null),  "one server named for a group of two");

            });

        }

        #endregion

        #region AGroupOfOneIsNamedAndAGroupOfMoreIsCounted()

        /// <summary>
        /// What a screen puts behind "checked against": the one server of a
        /// group of one by its name, and a group of more by numbers - how many
        /// were asked and how many answered - never by one of them.
        /// </summary>
        /// <remarks>
        /// Numbers rather than a phrase, because the screen says "checked
        /// against" in whichever language it is showing, and a phrase made up
        /// here would arrive in English. The last check used to be named as
        /// "legal (2 of 4 server(s))", which a charging station's display
        /// would have put behind its German "geprüft gegen" as it stood.
        /// Nothing has been checked here yet, and that is said as well: the
        /// counts are there and empty rather than missing.
        /// </remarks>
        [Test]
        public async Task AGroupOfOneIsNamedAndAGroupOfMoreIsCounted()
        {

            JObject one, four;

            await using (var node = Node("""{ "nts": { "servers": [ "a.example" ] } }"""))
                one  = (JObject) node.ClockJSON()["nts"]!;

            // The default four, which a file saying nothing leaves in place.
            await using (var node = Node("{ }"))
                four = (JObject) node.ClockJSON()["nts"]!;

            Assert.Multiple(() =>
            {

                Assert.That(one.Value<String>("server"),   Is.EqualTo("a.example"),      "the one server of a group of one, without the root's dot");
                Assert.That(four["server"]?.Type,          Is.EqualTo(JTokenType.Null),  "one of four named as though it were the one");

                foreach (var nts in new[] { one, four })
                {
                    Assert.That(nts["lastServer"]?.Type,   Is.EqualTo(JTokenType.Null),  "a server named before anything was checked");
                    Assert.That(nts["asked"]?.     Type,   Is.EqualTo(JTokenType.Null),  "how many were asked is missing, or made up");
                    Assert.That(nts["answered"]?.  Type,   Is.EqualTo(JTokenType.Null),  "how many answered is missing, or made up");
                }

            });

        }

        #endregion

        #region AClockThatIsNotCheckedNamesNobody()

        /// <summary>
        /// Switched off, the clock is checked against nobody, and says so -
        /// rather than naming servers that are not asked.
        /// </summary>
        [Test]
        public async Task AClockThatIsNotCheckedNamesNobody()
        {

            await using var node = Node("""{ "nts": { "enabled": false } }""");

            var nts = (JObject) node.ClockJSON()["nts"]!;

            Assert.Multiple(() =>
            {
                Assert.That(nts.Value<Boolean>("enabled"),  Is.False);
                Assert.That(nts["group"]?.     Type,        Is.EqualTo(JTokenType.Null));
                Assert.That(nts["servers"]?.   Type,        Is.EqualTo(JTokenType.Null));
                Assert.That(nts["minServers"]?.Type,        Is.EqualTo(JTokenType.Null));
            });

        }

        #endregion


        #region ARunningNodePutsANewIntervalIntoItsClockCheckAtOnce()

        /// <summary>
        /// How often the clock is checked, and whether it is, are put into the
        /// check of a running node at once - not at its next start.
        /// </summary>
        /// <remarks>
        /// The check runs on a timer set at the start, and a save used to change
        /// only the setting: the page said "in effect" about an interval the
        /// timer did not have until the next start. Seen here in the line the
        /// check writes whenever it is set. Started, and on a clock whose timers
        /// never fire, so that the checks those lines announce are never made -
        /// the one node in these tests that is started with its time client on.
        /// </remarks>
        [Test]
        public async Task ARunningNodePutsANewIntervalIntoItsClockCheckAtOnce()
        {

            var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();
            var port  = ((System.Net.IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();

            await using var node = new WWCPNode(
                                       HTTPPort:          IPPort.Parse((UInt16) port),
                                       AccountsPath:      Path.Combine(directory, "accounts"),
                                       ConfigFile:        new WWCPConfigFile(ConfigurationPath),
                                       CertificatesPath:  Path.Combine(directory, "certificates"),
                                       LogToConsole:      false,
                                       BridgeDebugLog:    false,
                                       TimeProvider:      ClockWithoutTimers.Instance
                                   );

            await node.Start();

            var before = node.Log.LastId;

            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "checkEverySeconds": 600 }"""), out var error),  Is.True,  error);
            Assert.That(node.TryUpdateNTSConfiguration(JObject.Parse("""{ "enabled": false }"""),          out error),      Is.True,  error);

            var said = node.Log.Recent(50, before, "clock").Select(entry => entry.Message).ToArray();

            Assert.Multiple(() =>
            {
                Assert.That(said,  Has.Some.Contains("will be checked against").And.Contains("every 10 minute(s)"),  String.Join(" | ", said));
                Assert.That(said,  Has.Some.Contains("is not being checked: NTS is switched off"),                   String.Join(" | ", said));
            });

        }

        #endregion

        #region AServerOfTheGroupIsTestedOnItsOwnPorts()

        /// <summary>
        /// The detailed test asks a server of the group on the ports that server
        /// is configured with, and not on those of the single client.
        /// </summary>
        /// <remarks>
        /// It used to take the single client's ports for every server, so a
        /// server with a port of its own was asked on the usual one and reported
        /// as not answering. Name resolution is switched off here, so that
        /// nothing goes out: the first step names the ports before anything is
        /// asked, and the rest fails at once.
        /// </remarks>
        [Test]
        public async Task AServerOfTheGroupIsTestedOnItsOwnPorts()
        {

            await using var node = Node("""
                                        { "dns": { "enabled": false },
                                          "nts": { "servers": [ "a.example",
                                                                { "hostname": "b.example", "ntsKEPort": 4461, "ntpPort": 1234 } ],
                                                   "timeoutSeconds": 1 } }
                                        """);

            var result = await node.TestTimeServerAsync("b.example");

            Assert.That(result["steps"]?[0]?.Value<String>("text"),
                        Does.Contain("key exchange on port 4461").And.Contain("time on port 1234"));

        }

        #endregion

        #region TheTestWritesTheNameAsItIsRead()

        /// <summary>
        /// The detailed test names the server the way everything else this
        /// node prints does: without the root's dot.
        /// </summary>
        /// <remarks>
        /// "Asking ptbtime2.ptb.de.: key exchange on port 4460" - the name is
        /// exact with the dot, and in the middle of a sentence it reads like a
        /// typing mistake. The steps and the log lines use the name as it is
        /// read; the name the result carries as data is left as it is. Name
        /// resolution is switched off, so that nothing goes out.
        /// </remarks>
        [Test]
        public async Task TheTestWritesTheNameAsItIsRead()
        {

            await using var node = Node("""
                                        { "dns": { "enabled": false },
                                          "nts": { "servers": [ "a.example", "b.example" ], "timeoutSeconds": 1 } }
                                        """);

            var before  = node.Log.LastId;
            var result  = await node.TestTimeServerAsync("b.example");
            var said    = node.Log.Recent(50, before, "test").Select(entry => entry.Message).ToArray();

            Assert.Multiple(() =>
            {
                Assert.That(result["steps"]?[0]?.Value<String>("text"),  Does.StartWith("Asking b.example:"));
                Assert.That(said,                                          Has.Some.EqualTo("NTS test: asking b.example ..."),  String.Join(" | ", said));
            });

        }

        #endregion

    }

}
