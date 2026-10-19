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
    /// The groups of time servers over the JSON API, the same on every kind of
    /// node: listed, made switched off, changed at their names, taken away
    /// switched off - and the routes from before there were groups as the
    /// legal group's.
    /// </summary>
    /// <remarks>
    /// The kit's node has its time client switched off, so nothing here asks a
    /// time server: what is asked of a group is asked of one that is switched
    /// off, or names nobody.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        private const String NTSGroupsPath = "api/v1/configuration/nts/groups";

        #region (private) OnDisk

        private JObject OnDisk
            => JObject.Parse(File.ReadAllText(Node.ConfigFile.Path));

        #endregion


        #region TheGroupsAreListedWithTheNamesLeftToSuggest()

        [Test]
        public async Task TheGroupsAreListedWithTheNamesLeftToSuggest()
        {

            using var http  = await SignedIn();

            var groups      = await GetJSON(http, NTSGroupsPath);

            Assert.Multiple(() => {
                Assert.That(groups["groups"]?.Select(group => group.Value<String>("id")),  Is.EqualTo(new[] { "legal" }));
                Assert.That(groups["groups"]?[0]?.Value<Boolean>("legal"),                 Is.True);
                Assert.That(groups["groups"]?[0]?.Value<Boolean>("enabled"),               Is.False,  "the kit's node has its time client switched off");
                Assert.That(groups["suggested"]?.Values<String>(),                         Is.EqualTo(new[] { "local", "grid" }),  "the names not taken yet");
                Assert.That(groups["limits"]?.Value<Int32>("maxIdLength"),                 Is.GreaterThan(0));
            });

        }

        #endregion

        #region AGroupIsMadeSwitchedOff()

        [Test]
        public async Task AGroupIsMadeSwitchedOff()
        {

            using var http         = await SignedIn();

            var (status, made)     = await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "local", "displayName": { "en": "Local time", "de": "Lokale Zeit" } }"""));
            var groups             = await GetJSON(http, NTSGroupsPath);
            var local              = await GetJSON(http, $"{NTSGroupsPath}/local");

            Assert.Multiple(() => {

                Assert.That(status,                                                        Is.EqualTo(HttpStatusCode.Created),  made.ToString());
                Assert.That(made.Value<String>("id"),                                      Is.EqualTo("local"));
                Assert.That(made.Value<Boolean>("enabled"),                                Is.False);
                Assert.That(made.Value<Boolean>("legal"),                                  Is.False);
                Assert.That(made["displayName"]?.Value<String>("de"),                      Is.EqualTo("Lokale Zeit"));
                Assert.That(made["timeSources"],                                           Is.Empty,  "naming no server yet");

                Assert.That(groups["groups"]?.Select(group => group.Value<String>("id")),  Is.EqualTo(new[] { "legal", "local" }));
                Assert.That(groups["suggested"]?.Values<String>(),                         Is.EqualTo(new[] { "grid" }));
                Assert.That(local.Value<String>("id"),                                     Is.EqualTo("local"));

                Assert.That(OnDisk["nts"]?["groups"]?["local"]?.Value<Boolean>("enabled"), Is.False,  "and written down");

            });

        }

        #endregion

        #region AGroupOfANameTakenIsAConflict()

        [Test]
        public async Task AGroupOfANameTakenIsAConflict()
        {

            using var http      = await SignedIn();

            var (legal,  _)     = await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "legal" }"""));
            var (first,  _)     = await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "grid" }"""));
            var (second, error) = await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "grid" }"""));

            Assert.Multiple(() => {
                Assert.That(legal,                        Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(first,                        Is.EqualTo(HttpStatusCode.Created));
                Assert.That(second,                       Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(error.Value<String>("error"), Does.Contain("has an NTS group 'grid' already"));
            });

        }

        #endregion

        #region WhatCannotBeAGroupIsRefused(Body, Says)

        [TestCase("""{ "id": "Local" }""",                                      "cannot be the name of a group")]
        [TestCase("""{ "id": 42 }""",                                           "'id' must be the name of the group")]
        [TestCase("""{ }""",                                                    "'id' must be the name of the group")]
        [TestCase("""{ "id": "local", "displayName": { "english": "x" } }""",  "'english' is not a language")]
        [TestCase("""{ "id": "local", "displayName": 42 }""",                  "'nts.groups.local.displayName' must be a string")]
        public async Task WhatCannotBeAGroupIsRefused(String Body, String Says)
        {

            using var http         = await SignedIn();

            var (status, error)    = await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse(Body));
            var groups             = await GetJSON(http, NTSGroupsPath);

            Assert.Multiple(() => {
                Assert.That(status,                                                        Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(error.Value<String>("error"),                                  Does.Contain(Says));
                Assert.That(groups["groups"]?.Select(group => group.Value<String>("id")),  Is.EqualTo(new[] { "legal" }));
            });

        }

        #endregion

        #region AGroupThereIsNotIsNotFound(Method, Path)

        [TestCase("GET",     "nothing")]
        [TestCase("PUT",     "nothing")]
        [TestCase("DELETE",  "nothing")]
        [TestCase("POST",    "nothing/sync")]
        [TestCase("POST",    "nothing/test")]
        [TestCase("GET",     "Legal")]
        public async Task AGroupThereIsNotIsNotFound(String Method, String Path)
        {

            using var http         = await SignedIn();

            var (status, error)    = await Send(http, new HttpMethod(Method), $"{NTSGroupsPath}/{Path}", Method == "GET" || Method == "DELETE" ? null : new JObject());

            Assert.Multiple(() => {
                Assert.That(status,                        Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(error.Value<String>("error"),  Does.Contain("has no NTS group"));
            });

        }

        #endregion

        #region AGroupIsChangedAtItsName()

        [Test]
        public async Task AGroupIsChangedAtItsName()
        {

            using var http          = await SignedIn();

            await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "local" }"""));

            var (changed, local)    = await Send(http, HttpMethod.Put, $"{NTSGroupsPath}/local", JObject.Parse("""{ "servers": [ "lc1.local", "lc2.local" ], "minServers": 2, "checkEverySeconds": 30 }"""));
            var (claimed, refusal)  = await Send(http, HttpMethod.Put, $"{NTSGroupsPath}/local", JObject.Parse("""{ "legalTimeAuthority": "PTB" }"""));
            var legal               = await GetJSON(http, $"{NTSGroupsPath}/legal");

            Assert.Multiple(() => {

                Assert.That(changed,                                                              Is.EqualTo(HttpStatusCode.OK),  local.ToString());
                Assert.That(local["timeSources"]?.Select(source => source.Value<String>("hostname")),  Is.EqualTo(new[] { "lc1.local.", "lc2.local." }));
                Assert.That(local["settings"]?.Value<Int32>("minServers"),                        Is.EqualTo(2));
                Assert.That(local["settings"]?.Value<Double>("checkEverySeconds"),                Is.EqualTo(30));

                Assert.That(claimed,                                                              Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(refusal.Value<String>("error"),                                       Does.Contain("only the group 'legal'"));

                Assert.That(legal["settings"]?.Value<Double>("checkEverySeconds"),                Is.Not.EqualTo(30),  "and the legal group is as it was");

            });

        }

        #endregion

        #region AGroupIsTakenAwayOnlySwitchedOff()

        [Test]
        public async Task AGroupIsTakenAwayOnlySwitchedOff()
        {

            using var http               = await SignedIn();

            await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "local" }"""));
            await Send(http, HttpMethod.Put,  $"{NTSGroupsPath}/local", JObject.Parse("""{ "servers": [ "lc1.local" ], "enabled": true }"""));

            var (whileOn,  refusal)      = await Send(http, HttpMethod.Delete, $"{NTSGroupsPath}/local");

            await Send(http, HttpMethod.Put,  $"{NTSGroupsPath}/local", JObject.Parse("""{ "enabled": false }"""));

            var (whileOff, left)         = await Send(http, HttpMethod.Delete, $"{NTSGroupsPath}/local");
            var (gone,     _)            = await Send(http, HttpMethod.Get,    $"{NTSGroupsPath}/local");

            Assert.Multiple(() => {

                Assert.That(whileOn,                                                      Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(refusal.Value<String>("error"),                               Does.Contain("switch it off before removing it"));

                Assert.That(whileOff,                                                     Is.EqualTo(HttpStatusCode.OK),  left.ToString());
                Assert.That(left["groups"]?.Select(group => group.Value<String>("id")),   Is.EqualTo(new[] { "legal" }),  "answered with the groups that are left");
                Assert.That(gone,                                                         Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(OnDisk["nts"]?["groups"]?["local"],                           Is.Null);

            });

        }

        #endregion

        #region TheRoutesFromBeforeGroupsAreTheLegalGroups()

        [Test]
        public async Task TheRoutesFromBeforeGroupsAreTheLegalGroups()
        {

            using var http          = await SignedIn();

            var (saved, _)          = await Send(http, HttpMethod.Put, "api/v1/configuration/nts", JObject.Parse("""{ "checkEverySeconds": 600 }"""));

            var old                 = await GetJSON(http, "api/v1/configuration/nts");
            var legal               = await GetJSON(http, $"{NTSGroupsPath}/legal");

            Assert.Multiple(() => {
                Assert.That(saved,                                                   Is.EqualTo(HttpStatusCode.OK));
                Assert.That(old.Value<String>("id"),                                 Is.EqualTo("legal"));
                Assert.That(JToken.DeepEquals(old["settings"], legal["settings"]),   Is.True,  "one group, by either route");
                Assert.That(legal["settings"]?.Value<Double>("checkEverySeconds"),   Is.EqualTo(600));
            });

        }

        #endregion

        #region WithoutALegalGroupTheRoutesFromBeforeGroupsAreNotFound()

        /// <summary>
        /// A node without legal time: its legal group switched off and taken
        /// away, the routes about it say 404 rather than making one up - until
        /// it is made again.
        /// </summary>
        [Test]
        public async Task WithoutALegalGroupTheRoutesFromBeforeGroupsAreNotFound()
        {

            using var http          = await SignedIn();

            var (removed, _)        = await Send(http, HttpMethod.Delete, $"{NTSGroupsPath}/legal");

            var (read,    _)        = await Send(http, HttpMethod.Get,  "api/v1/configuration/nts");
            var (changed, _)        = await Send(http, HttpMethod.Put,  "api/v1/configuration/nts",      new JObject(new JProperty("enabled", true)));
            var (synced,  _)        = await Send(http, HttpMethod.Post, "api/v1/configuration/nts/sync", new JObject());
            var (tested,  _)        = await Send(http, HttpMethod.Post, "api/v1/configuration/nts/test", new JObject());
            var clock               = await GetJSON(http, "api/v1/clock");

            var (madeAgain, _)      = await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "legal" }"""));
            var (readAgain, again)  = await Send(http, HttpMethod.Get,  "api/v1/configuration/nts");

            Assert.Multiple(() => {

                Assert.That(removed,                         Is.EqualTo(HttpStatusCode.OK));
                Assert.That(read,                            Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(changed,                         Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(synced,                          Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(tested,                          Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(clock.Value<Boolean>("legal"),   Is.False);
                Assert.That(clock["groups"],                 Is.Empty);
                Assert.That(Node.NTSEnabled,                 Is.False);

                Assert.That(madeAgain,                       Is.EqualTo(HttpStatusCode.Created));
                Assert.That(readAgain,                       Is.EqualTo(HttpStatusCode.OK));
                Assert.That(again.Value<Boolean>("enabled"), Is.False,  "made again switched off, like any group");

            });

        }

        #endregion

        #region AGroupSwitchedOffIsAskedNothing()

        [Test]
        public async Task AGroupSwitchedOffIsAskedNothing()
        {

            using var http           = await SignedIn();

            await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "grid" }"""));

            var (synced, sync)       = await Send(http, HttpMethod.Post, $"{NTSGroupsPath}/grid/sync", new JObject());
            var (tested, test)       = await Send(http, HttpMethod.Post, $"{NTSGroupsPath}/grid/test", new JObject());

            Assert.Multiple(() => {
                Assert.That(synced,                                       Is.EqualTo(HttpStatusCode.OK));
                Assert.That(sync["result"]?.Value<Boolean>("ok"),         Is.False);
                Assert.That(sync.Value<String>("id"),                     Is.EqualTo("grid"),  "answered with the group, as the legal one is");
                Assert.That(tested,                                       Is.EqualTo(HttpStatusCode.OK));
                Assert.That(test.Value<Boolean>("ok"),                    Is.False);
            });

        }

        #endregion

        #region TheClockSaysWhatEveryGroupFound()

        [Test]
        public async Task TheClockSaysWhatEveryGroupFound()
        {

            using var http  = await SignedIn();

            await Send(http, HttpMethod.Post, NTSGroupsPath, JObject.Parse("""{ "id": "local", "displayName": "Local time" }"""));

            var clock       = await GetJSON(http, "api/v1/clock");

            Assert.Multiple(() => {
                Assert.That(clock["groups"]?.Select(group => group.Value<String>("id")),  Is.EqualTo(new[] { "legal", "local" }));
                Assert.That(clock["groups"]?[1]?.Value<String>("displayName"),            Is.EqualTo("Local time"));
                Assert.That(clock["groups"]?[1]?["checkedAt"]?.Type,                      Is.EqualTo(JTokenType.Null),  "never checked");
            });

        }

        #endregion

    }

}
