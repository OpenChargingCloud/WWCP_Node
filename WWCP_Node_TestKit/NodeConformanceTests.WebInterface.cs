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

using NUnit.Framework;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// What a browser gets before it has signed in to anything: the
    /// single-page-application stub, the bundle it references, and the line
    /// between a page URL and a file that is not there.
    /// </summary>
    /// <remarks>
    /// The bundle is the one the kind of node was built with, which means
    /// these also say whether the build embedded it. A node built without one
    /// serves a browser nothing, and says so at every start; these tests are
    /// not run against it - inconclusive, and saying why - rather than passed.
    /// </remarks>
    public abstract partial class NodeConformanceTests
    {

        #region (private) HasAWebInterface()

        private void HasAWebInterface()

            => Assume.That(Node.WebInterface, Is.Not.Null,
                           $"This {Node.Kind.Name} was built without its web interface: {Node.Frontend.Description}");

        #endregion


        #region ServesTheApplicationStub()

        [Test]
        public async Task ServesTheApplicationStub()
        {

            HasAWebInterface();

            using var http     = Anonymous();

            var response       = await http.GetAsync("");
            var html           = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(response.IsSuccessStatusCode,                                 Is.True);
                Assert.That(response.Content.Headers.ContentType?.MediaType,              Is.EqualTo("text/html"));
                Assert.That(html.Contains("<div id=\"app\">", StringComparison.Ordinal),  Is.True,
                            "The stub is what the bundle renders into; without that element there is nothing to render into.");
            });

        }

        #endregion

        #region TheStubCarriesTheVersionOfTheNode()

        /// <summary>
        /// The server replaces {{ServerVersion}} as it serves the stub, and the
        /// bundle reads it out of a meta tag rather than from an inline script -
        /// which is what lets the Content-Security-Policy stay strict.
        /// </summary>
        [Test]
        public async Task TheStubCarriesTheVersionOfTheNode()
        {

            HasAWebInterface();

            using var http = Anonymous();

            var html = await http.GetStringAsync("");

            Assert.Multiple(() => {
                Assert.That(html.Contains($"content=\"v{Node.Version}\"", StringComparison.Ordinal),  Is.True,
                            $"The stub does not carry the version of the {Node.Kind.Name} that served it.");
                Assert.That(html.Contains("{{ServerVersion}}", StringComparison.Ordinal),             Is.False,
                            "The placeholder was served as it stands, so nothing replaced it.");
            });

        }

        #endregion

        #region TheStubReferencesABundleThatIsServed()

        /// <summary>
        /// Relative, and the &lt;base href&gt; above it is what it resolves
        /// against: the same bundle is served at "/" on a port of its own and
        /// below a path where several nodes share one server, and an absolute
        /// "/assets/..." would only ever have worked at the first.
        /// </summary>
        [Test]
        public async Task TheStubReferencesABundleThatIsServed()
        {

            HasAWebInterface();

            using var http = Anonymous();

            var html   = await http.GetStringAsync("");

            var start  = html.IndexOf("\"assets/main.", StringComparison.Ordinal);

            Assert.That(start, Is.GreaterThan(-1), "The stub references no bundle at all.");

            var script = html[(start + 1)..html.IndexOf('"', start + 1)];

            var bundle = await http.GetAsync(script);

            Assert.Multiple(() => {
                Assert.That(bundle.IsSuccessStatusCode,            Is.True, $"'{script}' is referenced and not served.");
                Assert.That(bundle.Content.Headers.ContentLength,  Is.GreaterThan(0));
            });

        }

        #endregion

        #region FaviconIcoIsPointedAtTheSVG()

        /// <summary>
        /// Browsers ask for /favicon.ico whatever the page says, and a bundle
        /// built by webpack carries an SVG.
        /// </summary>
        [Test]
        public async Task FaviconIcoIsPointedAtTheSVG()
        {

            HasAWebInterface();

            using var handler  = new HttpClientHandler { AllowAutoRedirect = false };
            using var http     = new HttpClient(handler) { BaseAddress = new Uri(BaseURL) };

            var response       = await http.GetAsync("favicon.ico");

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                    Is.EqualTo(HttpStatusCode.TemporaryRedirect));
                Assert.That(response.Headers.Location?.ToString(),  Does.EndWith("/favicon.svg"));
            });

        }

        #endregion

        #region ADeepPageURLGetsTheStub()

        /// <summary>
        /// A reload on a page below the root and a bookmark to it are the same
        /// request, and both have to arrive at the application rather than at a
        /// 404 - the router in the browser decides what that URL means.
        /// </summary>
        [Test]
        public async Task ADeepPageURLGetsTheStub()
        {

            HasAWebInterface();

            using var http = Anonymous();

            var response   = await http.GetAsync("configuration/nts");
            var html       = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(response.IsSuccessStatusCode,                                 Is.True);
                Assert.That(html.Contains("<div id=\"app\">", StringComparison.Ordinal),  Is.True);
            });

        }

        #endregion

        #region AMissingAssetIsARealNotFound()

        /// <summary>
        /// The other side of the line above, and the reason it is drawn at all:
        /// a mistyped script tag has to be a 404 rather than the stub with
        /// status 200, or the browser is handed HTML to execute and a
        /// deployment that forgot half its bundle looks healthy.
        /// </summary>
        [Test]
        public async Task AMissingAssetIsARealNotFound()
        {

            HasAWebInterface();

            using var http = Anonymous();

            var response   = await http.GetAsync("assets/nothing-was-built-here.js");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));

        }

        #endregion

    }

}
