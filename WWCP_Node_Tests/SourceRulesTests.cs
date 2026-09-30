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

using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The rules the kit holds every kind's C# source to, asked of lines made
    /// up for them - and of this node's own source.
    /// </summary>
    public class SourceRulesTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "node-source-rules-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }

        #endregion


        #region AnArticleBeforeANameIsFound(Line)

        /// <summary>
        /// An article in front of an interpolated name is found: the kind of a
        /// node, the kind of a certificate by AsText() or Describe(), the name
        /// of an algorithm, a label - "an" as well as "a", where it fits one
        /// name and not the next.
        /// </summary>
        [TestCase("""Assume.That(x, $"A {Node.Kind.Name} needs the identity it has just been given.");""")]
        [TestCase("""Error = $"That certificate is already in the store as a {existing.Kind.AsText()} " +""")]
        [TestCase("""Error = $"A {Kind.Describe()} has to carry its private key, and that file has none. " +""")]
        [TestCase("""Problem = $"is not a TLS identity, but a {entry.Kind.Describe(NodeName)}.";""")]
        [TestCase("""Error = $"An {algorithm.Name} key could not be generated: {e.Message}";""")]
        [TestCase("""Log.Notice($"'{user.Id}' put it in as a {entry.Label}.");""")]
        [TestCase("""var text = $@"out of a {kind.Name} key";""")]
        public void AnArticleBeforeANameIsFound(String Line)
        {

            File.WriteAllText(Path.Combine(directory, "Some.cs"), $"namespace Some\n{{\n    {Line}\n}}\n");

            var found = SourceRules.ArticlesBeforeANameIn(directory);

            Assert.That(found, Has.Count.EqualTo(1));
            Assert.That(found[0], Is.EqualTo($"{Path.GetFileName(directory)}/Some.cs:3: {Line}"));

        }

        #endregion

        #region WhatIsNoArticleBeforeANameIsNotFound(Line)

        /// <summary>
        /// What is not found: a name said with its article or without one, an
        /// article before what is no name, "a" inside a word, a comment, a
        /// string that interpolates nothing.
        /// </summary>
        [TestCase("""Assume.That(x, $"This {Node.Kind.Name} needs the identity it has just been given.");""")]
        [TestCase("""Error = $"{Kind.CapitalisedWithArticle()} has to carry its private key.";""")]
        [TestCase("""Error = $"already in the store as {existing.Kind.WithArticle()} ";""")]
        [TestCase("""yield return $"  It is shown here once and kept only as a {SecurePassword.PBKDF2SHA256} hash";""")]
        [TestCase("""Assert.That(elapsed, Is.LessThan(max), $"took {elapsed.TotalSeconds:F1} s, a {count} times");""")]
        [TestCase("""Log.Info($"signed in via {user.Name}");""")]
        [TestCase("""// Assume.That(x, $"A {Node.Kind.Name} needs ...") - in a comment, which is no text anybody reads.""")]
        [TestCase("""/// <code>Error = $"A {Kind.Describe()} has to carry its key";</code> in the documentation.""")]
        [TestCase("""var template = "A {Node.Kind.Name} with no $ in front";""")]
        public void WhatIsNoArticleBeforeANameIsNotFound(String Line)
        {

            File.WriteAllText(Path.Combine(directory, "Some.cs"), $"namespace Some\n{{\n    {Line}\n}}\n");

            Assert.That(SourceRules.ArticlesBeforeANameIn(directory), Is.Empty);

        }

        #endregion

        #region WhatIsBuiltIsNotRead()

        /// <summary>
        /// Below bin, obj and node_modules is what a build or npm made, and
        /// nobody's source.
        /// </summary>
        [Test]
        public void WhatIsBuiltIsNotRead()
        {

            foreach (var built in new[] { "bin", "obj", "node_modules" })
            {
                Directory.CreateDirectory(Path.Combine(directory, built, "Debug"));
                File.WriteAllText(Path.Combine(directory, built, "Debug", "Generated.cs"), "var x = $\"A {Node.Kind.Name}\";\n");
            }

            File.WriteAllText(Path.Combine(directory, "Some.cs"), "var x = $\"A {Node.Kind.Name}\";\n");

            Assert.That(SourceRules.ArticlesBeforeANameIn(directory), Is.EqualTo(new[] {
                            $"{Path.GetFileName(directory)}/Some.cs:1: var x = $\"A {{Node.Kind.Name}}\";"
                        }));

        }

        #endregion

        #region NoTextOfThisNodePutsAnArticleBeforeAName()

        /// <summary>
        /// Nothing the node or the kit says puts an article in front of a name
        /// it interpolates. The kit's said "A electric vehicle", "A energy meter"
        /// and "A EMSP" in the messages of the conformance tests every kind runs
        /// (found by the EV), and the node refused a keyless OEM provisioning
        /// certificate as "A OEM provisioning certificate - what this vehicle was
        /// born with has to carry its private key".
        /// </summary>
        [Test]
        public void NoTextOfThisNodePutsAnArticleBeforeAName()
        {

            var repository = SourceRules.RepositoryAbove(AppContext.BaseDirectory, "WWCP_Node", "WWCP_Node_TestKit");

            Assert.That(SourceRules.ArticlesBeforeANameIn(Path.Combine(repository, "WWCP_Node"),
                                                          Path.Combine(repository, "WWCP_Node_TestKit")),
                        Is.Empty);

        }

        #endregion

        #region TheRepositoryIsFoundAboveWhereItsTestsRun()

        /// <summary>
        /// The repository is the nearest directory above that holds what it is
        /// said to - and one that holds nothing of the kind is said to be
        /// nowhere, rather than taken to be the disk's root.
        /// </summary>
        [Test]
        public void TheRepositoryIsFoundAboveWhereItsTestsRun()
        {

            var repository = SourceRules.RepositoryAbove(AppContext.BaseDirectory, "WWCP_Node", "WWCP_Node_TestKit");

            Assert.Multiple(() => {
                Assert.That(File.Exists(Path.Combine(repository, "WWCP_Node_TestKit", "SourceRules.cs")), Is.True, repository);
                Assert.That(() => SourceRules.RepositoryAbove(directory, "no-such-" + Guid.NewGuid().ToString("N")),
                            Throws.TypeOf<DirectoryNotFoundException>());
            });

        }

        #endregion

    }

}
