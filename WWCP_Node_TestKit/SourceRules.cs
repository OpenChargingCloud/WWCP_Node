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

using System.Text.RegularExpressions;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// What the code of every kind of node is held to, asked of its C# source -
    /// as Frontend/test/pages.ts asks the pages'. A kind of node asks its own:
    /// <code>
    /// Assert.That(SourceRules.ArticlesBeforeANameIn(Path.Combine(SourceRules.RepositoryAbove(AppContext.BaseDirectory, "EV", "EVTests"), "EV")),
    ///             Is.Empty);
    /// </code>
    /// </summary>
    public static class SourceRules
    {

        #region Data

        /// <summary>
        /// "a" or "an" as a word of its own, right before a hole that holds a
        /// name: anything called ...Name, a kind's AsText() or Describe(), a
        /// label, a title.
        /// </summary>
        private static readonly Regex articleBeforeAName = new (@"(?<!\w)[Aa]n? \{[^{}]*\b(?:\w*Name|AsText\(\)|Describe\([^{}]*\)|Label|Title)\}",
                                                               RegexOptions.Compiled);

        #endregion


        #region ArticlesBeforeANameIn(params Directories)

        /// <summary>
        /// Every line of the C# files below the given directories that puts "a"
        /// or "an" in front of a name it interpolates.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Which article a name takes goes by how the name is said, and the
        /// text cannot know that for a name it is handed. "The store of a
        /// {Node.Kind.Name}" read "a electric vehicle", "a energy meter" and "a
        /// EMSP" (found by the EV); "as a {Kind.AsText()}" read "as a oemRoot";
        /// and "A {algorithm.Name} key could not be generated" was wrong for
        /// every key the local controller makes - "A ECDSA P-256", "A RSA 2048".
        /// A name is said with its article, as CertificateKind.WithArticle()
        /// says it, or without one: "this electric vehicle".
        /// </para>
        /// <para>
        /// Only lines that interpolate are read, and neither comments nor what
        /// is below bin, obj and node_modules - what a build or npm put there.
        /// </para>
        /// </remarks>
        /// <param name="Directories">Where the sources are.</param>
        /// <returns>For each such line "directory/file:line: the line", a directory's files before those below it.</returns>
        public static IReadOnlyList<String> ArticlesBeforeANameIn(params String[] Directories)
        {

            var found = new List<String>();

            foreach (var directory in Directories)
            {

                foreach (var file in SourcesBelow(directory))
                {

                    var relative = Path.GetRelativePath(directory, file).Replace('\\', '/');
                    var number   = 0;

                    foreach (var line in File.ReadLines(file))
                    {

                        number++;

                        var code = line.Trim();

                        if (code.StartsWith("//", StringComparison.Ordinal) ||
                            !code.Contains("$\"",  StringComparison.Ordinal) &&
                            !code.Contains("$@\"", StringComparison.Ordinal))
                        {
                            continue;
                        }

                        if (articleBeforeAName.IsMatch(code))
                            found.Add($"{Path.GetFileName(Path.TrimEndingDirectorySeparator(directory))}/{relative}:{number}: {code}");

                    }

                }

            }

            return found;

        }

        #endregion

        #region (private) SourcesBelow(Directory)

        /// <summary>
        /// The C# files of a directory, then those of the directories below it,
        /// but for bin, obj and node_modules - which are not walked at all: a
        /// frontend's node_modules holds tens of thousands of files.
        /// </summary>
        private static IEnumerable<String> SourcesBelow(String Directory)
        {

            foreach (var file in System.IO.Directory.EnumerateFiles(Directory, "*.cs").Order(StringComparer.Ordinal))
                yield return file;

            foreach (var below in System.IO.Directory.EnumerateDirectories(Directory).Order(StringComparer.Ordinal))
                if (Path.GetFileName(below) is not ("bin" or "obj" or "node_modules"))
                    foreach (var file in SourcesBelow(below))
                        yield return file;

        }

        #endregion

        #region RepositoryAbove(Start, params Holding)

        /// <summary>
        /// The nearest directory at or above the given one that holds all of the
        /// given directories: a repository's own, found from where its tests
        /// run - "RepositoryAbove(AppContext.BaseDirectory, "WWCP_Node",
        /// "WWCP_Node_TestKit")".
        /// </summary>
        /// <param name="Start">Where to begin, usually AppContext.BaseDirectory.</param>
        /// <param name="Holding">The directories it has to hold.</param>
        /// <exception cref="DirectoryNotFoundException">No directory above holds them all.</exception>
        public static String RepositoryAbove(String           Start,
                                             params String[]  Holding)
        {

            for (var directory = new DirectoryInfo(Start); directory is not null; directory = directory.Parent)
                if (Holding.All(name => Directory.Exists(Path.Combine(directory.FullName, name))))
                    return directory.FullName;

            throw new DirectoryNotFoundException($"No directory at or above '{Start}' holds {String.Join(" and ", Holding)}.");

        }

        #endregion

    }

}
