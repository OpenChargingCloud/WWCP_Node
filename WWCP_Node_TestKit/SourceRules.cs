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
    /// as Frontend/test/pages.ts asks the pages'. A kind of node asks its own,
    /// its repository found by a file of each project rather than by their
    /// directories:
    /// <code>
    /// var repository = SourceRules.RepositoryAbove(AppContext.BaseDirectory, "LocalController/LocalController.csproj",
    ///                                                                        "LocalControllerTests/LocalControllerTests.csproj");
    ///
    /// Assert.That(SourceRules.ArticlesBeforeANameIn(Path.Combine(repository, "LocalController")), Is.Empty);
    /// </code>
    /// </summary>
    public static class SourceRules
    {

        #region Data

        /// <summary>
        /// A hole that holds a name: anything called ...Name, a kind's AsText()
        /// or Describe(), a label, a title.
        /// </summary>
        private const String aName = @"\{[^{}]*\b(?:\w*Name|AsText\(\)|Describe\([^{}]*\)|Label|Title)\}";

        /// <summary>
        /// "a" or "an" as a word of its own, right before a hole that holds a
        /// name.
        /// </summary>
        private static readonly Regex articleBeforeAName  = new (@"(?<!\w)[Aa]n? " + aName, RegexOptions.Compiled);

        /// <summary>
        /// "a" or "an" as a word of its own at the end of a string that goes on
        /// in the next line: "... is a " + - or with the + in front of the next.
        /// </summary>
        private static readonly Regex articleAtTheEnd     = new (@"(?<!\w)[Aa]n? ""\s*\+?$", RegexOptions.Compiled);

        /// <summary>
        /// A string that begins with a hole that holds a name, where it goes on
        /// from the line before: $"{Kind.AsText()} ..." - or + $"{Kind.AsText()} ...".
        /// </summary>
        private static readonly Regex beginsWithAName     = new (@"^(?:\+\s*)?\$@?""" + aName, RegexOptions.Compiled);

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
        /// An article at the end of a line whose string goes on in the next one
        /// is read with that one, where it begins with a name: "is a " + and
        /// $"{entry.Kind.AsText()} ..." below it read "is a oemRoot", one line
        /// at a time unseen (found by the EV). A directory with no C# file below
        /// it is refused rather than found clean: asked of nothing, the rule
        /// says nothing, and a repository taken to be a build's artifacts/bin
        /// passed that way (found by the charging station).
        /// </para>
        /// </remarks>
        /// <param name="Directories">Where the sources are.</param>
        /// <returns>For each such line "directory/file:line: the line" - the line with the article, and the next one after it where the name is there - a directory's files before those below it.</returns>
        /// <exception cref="InvalidOperationException">A directory holds no C# file.</exception>
        public static IReadOnlyList<String> ArticlesBeforeANameIn(params String[] Directories)
        {

            var found = new List<String>();

            foreach (var directory in Directories)
            {

                var read = 0;

                foreach (var file in SourcesBelow(directory))
                {

                    read++;

                    var where    = $"{Path.GetFileName(Path.TrimEndingDirectorySeparator(directory))}/{Path.GetRelativePath(directory, file).Replace('\\', '/')}";
                    var number   = 0;
                    var before   = (String?) null;

                    foreach (var line in File.ReadLines(file))
                    {

                        number++;

                        var code     = line.Trim();
                        var ended    = before;

                        before       = null;

                        if (code.StartsWith("//", StringComparison.Ordinal))
                            continue;

                        if (ended is not null && beginsWithAName.IsMatch(code))
                            found.Add($"{where}:{number - 1}: {ended} {code}");

                        if (articleAtTheEnd.IsMatch(code))
                            before = code;

                        if (!code.Contains("$\"",  StringComparison.Ordinal) &&
                            !code.Contains("$@\"", StringComparison.Ordinal))
                        {
                            continue;
                        }

                        if (articleBeforeAName.IsMatch(code))
                            found.Add($"{where}:{number}: {code}");

                    }

                }

                if (read == 0)
                    throw new InvalidOperationException($"There is no C# file below '{directory}' to ask: a rule asked of nothing says nothing. " +
                                                         "Is it where the sources are?");

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
        /// given files or directories, each named by its path below it: a
        /// repository's own, found from where its tests run -
        /// "RepositoryAbove(AppContext.BaseDirectory, "WWCP_Node/WWCP_Node.csproj",
        /// "WWCP_Node_TestKit/WWCP_Node_TestKit.csproj")".
        /// </summary>
        /// <remarks>
        /// Name a file of each project, not its directory. Built with
        /// --artifacts-path, a build's artifacts/bin holds a directory named
        /// after every project, and was taken for the repository its tests ran
        /// in when directories were named (found by the charging station).
        /// </remarks>
        /// <param name="Start">Where to begin, usually AppContext.BaseDirectory.</param>
        /// <param name="Holding">The files or directories it has to hold, by their paths below it.</param>
        /// <exception cref="DirectoryNotFoundException">No directory above holds them all.</exception>
        public static String RepositoryAbove(String           Start,
                                             params String[]  Holding)
        {

            for (var directory = new DirectoryInfo(Start); directory is not null; directory = directory.Parent)
                if (Holding.All(name => File.     Exists(Path.Combine(directory.FullName, name)) ||
                                        Directory.Exists(Path.Combine(directory.FullName, name))))
                    return directory.FullName;

            throw new DirectoryNotFoundException($"No directory at or above '{Start}' holds {String.Join(" and ", Holding)}.");

        }

        #endregion

    }

}
