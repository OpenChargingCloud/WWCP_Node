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

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// Nodes of no particular kind, one directory to each, for the tests that
    /// ask a node something without going through its web interface.
    /// </summary>
    /// <remarks>
    /// Its own class rather than a few protected methods on a fixture base,
    /// because not every test wants a node that is started and taken away again
    /// for it: the clock is a question one can be asked without a socket, and
    /// the start is what some of these tests are about.
    /// </remarks>
    internal static class TestNodes
    {

        #region New(Directory, Configuration = null, Clock = null, ...)

        /// <summary>
        /// A node, built and not started.
        /// </summary>
        /// <remarks>
        /// Not started, and that is often the point: it is <c>Start()</c> that
        /// puts a timer on the network to check the clock, so a node that was
        /// only built is also one that will not quietly go and ask a time
        /// server in the middle of a test run.
        ///
        /// It is also <c>Start()</c> that makes the accounts, so a node that
        /// was only built has none yet and no password to show for them.
        /// </remarks>
        /// <param name="Directory">Where its accounts, its configuration and its certificates go; created when it does not exist.</param>
        /// <param name="Configuration">What its configuration file says, or null for a node nobody has configured.</param>
        /// <param name="Clock">Where it reads the time, for a test that needs to decide what time it is.</param>
        /// <param name="LogToConsole">Whether its log reaches the console, for a test about who gets to write there. Off otherwise, because a test run's console is for the test run.</param>
        /// <param name="LogPath">A directory for its log files, for a test about those. None otherwise.</param>
        public static WWCPNode New(String         Directory,
                                   JObject?       Configuration   = null,
                                   TimeProvider?  Clock           = null,
                                   Boolean        LogToConsole    = false,
                                   String?        LogPath         = null)
        {

            System.IO.Directory.CreateDirectory(Directory);

            var configFile = Path.Combine(Directory, WWCPConfigFile.DefaultFileName);

            if (Configuration is not null)
                File.WriteAllText(configFile, Configuration.ToString());

            return new WWCPNode(
                       HTTPPort:          IPPort.Parse(TestPorts.Free()),
                       AccountsPath:      Path.Combine(Directory, "accounts"),
                       ConfigFile:        new WWCPConfigFile(configFile),
                       CertificatesPath:  Path.Combine(Directory, "certificates"),
                       LogToConsole:      LogToConsole,
                       LogPath:           LogPath,
                       BridgeDebugLog:    false,
                       TimeProvider:      Clock
                   );

        }

        #endregion

        #region Offline

        /// <summary>
        /// A configuration with the time client switched off.
        /// </summary>
        /// <remarks>
        /// Written before a node is built, because that is when it is read, and
        /// switched off there rather than afterwards because it is
        /// <c>Start()</c> that would otherwise schedule the first check. A test
        /// run has no business asking a public time server anything.
        /// </remarks>
        public static JObject Offline

            => new (
                   new JProperty("nts", new JObject(
                       new JProperty("enabled", false)
                   ))
               );

        #endregion

        #region TemporaryDirectory(Purpose)

        /// <summary>
        /// A directory of its own for one test, so that no two of them read
        /// each other's accounts or configuration.
        /// </summary>
        public static String TemporaryDirectory(String Purpose)

            => Path.Combine(
                   Path.GetTempPath(),
                   $"node-{Purpose}-{Guid.NewGuid().ToString("N")[..12]}"
               );

        #endregion

        #region Remove(Directory)

        /// <summary>
        /// Take a test's directory away again.
        /// </summary>
        /// <remarks>
        /// A directory that survives a failed run is untidy and nothing more,
        /// so this never throws: failing a teardown over it would hide the
        /// failure that actually matters.
        /// </remarks>
        public static void Remove(String? Directory)
        {

            try
            {
                if (Directory is not null && System.IO.Directory.Exists(Directory))
                    System.IO.Directory.Delete(Directory, true);
            }
            catch (IOException)
            { }
            catch (UnauthorizedAccessException)
            { }

        }

        #endregion

    }

}
