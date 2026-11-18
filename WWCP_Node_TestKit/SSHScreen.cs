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

using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.TestKit
{

    /// <summary>
    /// What a shell over SSH writes, as it arrives - and a line typed at its
    /// prompt, with what that line answered.
    /// </summary>
    /// <remarks>
    /// The prompt alone does not say that a command has answered. The command
    /// line draws its row anew with every key typed - a carriage return, the
    /// row blanked, another carriage return, the prompt and what has been typed
    /// so far - so the prompt is on the screen again before Enter has even
    /// been read, and a test that waited for it after typing took the echo of
    /// its own keys for the answer (NTSServer CI, Windows).
    ///
    /// What does say it: none of those redraws has a line feed, and Enter ends
    /// the row with one, straight after the prompt and the whole line. A log
    /// line written above the row while it is typed has a line feed too, but
    /// never the prompt and the line right before it. And while a command runs
    /// nothing is typed and the row is not drawn again, so the next prompt
    /// after that line feed is the end of the answer. <see cref="Run"/> waits
    /// for exactly that.
    /// </remarks>
    public sealed class SSHScreen
    {

        #region Data

        private readonly StringBuilder  received  = new ();
        private readonly Lock           padlock   = new ();

        #endregion

        #region Properties

        /// <summary>
        /// The shell, for whatever is typed without waiting for an answer:
        /// Tab, the arrow keys, half a line.
        /// </summary>
        public SshClientShell  Shell     { get; }

        /// <summary>
        /// The prompt the command line draws, as it is written.
        /// </summary>
        public String          Prompt    { get; }

        /// <summary>
        /// Everything the shell has written so far.
        /// </summary>
        public String Text
        {
            get { lock (padlock) { return received.ToString(); } }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Read everything the given shell writes from now on.
        /// </summary>
        /// <param name="Shell">The shell over SSH.</param>
        /// <param name="Prompt">The prompt its command line draws.</param>
        public SSHScreen(SshClientShell  Shell,
                         String          Prompt)
        {

            this.Shell   = Shell;
            this.Prompt  = Prompt;

            _ = Task.Run(async () => {

                    var buffer = new Byte[4096];

                    try
                    {
                        Int32 read;
                        while ((read = await Shell.Output.ReadAsync(buffer)) > 0)
                            lock (padlock) { received.Append(Encoding.UTF8.GetString(buffer, 0, read)); }
                    }
                    catch { }

                });

        }

        #endregion


        #region AtPrompt(Seconds = 10)

        /// <summary>
        /// Wait for the first prompt, and return everything written up to it:
        /// the greeting.
        /// </summary>
        /// <param name="Seconds">How long to wait at most.</param>
        public async Task<String> AtPrompt(Int32 Seconds = 10)
        {

            var at = await IndexOf(Prompt, 0, DateTime.UtcNow.AddSeconds(Seconds));

            return Text[..at];

        }

        #endregion

        #region Run(Line, Seconds = 10)

        /// <summary>
        /// Type the given line and Enter, and return what it answered: what was
        /// written after the line was entered and before the next prompt,
        /// without the echo of the keys typed.
        /// </summary>
        /// <param name="Line">The line typed.</param>
        /// <param name="Seconds">How long to wait at most, for the line to be entered and for its answer.</param>
        public async Task<String> Run(String  Line,
                                      Int32   Seconds = 10)
        {

            var until  = DateTime.UtcNow.AddSeconds(Seconds);
            var mark   = Text.Length;

            await Shell.WriteAsync(Line + "\r");

            while (true)
            {

                if (AnswerIn(Text, mark, Prompt, Line) is String answer)
                    return answer;

                if (DateTime.UtcNow >= until)
                    break;

                await Task.Delay(20);

            }

            Assert.Fail($"Waited in vain for what '{Line}' answered. The session said:\n{Visible(Text[Math.Min(mark, Text.Length)..])}");
            return "";

        }

        #endregion

        #region (internal static) AnswerIn(Text, Since, Prompt, Line)

        /// <summary>
        /// What the given line answered, in what a shell wrote after Since - or
        /// null where it has not answered yet: where the line has not been
        /// entered, or its answer has no prompt after it.
        /// </summary>
        /// <param name="Text">What the shell wrote.</param>
        /// <param name="Since">Where in it the line was typed.</param>
        /// <param name="Prompt">The prompt of the command line.</param>
        /// <param name="Line">The line typed.</param>
        internal static String? AnswerIn(String  Text,
                                         Int32   Since,
                                         String  Prompt,
                                         String  Line)
        {

            // From a prompt's length before Since: where the keys are echoed
            // one by one rather than the row drawn anew, the prompt the line
            // is entered after was written before the line was typed.
            var entered  = Prompt + Line + "\r\n";
            var at       = Text.IndexOf(entered, Math.Max(0, Math.Min(Since, Text.Length) - Prompt.Length), StringComparison.Ordinal);

            if (at < 0)
                return null;

            var answer   = at + entered.Length;
            var end      = Text.IndexOf(Prompt, answer, StringComparison.Ordinal);

            return end < 0 ? null : Text[answer..end];

        }

        #endregion

        #region WaitFor(What, Since = 0, Seconds = 10)

        /// <summary>
        /// Wait until the given text has been written after what was there when
        /// Since was taken, and return what was written since. For what is not
        /// a whole line typed: a line whose answer is all a test wants is what
        /// <see cref="Run"/> is for.
        /// </summary>
        /// <param name="What">The text waited for.</param>
        /// <param name="Since">Where in the text to look from.</param>
        /// <param name="Seconds">How long to wait at most.</param>
        public async Task<String> WaitFor(String  What,
                                          Int32   Since    = 0,
                                          Int32   Seconds  = 10)
        {

            await IndexOf(What, Since, DateTime.UtcNow.AddSeconds(Seconds));

            var text = Text;

            return text[Math.Min(Since, text.Length)..];

        }

        #endregion


        #region (private) IndexOf(What, Since, Until)

        /// <summary>
        /// Where the given text was first written after Since, waited for until
        /// the given time - and failed with all the session said where it is
        /// not written by then.
        /// </summary>
        private async Task<Int32> IndexOf(String    What,
                                          Int32     Since,
                                          DateTime  Until)
        {

            while (true)
            {

                var text  = Text;
                var at    = text.IndexOf(What, Math.Min(Since, text.Length), StringComparison.Ordinal);

                if (at >= 0)
                    return at;

                if (DateTime.UtcNow >= Until)
                    break;

                await Task.Delay(20);

            }

            Assert.Fail($"Waited in vain for '{Visible(What)}'. The session said:\n{Visible(Text)}");
            return -1;

        }

        #endregion

        #region (private static) Visible(Text)

        /// <summary>
        /// The given text with its carriage returns and line feeds shown, so
        /// that a failure says which of them came where.
        /// </summary>
        private static String Visible(String Text)

            => Text.Replace("\r", "\\r").Replace("\n", "\\n\n");

        #endregion

    }

}
