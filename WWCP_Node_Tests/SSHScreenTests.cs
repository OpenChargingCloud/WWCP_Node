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
    /// When the kit's screen says a line typed over SSH has answered: not
    /// before the line has been entered, whatever the screen shows of the
    /// prompt until then.
    /// </summary>
    /// <remarks>
    /// Told what a shell wrote rather than read from one, because the race is
    /// one of timing: the echo of the keys comes before the answer only now
    /// and then, and a test that waited for it to happen would pass on most
    /// runs whether the kit is right or not. The rows are drawn as the command
    /// line draws them.
    /// </remarks>
    [TestFixture]
    public class SSHScreenTests
    {

        #region Data

        private const           String Prompt  = "nts:52556> ";

        /// <summary>
        /// A row blanked, as Styx's LineView.Clearing blanks it: a carriage
        /// return, the row written over with spaces, another carriage return.
        /// </summary>
        private static readonly String Blank   = "\r" + new String(' ', 159) + "\r";

        /// <summary>
        /// A row drawn anew, as it is with every key typed.
        /// </summary>
        private static String Drawn(String Typed)

            => Blank + Prompt + Typed;

        /// <summary>
        /// What the shell wrote while the given line was typed, key by key,
        /// before Enter.
        /// </summary>
        private static String Typing(String Line)

            => String.Concat(Enumerable.Range(1, Line.Length).Select(keys => Drawn(Line[..keys])));

        #endregion


        #region TheEchoOfTheKeysIsNoAnswer

        /// <summary>
        /// The keys typed, each drawing the prompt anew - what the shell had
        /// written when the test of timeServer took it for the answer (NTSServer
        /// CI, Windows) - have not answered yet.
        /// </summary>
        [Test]
        public void TheEchoOfTheKeysIsNoAnswer()
        {

            var written = Prompt + Typing("timeServer");

            Assert.That(written.IndexOf(Prompt, Prompt.Length, StringComparison.Ordinal), Is.GreaterThan(0), "the prompt is on the screen again");
            Assert.That(SSHScreen.AnswerIn(written, Prompt.Length, Prompt, "timeServer"), Is.Null);

        }

        #endregion

        #region ALineEnteredHasNotAnsweredBeforeItsPrompt

        /// <summary>
        /// Entered, and half its answer written, a line has not answered until
        /// the prompt is drawn after it.
        /// </summary>
        [Test]
        public void ALineEnteredHasNotAnsweredBeforeItsPrompt()
        {

            var written = Prompt + Typing("timeServer") + "\r\n" + "time source     this machine's clock\r\n";

            Assert.That(SSHScreen.AnswerIn(written, Prompt.Length, Prompt, "timeServer"), Is.Null);

        }

        #endregion

        #region TheAnswerIsWhatComesBetweenTheLineAndTheNextPrompt

        /// <summary>
        /// The answer is what was written after Enter and before the next
        /// prompt: nothing of the keys typed, nothing of that prompt.
        /// </summary>
        [Test]
        public void TheAnswerIsWhatComesBetweenTheLineAndTheNextPrompt()
        {

            var answer   = "time source     this machine's clock\r\n" +
                           "answered        0 NTP response(s) to 0 request(s), 0 key exchange(s) of 0 connection(s)\r\n";

            var written  = Prompt + Typing("timeServer") + "\r\n" + answer + Prompt;

            Assert.That(SSHScreen.AnswerIn(written, Prompt.Length, Prompt, "timeServer"), Is.EqualTo(answer));

        }

        #endregion

        #region ALogLineAboveTheRowIsNotEnter

        /// <summary>
        /// A log line written above the row while it is typed ends with a line
        /// feed too, and the row is drawn anew below it - with the prompt, which
        /// is not the end of an answer either.
        /// </summary>
        [Test]
        public void ALogLineAboveTheRowIsNotEnter()
        {

            var written = Prompt + Typing("time") + Blank + "the clock was checked\r\n" + Drawn("time") + Drawn("timeS");

            Assert.That(SSHScreen.AnswerIn(written, Prompt.Length, Prompt, "timeServer"), Is.Null);

        }

        #endregion

        #region ALineTypedBeforeIsNotThisOnesAnswer

        /// <summary>
        /// What a line typed before Since answered is not taken for the answer
        /// of the same line typed again.
        /// </summary>
        [Test]
        public void ALineTypedBeforeIsNotThisOnesAnswer()
        {

            var before   = Prompt + Typing("help") + "\r\n" + "the first answer\r\n" + Prompt;
            var written  = before + Typing("help");

            Assert.That(SSHScreen.AnswerIn(written, before.Length, Prompt, "help"), Is.Null);
            Assert.That(SSHScreen.AnswerIn(written + "\r\n" + "the second answer\r\n" + Prompt, before.Length, Prompt, "help"),
                        Is.EqualTo("the second answer\r\n"));

        }

        #endregion

        #region KeysEchoedOneByOneAreEnteredToo

        /// <summary>
        /// Where the keys are echoed as they are, not the row drawn anew, the
        /// prompt the line is entered after was written before Since - and the
        /// line has answered all the same.
        /// </summary>
        [Test]
        public void KeysEchoedOneByOneAreEnteredToo()
        {

            var written = Prompt + "help" + "\r\n" + "what can be typed\r\n" + Prompt;

            Assert.That(SSHScreen.AnswerIn(written, Prompt.Length, Prompt, "help"), Is.EqualTo("what can be typed\r\n"));

        }

        #endregion

    }

}
