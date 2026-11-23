/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Text;
using System.Collections.Concurrent;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.PKI
{

    /// <summary>
    /// The messages of a PKI over one stream of lines - the channel of an SSH
    /// subsystem, or a WebSocket whose text messages are read as lines: requests
    /// sent and their responses waited for, and requests that come answered by
    /// a handler.
    /// </summary>
    /// <remarks>
    /// Every message is one line, written at once, so that over a WebSocket it
    /// is one text message. A line longer than <see cref="PKIWireNames.MaxMessageSize"/>
    /// ends the channel: the other end says no more that can be read.
    /// </remarks>
    public sealed class PKIMessageChannel : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// How long a request waits for its response, unless said otherwise.
        /// </summary>
        public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

        private readonly Stream                                                    stream;
        private readonly Func<String, JObject, CancellationToken, Task<JObject>>?  handler;
        private readonly SemaphoreSlim                                             writing   = new (1, 1);
        private readonly ConcurrentDictionary<String, TaskCompletionSource<PKIMessage>>  pending  = new ();
        private readonly CancellationTokenSource                                   ending    = new ();
        private          Int64                                                     nextId;

        #endregion

        #region Properties

        /// <summary>
        /// Ends when the other end says nothing more: when the stream ended, or
        /// said something that is no message.
        /// </summary>
        public Task     Ended      { get; }

        /// <summary>
        /// Why it ended, where it was not simply closed.
        /// </summary>
        public String?  WhyEnded   { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The messages of a PKI over the given stream of lines, read from now on.
        /// </summary>
        /// <param name="Stream">The stream of lines.</param>
        /// <param name="Handler">What answers a request - action, payload: the payload of its response, or a <see cref="PKIException"/> that is answered as an error -; null to answer every request with NotSupported.</param>
        public PKIMessageChannel(Stream                                                    Stream,
                                 Func<String, JObject, CancellationToken, Task<JObject>>?  Handler = null)
        {

            this.stream   = Stream;
            this.handler  = Handler;

            Ended         = Task.Run(Read);

        }

        #endregion


        #region Request(Action, Payload, Timeout = null, CancellationToken = default)

        /// <summary>
        /// Send a request, and wait for its response: its payload, or the error
        /// it was answered with as a <see cref="PKIException"/>.
        /// </summary>
        public async Task<JObject> Request(String             Action,
                                           JObject            Payload,
                                           TimeSpan?          Timeout            = null,
                                           CancellationToken  CancellationToken  = default)
        {

            var id       = Interlocked.Increment(ref nextId).ToString();
            var answer   = new TaskCompletionSource<PKIMessage>(TaskCreationOptions.RunContinuationsAsynchronously);

            pending[id]  = answer;

            try
            {

                await Send(PKIMessage.Request(id, Action, Payload), CancellationToken);

                using var timeout  = new CancellationTokenSource(Timeout ?? DefaultTimeout);
                using var both     = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, timeout.Token, ending.Token);

                PKIMessage message;

                try
                {
                    message = await answer.Task.WaitAsync(both.Token);
                }
                catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
                {
                    throw timeout.IsCancellationRequested
                              ? new TimeoutException($"The PKI did not answer '{Action}' within {(Timeout ?? DefaultTimeout).TotalSeconds} s.")
                              : new IOException($"The connection to the PKI ended before it answered '{Action}'{(WhyEnded is null ? "" : $": {WhyEnded}")}.");
                }

                return message.Type == PKIMessageType.Error
                           ? throw new PKIException(message.ErrorCode ?? PKIErrorCodes.GenericError, message.ErrorDescription ?? "", message.Payload)
                           : message.Payload;

            }
            finally
            {
                pending.TryRemove(id, out _);
            }

        }

        #endregion

        #region (private) Send(Message, CancellationToken)

        private async Task Send(PKIMessage         Message,
                                CancellationToken  CancellationToken)
        {

            var line = Encoding.UTF8.GetBytes(Message.ToLine() + "\n");

            await writing.WaitAsync(CancellationToken);

            try
            {
                await stream.WriteAsync(line, CancellationToken);
                await stream.FlushAsync(CancellationToken);
            }
            finally
            {
                writing.Release();
            }

        }

        #endregion

        #region (private) Read()

        private async Task Read()
        {

            var buffer  = new Byte[16 * 1024];
            var line    = new MemoryStream();

            try
            {

                while (!ending.IsCancellationRequested)
                {

                    var read = await stream.ReadAsync(buffer, ending.Token);

                    if (read == 0)
                        return;

                    var start = 0;

                    for (var i = 0; i < read; i++)
                    {

                        if (buffer[i] != (Byte) '\n')
                            continue;

                        line.Write(buffer, start, i - start);
                        start = i + 1;

                        var text = Encoding.UTF8.GetString(line.GetBuffer(), 0, (Int32) line.Length).TrimEnd('\r');
                        line.SetLength(0);

                        if (text.Length > 0)
                            await Received(text);

                    }

                    line.Write(buffer, start, read - start);

                    if (line.Length > PKIWireNames.MaxMessageSize)
                    {
                        WhyEnded = $"a message is longer than {PKIWireNames.MaxMessageSize} bytes";
                        return;
                    }

                }

            }
            catch (OperationCanceledException)
            { }
            catch (Exception e)
            {
                WhyEnded ??= e.Message;
            }
            finally
            {

                await ending.CancelAsync();

                foreach (var waiting in pending.Values)
                    waiting.TrySetCanceled();

            }

        }

        #endregion

        #region (private) Received(Text)

        private async Task Received(String Text)
        {

            if (!PKIMessage.TryParse(Text, out var message, out var id, out var error))
            {

                if (id is not null)
                    await SendQuietly(PKIMessage.Error(id, PKIErrorCodes.FormatViolation, error));

                return;

            }

            switch (message.Type)
            {

                case PKIMessageType.Response:
                case PKIMessageType.Error:
                    if (pending.TryGetValue(message.Id, out var waiting))
                        waiting.TrySetResult(message);
                    return;

                default:
                    // Answered one after the other: a registration authority asks,
                    // and waits; nothing is gained by signing in parallel.
                    await SendQuietly(await Answer(message));
                    return;

            }

        }

        private async Task<PKIMessage> Answer(PKIMessage Request)
        {

            if (handler is null)
                return PKIMessage.Error(Request.Id, PKIErrorCodes.NotSupported, $"Nothing is asked of this end: '{Request.Action}' is not answered here.");

            try
            {
                return PKIMessage.Response(Request.Id, await handler(Request.Action!, Request.Payload, ending.Token));
            }
            catch (PKIException e)
            {
                return PKIMessage.Error(Request.Id, e.Code, e.Description, e.Details);
            }
            catch (Exception e)
            {
                return PKIMessage.Error(Request.Id, PKIErrorCodes.InternalError, e.Message);
            }

        }

        private async Task SendQuietly(PKIMessage Message)
        {
            try
            {
                await Send(Message, ending.Token);
            }
            catch
            { }
        }

        #endregion


        #region DisposeAsync()

        public async ValueTask DisposeAsync()
        {

            await ending.CancelAsync();

            try { await stream.DisposeAsync(); } catch { }

            try { await Ended; } catch { }

        }

        #endregion

    }

}
