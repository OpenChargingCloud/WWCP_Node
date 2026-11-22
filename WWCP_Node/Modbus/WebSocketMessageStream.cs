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

using System.IO.Pipelines;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Modbus
{

    /// <summary>
    /// A WebSocket as a stream of bytes: what its binary messages carry, read
    /// one after the other, and every write sent as one binary message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What Modbus over a WebSocket needs, so that the very code that reads and
    /// writes frames over a TCP connection, a TLS stream or an SSH channel reads
    /// and writes them here as well. A frame is read across message boundaries
    /// as over any stream; a frame is written in one write, by the Modbus client
    /// and server alike, and so goes as one message.
    /// </para>
    /// <para>
    /// Ends - a read answers 0 - when the WebSocket is closed, from either end;
    /// disposing it closes the WebSocket.
    /// </para>
    /// </remarks>
    /// <param name="Send">Sends one binary message.</param>
    /// <param name="CloseWebSocket">Closes the WebSocket.</param>
    public sealed class WebSocketMessageStream(Func<Byte[], CancellationToken, Task>  Send,
                                               Func<Task>                             CloseWebSocket) : Stream
    {

        #region Data

        private readonly Pipe   pipe    = new ();
        private          Stream? reader;
        private          Int32  ended;
        private          Int32  disposed;

        #endregion

        #region Properties

        /// <summary>
        /// Whether the WebSocket is closed, and nothing more will be read.
        /// </summary>
        public Boolean  HasEnded
            => Volatile.Read(ref ended) != 0;

        public override Boolean  CanRead   => !HasEnded;
        public override Boolean  CanWrite  => !HasEnded;
        public override Boolean  CanSeek   => false;
        public override Int64    Length    => throw new NotSupportedException();
        public override Int64    Position  { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        #endregion


        #region Deliver(Message) / End()

        /// <summary>
        /// A binary message came: its bytes are read next.
        /// </summary>
        public async Task Deliver(Byte[] Message)
        {

            if (HasEnded || Message.Length == 0)
                return;

            try
            {
                await pipe.Writer.WriteAsync(Message);
            }
            catch (InvalidOperationException)
            {
                // Ended while the message came.
            }

        }

        /// <summary>
        /// The WebSocket is closed: what came is still read, and then nothing.
        /// </summary>
        public void End()
        {
            if (Interlocked.Exchange(ref ended, 1) == 0)
                pipe.Writer.Complete();
        }

        #endregion


        #region Read / Write

        public override async ValueTask<Int32> ReadAsync(Memory<Byte> Buffer, CancellationToken CancellationToken = default)
        {
            reader ??= pipe.Reader.AsStream();
            return await reader.ReadAsync(Buffer, CancellationToken);
        }

        public override Task<Int32> ReadAsync(Byte[] Buffer, Int32 Offset, Int32 Count, CancellationToken CancellationToken)
            => ReadAsync(Buffer.AsMemory(Offset, Count), CancellationToken).AsTask();

        public override Int32 Read(Byte[] Buffer, Int32 Offset, Int32 Count)
            => ReadAsync(Buffer.AsMemory(Offset, Count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<Byte> Buffer, CancellationToken CancellationToken = default)
        {

            if (HasEnded)
                throw new IOException("The WebSocket is closed.");

            await Send(Buffer.ToArray(), CancellationToken);

        }

        public override Task WriteAsync(Byte[] Buffer, Int32 Offset, Int32 Count, CancellationToken CancellationToken)
            => WriteAsync(Buffer.AsMemory(Offset, Count), CancellationToken).AsTask();

        public override void Write(Byte[] Buffer, Int32 Offset, Int32 Count)
            => WriteAsync(Buffer.AsMemory(Offset, Count)).AsTask().GetAwaiter().GetResult();

        public override void Flush() { }

        public override Task FlushAsync(CancellationToken CancellationToken)
            => Task.CompletedTask;

        public override Int64 Seek(Int64 Offset, SeekOrigin Origin)
            => throw new NotSupportedException();

        public override void SetLength(Int64 Value)
            => throw new NotSupportedException();

        #endregion

        #region Dispose

        protected override void Dispose(Boolean Disposing)
        {

            if (Disposing && Interlocked.Exchange(ref disposed, 1) == 0)
            {
                End();
                _ = CloseQuietly();
            }

            base.Dispose(Disposing);

        }

        private async Task CloseQuietly()
        {
            try
            {
                await CloseWebSocket();
            }
            catch
            { }
        }

        #endregion

    }

}
