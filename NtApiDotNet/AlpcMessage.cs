//  Copyright 2019 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer to contain an ALPC port message.
    /// </summary>
    public class SafeAlpcPortMessageBuffer : SafeStructureInOutBuffer<AlpcPortMessage>
    {
        private SafeAlpcPortMessageBuffer(int data_length)
            : base(data_length, true)
        {
            BufferUtils.ZeroBuffer(this);
        }

        internal SafeAlpcPortMessageBuffer() : base(IntPtr.Zero, 0, false)
        {
        }

        /// <summary>
        /// Get a NULL safe buffer.
        /// </summary>
        new public static SafeAlpcPortMessageBuffer Null => new SafeAlpcPortMessageBuffer();

        /// <summary>
        /// Create a new safe buffer from a byte array.
        /// </summary>
        /// <param name="data">The raw bytes which represents the message.</param>
        /// <returns>The created safe buffer.</returns>
        public static SafeAlpcPortMessageBuffer Create(byte[] data)
        {
            SafeAlpcPortMessageBuffer buffer = Create(data.Length, true);
            buffer.Data.WriteBytes(data);
            return buffer;
        }

        /// <summary>
        /// Create a new safe buffer with a specified size.
        /// </summary>
        /// <param name="data_length">The length of allocated memory.</param>
        /// <param name="initialize">Indicate whether to initialize the message headers.</param>
        /// <returns>The created safe buffer.</returns>
        public static SafeAlpcPortMessageBuffer Create(int data_length, bool initialize)
        {
            var buffer = new SafeAlpcPortMessageBuffer(data_length);
            if (initialize)
            {
                buffer.Result = new AlpcPortMessage()
                {
                    u1 = new AlpcPortMessage.PortMessageUnion1()
                    { TotalLength = (short)buffer.Length, DataLength = (short)data_length }
                };
            }
            return buffer;
        }
    }

    /// <summary>
    /// Base class to represent an ALPC message.
    /// </summary>
    public class AlpcMessage : IDisposable
    {
        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data_length">The length of allocated memory.</param>
        /// <param name="initialize">Indicate whether to initialize the message headers.</param>
        protected AlpcMessage(int data_length, bool initialize)
        {
            Buffer = SafeAlpcPortMessageBuffer.Create(data_length, initialize);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">The raw bytes which represents the message.</param>
        protected AlpcMessage(byte[] data)
        {
            Buffer = SafeAlpcPortMessageBuffer.Create(data);
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// The process ID of the sender.
        /// </summary>
        public int ProcessId => Buffer.Result.ClientId.UniqueProcess.ToInt32();

        /// <summary>
        /// The thread ID of the sender.
        /// </summary>
        public int ThreadId => Buffer.Result.ClientId.UniqueThread.ToInt32();

        /// <summary>
        /// Get total length of the message.
        /// </summary>
        public int TotalLength => Buffer.Result.u1.TotalLength;

        /// <summary>
        /// Get data length of the message.
        /// </summary>
        public int DataLength => Buffer.Result.u1.DataLength;

        /// <summary>
        /// Get the message ID.
        /// </summary>
        public int MessageId => Buffer.Result.MessageId;

        /// <summary>
        /// Get underlying buffer.
        /// </summary>
        public SafeAlpcPortMessageBuffer Buffer { get; }
        #endregion

        #region Static Methods
        /// <summary>
        /// Create an ALPC message from raw bytes.
        /// </summary>
        /// <param name="data">The raw bytes which represents the message.</param>
        /// <returns>The created ALPC message.</returns>
        public static AlpcMessage Create(byte[] data)
        {
            return new AlpcMessage(data);
        }

        /// <summary>
        /// Create an ALPC message from raw bytes.
        /// </summary>
        /// <param name="data_length">The length of allocated memory.</param>
        /// <param name="initialize">Indicate whether to initialize the message headers.</param>
        /// <returns>The created ALPC message.</returns>
        public static AlpcMessage Create(int data_length, bool initialize)
        {
            return new AlpcMessage(data_length, initialize);
        }

        /// <summary>
        /// Create a typed ALPC message.
        /// </summary>
        /// <typeparam name="T">The type representing the data.</typeparam>
        /// <param name="value">A value to initialize the buffer.</param>
        /// <returns>The ALPC message.</returns>
        public static AlpcMessage<T> Create<T>(T value) where T : struct
        {
            return new AlpcMessage<T>(value);
        }

        /// <summary>
        /// Create a typed ALPC message.
        /// </summary>
        /// <typeparam name="T">The type representing the data.</typeparam>
        /// <returns>The ALPC message.</returns>
        /// <remarks>Note that the size fields in the header will not be initialized.</remarks>
        public static AlpcMessage<T> Create<T>() where T : struct
        {
            return new AlpcMessage<T>(false);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Virtual Dispose method.
        /// </summary>
        public virtual void Dispose()
        {
            Buffer.Dispose();
        }

        #endregion
    }

    /// <summary>
    /// An ALPC message which holds a specific type.
    /// </summary>
    /// <typeparam name="T">The type representing the data.</typeparam>
    public sealed class AlpcMessage<T> : AlpcMessage where T : struct
    {
        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="initialize">Indicate whether to initialize the message headers.</param>
        internal AlpcMessage(bool initialize) 
            : base(Marshal.SizeOf(typeof(T)), initialize)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The initial value to set..</param>
        internal AlpcMessage(T value) : this(true)
        {
            Result = value;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set the type in the buffer.
        /// </summary>
        public T Result
        {
            get => Buffer.Data.Read<T>(0);
            set => Buffer.Data.Write(0, value);
        }
        #endregion
    }
}
