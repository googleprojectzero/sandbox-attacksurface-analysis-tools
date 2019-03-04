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
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer to contain an ALPC port message.
    /// </summary>
    public class SafeAlpcPortMessageBuffer : SafeStructureInOutBuffer<AlpcPortMessage>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="header">The port message header.</param>
        /// <param name="data">The trailing data.</param>
        public SafeAlpcPortMessageBuffer(AlpcPortMessage header, byte[] data)
            : base(header, data.Length, true)
        {
            Data.WriteBytes(data);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="header">The port message header.</param>
        /// <param name="data_length">The trailing data to initialize.</param>
        public SafeAlpcPortMessageBuffer(AlpcPortMessage header, int data_length)
            : base(header, data_length, true)
        {
            Data.ZeroBuffer();
        }

        /// <summary>
        /// Constructor. Creates a receive buffer with a set length.
        /// </summary>
        /// <param name="data_length">The trailing data to initialize.</param>
        public SafeAlpcPortMessageBuffer(int data_length)
            : this(new AlpcPortMessage(), data_length)
        {
        }

        internal SafeAlpcPortMessageBuffer() : base(IntPtr.Zero, 0, false)
        {
        }

        internal SafeAlpcPortMessageBuffer(IntPtr buffer, int length) 
            : base(buffer, length, true)
        {
        }

        /// <summary>
        /// Get a NULL safe buffer.
        /// </summary>
        new public static SafeAlpcPortMessageBuffer Null => new SafeAlpcPortMessageBuffer();

        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        new public SafeAlpcPortMessageBuffer Detach()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                return new SafeAlpcPortMessageBuffer(handle, Length);
            }
            finally
            {
            }
        }
    }

    /// <summary>
    /// Base class to represent an ALPC message.
    /// </summary>
    public class AlpcMessage
    {
        #region Private Members
        private byte[] _data;
        private NtAlpc _port;
        #endregion

        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="header">The port message header.</param>
        /// <param name="data">The data to allocate.</param>
        /// <param name="initialize">True to initialize the header length fields</param>
        public AlpcMessage(AlpcPortMessage header, byte[] data, bool initialize)
        {
            Header = header;
            _data = data;
            if (initialize)
            {
                UpdateHeaderLength();
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">The data to allocate.</param>
        public AlpcMessage(byte[] data) 
            : this(new AlpcPortMessage(), data, true)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data_length">The length of data to allocate.</param>
        /// <param name="initialize">True to initialize the header length fields</param>
        public AlpcMessage(int data_length, bool initialize)
            : this(new AlpcPortMessage(), new byte[data_length], initialize)
        {
        }

        /// <summary>
        /// Constructor from a safe buffer.
        /// </summary>
        /// <param name="buffer">The safe buffer to initialize from.</param>
        /// <param name="port">Port associated with this message. Optional.</param>
        /// <remarks>Note that the port object is not referenced, however the message becomes invalid once
        /// the port closes so this isn't a major concern.</remarks>
        public AlpcMessage(SafeAlpcPortMessageBuffer buffer, NtAlpc port)
        {
            FromSafeBuffer(buffer, port);
        }

        private void UpdateHeaderLength()
        {
            Header.u1.TotalLength = (short)(Marshal.SizeOf(typeof(AlpcPortMessage)) + _data.Length);
            Header.u1.DataLength = (short)_data.Length;
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get or set the header.
        /// </summary>
        public AlpcPortMessage Header { get; set; }

        /// <summary>
        /// The process ID of the sender.
        /// </summary>
        public int ProcessId => Header.ClientId.UniqueProcess.ToInt32();

        /// <summary>
        /// The thread ID of the sender.
        /// </summary>
        public int ThreadId => Header.ClientId.UniqueThread.ToInt32();

        /// <summary>
        /// Get total length of the message.
        /// </summary>
        public int TotalLength => Header.u1.TotalLength;

        /// <summary>
        /// Get data length of the message.
        /// </summary>
        public int DataLength => Header.u1.DataLength;

        /// <summary>
        /// Get the message ID.
        /// </summary>
        public int MessageId => Header.MessageId;

        /// <summary>
        /// Get the callback ID.
        /// </summary>
        public int CallbackId => Header.u3.CallbackId;

        /// <summary>
        /// Get or set the message data.
        /// </summary>
        /// <remarks>When you set the data it'll update the DataLength and TotalLength fields.</remarks>
        public byte[] Data
        {
            get => _data;
            set
            {
                _data = value;
                UpdateHeaderLength();
            }
        }

        /// <summary>
        /// Get direct status for the message.
        /// </summary>
        /// <returns>The direct status for the message. Returns STATUS_PENDING if the message is yet to be processed.</returns>
        public NtStatus DirectStatus
        {
            get
            {
                if (_port == null)
                {
                    throw new ArgumentNullException("Message must be associated with a port");
                }
                return NtSystemCalls.NtAlpcQueryInformationMessage(_port.Handle, Header,
                    AlpcMessageInformationClass.AlpcMessageDirectStatusInformation,
                    IntPtr.Zero, 0, IntPtr.Zero);
            }
        }

        #endregion

        #region Static Methods
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
        /// Create a safe buffer for this message.
        /// </summary>
        /// <returns>The safe buffer.</returns>
        public virtual SafeAlpcPortMessageBuffer ToSafeBuffer()
        {
            return new SafeAlpcPortMessageBuffer(Header, Data);
        }

        internal virtual void FromSafeBuffer(SafeAlpcPortMessageBuffer buffer, NtAlpc port)
        {
            Header = buffer.Result;
            _data = buffer.Data.ReadBytes(Header.u1.DataLength);
            _port = port;
        }

        /// <summary>
        /// Method to query information for a message.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="port">The port which has processed the message.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public NtStatus QueryInformation(NtAlpc port, AlpcMessageInformationClass info_class,
            SafeBuffer buffer, out int return_length)
        {
            if (_port == null)
            {
                throw new ArgumentNullException("Message must be associated with a port");
            }
            return NtSystemCalls.NtAlpcQueryInformationMessage(port.Handle, Header,
                info_class, buffer, buffer.GetLength(), out return_length);
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="port">The port which has processed the message.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtResult<T> Query<T>(NtAlpc port, AlpcMessageInformationClass info_class, 
            T default_value, bool throw_on_error) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>(default_value))
            {
                return QueryInformation(port, info_class, 
                    buffer, out int return_length).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="port">The port which has processed the message.</param>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public T Query<T>(NtAlpc port, AlpcMessageInformationClass info_class, T default_value) where T : new()
        {
            return Query(port, info_class, default_value, true).Result;
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="port">The port which has processed the message.</param>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public T Query<T>(NtAlpc port, AlpcMessageInformationClass info_class) where T : new()
        {
            return Query(port, info_class, new T());
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
            Value = new T();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The initial value to set..</param>
        internal AlpcMessage(T value) : this(true)
        {
            Value = value;
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Create a safe buffer for this message.
        /// </summary>
        /// <returns>The safe buffer.</returns>
        public override SafeAlpcPortMessageBuffer ToSafeBuffer()
        {
            using (var buffer = base.ToSafeBuffer())
            {
                buffer.Data.Write(0, Value);
                return buffer.Detach();
            }
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set the type in the buffer.
        /// </summary>
        public T Value { get; set; }
        #endregion

        #region Internal Members
        internal override void FromSafeBuffer(SafeAlpcPortMessageBuffer buffer, NtAlpc port)
        {
            base.FromSafeBuffer(buffer, port);
            Value = buffer.Data.Read<T>(0);
        }
        #endregion
    }
}
