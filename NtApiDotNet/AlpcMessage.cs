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

using NtApiDotNet.Utilities.Text;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Base class to represent an ALPC message.
    /// </summary>
    public abstract class AlpcMessage
    {
        #region Private Members

        static readonly int _header_size = Marshal.SizeOf(typeof(AlpcPortMessage));
        private NtAlpc _port;

        #endregion

        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="header">The port message header.</param>
        protected AlpcMessage(AlpcPortMessage header)
        {
            Header = header;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        protected AlpcMessage() : this(new AlpcPortMessage())
        {
        }

        #endregion

        #region Protected Members

        /// <summary>
        /// Update the header length fields.
        /// </summary>
        /// <param name="data_length">The length of the valid data.</param>
        /// <param name="allocated_data_length">The maximum data length supported by the packet.</param>
        protected void UpdateHeaderLength(int data_length, int allocated_data_length)
        {
            if (data_length > allocated_data_length)
            {
                throw new ArgumentException("Data length is larger than allocated total length", nameof(allocated_data_length));
            }

            if (allocated_data_length > MaximumDataLength)
            {
                throw new ArgumentException("Total length is larger than maximum allowed length.", nameof(allocated_data_length));
            }

            AllocatedDataLength = allocated_data_length;
            Header.u1.TotalLength = (ushort)(_header_size + data_length);
            Header.u1.DataLength = (ushort)data_length;
        }

        /// <summary>
        /// Method to handle when ToSafeBuffer is called.
        /// </summary>
        /// <param name="buffer">The message buffer being created.</param>
        protected abstract void OnToSafeBuffer(SafeAlpcPortMessageBuffer buffer);

        /// <summary>
        /// Method to handle when FromSafeBuffer is called.
        /// </summary>
        /// <param name="buffer">The message buffer to initialize from..</param>
        /// <param name="port">The ALPC port associated with this message.</param>
        protected abstract void OnFromSafeBuffer(SafeAlpcPortMessageBuffer buffer, NtAlpc port);

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
        /// Get the allocated data length for the message.
        /// </summary>
        public int AllocatedDataLength { get; private set; }

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
        /// Get the message type.
        /// </summary>
        public AlpcMessageType MessageType => (AlpcMessageType)(Header.u2.Type & 0xFF);

        /// <summary>
        /// Get additional flags on message type.
        /// </summary>
        public AlpcMessageTypeFlags MessageTypeFlags => (AlpcMessageTypeFlags)(Header.u2.Type & 0xFF00);

        /// <summary>
        /// Indicates that the message requires a reply (otherwise things can leak).
        /// </summary>
        public bool ContinuationRequired => (MessageTypeFlags & AlpcMessageTypeFlags.ContinuationRequired) != 0;

        /// <summary>
        /// Indicates that the message requires a reply (obsolete).
        /// </summary>
        [Obsolete("Use ContinuationRequired")]
        public bool RequiresReply => ContinuationRequired;

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
                    return NtStatus.STATUS_INVALID_PORT_HANDLE;
                }
                return NtSystemCalls.NtAlpcQueryInformationMessage(_port.Handle, Header,
                    AlpcMessageInformationClass.AlpcMessageDirectStatusInformation,
                    IntPtr.Zero, 0, IntPtr.Zero);
            }
        }

        #endregion

        #region Static Properties

        /// <summary>
        /// Get the maximum size of a message minus the header size.
        /// </summary>
        public static int MaximumDataLength => NtAlpcNativeMethods.AlpcMaxAllowedMessageLength() - _header_size;

        #endregion

        #region Public Methods

        /// <summary>
        /// Create a safe buffer for this message.
        /// </summary>
        /// <returns>The safe buffer.</returns>
        public SafeAlpcPortMessageBuffer ToSafeBuffer()
        {
            using (SafeAlpcPortMessageBuffer buffer = new SafeAlpcPortMessageBuffer(Header, AllocatedDataLength))
            {
                OnToSafeBuffer(buffer);
                return buffer.Detach();
            }
        }

        internal void FromSafeBuffer(SafeAlpcPortMessageBuffer buffer, NtAlpc port)
        {
            Header = buffer.Result;
            AllocatedDataLength = buffer.Length - _header_size;
            OnFromSafeBuffer(buffer, port);
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
        public NtResult<T> Query<T>(NtAlpc port, AlpcMessageInformationClass info_class, 
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
    /// An ALPC message which holds a raw set of bytes.
    /// </summary>
    public sealed class AlpcMessageRaw : AlpcMessage
    {
        #region Private Members
        private byte[] _data;
        #endregion

        #region Constructors

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">Data to initialize the message with.</param>
        /// <param name="allocated_data_length">Maximum length of the message buffer.</param>
        /// <param name="encoding">Specify a text encoding for the DataString property.</param>
        public AlpcMessageRaw(byte[] data, int allocated_data_length, Encoding encoding)
        {
            Encoding = encoding;
            _data = (byte[])data.Clone();
            UpdateHeaderLength(_data.Length, allocated_data_length);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">Data to initialize the message with.</param>
        /// <param name="allocated_data_length">Maximum length of the message buffer.</param>
        public AlpcMessageRaw(byte[] data, int allocated_data_length) 
            : this(data, allocated_data_length, BinaryEncoding.Instance)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">Data to initialize the message with.</param>
        public AlpcMessageRaw(byte[] data) : this(data, data.Length)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">Data to initialize the message with.</param>
        /// <param name="encoding">Specify a text encoding for the DataString property.</param>
        public AlpcMessageRaw(byte[] data, Encoding encoding) 
            : this(data, data.Length, encoding)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="allocated_data_length">Total allocated length of the message buffer.</param>
        public AlpcMessageRaw(int allocated_data_length) 
            : this(new byte[0], allocated_data_length)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="allocated_data_length">Total allocated length of the message buffer.</param>
        /// <param name="encoding">Specify a text encoding for the DataString property.</param>
        public AlpcMessageRaw(int allocated_data_length, Encoding encoding)
            : this(new byte[0], allocated_data_length, encoding)
        {
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set the message data.
        /// </summary>
        /// <remarks>When you set the data it'll update the DataLength and TotalLength fields.</remarks>
        public byte[] Data
        {
            get => _data;
            set
            {
                UpdateHeaderLength(value.Length, Math.Max(value.Length, AllocatedDataLength));
                _data = value;
            }
        }

        /// <summary>
        /// Get or set the message data as an encoding string.
        /// </summary>
        /// <remarks>When you set the data it'll update the DataLength and TotalLength fields.</remarks>
        public string DataString
        {
            get => Encoding.GetString(Data);
            set => Data = Encoding.GetBytes(value);
        }

        /// <summary>
        /// Get or set the text encoding in this raw message.
        /// </summary>
        public Encoding Encoding { get; set; }

        #endregion

        #region Protected Members

        /// <summary>
        /// Method to handle when FromSafeBuffer is called.
        /// </summary>
        /// <param name="buffer">The message buffer to initialize from..</param>
        /// <param name="port">The ALPC port associated with this message.</param>
        protected override void OnFromSafeBuffer(SafeAlpcPortMessageBuffer buffer, NtAlpc port)
        {
            _data = buffer.Data.ReadBytes(DataLength);
        }

        /// <summary>
        /// Method to handle when ToSafeBuffer is called.
        /// </summary>
        /// <param name="buffer">The message buffer being created.</param>
        protected override void OnToSafeBuffer(SafeAlpcPortMessageBuffer buffer)
        {
            buffer.Data.WriteBytes(_data);
        }

        #endregion

        #region Public Methods
        #endregion
    }

    /// <summary>
    /// An ALPC message which holds a specific type with optional trailing data.
    /// </summary>
    /// <typeparam name="T">The type representing the data.</typeparam>
    public sealed class AlpcMessageType<T> : AlpcMessage where T : struct
    {
        #region Private Members
        private static readonly int _header_size = Marshal.SizeOf(typeof(T));
        private byte[] _trailing;
        #endregion

        #region Constructors

        private AlpcMessageType(bool receive_buffer, int total_length)
        {
            // Ensure length is at least the header size.
            total_length = Math.Max(total_length, _header_size);
            UpdateHeaderLength(receive_buffer ? 0 : total_length, total_length);
        }

        /// <summary>
        /// Constructor for a receive buffer.
        /// </summary>
        public AlpcMessageType() : this(true, 0)
        {
        }

        /// <summary>
        /// Constructor for a receive buffer.
        /// </summary>
        /// <param name="total_length">Length of message. This will be rounded up to at least accomodate the header.</param>
        public AlpcMessageType(int total_length) : this(true, total_length)
        {
        }

        /// <summary>
        /// Constructor for a send/receive buffer.
        /// </summary>
        /// <param name="value">The initial value to set.</param>
        /// <param name="trailing">Trailing data.</param>
        public AlpcMessageType(T value, byte[] trailing) : this(false, 0)
        {
            Value = value;
            Trailing = trailing;
        }

        /// <summary>
        /// Constructor for a send/receive buffer.
        /// </summary>
        /// <param name="value">The initial value to set.</param>
        public AlpcMessageType(T value) : this(false, 0)
        {
            Value = value;
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Get or set the type in the buffer.
        /// </summary>
        public T Value { get; set; }

        /// <summary>
        /// Get or set any trailing data after the value.
        /// </summary>
        public byte[] Trailing
        {
            get => _trailing;
            set
            {
                _trailing = value;
                int length = _header_size + _trailing.Length;
                UpdateHeaderLength(length, length);
            }
        }

        #endregion

        #region Protected Members

        /// <summary>
        /// Method to handle when FromSafeBuffer is called.
        /// </summary>
        /// <param name="buffer">The message buffer to initialize from..</param>
        /// <param name="port">The ALPC port associated with this message.</param>
        protected override void OnFromSafeBuffer(SafeAlpcPortMessageBuffer buffer, NtAlpc port)
        {
            Value = buffer.Data.Read<T>(0);

            int trailing_length = buffer.Result.u1.DataLength - _header_size;
            _trailing = buffer.Data.ReadBytes((ulong)_header_size, trailing_length);
        }

        /// <summary>
        /// Method to handle when ToSafeBuffer is called.
        /// </summary>
        /// <param name="buffer">The message buffer being created.</param>
        protected override void OnToSafeBuffer(SafeAlpcPortMessageBuffer buffer)
        {
            buffer.Data.Write(0, Value);
            if (_trailing != null && _trailing.Length > 0)
            {
                buffer.Data.WriteBytes((ulong)_header_size, _trailing);
            }
        }

        #endregion
    }
}
