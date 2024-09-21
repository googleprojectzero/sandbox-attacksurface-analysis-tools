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

using NtCoreLib.Native.SafeBuffers;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Kernel.Alpc;

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
