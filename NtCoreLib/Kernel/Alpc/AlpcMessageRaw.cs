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
using NtCoreLib.Utilities.Text;
using System;
using System.Text;

namespace NtCoreLib.Kernel.Alpc;

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
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        Encoding = encoding;
        _data = data.CloneBytes();
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
