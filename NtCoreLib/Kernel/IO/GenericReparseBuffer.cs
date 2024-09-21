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
using System.IO;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Generic GUID reparse buffer.
/// </summary>
public sealed class GenericReparseBuffer : ReparseBuffer
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="tag">The reparse tag.</param>
    /// <param name="guid">The reparse GUID</param>
    /// <param name="data">Additional reparse data.</param>
    public GenericReparseBuffer(uint tag, Guid guid, byte[] data) : base((ReparseTag)tag)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        Data = data.CloneBytes();
        Guid = guid;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="tag">The reparse tag.</param>
    /// <param name="guid">The reparse GUID</param>
    /// <param name="data">Additional reparse data.</param>
    public GenericReparseBuffer(ReparseTag tag, Guid guid, byte[] data) : base(tag)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        Data = data.CloneBytes();
        Guid = guid;
    }

    internal GenericReparseBuffer(ReparseTag tag) : base(tag)
    {
    }

    /// <summary>
    /// The reparse GUID.
    /// </summary>
    public Guid Guid { get; set; }

    /// <summary>
    /// Additional reparse data.
    /// </summary>
    public byte[] Data { get; set; }

    /// <summary>
    /// Get reparse buffer data as a byte array (not including header).
    /// </summary>
    /// <returns>The reparse buffer data.</returns>
    protected override byte[] GetBuffer()
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        writer.Write(Data);
        return stm.ToArray();
    }

    /// <summary>
    /// Function to initialize this class by parsing the reparse buffer data (not including header).
    /// </summary>
    /// <param name="data_length">The length of the data to read.</param>
    /// <param name="reader">The stream to read from.</param>
    protected override void ParseBuffer(int data_length, BinaryReader reader)
    {
        Guid = new Guid(reader.ReadAllBytes(16));
        Data = reader.ReadAllBytes(data_length);
    }
}
