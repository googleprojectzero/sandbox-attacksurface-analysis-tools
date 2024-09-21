//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Text;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// A single EA entry.
/// </summary>
public sealed class EaBufferEntry
{
    /// <summary>
    /// Name of the entry
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Data associated with the entry
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Flags
    /// </summary>
    public EaBufferEntryFlags Flags { get; }

    internal EaBufferEntry Clone()
    {
        return new EaBufferEntry(Name, Data.CloneBytes(), Flags);
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="name">The name of the entry</param>
    /// <param name="data">Data associated with the entry</param>
    /// <param name="flags">Flags for entry.</param>
    public EaBufferEntry(string name, byte[] data, EaBufferEntryFlags flags)
    {
        Name = name;
        Data = data;
        Flags = flags;
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="name">The name of the entry</param>
    /// <param name="data">Data associated with the entry</param>
    /// <param name="flags">Flags for entry.</param>
    public EaBufferEntry(string name, int data, EaBufferEntryFlags flags)
        : this(name, BitConverter.GetBytes(data), flags)
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="name">The name of the entry</param>
    /// <param name="data">Data associated with the entry</param>
    /// <param name="flags">Flags for entry.</param>
    public EaBufferEntry(string name, string data, EaBufferEntryFlags flags)
        : this(name, Encoding.Unicode.GetBytes(data), flags)
    {
    }

    /// <summary>
    /// Get the EA buffer data as a string.
    /// </summary>
    /// <returns>The data as a string.</returns>
    public string DataAsString()
    {
        if (Data.Length % 2 != 0)
        {
            throw new ArgumentException("Invalid data length for a Unicode string");
        }
        return Encoding.Unicode.GetString(Data);
    }

    /// <summary>
    /// Get the EA buffer data as an Int32.
    /// </summary>
    /// <returns>The data as an Int32.</returns>
    public int DataAsInt32()
    {
        if (Data.Length != 4)
        {
            throw new ArgumentException("Invalid data length for an Int32");
        }
        return BitConverter.ToInt32(Data, 0);
    }

    /// <summary>
    /// Convert entry to a string
    /// </summary>
    /// <returns>The entry as a string</returns>
    public override string ToString()
    {
        return $"Name: {Name} - Data Size: {Data.Length} - Flags {Flags}";
    }
}
