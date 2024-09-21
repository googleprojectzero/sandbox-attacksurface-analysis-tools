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

using NtCoreLib.Native.SafeBuffers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Class to create an Extended Attributes buffer for NtCreateFile
/// </summary>
public sealed class EaBuffer
{
    /// <summary>
    /// Constructor
    /// </summary>
    public EaBuffer() : this(new EaBufferEntry[0])
    {
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="entries">List of entries to add.</param>
    public EaBuffer(IEnumerable<EaBufferEntry> entries)
    {
        _buffers = new List<EaBufferEntry>(entries);
    }

    /// <summary>
    /// Constructor from a binary EA buffer
    /// </summary>
    /// <param name="buffer">The EA buffer to parse</param>
    public EaBuffer(byte[] buffer)
    {
        MemoryStream stm = new(buffer);
        BinaryReader reader = new(stm);
        bool finished = false;
        _buffers = new List<EaBufferEntry>();
        while (!finished)
        {
            finished = DeserializeEntry(reader, out EaBufferEntry entry);
            _buffers.Add(entry);
        }
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="buffer">Existing buffer to copy.</param>
    public EaBuffer(EaBuffer buffer)
        : this(buffer.Entries.Select(e => e.Clone()))
    {
    }

    #region Private Members
    private readonly List<EaBufferEntry> _buffers;

    private bool DeserializeEntry(BinaryReader reader, out EaBufferEntry entry)
    {
        long start_position = reader.BaseStream.Position;
        int next_offset = reader.ReadInt32();
        EaBufferEntryFlags flags = (EaBufferEntryFlags)reader.ReadByte();
        int ea_name_length = reader.ReadByte();
        int data_length = reader.ReadUInt16();
        string name = Encoding.ASCII.GetString(reader.ReadAllBytes(ea_name_length));
        reader.ReadByte();
        byte[] data = reader.ReadAllBytes(data_length);
        entry = new EaBufferEntry(name, data, flags);
        if (next_offset == 0)
        {
            return true;
        }
        reader.BaseStream.Position = start_position + next_offset;
        return false;
    }

    private byte[] SerializeEntry(EaBufferEntry entry, bool final)
    {
        int entry_size = entry.Name.Length + entry.Data.Length + 9 + 3 & ~3;

        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        // NextEntryOffset
        if (final)
        {
            writer.Write(0);
        }
        else
        {
            writer.Write(entry_size);
        }
        // Flags
        writer.Write((byte)entry.Flags);
        // EaNameLength
        writer.Write((byte)entry.Name.Length);
        // EaValueLength
        writer.Write((ushort)entry.Data.Length);
        // EaName
        writer.Write(Encoding.ASCII.GetBytes(entry.Name));
        // NUL terminator (not counted in name length)
        writer.Write((byte)0);
        // Data
        writer.Write(entry.Data);
        // Pad to next 4 byte boundary
        while (stm.Length < entry_size)
        {
            writer.Write((byte)0);
        }
        return stm.ToArray();
    }

    private void AddEntry(string name, byte[] data, EaBufferEntryFlags flags, bool clone)
    {
        _buffers.Add(new EaBufferEntry(name, clone ? data.CloneBytes() : data, flags));
    }
    private EaBufferEntry GetEntry(string name, bool throw_on_missing)
    {
        var ret = _buffers.Where(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
        if (ret == null && throw_on_missing)
        {
            throw new KeyNotFoundException();
        }
        return ret;
    }

    #endregion

    #region Public Methods
    /// <summary>
    /// Add a new EA entry from an old entry. The data will be cloned.
    /// </summary>
    /// <param name="entry">The entry to add.</param>
    public void AddEntry(EaBufferEntry entry)
    {
        AddEntry(entry.Name, entry.Data, entry.Flags);
    }

    /// <summary>
    /// Add a new EA entry
    /// </summary>
    /// <param name="name">The name of the entry</param>
    /// <param name="data">The associated data, will be cloned</param>
    /// <param name="flags">The entry flags.</param>
    public void AddEntry(string name, byte[] data, EaBufferEntryFlags flags)
    {
        AddEntry(name, data, flags, true);
    }

    /// <summary>
    /// Add a new EA entry
    /// </summary>
    /// <param name="name">The name of the entry</param>
    /// <param name="data">The associated data</param>
    /// <param name="flags">The entry flags.</param>
    public void AddEntry(string name, int data, EaBufferEntryFlags flags)
    {
        AddEntry(name, BitConverter.GetBytes(data), flags, false);
    }

    /// <summary>
    /// Add a new EA entry
    /// </summary>
    /// <param name="name">The name of the entry</param>
    /// <param name="data">The associated data</param>
    /// <param name="flags">The entry flags.</param>
    public void AddEntry(string name, string data, EaBufferEntryFlags flags)
    {
        AddEntry(name, Encoding.Unicode.GetBytes(data), flags, false);
    }

    /// <summary>
    /// Get an entry by name.
    /// </summary>
    /// <param name="name">The name of the entry.</param>
    /// <returns>The found entry.</returns>
    /// <exception cref="KeyNotFoundException">Thrown if no entry by that name.</exception>
    public EaBufferEntry GetEntry(string name)
    {
        return GetEntry(name, true);
    }

    /// <summary>
    /// Remove an entry from the buffer.
    /// </summary>
    /// <param name="entry">The entry to remove.</param>
    public void RemoveEntry(EaBufferEntry entry)
    {
        _buffers.Remove(entry);
    }

    /// <summary>
    /// Remove an entry from the buffer by name.
    /// </summary>
    /// <param name="name">The name of the entry.</param>
    /// <exception cref="KeyNotFoundException">Thrown if no entry by that name.</exception>
    public void RemoveEntry(string name)
    {
        RemoveEntry(GetEntry(name, true));
    }

    /// <summary>
    /// Convert to a byte array
    /// </summary>
    /// <returns>The byte array</returns>
    public byte[] ToByteArray()
    {
        MemoryStream stm = new();
        for (int i = 0; i < _buffers.Count; ++i)
        {
            byte[] entry = SerializeEntry(_buffers[i], i == _buffers.Count - 1);
            stm.Write(entry, 0, entry.Length);
        }
        return stm.ToArray();
    }

    /// <summary>
    /// Convert to a safe buffer.
    /// </summary>
    /// <returns>The safe buffer.</returns>
    public SafeBufferGeneric ToBuffer()
    {
        return ToByteArray().ToBuffer();
    }

    /// <summary>
    /// Get whether the buffer contains a specific entry.
    /// </summary>
    /// <param name="name">The name of the entry.</param>
    /// <returns>True if the buffer contains an entry with the name.</returns>
    public bool ContainsEntry(string name)
    {
        return GetEntry(name, false) != null;
    }

    /// <summary>
    /// Clear all entries.
    /// </summary>
    public void Clear()
    {
        _buffers.Clear();
    }

    #endregion

    #region Public Properties
    /// <summary>
    /// Get the list of entries.
    /// </summary>
    public IEnumerable<EaBufferEntry> Entries => _buffers.AsReadOnly();

    /// <summary>
    /// Get number of entries.
    /// </summary>
    public int Count => _buffers.Count;

    /// <summary>
    /// Index to get an entry by name.
    /// </summary>
    /// <param name="name">The name of the entry.</param>
    /// <returns>The found entry.</returns>
    /// <exception cref="KeyNotFoundException">Thrown if no entry by that name.</exception>
    public EaBufferEntry this[string name] => GetEntry(name, true);
    #endregion
}
