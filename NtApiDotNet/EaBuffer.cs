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

using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// A single EA entry.
    /// </summary>
    public sealed class EaBufferEntry
    {
        /// <summary>
        /// Name of the entry
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// Data associated with the entry
        /// </summary>
        public byte[] Data { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">The name of the entry</param>
        /// <param name="data">Data associated with the entry</param>
        public EaBufferEntry(string name, byte[] data)
        {
            Name = name;
            Data = data;
        }

        /// <summary>
        /// Convery entry to a string
        /// </summary>
        /// <returns>The entry as a string</returns>
        public override string ToString()
        {
            return string.Format("Name: {0} - Data Size: {1}", Name, Data.Length);
        }
    }

    /// <summary>
    /// Class to create an Extended Attributes buffer for NtCreateFile
    /// </summary>
    public sealed class EaBuffer : List<EaBufferEntry>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public EaBuffer()
        {
            _buffers = new List<EaBufferEntry>();
        }

        /// <summary>
        /// Constructor from a binary EA buffer
        /// </summary>
        /// <param name="buffer">The EA buffer to parse</param>
        public EaBuffer(byte[] buffer)
        {
            MemoryStream stm = new MemoryStream(buffer);
            BinaryReader reader = new BinaryReader(stm);
            bool finished = false;

            while(finished)
            {
                EaBufferEntry entry;
                finished = DeserializeEntry(reader, out entry);
                Add(entry);
            }
        }

        private List<EaBufferEntry> _buffers;

        private bool DeserializeEntry(BinaryReader reader, out EaBufferEntry entry)
        {
            long start_position = reader.BaseStream.Position;
            int next_offset = reader.ReadInt32();
            // Flags
            reader.ReadByte();
            int ea_name_length = reader.ReadByte();
            int data_length = reader.ReadUInt16();
            string name = Encoding.ASCII.GetString(reader.ReadAllBytes(ea_name_length));
            reader.ReadByte();
            byte[] data = reader.ReadAllBytes(data_length);
            entry = new EaBufferEntry(name, data);
            if (next_offset == 0)
            {
                return false;
            }
            reader.BaseStream.Position = start_position = next_offset;
            return true;
        }

        private byte[] SerializeEntry(string name, byte[] data, bool final)
        {
            int entry_size = (name.Length + data.Length + 9 + 3) & ~3;

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
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
            writer.Write((byte)0);
            // EaNameLength
            writer.Write((byte)name.Length);
            // EaValueLength
            writer.Write((ushort)data.Length);
            // EaName
            writer.Write(Encoding.ASCII.GetBytes(name));
            // NUL terminator (not counted in name length)
            writer.Write((byte)0);
            // Data
            writer.Write(data);
            // Pad to next 4 byte boundary
            while (stm.Length < entry_size)
            {
                writer.Write((byte)0);
            }
            return stm.ToArray();
        }

        /// <summary>
        /// Add a new EA entry
        /// </summary>
        /// <param name="name">The name of the entry</param>
        /// <param name="data">The associated data</param>
        public void AddEntry(string name, byte[] data)
        {
            _buffers.Add(new EaBufferEntry(name, (byte[])data.Clone()));
        }

        /// <summary>
        /// Convert to a byte array
        /// </summary>
        /// <returns>The byte array</returns>
        public byte[] ToByteArray()
        {
            MemoryStream stm = new MemoryStream();
            for (int i = 0; i < _buffers.Count; ++i)
            {
                byte[] entry = SerializeEntry(_buffers[i].Name, _buffers[i].Data, i == _buffers.Count - 1);
                stm.Write(entry, 0, entry.Length);
            }
            return stm.ToArray();
        }
    }

}
