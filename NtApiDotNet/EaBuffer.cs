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
        public string Name { get; private set; }
        public byte[] Data { get; private set; }

        public EaBufferEntry(string name, byte[] data)
        {
            Name = name;
            Data = data;
        }

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
        public EaBuffer()
        {
            _buffers = new List<EaBufferEntry>();
        }

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

        public void AddEntry(string name, byte[] data)
        {
            _buffers.Add(new EaBufferEntry(name, (byte[])data.Clone()));
        }

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
