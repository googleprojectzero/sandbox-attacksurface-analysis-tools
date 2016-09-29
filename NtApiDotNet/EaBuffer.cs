using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to create an Extended Attributes buffer for NtCreateFile
    /// </summary>
    public sealed class EaBuffer
    {
        public EaBuffer()
        {
            _buffers = new List<Tuple<string, byte[]>>();
        }

        private List<Tuple<string, byte[]>> _buffers;

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
            _buffers.Add(new Tuple<string, byte[]>(name, (byte[])data.Clone()));
        }

        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            for (int i = 0; i < _buffers.Count; ++i)
            {
                byte[] entry = SerializeEntry(_buffers[i].Item1, _buffers[i].Item2, i == _buffers.Count - 1);
                stm.Write(entry, 0, entry.Length);
            }
            return stm.ToArray();
        }
    }

}
