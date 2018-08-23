//  Copyright 2015 Google Inc. All Rights Reserved.
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

using Be.Windows.Forms;
using NtApiDotNet;
using System;

namespace EditSection
{
    class NativeMappedFileByteProvider : IByteProvider
    {
        private readonly NtMappedSection _map;
        private readonly bool _readOnly;
        private bool _disable_byte_written;

        public NativeMappedFileByteProvider(NtMappedSection map, bool readOnly, long length)
        {
            _readOnly = readOnly;
            _map = map;
            Length = Math.Min(length, map.ValidLength);
        }

        public void ApplyChanges()
        {
        }

#pragma warning disable 67
        public event EventHandler Changed;
#pragma warning restore 67

        public void DeleteBytes(long index, long length)
        {
            throw new NotImplementedException();
        }

        public bool HasChanges()
        {
            return false;
        }

        public void InsertBytes(long index, byte[] bs)
        {
        }

        public long Length { get; }

#pragma warning disable 67
        public event EventHandler LengthChanged;
#pragma warning restore 67

        public byte ReadByte(long index)
        {
            if (index < Length)
            {
                return _map.Read<byte>((ulong)index);
            }

            return 0;
        }

        public byte[] ReadBytes(long index, int length)
        {
            byte[] ret = new byte[length];
            _map.ReadArray((ulong)index, ret, 0, length);
            return ret;
        }

        public bool SupportsDeleteBytes()
        {
            return false;
        }

        public bool SupportsInsertBytes()
        {
            return false;
        }

        public bool SupportsWriteByte()
        {
            return !_readOnly;
        }

        public void DisableByteWritten(bool disable)
        {
            _disable_byte_written = disable;
            if (!_disable_byte_written)
            {
                ByteWritten?.Invoke(this, new EventArgs());
            }
        }

        public void WriteBytes(long index, byte[] value)
        {
            if (index < Length)
            {
                try
                {
                    long count = Math.Min(Length - index, value.Length);
                    _map.WriteArray((ulong)index, value, 0, (int)count);
                    if (!_disable_byte_written)
                        ByteWritten?.Invoke(this, new EventArgs());
                }
                catch
                {
                }
            }
        }

        public void WriteByte(long index, byte value)
        {
            if (index < Length)
            {
                try
                {
                    _map.Write((ulong)index, value);
                    if (!_disable_byte_written)
                        ByteWritten?.Invoke(this, new EventArgs());
                }
                catch
                {
                }
            }
        }

        public event EventHandler ByteWritten;
    }
}
