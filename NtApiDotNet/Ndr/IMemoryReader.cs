//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Ndr
{
    internal interface IMemoryReader
    {
        byte ReadByte(IntPtr address);
        byte[] ReadBytes(IntPtr address, int length);
        short ReadInt16(IntPtr address);
        IntPtr ReadIntPtr(IntPtr address);
        int ReadInt32(IntPtr address);
        T ReadStruct<T>(IntPtr address) where T : struct;
        BinaryReader GetReader(IntPtr address);
    }

    internal class CurrentProcessMemoryReader : IMemoryReader
    {
        public BinaryReader GetReader(IntPtr address)
        {
            return new BinaryReader(new UnmanagedMemoryStream(new SafeBufferWrapper(address), 0, int.MaxValue));
        }

        public byte ReadByte(IntPtr address)
        {
            return Marshal.ReadByte(address);
        }

        public short ReadInt16(IntPtr address)
        {
            return Marshal.ReadInt16(address);
        }

        public int ReadInt32(IntPtr address)
        {
            return Marshal.ReadInt32(address);
        }

        public IntPtr ReadIntPtr(IntPtr address)
        {
            return Marshal.ReadIntPtr(address);
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            byte[] ret = new byte[length];
            Marshal.Copy(address, ret, 0, length);
            return ret;
        }

        public T ReadStruct<T>(IntPtr address) where T : struct
        {
            return (T)Marshal.PtrToStructure(address, typeof(T));
        }
    }

    internal class ProcessMemoryStream : Stream
    {
        private readonly long _base_address;
        private readonly NtProcess _process;

        internal ProcessMemoryStream(NtProcess process, IntPtr base_address)
        {
            _process = process;
            _base_address = base_address.ToInt64();
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var result = _process.ReadMemory(_base_address, count);
            Array.Copy(result, 0, buffer, offset, result.Length);
            return result.Length;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>
    /// Class for a process which matches the current bitness.
    /// </summary>
    internal class ProcessMemoryReader : IMemoryReader
    {
        private readonly NtProcess _process;

        internal ProcessMemoryReader(NtProcess process)
        {
            if (process.Is64Bit != Environment.Is64BitProcess)
            {
                throw new ArgumentException("Currently do not support cross bitness reading");
            }
            _process = process;
        }

        public BinaryReader GetReader(IntPtr address)
        {
            return new BinaryReader(new ProcessMemoryStream(_process, address));
        }

        public byte ReadByte(IntPtr address)
        {
            return _process.ReadMemory<byte>(address.ToInt64());
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            return _process.ReadMemory(address.ToInt64(), length);
        }

        public short ReadInt16(IntPtr address)
        {
            return _process.ReadMemory<short>(address.ToInt64());
        }

        public int ReadInt32(IntPtr address)
        {
            return _process.ReadMemory<int>(address.ToInt64());
        }

        public IntPtr ReadIntPtr(IntPtr address)
        {
            return _process.ReadMemory<IntPtr>(address.ToInt64());
        }

        public T ReadStruct<T>(IntPtr address) where T : struct
        {
            return _process.ReadMemory<T>(address.ToInt64());
        }
    }
}
