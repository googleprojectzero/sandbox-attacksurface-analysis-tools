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
using System.Text;

namespace NtApiDotNet.Utilities.Memory
{
    /// <summary>
    /// IMemoryReader implementation for a process.
    /// </summary>
    internal class ProcessMemoryReader : IMemoryReader
    {
        protected readonly NtProcess _process;

        internal ProcessMemoryReader(NtProcess process)
        {
            _process = process;
            PointerSize = _process.Is64Bit ? 8 : 4;
        }

        public bool InProcess => false;

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
            return _process.ReadMemory(address.ToInt64(), length, true);
        }

        public short ReadInt16(IntPtr address)
        {
            return _process.ReadMemory<short>(address.ToInt64());
        }

        public int ReadInt32(IntPtr address)
        {
            return _process.ReadMemory<int>(address.ToInt64());
        }

        public virtual IntPtr ReadIntPtr(IntPtr address)
        {
            return _process.ReadMemory<IntPtr>(address.ToInt64());
        }

        public virtual T ReadStruct<T>(IntPtr address) where T : struct
        {
            return _process.ReadMemory<T>(address.ToInt64());
        }

        public virtual T[] ReadArray<T>(IntPtr address, int count) where T : struct
        {
            T[] ret = new T[count];
            int size = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            for (int i = 0; i < count; ++i)
            {
                ret[i] = ReadStruct<T>(address + i * size);
            }
            return ret;
        }

        public string ReadAnsiStringZ(IntPtr address)
        {
            ProcessMemoryStream stm = new ProcessMemoryStream(_process, address);
            StringBuilder builder = new StringBuilder();
            int ch = stm.ReadByte();
            while (ch > 0)
            {
                builder.Append((char)ch);
                ch = stm.ReadByte();
            }
            return builder.ToString();
        }

        public int PointerSize { get; }

        public static ProcessMemoryReader Create(NtProcess process)
        {
            if (!Environment.Is64BitProcess && process.Is64Bit)
            {
                throw new ArgumentException("Do not support 32 to 64 bit reading.");
            }

            if (Environment.Is64BitProcess != process.Is64Bit)
            {
                return new CrossBitnessProcessMemoryReader(process);
            }
            else
            {
                return new ProcessMemoryReader(process);
            }
        }
    }
}
