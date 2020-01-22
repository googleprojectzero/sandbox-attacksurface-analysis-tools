//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Utilities.Memory
{
    internal class CurrentProcessMemoryReader : IMemoryReader
    {
        private List<Tuple<long, long>> _restricted_zones = new List<Tuple<long, long>>();

        internal CurrentProcessMemoryReader()
        {
        }

        internal CurrentProcessMemoryReader(IEnumerable<Tuple<long, int>> restricted_zones)
        {
            _restricted_zones.AddRange(restricted_zones.Select(t => Tuple.Create(t.Item1, t.Item1 + t.Item2)).OrderBy(t => t.Item1));
        }

        private void CheckAddress(IntPtr address, int size)
        {
            if (_restricted_zones.Count == 0)
            {
                return;
            }

            long base_address = address.ToInt64();
            foreach (var t in _restricted_zones)
            {
                if (base_address >= t.Item1 && base_address < t.Item2)
                {
                    return;
                }
            }
            throw new NtException(NtStatus.STATUS_NO_MEMORY);
        }

        public bool InProcess => true;

        public BinaryReader GetReader(IntPtr address)
        {
            CheckAddress(address, 1);
            return new BinaryReader(new UnmanagedMemoryStream(new SafeBufferWrapper(address), 0, int.MaxValue));
        }

        public byte ReadByte(IntPtr address)
        {
            CheckAddress(address, 1);
            return System.Runtime.InteropServices.Marshal.ReadByte(address);
        }

        public short ReadInt16(IntPtr address)
        {
            CheckAddress(address, 2);
            return System.Runtime.InteropServices.Marshal.ReadInt16(address);
        }

        public int ReadInt32(IntPtr address)
        {
            CheckAddress(address, 4);
            return System.Runtime.InteropServices.Marshal.ReadInt32(address);
        }

        public IntPtr ReadIntPtr(IntPtr address)
        {
            CheckAddress(address, IntPtr.Size);
            return System.Runtime.InteropServices.Marshal.ReadIntPtr(address);
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            CheckAddress(address, length);
            byte[] ret = new byte[length];
            System.Runtime.InteropServices.Marshal.Copy(address, ret, 0, length);
            return ret;
        }

        public T ReadStruct<T>(IntPtr address) where T : struct
        {
            CheckAddress(address, System.Runtime.InteropServices.Marshal.SizeOf(typeof(T)));
            return (T)System.Runtime.InteropServices.Marshal.PtrToStructure(address, typeof(T));
        }

        public T[] ReadArray<T>(IntPtr address, int count) where T : struct
        {
            CheckAddress(address, System.Runtime.InteropServices.Marshal.SizeOf(typeof(T)) * count);
            var buffer = new SafeBufferWrapper(address);
            T[] ret = new T[count];
            buffer.ReadArray(0, ret, 0, count);
            return ret;
        }

        public string ReadAnsiStringZ(IntPtr address)
        {
            CheckAddress(address, 1);
            return System.Runtime.InteropServices.Marshal.PtrToStringAnsi(address);
        }

        public int PointerSize { get { return IntPtr.Size; } }
    }
}
