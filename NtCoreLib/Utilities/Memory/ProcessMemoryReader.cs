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

namespace NtCoreLib.Utilities.Memory;

/// <summary>
/// IMemoryReader implementation for a process.
/// </summary>
internal sealed class ProcessMemoryReader : IMemoryReader
{
    private readonly NtProcess _process;

    internal ProcessMemoryReader(NtProcess process)
    {
        _process = process;
        Is64Bit = _process.Is64Bit;
        PointerSize = Is64Bit ? 8 : 4;
    }

    public bool InProcess => false;

    public Stream GetStream(IntPtr address, int length)
    {
        return new MemoryReaderStream(this, address, length);
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

    public IntPtr ReadIntPtr(IntPtr address)
    {
        return _process.ReadMemory<IntPtr>(address.ToInt64());
    }

    public T ReadStruct<T>(IntPtr address, int index) where T : struct
    {
        int offset = index > 0 ? index * Marshal.SizeOf<T>() : 0;
        return _process.ReadMemory<T>(address.ToInt64() + offset);
    }

    public T[] ReadArray<T>(IntPtr address, int count) where T : struct
    {
        T[] ret = new T[count];
        for (int i = 0; i < count; ++i)
        {
            ret[i] = ReadStruct<T>(address, i);
        }
        return ret;
    }

    public string ReadAnsiStringZ(IntPtr address)
    {
        return new MemoryReaderStream(this, address, int.MaxValue).ReadAnsiStringZ();
    }

    public string ReadUnicodeStringZ(IntPtr address)
    {
        return new MemoryReaderStream(this, address, int.MaxValue).ReadUnicodeStringZ();
    }

    public int PointerSize { get; }

    public bool Is64Bit { get; }
}
