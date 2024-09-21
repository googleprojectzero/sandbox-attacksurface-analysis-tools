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
using System.IO;
using System.Linq;

namespace NtCoreLib.Utilities.Memory;

internal sealed class CrossBitnessMemoryReader : IMemoryReader
{
    private readonly IMemoryReader _reader;

    public CrossBitnessMemoryReader(IMemoryReader reader)
    {
        _reader = reader;
    }

    public CrossBitnessMemoryReader(NtProcess process) 
        : this(new ProcessMemoryReader(process))
    {
    }

    public bool InProcess => false;

    public int PointerSize => 4;

    public bool Is64Bit => false;

    public Stream GetStream(IntPtr address, int length)
    {
        return _reader.GetStream(address, length);
    }

    public string ReadAnsiStringZ(IntPtr address)
    {
        return _reader.ReadAnsiStringZ(address);
    }

    public string ReadUnicodeStringZ(IntPtr address)
    {
        return _reader.ReadUnicodeStringZ(address);
    }

    public byte ReadByte(IntPtr address)
    {
        return _reader.ReadByte(address);
    }

    public byte[] ReadBytes(IntPtr address, int length)
    {
        return _reader.ReadBytes(address, length);
    }

    public short ReadInt16(IntPtr address)
    {
        return _reader.ReadInt16(address);
    }

    public int ReadInt32(IntPtr address)
    {
        return _reader.ReadInt32(address);
    }

    public IntPtr ReadIntPtr(IntPtr address)
    {
        return _reader.ReadStruct<IntPtr32>(address).Convert();
    }

    public T ReadStruct<T>(IntPtr address, int index) where T : struct
    {
        if (typeof(T) == typeof(IntPtr))
        {
            return (T)(object)_reader.ReadStruct<IntPtr32>(address, index).Convert();
        }

        if (new T() is IConvertToNative<T> convert)
        {
            return convert.Read(_reader, address, index);
        }

        return _reader.ReadStruct<T>(address, index);
    }

    public T[] ReadArray<T>(IntPtr address, int count) where T : struct
    {
        if (typeof(T) == typeof(IntPtr))
        {
            return _reader.ReadArray<IntPtr32>(address, count).Select(i => i.Convert()).Cast<T>().ToArray();
        }

        if (new T() is IConvertToNative<T> convert)
        {
            T[] ret = new T[count];
            for (int i = 0; i < count; ++i)
            {
                ret[i] = convert.Read(_reader, address, i);
            }
            return ret;
        }

        return _reader.ReadArray<T>(address, count);
    }
}