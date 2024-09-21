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
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

#nullable enable

namespace NtCoreLib.Utilities.Memory;

internal class CurrentProcessMemoryReader : IMemoryReader
{
    private readonly List<MemoryZone> _restricted_zones = new();

    [HandleProcessCorruptedStateExceptions]
    private static T RunWithAccessCatch<T>(Func<T> func)
    {
        try
        {
            return func();
        }
        catch
        {
            throw new NtException(NtStatus.STATUS_ACCESS_VIOLATION);
        }
    }

    internal CurrentProcessMemoryReader()
    {
    }

    internal CurrentProcessMemoryReader(IEnumerable<Tuple<long, int>> restricted_zones)
    {
        _restricted_zones = MemoryZone.MergeZones(restricted_zones.Select(
            t => new MemoryZone(t.Item1, t.Item1 + t.Item2)).OrderBy(t => t.StartAddress));
    }

    private void CheckAddress(IntPtr address, int size)
    {
        if (_restricted_zones.Count == 0)
        {
            return;
        }

        long base_address = address.ToInt64();
        MemoryZone zone = MemoryZone.FindZone(_restricted_zones, base_address) ?? throw new NtException(NtStatus.STATUS_ACCESS_VIOLATION);
        if (base_address + size >= zone.EndAddress)
        {
            throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
        }
    }

    public bool InProcess => true;

    public Stream GetStream(IntPtr address, int length)
    {
        long max_length = int.MaxValue;
        if (_restricted_zones.Count > 0)
        {
            MemoryZone zone = MemoryZone.FindZone(_restricted_zones, address.ToInt64()) ?? throw new NtException(NtStatus.STATUS_ACCESS_VIOLATION);
            max_length = zone.EndAddress - address.ToInt64();
        }

        return new UnmanagedMemoryStream(new SafeBufferWrapper(address), 0, Math.Min(length, max_length));
    }

    public byte ReadByte(IntPtr address)
    {
        CheckAddress(address, 1);
        return RunWithAccessCatch(() => Marshal.ReadByte(address));
    }

    public short ReadInt16(IntPtr address)
    {
        CheckAddress(address, 2);
        return RunWithAccessCatch(() => Marshal.ReadInt16(address));
    }

    public int ReadInt32(IntPtr address)
    {
        CheckAddress(address, 4);
        return RunWithAccessCatch(() => Marshal.ReadInt32(address));
    }

    public IntPtr ReadIntPtr(IntPtr address)
    {
        CheckAddress(address, IntPtr.Size);
        return RunWithAccessCatch(() => Marshal.ReadIntPtr(address));
    }

    public byte[] ReadBytes(IntPtr address, int length)
    {
        CheckAddress(address, length);
        byte[] ret = new byte[length];
        return RunWithAccessCatch(() =>
        {
            Marshal.Copy(address, ret, 0, length); 
            return ret;
        });
    }

    public T ReadStruct<T>(IntPtr address, int index) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        int offset = index > 0 ? index * Marshal.SizeOf<T>() : 0;
        CheckAddress(address + offset, size) ;
        return RunWithAccessCatch(() => Marshal.PtrToStructure<T>(address + offset));
    }

    public T[] ReadArray<T>(IntPtr address, int count) where T : struct
    {
        CheckAddress(address, Marshal.SizeOf<T>() * count);
        var buffer = new SafeBufferWrapper(address);
        T[] ret = new T[count];
        return RunWithAccessCatch(() =>
        {
            buffer.ReadArray(0, ret, 0, count);
            return ret;
        });
    }

    public string ReadAnsiStringZ(IntPtr address)
    {
        return GetStream(address, int.MaxValue).ReadAnsiStringZ();
    }

    public string ReadUnicodeStringZ(IntPtr address)
    {
        return GetStream(address, int.MaxValue).ReadUnicodeStringZ();
    }

    public int PointerSize => IntPtr.Size;

    public bool Is64Bit => Environment.Is64BitProcess;
}
