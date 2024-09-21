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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

#nullable enable

namespace NtCoreLib.Image;

internal sealed class ImageFileMemoryReader : IMemoryReader
{
    private sealed class BackedMemoryZone : MemoryZone
    {
        private byte[] _data;
        public byte[] Data => _data;

        public BackedMemoryZone(ImageFile image_file, ImageSection section)
            : base(image_file.OriginalImageBase + section.RelativeVirtualAddress, section.VirtualSize)
        {
            _data = section.ToArray();
        }

        internal override void Merge<T>(T zone)
        {
            if (zone is BackedMemoryZone m)
            {
                int old_length = _data.Length;
                Array.Resize(ref _data, old_length + m._data.Length);
                Array.Copy(m._data, 0, _data, old_length, m._data.Length);
            }
            base.Merge(zone);
        }

        public int GetOffset(IntPtr address)
        {
            return (int)(address.ToInt64() - StartAddress);
        }

        public int GetSize(IntPtr address)
        {
            return (int)(EndAddress - address.ToInt64());
        }
    }

    private readonly List<BackedMemoryZone> _zones;

    private BackedMemoryZone GetZone(IntPtr address, int? size = null)
    {
        BackedMemoryZone zone = MemoryZone.FindZone(_zones, address.ToInt64()) ?? throw new NtException(NtStatus.STATUS_ACCESS_VIOLATION);
        if (size.HasValue && zone.GetSize(address) < size.Value)
        {
            throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
        }
        return zone;
    }

    public ImageFileMemoryReader(ImageFile image_file)
    {
        _zones = image_file.ImageSections.Select(s => new BackedMemoryZone(image_file, s)).ToList();
        Is64Bit = image_file.Is64bit;
    }

    public bool InProcess => false;

    public int PointerSize => Is64Bit ? 8 : 4;

    public bool Is64Bit { get; }

    public Stream GetStream(IntPtr address, int length = int.MaxValue)
    {
        BackedMemoryZone zone = GetZone(address);
        return new MemoryStream(zone.Data, zone.GetOffset(address), Math.Min(length, zone.GetSize(address)));
    }

    public string ReadAnsiStringZ(IntPtr address)
    {
        return GetStream(address, int.MaxValue).ReadAnsiStringZ();
    }

    public string ReadUnicodeStringZ(IntPtr address)
    {
        return GetStream(address, int.MaxValue).ReadUnicodeStringZ();
    }

    public T[] ReadArray<T>(IntPtr address, int count) where T : struct
    {
        BackedMemoryZone zone = GetZone(address, Marshal.SizeOf<T>() * count);
        using var buffer = zone.Data.ToBuffer();
        return buffer.ReadArray<T>(zone.GetOffset(address), count);
    }

    public byte ReadByte(IntPtr address)
    {
        BackedMemoryZone zone = GetZone(address, 1);
        return zone.Data[zone.GetOffset(address)];
    }

    public byte[] ReadBytes(IntPtr address, int length)
    {
        BackedMemoryZone zone = GetZone(address, length);
        byte[] ret = new byte[length];
        Array.Copy(zone.Data, zone.GetOffset(address), ret, 0, length);
        return ret;
    }

    public short ReadInt16(IntPtr address)
    {
        BackedMemoryZone zone = GetZone(address, 2);
        return BitConverter.ToInt16(zone.Data, zone.GetOffset(address));
    }

    public int ReadInt32(IntPtr address)
    {
        BackedMemoryZone zone = GetZone(address, 4);
        return BitConverter.ToInt32(zone.Data, zone.GetOffset(address));
    }

    public long ReadInt64(IntPtr address)
    {
        BackedMemoryZone zone = GetZone(address, 8);
        return BitConverter.ToInt64(zone.Data, zone.GetOffset(address));
    }

    public IntPtr ReadIntPtr(IntPtr address)
    {
        if (Is64Bit)
        {
            return new IntPtr(ReadInt64(address));
        }
        return new IntPtr(ReadInt32(address));
    }

    public T ReadStruct<T>(IntPtr address, int index = 0) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        int offset = index * size;
        BackedMemoryZone zone = GetZone(address + offset, size);
        using var buffer = zone.Data.ToBuffer();
        return buffer.Read<T>((ulong)(offset + zone.GetOffset(address)));
    }
}