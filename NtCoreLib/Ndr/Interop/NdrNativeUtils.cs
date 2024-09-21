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

using NtCoreLib.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Ndr.Interop;

internal static class NdrNativeUtils
{
    internal static byte[] ReadAll(this BinaryReader reader, int length)
    {
        byte[] ret = reader.ReadBytes(length);
        if (ret.Length != length)
        {
            throw new EndOfStreamException();
        }
        return ret;
    }

    internal static Guid ReadComGuid(this IMemoryReader reader, IntPtr p)
    {
        if (p == IntPtr.Zero)
        {
            return IID_IUnknown;
        }
        return new Guid(reader.ReadBytes(p, 16));
    }

    internal static T[] EnumeratePointerList<T>(this IMemoryReader reader, IntPtr p, Func<IntPtr, T> load_type)
    {
        List<T> ret = new();

        if (p == IntPtr.Zero)
        {
            return new T[0];
        }

        IntPtr curr = p;
        IntPtr value;
        while ((value = reader.ReadIntPtr(curr)) != IntPtr.Zero)
        {
            ret.Add(load_type(value));
            curr += reader.PointerSize;
        }
        return ret.ToArray();
    }

    internal static T[] EnumeratePointerList<T>(this IMemoryReader reader, IntPtr p) where T : struct
    {
        return reader.EnumeratePointerList(p, i => reader.ReadStruct<T>(i));
    }

    internal static T[] ReadPointerArray<T>(this IMemoryReader reader, IntPtr p, int count, Func<IntPtr, T> load_type)
    {
        T[] ret = new T[count];
        if (p == IntPtr.Zero)
        {
            return ret;
        }

        for (int i = 0; i < count; ++i)
        {
            IntPtr curr = reader.ReadIntPtr(p + i * reader.PointerSize);
            if (curr == IntPtr.Zero)
            {
                ret[i] = default;
            }
            else
            {
                ret[i] = load_type(curr);
            }
        }
        return ret;
    }

    internal static T[] ReadPointerArray<T>(this IMemoryReader reader, IntPtr p, int count) where T : struct
    {
        return reader.ReadPointerArray(p, count, i => reader.ReadStruct<T>(i));
    }

    internal static RPC_VERSION ToRpcVersion(this Version version)
    {
        return new RPC_VERSION() { MajorVersion = (ushort)version.Major, MinorVersion = (ushort)version.Minor };
    }

    internal static int GetPrimitiveTypeSize<T>() where T : struct
    {
        if (!typeof(T).IsPrimitive)
        {
            throw new ArgumentException($"Type {typeof(T)} not primitive");
        }

        // The "native" size of a char is 1 due to defaulting to ANSI!
        if (typeof(T) == typeof(char))
        {
            return 2;
        }

        return System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
    }

    internal static int CalculateAlignment(int offset, int alignment)
    {
        int result = alignment - offset % alignment;
        if (result < alignment)
        {
            return result;
        }
        return 0;
    }

    internal static U[] Cast<T, U>(this T[] array)
    {
        return (U[])(Array)array;
    }

    internal static readonly Guid IID_IUnknown = new("00000000-0000-0000-C000-000000000046");
    internal static readonly Guid IID_IDispatch = new("00020400-0000-0000-C000-000000000046");
    internal static readonly Guid IID_IInspectable = new("AF86E2E0-B12D-4c6a-9C5A-D7AA65101E90");
    internal static readonly Guid IID_IPSFactoryBuffer = new("D5F569D0-593B-101A-B569-08002B2DBF7A");
    internal static readonly Guid DCE_TransferSyntax = new("8A885D04-1CEB-11C9-9FE8-08002B104860");
    internal static readonly Guid NDR64_TransferSyntax = new("71710533-BEBA-4937-8319-B5DBEF9CCC36");
    internal static readonly Guid FakeNDR64_TransferSyntax = new("B4537DA9-3D03-4F6B-B594-52B2874EE9D0");
}
