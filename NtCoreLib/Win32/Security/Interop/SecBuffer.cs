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
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Security.Buffers;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal sealed class SecBuffer
{
    public int cbBuffer;
    public SecurityBufferType BufferType;
    public IntPtr pvBuffer;

    public SecBuffer()
    {
    }

    public SecBuffer(SecurityBufferType type)
    {
        BufferType = type;
    }

    public SecBuffer(SecurityBufferType type, IntPtr buffer, int size) 
        : this(type)
    {
        pvBuffer = buffer;
        cbBuffer = size;
    }

    public SecBuffer(SecurityBufferType type, SafeBufferGeneric buffer) 
        : this(type, buffer.DangerousGetHandle(), buffer.Length)
    {
    }

    public static SecBuffer Create(SecurityBufferType type, byte[] data, DisposableList list)
    {
        return new SecBuffer(type, list.AddResource(new SafeHGlobalBuffer(data)));
    }

    public static SecBuffer Create(SecurityBufferType type, int length, DisposableList list)
    {
        var buffer = list.AddResource(new SafeHGlobalBuffer(length));
        buffer.FillBuffer(0);
        return new SecBuffer(type, buffer);
    }

    public byte[] ToArray()
    {
        byte[] ret = new byte[cbBuffer];
        Marshal.Copy(pvBuffer, ret, 0, ret.Length);
        return ret;
    }
}
