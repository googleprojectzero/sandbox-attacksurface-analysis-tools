﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;
using NtCoreLib.Native.SafeBuffers;

namespace NtCoreLib.Win32.Security.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct SEC_WINNT_AUTH_BYTE_VECTOR
{
    public uint ByteArrayOffset;
    public ushort ByteArrayLength;

    public byte[] ReadBytes(SafeBufferGeneric buffer)
    {
        if (ByteArrayOffset == 0)
            return new byte[0];
        return buffer.ReadBytes(ByteArrayOffset, ByteArrayLength);
    }
}
