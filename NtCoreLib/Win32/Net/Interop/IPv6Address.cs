//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Net.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct IPv6Address
{
    // The way this reads from memory it doesn't like automatic inline arrays. 
    // So fake it with 4 32bit ints (need to be 32bit to ensure propert alignment)
    public uint Addr0;
    public uint Addr1;
    public uint Addr2;
    public uint Addr3;

    public byte[] ToArray()
    {
        // Endian shouldn't matter here.
        byte[] ret = new byte[16];
        Buffer.BlockCopy(BitConverter.GetBytes(Addr0), 0, ret, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(Addr1), 0, ret, 4, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(Addr2), 0, ret, 8, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(Addr3), 0, ret, 12, 4);
        return ret;
    }
}
