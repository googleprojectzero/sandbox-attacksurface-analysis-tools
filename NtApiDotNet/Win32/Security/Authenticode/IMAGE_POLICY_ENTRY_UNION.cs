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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authenticode
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_POLICY_ENTRY_UNION
    {
        [FieldOffset(0)]
        public IntPtr None;
        [MarshalAs(UnmanagedType.U1), FieldOffset(0)]
        public bool BoolValue;
        [FieldOffset(0)]
        public sbyte Int8Value;
        [FieldOffset(0)]
        public byte UInt8Value;
        [FieldOffset(0)]
        public short Int16Value;
        [FieldOffset(0)]
        public ushort UInt16Value;
        [FieldOffset(0)]
        public int Int32Value;
        [FieldOffset(0)]
        public uint UInt32Value;
        [FieldOffset(0)]
        public long Int64Value;
        [FieldOffset(0)]
        public ulong UInt64Value;
        [FieldOffset(0)]
        public IntPtr AnsiStringValue;
        [FieldOffset(0)]
        public IntPtr UnicodeStringValue;
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
