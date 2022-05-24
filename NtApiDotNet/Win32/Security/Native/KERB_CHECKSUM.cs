//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
    // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_CHECKSUM
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus InitializeExFunc(byte[] key, int key_size, KerberosKeyUsage key_usage, out IntPtr context);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus SumFunc(IntPtr context, int size, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus FinalizeFunc(IntPtr context, byte[] hash);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus FinishFunc(ref IntPtr context);

        public KerberosChecksumType Type;
        public int Size;
        public int Flags;
        public IntPtr Initialize;
        public SumFunc Sum;
        public FinalizeFunc Finalize;
        public FinishFunc Finish;
        public InitializeExFunc InitializeEx;
        public IntPtr InitializeEx2;
    }
}
