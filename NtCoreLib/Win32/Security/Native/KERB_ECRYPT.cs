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
    internal struct KERB_ECRYPT
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus InitializeFunc(byte[] key, int key_size, KerberosKeyUsage key_usage, out IntPtr context);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus EncryptFunc(IntPtr context, byte[] input, int input_size, byte[] output, ref int output_size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus DecryptFunc(IntPtr context, byte[] input, int input_size, byte[] output, ref int output_size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus FinishFunc(ref IntPtr context);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus HashPasswordFunc(UnicodeString password, UnicodeString salt, int iterations, byte[] output);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate NtStatus RandomKeyFunc(byte[] existing_key, int existing_key_size, byte[] key);

        public KerberosEncryptionType Type;
        public int BlockSize;
        public KerberosEncryptionType ExportType;
        public int KeySize;
        public int AdditionalEncryptionSize;
        public KerberosChecksumType ChecksumType;
        public int Flags;         // 4 seems to indicate a valid encryption algorithm.
        public string AlgName;
        [MarshalAs(UnmanagedType.FunctionPtr)]
        public InitializeFunc Initialize;
        public EncryptFunc Encrypt;
        public DecryptFunc Decrypt;
        public FinishFunc Finish;
        public HashPasswordFunc HashPassword;
        public RandomKeyFunc RandomKey;
        public IntPtr Control;
        public IntPtr PlainEncrypt;
        public IntPtr PlainDecrypt;
        public IntPtr PRF;
        public IntPtr PRFPlus;
    }
}
