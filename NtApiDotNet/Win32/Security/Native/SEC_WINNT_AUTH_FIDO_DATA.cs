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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SEC_WINNT_AUTH_FIDO_DATA
    {
        public ushort cbHeaderLength;
        public ushort cbStructureLength;
        public SEC_WINNT_AUTH_BYTE_VECTOR Secret; // offsets are from the beginning of this structure
        public SEC_WINNT_AUTH_BYTE_VECTOR NewSecret;
        public SEC_WINNT_AUTH_BYTE_VECTOR EncryptedNewSecret; // For storage by cloud AP
        public SEC_WINNT_AUTH_BYTE_VECTOR NetworkLogonBuffer; // Opaque data, understood by plugin, may contain signed Nonce and other data to perform a network logon
        public ulong ulSignatureCount; // signature count to be stored in public cached info, required for CredProv
    }
}
