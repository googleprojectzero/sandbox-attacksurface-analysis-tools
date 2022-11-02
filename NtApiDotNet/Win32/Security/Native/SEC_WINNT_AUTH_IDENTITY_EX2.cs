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

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SEC_WINNT_AUTH_IDENTITY_EX2
    {
        public const int SEC_WINNT_AUTH_IDENTITY_VERSION_2 = 513;

        public int Version;
        public ushort cbHeaderLength;
        public int cbStructureLength;
        public uint UserOffset;
        public ushort UserLength;
        public uint DomainOffset;
        public ushort DomainLength;
        public uint PackedCredentialsOffset;
        public ushort PackedCredentialsLength;
        public SecWinNtAuthIdentityFlags Flags;
        public uint PackageListOffset;
        public ushort PackageListLength;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    internal struct SEC_WINNT_AUTH_DATA
    {
        public Guid CredType;
        public SEC_WINNT_AUTH_BYTE_VECTOR CredData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SEC_WINNT_AUTH_PACKED_CREDENTIALS
    {
        public ushort cbHeaderLength;    // the length of the header
        public ushort cbStructureLength; // pay load length including the header
        public SEC_WINNT_AUTH_DATA AuthData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SEC_WINNT_AUTH_DATA_PASSWORD
    {
        public SEC_WINNT_AUTH_BYTE_VECTOR UnicodePassword;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SEC_WINNT_AUTH_CERTIFICATE_DATA
    {
        public ushort cbHeaderLength;
        public ushort cbStructureLength;
        SEC_WINNT_AUTH_BYTE_VECTOR Certificate;
    }


    [Flags]
    internal enum NGC_DATA_FLAG
    {
        NGC_DATA_FLAG_KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES = 0x1,
        NGC_DATA_FLAG_KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO = 0x2,
        NGC_DATA_FLAG_IS_SMARTCARD_DATA = 0x4
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SEC_WINNT_AUTH_NGC_DATA
    {
        public Luid LogonId;
        public NGC_DATA_FLAG Flags;
        public SEC_WINNT_AUTH_BYTE_VECTOR CspInfo;
        public SEC_WINNT_AUTH_BYTE_VECTOR UserIdKeyAuthTicket;
        public SEC_WINNT_AUTH_BYTE_VECTOR DecryptionKeyName;
        public SEC_WINNT_AUTH_BYTE_VECTOR DecryptionKeyAuthTicket;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS_DATA
    {
        public IntPtr pcc;
        public IntPtr hProv;
        public string pwszECDHKeyName; // only optionally set for ECDSA smartcards
    }

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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SEC_WINNT_AUTH_SHORT_VECTOR
    {
        public uint ShortArrayOffset; // each element is a short
        public ushort ShortArrayCount; // number of characters
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX
    {
        public ushort cbHeaderLength;
        public SecWinNtAuthIdentityFlags Flags; // contains the Flags field in
                                                // SEC_WINNT_AUTH_IDENTITY_EX
        public SEC_WINNT_AUTH_BYTE_VECTOR PackedCredentials;
        public SEC_WINNT_AUTH_SHORT_VECTOR PackageList;
    }
}
