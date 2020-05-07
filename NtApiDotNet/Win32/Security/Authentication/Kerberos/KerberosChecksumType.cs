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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Kerberos Checksum Type.
    /// </summary>
    public enum KerberosChecksumType
    {
        NONE = 0,
        CRC32 = 1,
        RSA_MD4 = 2,
        RSA_MD4_DES = 3,
        DES_MAC = 4,
        DES_MAC_K = 5,
        RSA_MD4_DES_K = 6,
        RSA_MD5 = 7,
        RSA_MD5_DES = 8,
        RSA_MD5_DES3 = 9,
        SHA1_OTHER = 10,
        HMAC_SHA1_DES3 = 12,
        SHA1 = 14,
        HMAC_SHA1_96_AES_128 = 15,
        HMAC_SHA1_96_AES_256 = 16,
        GSSAPI = 32771,
        HMAC_MD5 = -138,
        HMAC_MD5_ENC = -1138
    }
}
