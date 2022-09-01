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
    /// Kerberos Encryption Type.
    /// </summary>
    public enum KerberosEncryptionType
    {
        NULL = 0,
        DES_CBC_CRC = 1,
        DES_CBC_MD4 = 2,
        DES_CBC_MD5 = 3,
        DES3_CBC_MD5 = 5,
        OLD_DES3_CBC_SHA1 = 7,
        SIGN_DSA_GENERATE = 8,
        ENCRYPT_RSA_PRIV = 9,
        ENCRYPT_RSA_PUB = 10,
        RSA_SHA1 = 11,
        RC2_CBC = 12,
        RSA = 13,
        RSAES_OAEP = 14,
        DES_EDE3_CBC = 15,
        DES3_CBC_SHA1 = 16,
        AES128_CTS_HMAC_SHA1_96 = 17,
        AES256_CTS_HMAC_SHA1_96 = 18,
        ARCFOUR_HMAC_MD5 = 23,
        ARCFOUR_HMAC_MD5_56 = 24,
        ENCTYPE_PK_CROSS = 48,
        ARCFOUR_MD4 = -128,
        DES_PLAIN = -132,
        ARCFOUR_HMAC_OLD = -133,
        ARCFOUR_OLD = -134,
        ARCFOUR_HMAC_OLD_EXP = -135,
        AESFOUR_OLD_EXP = -136,
        ARCFOUR_PLAIN = -140,
        ARCFOUR_PLAIN_EXP = -141,
        AES128_CTS_HMAC_SHA1_96_PLAIN = -148,
        AES256_CTS_HMAC_SHA1_96_PLAIN = -149,
        WRAPPED_KEY = -180,
        DES_CBC_NONE = -4096,
        DES3_CBC_NONE = -4097,
        DES_CFB64_NONE = -4098,
        DES_PCBC_NONE = -4099,
        DIGEST_MD5_NONE = -4100,
        CRAM_MD5_NONE = -4101
    }
}
