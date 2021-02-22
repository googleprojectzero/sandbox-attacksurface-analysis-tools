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

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    /// <summary>
    /// Algorithm identifiers for the crypto APIs and Schannel.
    /// </summary>
    public enum SchannelAlgorithmType
    {
        None = 0,
        TRIPLEDES = 26115,
        TRIPLEDES_112 = 26121,
        AES = 26129,
        AES_128 = 26126,
        AES_192 = 26127,
        AES_256 = 26128,
        AGREEDKEY_ANY = 43523,
        CYLINK_MEK = 26124,
        DES = 26113,
        DESX = 26116,
        DH_EPHEM = 43522,
        DH_SF = 43521,
        DSS_SIGN = 8704,
        HASH_REPLACE_OWF = 32779,
        HMAC = 32777,
        HUGHES_MD5 = 40963,
        KEA_KEYX = 43524,
        MAC = 32773,
        MD2 = 32769,
        MD4 = 32770,
        MD5 = 32771,
        NO_SIGN = 8192,
        PCT1_MASTER = 19460,
        RC2 = 26114,
        RC4 = 26625,
        RC5 = 26125,
        RSA_KEYX = 41984,
        RSA_SIGN = 9216,
        SCHANNEL_ENC_KEY = 19463,
        SCHANNEL_MAC_KEY = 19459,
        SCHANNEL_MASTER_HASH = 19458,
        SEAL = 26626,
        SHA = 32772,
        SHA1 = 32772,
        SHA_256 = 32780,
        SHA_384 = 32781,
        SHA_512 = 32782,
        SKIPJACK = 26122,
        SSL2_MASTER = 19461,
        SSL3_MASTER = 19457,
        SSL3_SHAMD5 = 32776,
        TEK = 26123,
        TLS1_MASTER = 19462,
        TLS1PRF = 32778,
        ECDH = 43525,
        ECDH_EPHEM = 44550,
        ECDSA = 8707,
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
