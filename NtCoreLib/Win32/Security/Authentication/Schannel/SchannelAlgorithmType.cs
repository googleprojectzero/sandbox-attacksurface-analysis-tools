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

using NtApiDotNet.Utilities.Reflection;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    /// <summary>
    /// Algorithm identifiers for the crypto APIs and Schannel.
    /// </summary>
    public enum SchannelAlgorithmType
    {
        None = 0,
        [SDKName("CALG_3DES")]
        TripleDES = 26115,
        [SDKName("CALG_3DES_112")]
        TripleDES112 = 26121,
        [SDKName("CALG_AES")]
        AES = 26129,
        [SDKName("CALG_AES_128")]
        AES128 = 26126,
        [SDKName("CALG_AES_192")]
        AES192 = 26127,
        [SDKName("CALG_AES_256")]
        AES256 = 26128,
        [SDKName("CALG_AGREEDKEY_ANY")]
        AgreedKey = 43523,
        [SDKName("CALG_CYLINK_MEK")]
        CylinkMEK = 26124,
        [SDKName("CALG_DES")]
        DES = 26113,
        [SDKName("CALG_DESX")]
        DESX = 26116,
        [SDKName("CALG_DH_EPHEM")]
        DHEphem = 43522,
        [SDKName("CALG_DH_SF")]
        DHSf = 43521,
        [SDKName("CALG_DSS_SIGN")]
        DSSSign = 8704,
        [SDKName("CALG_HASH_REPLACE_OWF")]
        HashReplaceOWF = 32779,
        [SDKName("CALG_HMAC")]
        HMAC = 32777,
        [SDKName("CALG_HUGHES_MD5")]
        HughesMD5 = 40963,
        [SDKName("CALG_KEA_KEYX")]
        KEAKeyX = 43524,
        [SDKName("CALG_MAC")]
        MAC = 32773,
        [SDKName("CALG_MD2")]
        MD2 = 32769,
        [SDKName("CALG_MD4")]
        MD4 = 32770,
        [SDKName("CALG_MD5")]
        MD5 = 32771,
        [SDKName("CALG_NO_SIGN")]
        NoSign = 8192,
        [SDKName("CALG_PCT1_MASTER")]
        PCT1Master = 19460,
        [SDKName("CALG_RC2")]
        RC2 = 26114,
        [SDKName("CALG_RC4")]
        RC4 = 26625,
        [SDKName("CALG_RC5")]
        RC5 = 26125,
        [SDKName("CALG_RSA_KEYX")]
        RSAKeyX = 41984,
        [SDKName("CALG_RSA_SIGN")]
        RSASign = 9216,
        [SDKName("CALG_SCHANNEL_ENC_KEY")]
        SchannelEncKey = 19463,
        [SDKName("CALG_SCHANNEL_MAC_KEY")]
        SchannelMACKey = 19459,
        [SDKName("CALG_SCHANNEL_MASTER_HASH")]
        SchannelMasterHash = 19458,
        [SDKName("CALG_SEAL")]
        SEAL = 26626,
        [SDKName("CALG_SHA")]
        SHA = 32772,
        [SDKName("CALG_SHA1")]
        SHA1 = 32772,
        [SDKName("CALG_SHA_256")]
        SHA256 = 32780,
        [SDKName("CALG_SHA_384")]
        SHA384 = 32781,
        [SDKName("CALG_SHA_512")]
        SHA512 = 32782,
        [SDKName("CALG_SKIPJACK")]
        SKIPJACK = 26122,
        [SDKName("CALG_SSL2_MASTER")]
        SSL2Master = 19461,
        [SDKName("CALG_SSL3_MASTER")]
        SSL3Master = 19457,
        [SDKName("CALG_SSL3_SHAMD5")]
        SSL3SHAMD5 = 32776,
        [SDKName("CALG_TEK")]
        TEK = 26123,
        [SDKName("CALG_TLS1_MASTER")]
        TLS10Master = 19462,
        [SDKName("CALG_TLS1PRF")]
        TLS10Prf = 32778,
        [SDKName("CALG_ECDH")]
        ECDH = 43525,
        [SDKName("CALG_ECDH_EPHEM")]
        ECDHEphem = 44550,
        [SDKName("CALG_ECDSA")]
        ECDSA = 8707,
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
