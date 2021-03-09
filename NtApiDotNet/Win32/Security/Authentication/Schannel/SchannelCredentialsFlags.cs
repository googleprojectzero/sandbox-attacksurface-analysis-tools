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
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Flags for the Schannel credentials.
    /// </summary>
    [Flags]
    public enum SchannelCredentialsFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("SCH_CRED_NO_SYSTEM_MAPPER")]
        NoSystemMapper = 0x00000002,
        [SDKName("SCH_CRED_NO_SERVERNAME_CHECK")]
        NoServerNameCheck = 0x00000004,
        [SDKName("SCH_CRED_MANUAL_CRED_VALIDATION")]
        ManualCredValidation = 0x00000008,
        [SDKName("SCH_CRED_NO_DEFAULT_CREDS")]
        NoDefaultCreds = 0x00000010,
        [SDKName("SCH_CRED_AUTO_CRED_VALIDATION")]
        AutoCredValidation = 0x00000020,
        [SDKName("SCH_CRED_USE_DEFAULT_CREDS")]
        UseDefaultCreds = 0x00000040,
        [SDKName("SCH_CRED_DISABLE_RECONNECTS")]
        DisableReconnects = 0x00000080,
        [SDKName("SCH_CRED_REVOCATION_CHECK_END_CERT")]
        RevocationCheckEndCert = 0x00000100,
        [SDKName("SCH_CRED_REVOCATION_CHECK_CHAIN")]
        RevocationCheckChain = 0x00000200,
        [SDKName("SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT")]
        RevocationCheckChainExcludeRoot = 0x00000400,
        [SDKName("SCH_CRED_IGNORE_NO_REVOCATION_CHECK")]
        IgnoreNoRevocationCheck = 0x00000800,
        [SDKName("SCH_CRED_IGNORE_REVOCATION_OFFLINE")]
        IgnoreRevocationOffline = 0x00001000,
        [SDKName("SCH_CRED_RESTRICTED_ROOTS")]
        RestrictedRoots = 0x00002000,
        [SDKName("SCH_CRED_REVOCATION_CHECK_CACHE_ONLY")]
        RevocationCheckCacheOnly = 0x00004000,
        [SDKName("SCH_CRED_CACHE_ONLY_URL_RETRIEVAL")]
        CacheOnlyUrlRetrieval = 0x00008000,
        [SDKName("SCH_CRED_MEMORY_STORE_CERT")]
        MemoryStoreCert = 0x00010000,
        [SDKName("SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE")]
        CacheOnlyUrlRetrievalOnCreate = 0x00020000,
        [SDKName("SCH_SEND_ROOT_CERT")]
        SendRootCert = 0x00040000,
        [SDKName("SCH_CRED_SNI_CREDENTIAL")]
        SNICredential = 0x00080000,
        [SDKName("SCH_CRED_SNI_ENABLE_OCSP")]
        SNIEnableOCSP = 0x00100000,
        [SDKName("SCH_SEND_AUX_RECORD")]
        SendAUXRecord = 0x00200000,
        [SDKName("SCH_USE_STRONG_CRYPTO")]
        UseStrongCrypto = 0x00400000,
        [SDKName("SCH_USE_PRESHAREDKEY_ONLY")]
        UsePresharedKeyOnly = 0x00800000,
        [SDKName("SCH_USE_DTLS_ONLY")]
        UseDTLSOnly = 0x01000000,
        [SDKName("SCH_ALLOW_NULL_ENCRYPTION")]
        AllowNullEncryption = 0x02000000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
