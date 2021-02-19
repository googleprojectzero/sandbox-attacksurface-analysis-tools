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
        NoSystemMapper = 0x00000002,
        NoServerNameCheck = 0x00000004,
        ManualCredValidation = 0x00000008,
        NoDefaultCreds = 0x00000010,
        AutoCredValidation = 0x00000020,
        UseDefaultCreds = 0x00000040,
        DisableReconnects = 0x00000080,
        RevocationCheckEndCert = 0x00000100,
        RevocationCheckChain = 0x00000200,
        RevocationCheckChainExcludeRoot = 0x00000400,
        IgnoreNoRevocationCheck = 0x00000800,
        IgnoreRevocationOffline = 0x00001000,
        RestrictedRoots = 0x00002000,
        RevocationCheckCacheOnly = 0x00004000,
        CacheOnlyUrlRetrieval = 0x00008000,
        MemoryStoreCert = 0x00010000,
        CacheOnlyUrlRetrievalOnCreate = 0x00020000,
        SendRootCert = 0x00040000,
        SNICredential = 0x00080000,
        SNIEnableOCSP = 0x00100000,
        SendAUXRecord = 0x00200000,
        UseStrongCrypto = 0x00400000,
        UsePresharedKeyOnly = 0x00800000,
        UseDTLSOnly = 0x01000000,
        AllowNullEncryption = 0x02000000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
