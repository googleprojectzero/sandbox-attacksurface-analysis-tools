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
    /// Protocol type for Schannel.
    /// </summary>
    [Flags]
    public enum SchannelProtocolType : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("SP_PROT_PCT1_SERVER")]
        PCT1Server = 0x00000001,
        [SDKName("SP_PROT_PCT1_CLIENT")]
        PCT1Client = 0x00000002,
        [SDKName("SP_PROT_SSL2_SERVER")]
        SSL2Server = 0x00000004,
        [SDKName("SP_PROT_SSL2_CLIENT")]
        SSL2Client = 0x00000008,
        [SDKName("SP_PROT_SSL3_SERVER")]
        SSL3Server = 0x00000010,
        [SDKName("SP_PROT_SSL3_CLIENT")]
        SSL3Client = 0x00000020,
        [SDKName("SP_PROT_TLS1_SERVER")]
        TLS10Server = 0x00000040,
        [SDKName("SP_PROT_TLS1_CLIENT")]
        TLS10Client = 0x00000080,
        [SDKName("SP_PROT_UNI_SERVER")]
        UniServer = 0x40000000,
        [SDKName("SP_PROT_UNI_CLIENT")]
        UniClient = 0x80000000,
        [SDKName("SP_PROT_TLS1_1_SERVER")]
        TLS11Server = 0x00000100,
        [SDKName("SP_PROT_TLS1_1_CLIENT")]
        TLS11Client = 0x00000200,
        [SDKName("SP_PROT_TLS1_2_SERVER")]
        TLS12Server = 0x00000400,
        [SDKName("SP_PROT_TLS1_2_CLIENT")]
        TLS12Client = 0x00000800,
        [SDKName("SP_PROT_TLS1_3_SERVER")]
        TLS13Server = 0x00001000,
        [SDKName("SP_PROT_TLS1_3_CLIENT")]
        TLS13Client = 0x00002000,
        [SDKName("SP_PROT_DTLS_SERVER")]
        DTLSServer = 0x00010000,
        [SDKName("SP_PROT_DTLS_CLIENT")]
        DTLSClient = 0x00020000,
        [SDKName("SP_PROT_DTLS1_2_SERVER")]
        DTLS12Server = 0x00040000,
        [SDKName("SP_PROT_DTLS1_2_CLIENT")]
        DTLS12Client = 0x00080000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
