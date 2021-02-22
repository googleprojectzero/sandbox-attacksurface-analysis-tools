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
    /// Protocol type for Schannel.
    /// </summary>
    [Flags]
    public enum SchannelProtocolType : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        PCT1_SERVER = 0x00000001,
        PCT1_CLIENT = 0x00000002,
        SSL2_SERVER = 0x00000004,
        SSL2_CLIENT = 0x00000008,
        SSL3_SERVER = 0x00000010,
        SSL3_CLIENT = 0x00000020,
        TLS1_SERVER = 0x00000040,
        TLS1_CLIENT = 0x00000080,
        UNI_SERVER = 0x40000000,
        UNI_CLIENT = 0x80000000,
        TLS1_1_SERVER = 0x00000100,
        TLS1_1_CLIENT = 0x00000200,
        TLS1_2_SERVER = 0x00000400,
        TLS1_2_CLIENT = 0x00000800,
        TLS1_3_SERVER = 0x00001000,
        TLS1_3_CLIENT = 0x00002000,
        DTLS_SERVER = 0x00010000,
        DTLS_CLIENT = 0x00020000,
        DTLS1_2_SERVER = 0x00040000,
        DTLS1_2_CLIENT = 0x00080000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
