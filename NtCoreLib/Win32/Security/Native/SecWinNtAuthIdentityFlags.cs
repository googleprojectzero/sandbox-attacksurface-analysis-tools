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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Security.Native
{
    [Flags]
    internal enum SecWinNtAuthIdentityFlags
    {
        [SDKName("SEC_WINNT_AUTH_IDENTITY_ANSI")]
        Ansi = 0x1,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_UNICODE")]
        Unicode = 0x2,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_MARSHALLED")]
        IdentityMarshalled = 0x4,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_ONLY")]
        IdentityOnly = 0x8,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED")]
        ProcessEncrypted = 0x10,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED")]
        SystemProtected = 0x20,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED")]
        UserProtected = 0x40,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED")]
        SystemEncrypted = 0x80,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED")]
        Reserved = 0x10000,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER")]
        NullUser = 0x20000,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN")]
        NullDomain = 0x40000,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER")]
        IdProvider = 0x80000
    }
}
