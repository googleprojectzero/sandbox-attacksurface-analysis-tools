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

namespace NtApiDotNet.Win32.Security.Native
{
#pragma warning disable 1591
    /// <summary>
    /// Logon UserFlags.
    /// </summary>
    [Flags]
    public enum LsaLogonUserFlags
    {
        Guest = 0x01,
        NoEncryption = 0x02,
        CachedAccount = 0x04,
        UsedLmPassword = 0x08,
        ExtraSids = 0x20,
        SubAuthSessionKey = 0x40,
        ServerTrustAccount = 0x80,
        NtlmV2Enabled = 0x100,
        ResourceGroups = 0x200,
        ProfilePathReturned = 0x400,
        NtV2 = 0x800,
        LmV2 = 0x1000,
        NtlmV2 = 0x2000,
        Optimized = 0x4000,
        WinLogon = 0x8000,
        PKInit = 0x10000,
        NoOptimized = 0x20000,
        NoElevation = 0x40000,
        ManagedService = 0x80000,
    }
}
