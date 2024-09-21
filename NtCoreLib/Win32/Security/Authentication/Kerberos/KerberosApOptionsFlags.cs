//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Flags for the AD-AUTH-DATA-AP-OPTIONS authorization data.
/// </summary>
[Flags]
public enum KerberosApOptionsFlags : uint
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("KERB_AP_OPTIONS_CBT")]
    ChannelBindingToken = 0x4000,
    UnverifiedTargetName = 0x8000,
    MutualRequired = 0x20000000,
    UseSessionKey = 0x40000000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
