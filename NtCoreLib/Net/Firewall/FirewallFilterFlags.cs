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

using NtApiDotNet.Utilities.Reflection;
using System;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    [Flags]
    public enum FirewallFilterFlags
    {
        [SDKName("FWPM_FILTER_FLAG_NONE")]
        None = 0x00000000,
        [SDKName("FWPM_FILTER_FLAG_PERSISTENT")]
        Persistent = 0x00000001,
        [SDKName("FWPM_FILTER_FLAG_BOOTTIME")]
        Boottime = 0x00000002,
        [SDKName("FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT")]
        HasProviderContext = 0x00000004,
        [SDKName("FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT")]
        ClearActionRight = 0x00000008,
        [SDKName("FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED")]
        PermitIfCalloutUnregistered = 0x00000010,
        [SDKName("FWPM_FILTER_FLAG_DISABLED")]
        Disabled = 0x00000020,
        [SDKName("FWPM_FILTER_FLAG_INDEXED")]
        Indexed = 0x00000040,
        [SDKName("FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT")]
        HasSecurityRealmProviderContext = 0x00000080,
        [SDKName("FWPM_FILTER_FLAG_SYSTEMOS_ONLY")]
        SystemOSOnly = 0x00000100,
        [SDKName("FWPM_FILTER_FLAG_GAMEOS_ONLY")]
        GameOSOnly = 0x00000200,
        [SDKName("FWPM_FILTER_FLAG_SILENT_MODE")]
        SilentMode = 0x00000400,
        [SDKName("FWPM_FILTER_FLAG_IPSEC_NO_ACQUIRE_INITIATE")]
        IPSecNoAcquireInitiate = 0x00000800,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member