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
    /// <summary>
    /// Flags for a firewall callout.
    /// </summary>
    [Flags]
    public enum FirewallCalloutFlags
    {
        None = 0,
        [SDKName("FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW")]
        ConditionalOnFlow = 0x00000001,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_OFFLOAD")]
        AllowOffload = 0x00000002,
        [SDKName("FWP_CALLOUT_FLAG_ENABLE_COMMIT_ADD_NOTIFY")]
        EnableCommitAddNotify = 0x00000004,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_MID_STREAM_INSPECTION")]
        AllowMidStreamInspection = 0x00000008,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_RECLASSIFY")]
        AllowReclassify = 0x00000010,
        [SDKName("FWP_CALLOUT_FLAG_RESERVED1")]
        Reserved1 = 0x00000020,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_RSC")]
        AllowRsc = 0x00000040,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_L2_BATCH_CLASSIFY")]
        AllowL2BatchClassify = 0x00000080,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_USO")]
        AllowUSO = 0x00000100,
        [SDKName("FWP_CALLOUT_FLAG_ALLOW_URO")]
        AllowURO = 0x00000200,
        [SDKName("FWPM_CALLOUT_FLAG_PERSISTENT")]
        Persistent = 0x00010000,
        [SDKName("FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT")]
        UsesProviderContext = 0x00020000,
        [SDKName("FWPM_CALLOUT_FLAG_REGISTERED")]
        Registered = 0x00040000,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member