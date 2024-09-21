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

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Type of network event.
/// </summary>
[SDKName("FWPM_NET_EVENT_TYPE")]
public enum FirewallNetEventType
{
    [SDKName("FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE")]
    IkeExtMmFailure,
    [SDKName("FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE")]
    IkeExtQmFailure,
    [SDKName("FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE")]
    IkeExtEmFailure,
    [SDKName("FWPM_NET_EVENT_TYPE_CLASSIFY_DROP")]
    ClassifyDrop,
    [SDKName("FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP")]
    IPsecKernelDrop,
    [SDKName("FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP")]
    IPsecDoSPDrop,
    [SDKName("FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW")]
    ClassifyAllow,
    [SDKName("FWPM_NET_EVENT_TYPE_CAPABILITY_DROP")]
    CapabilityDrop,
    [SDKName("FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW")]
    CapabilityAllow,
    [SDKName("FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC")]
    ClassifyDropMac,
    [SDKName("FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL")]
    LpmPacketArrival
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member