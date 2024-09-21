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
    /// Flags for network events to capture.
    /// </summary>
    [Flags]
    public enum FirewallNetEventKeywords : uint
    {
        None = 0,
        [SDKName("FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST")]
        InboundMCast = 0x00000001,
        [SDKName("FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST")]
        InboundBCast = 0x00000002,
        [SDKName("FWPM_NET_EVENT_KEYWORD_CAPABILITY_DROP")]
        CapabilityDrop = 0x00000004,
        [SDKName("FWPM_NET_EVENT_KEYWORD_CAPABILITY_ALLOW")]
        CapabilityAllow = 0x00000008,
        [SDKName("FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW")]
        ClassifyAllow = 0x00000010,
        [SDKName("FWPM_NET_EVENT_KEYWORD_PORT_SCANNING_DROP")]
        PortScanningDrop = 0x00000020,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member