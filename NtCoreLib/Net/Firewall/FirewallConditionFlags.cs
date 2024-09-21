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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Firewall condition flags.
    /// </summary>
    [Flags]
    public enum FirewallConditionFlags : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("FWP_CONDITION_FLAG_IS_LOOPBACK")]
        IsLoopback = 0x00000001,
        [SDKName("FWP_CONDITION_FLAG_IS_IPSEC_SECURED")]
        IsIPSecSecured = 0x00000002,
        [SDKName("FWP_CONDITION_FLAG_IS_REAUTHORIZE")]
        IsReauthorize = 0x00000004,
        [SDKName("FWP_CONDITION_FLAG_IS_WILDCARD_BIND")]
        IsWildcardBind = 0x00000008,
        [SDKName("FWP_CONDITION_FLAG_IS_RAW_ENDPOINT")]
        IsRawEndpoint = 0x00000010,
        [SDKName("FWP_CONDITION_FLAG_IS_FRAGMENT")]
        IsFragment = 0x00000020,
        [SDKName("FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP")]
        IsFragmentGroup = 0x00000040,
        [SDKName("FWP_CONDITION_FLAG_IS_IPSEC_NATT_RECLASSIFY")]
        IsIPSecNATTReclassify = 0x00000080,
        [SDKName("FWP_CONDITION_FLAG_REQUIRES_ALE_CLASSIFY")]
        RequiresALEClassify = 0x00000100,
        [SDKName("FWP_CONDITION_FLAG_IS_IMPLICIT_BIND")]
        IsImplicitBind = 0x00000200,
        [SDKName("FWP_CONDITION_FLAG_IS_REASSEMBLED")]
        IsReassembled = 0x00000400,
        [SDKName("FWP_CONDITION_FLAG_IS_NAME_APP_SPECIFIED")]
        IsNameAppSpecified = 0x00004000,
        [SDKName("FWP_CONDITION_FLAG_IS_PROMISCUOUS")]
        IsPromiscuous = 0x00008000,
        [SDKName("FWP_CONDITION_FLAG_IS_AUTH_FW")]
        IsAuthFW = 0x00010000,
        [SDKName("FWP_CONDITION_FLAG_IS_RECLASSIFY")]
        IsReclassify = 0x00020000,
        [SDKName("FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU")]
        IsOutboundPassThru = 0x00040000,
        [SDKName("FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU")]
        IsInboundPassThru = 0x00080000,
        [SDKName("FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED")]
        IsConnectionRedirected = 0x00100000,
        [SDKName("FWP_CONDITION_FLAG_IS_PROXY_CONNECTION")]
        IsProxyConnection = 0x00200000,
        [SDKName("FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK")]
        IsAppContainerLoopback = 0x00400000,
        [SDKName("FWP_CONDITION_FLAG_IS_NON_APPCONTAINER_LOOPBACK")]
        IsNonAppContainerLoopback = 0x00800000,
        [SDKName("FWP_CONDITION_FLAG_IS_RESERVED")]
        IsReserved = 0x01000000,
        [SDKName("FWP_CONDITION_FLAG_IS_HONORING_POLICY_AUTHORIZE")]
        IsHonoringPolicyAuthorize = 0x02000000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
