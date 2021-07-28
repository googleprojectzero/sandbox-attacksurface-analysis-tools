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

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Engine option to query or set.
    /// </summary>
    [SDKName("FWPM_ENGINE_OPTION")]
    public enum FirewallEngineOption
    {
        [SDKName("FWPM_ENGINE_COLLECT_NET_EVENTS")]
        CollectNetEvents = 0,
        [SDKName("FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS")]
        NetEventMatchAnyKeywords,
        [SDKName("FWPM_ENGINE_NAME_CACHE")]
        NameCache,
        [SDKName("FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS")]
        MonitorIPsecConnections,
        [SDKName("FWPM_ENGINE_PACKET_QUEUING")]
        PacketQueuing,
        [SDKName("FWPM_ENGINE_TXN_WATCHDOG_TIMEOUT_IN_MSEC")]
        TxnWatchdogTimeoutInMsec
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member