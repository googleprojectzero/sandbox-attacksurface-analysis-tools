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

using NtCoreLib.Utilities.Memory;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Class to represent a network event capability drop.
/// </summary>
public sealed class FirewallNetEventCapabilityDrop : FirewallNetEvent
{
    /// <summary>
    /// AppContainer network capability.
    /// </summary>
    public FirewallNetworkCapabilityType NetworkCapabilityId { get; }

    /// <summary>
    /// Filter ID.
    /// </summary>
    public ulong FilterId { get; }

    /// <summary>
    /// Indicates whether the packet originated from (or was heading to) the loopback adapter.
    /// </summary>
    public bool IsLoopback { get; }

    internal FirewallNetEventCapabilityDrop(IFwNetEvent net_event) : base(net_event)
    {
        var inner_event = net_event.Value.ReadStruct<FWPM_NET_EVENT_CAPABILITY_DROP0>();
        NetworkCapabilityId = inner_event.networkCapabilityId;
        FilterId = inner_event.filterId;
        IsLoopback = inner_event.isLoopback;
    }
}
