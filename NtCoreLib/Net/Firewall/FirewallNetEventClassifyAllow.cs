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
/// Class to represent a firewall classification allow.
/// </summary>
public sealed class FirewallNetEventClassifyAllow : FirewallNetEvent
{
    /// <summary>
    /// Filter ID.
    /// </summary>
    public ulong FilterId { get; }

    /// <summary>
    /// Layer ID.
    /// </summary>
    public ushort LayerId { get; }

    /// <summary>
    /// Reason for reauthorizing 
    /// </summary>
    public uint ReauthReason { get; }

    /// <summary>
    /// The original profile the connection was received on.
    /// </summary>
    public FirewallProfileId OriginalProfile { get; }

    /// <summary>
    /// The profile the error occurred on.
    /// </summary>
    public FirewallProfileId CurrentProfile { get; }

    /// <summary>
    /// Indicates the direction of the packet transmission.
    /// </summary>
    public FirewallNetEventDirectionType MsFwpDirection { get; }

    /// <summary>
    /// Indicates whether the packet originated from (or was heading to) the loopback adapter.
    /// </summary>
    public bool IsLoopback { get; }

    internal FirewallNetEventClassifyAllow(IFwNetEvent net_event) : base(net_event)
    {
        var inner_event = net_event.Value.ReadStruct<FWPM_NET_EVENT_CLASSIFY_ALLOW0>();
        FilterId = inner_event.filterId;
        LayerId = inner_event.layerId;
        ReauthReason = inner_event.reauthReason;
        OriginalProfile = inner_event.originalProfile;
        CurrentProfile = inner_event.currentProfile;
        MsFwpDirection = inner_event.msFwpDirection;
        IsLoopback = inner_event.isLoopback;
    }
}
