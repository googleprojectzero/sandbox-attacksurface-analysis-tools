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

using NtCoreLib.Utilities.Collections;
using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Template for network event enumeration.
/// </summary>
public sealed class FirewallNetEventEnumTemplate : FirewallConditionBuilder, IFirewallEnumTemplate<FirewallNetEvent>
{
    /// <summary>
    /// Start time for events.
    /// </summary>
    public DateTime StartTime { get; set; }

    /// <summary>
    /// End time for event.s
    /// </summary>
    public DateTime EndTime { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public FirewallNetEventEnumTemplate()
    {
        StartTime = DateTime.FromFileTime(0);
        EndTime = DateTime.MaxValue;
    }

    private static bool IsValidCondition(FirewallFilterCondition condition)
    {
        Guid key = condition.FieldKey;
        return key == FirewallConditionGuids.FWPM_CONDITION_IP_PROTOCOL ||
            key == FirewallConditionGuids.FWPM_CONDITION_IP_LOCAL_ADDRESS ||
            key == FirewallConditionGuids.FWPM_CONDITION_IP_REMOTE_ADDRESS ||
            key == FirewallConditionGuids.FWPM_CONDITION_IP_LOCAL_PORT ||
            key == FirewallConditionGuids.FWPM_CONDITION_IP_REMOTE_PORT ||
            key == FirewallConditionGuids.FWPM_CONDITION_ALE_APP_ID ||
            key == FirewallConditionGuids.FWPM_CONDITION_NET_EVENT_TYPE ||
            key == FirewallConditionGuids.FWPM_CONDITION_ALE_USER_ID;
    }

    private static FirewallFilterCondition ConvertUserId(FirewallFilterCondition condition)
    {
        if (condition.FieldKey != FirewallConditionGuids.FWPM_CONDITION_ALE_USER_ID)
            return condition;
        if (condition.Value.Type == FirewallDataType.Sid)
            return condition;
        if (!(condition.Value.Value is FirewallTokenInformation token_info))
            throw new ArgumentException("Must specify a SID or FirewallTokenInformation for FWPM_CONDITION_ALE_USER_ID.");
        if (token_info.UserSid == null)
            throw new ArgumentException("Must specify a user SID for the TokenInformation for FWPM_CONDITION_ALE_USER_ID.");
        return new FirewallFilterCondition(condition.MatchType, condition.FieldKey, FirewallValue.FromSid(token_info.UserSid));
    }

    SafeBuffer IFirewallEnumTemplate<FirewallNetEvent>.ToTemplateBuffer(DisposableList list)
    {
        var template = new FWPM_NET_EVENT_ENUM_TEMPLATE0
        {
            startTime = new Luid(StartTime.ToFileTime()),
            endTime = new Luid(EndTime.ToFileTime())
        };

        var conditions = Conditions.Where(IsValidCondition).Select(ConvertUserId);
        int count = conditions.Count();

        if (count > 0)
        {
            template.numFilterConditions = count;
            template.filterCondition = list.AddList(conditions.Select(c => c.ToStruct(list))).DangerousGetHandle();
        }

        return list.AddStructureRef(template);
    }

    Func<FirewallNetEvent, bool> IFirewallEnumTemplate<FirewallNetEvent>.GetFilterFunc(DisposableList list)
    {
        return null;
    }
}
