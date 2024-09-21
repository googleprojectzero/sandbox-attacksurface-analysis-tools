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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Security.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Options for enumerating a filter.
/// </summary>
public sealed class FirewallFilterEnumTemplate : FirewallConditionBuilder, IFirewallEnumTemplate<FirewallFilter>
{
    /// <summary>
    /// Specify the key for the layer to search for.
    /// </summary>
    public Guid LayerKey { get; set; }

    /// <summary>
    /// Specify the provider key.
    /// </summary>
    public Guid? ProviderKey { get; set; }

    /// <summary>
    /// Specify the flags for the enumeration.
    /// </summary>
    public FirewallFilterEnumFlags Flags { get; set; }

    /// <summary>
    /// Specify the action type.
    /// </summary>
    public FirewallActionType ActionType { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="layer_key">The layer key.</param>
    public FirewallFilterEnumTemplate(Guid layer_key)
    {
        LayerKey = layer_key;
        ActionType = FirewallActionType.All;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="ale_layer">The ALE layer type..</param>
    public FirewallFilterEnumTemplate(FirewallAleLayer ale_layer)
        : this(FirewallUtils.GetLayerGuidForAleLayer(ale_layer))
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public FirewallFilterEnumTemplate() 
        : this(Guid.Empty)
    {
    }

    private bool CheckUserId(FirewallFilter filter, Guid condition_guid, AuthZContext context)
    {
        if (!filter.HasCondition(condition_guid))
            return true;

        FirewallFilterCondition condition = filter.GetCondition(condition_guid);
        if (!(condition.Value.Value is SecurityDescriptor sd))
            return false;
        switch (condition.MatchType)
        {
            case FirewallMatchType.Equal:
            case FirewallMatchType.NotEqual:
                break;
            default:
                return false;
        }

        if (sd.Owner == null || sd.Group == null)
        {
            sd = sd.Clone();
            if (sd.Owner == null)
                sd.Owner = new SecurityDescriptorSid(KnownSids.LocalSystem, true);
            if (sd.Group == null)
                sd.Group = new SecurityDescriptorSid(KnownSids.LocalSystem, true);
        }
        bool result = context.AccessCheck(sd, null, FirewallFilterAccessRights.Match,
            null, null, FirewallUtils.FirewallFilterType).First().IsSuccess;
        return condition.MatchType == FirewallMatchType.Equal ? result : !result;
    }

    private bool FilterFunc(Dictionary<Guid, AuthZContext> contexts, FirewallFilter filter)
    {
        bool result = true;
        foreach (var pair in contexts)
        {
            result &= CheckUserId(filter, pair.Key, pair.Value);
        }
        return result;
    }

    Func<FirewallFilter, bool> IFirewallEnumTemplate<FirewallFilter>.GetFilterFunc(DisposableList list)
    {
        var user_conditions = Conditions.Where(c => FirewallConditionGuids.IsUserId(c.FieldKey));

        if (!user_conditions.Any())
            return _ => true;

        var rm = list.AddResource(AuthZResourceManager.Create());
        Dictionary<Guid, AuthZContext> contexts = new();
        foreach (var condition in user_conditions)
        {
            if (contexts.ContainsKey(condition.FieldKey))
            {
                continue;
            }
            if (!(condition.Value.ContextValue is FirewallTokenInformation token) || token.UserSid == null)
            {
                continue;
            }
            contexts.Add(condition.FieldKey, token.CreateContext(rm, list));
        }

        return f => FilterFunc(contexts, f);
    }

    SafeBuffer IFirewallEnumTemplate<FirewallFilter>.ToTemplateBuffer(DisposableList list)
    {
        FirewallActionType action_type = ActionType;
        switch (action_type)
        {
            case FirewallActionType.Permit:
            case FirewallActionType.Block:
                action_type &= ~FirewallActionType.Terminating;
                break;
        }

        var template = new FWPM_FILTER_ENUM_TEMPLATE0
        {
            layerKey = LayerKey,
            flags = Flags,
            providerKey = ProviderKey.HasValue ? list.AddResource(ProviderKey.Value.ToBuffer()).DangerousGetHandle() : IntPtr.Zero,
            actionMask = action_type
        };

        var valid_conditions = Conditions.Where(c => !FirewallConditionGuids.IsUserId(c.FieldKey));
        int count = valid_conditions.Count();
        if (count > 0)
        {
            template.numFilterConditions = count;
            template.filterCondition = list.AddList(valid_conditions.Select(c => c.ToStruct(list))).DangerousGetHandle();
        }

        return list.AddStructure(template);
    }
}
