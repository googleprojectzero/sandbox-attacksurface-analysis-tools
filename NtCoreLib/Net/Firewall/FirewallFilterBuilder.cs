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

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// A builder to create a new firewall filter.
/// </summary>
public sealed class FirewallFilterBuilder : FirewallConditionBuilder
{
    #region Public Properties
    /// <summary>
    /// The name of the filter.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// The description of the filter.
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// The filter key. If empty will be automatically assigned.
    /// </summary>
    public Guid FilterKey { get; set; }

    /// <summary>
    /// The layer key.
    /// </summary>
    public Guid LayerKey { get; set; }

    /// <summary>
    /// The sub-layer key.
    /// </summary>
    public Guid SubLayerKey { get; set; }

    /// <summary>
    /// Flags for the filter.
    /// </summary>
    public FirewallFilterFlags Flags { get; set; }

    /// <summary>
    /// Specify the initial weight.
    /// </summary>
    /// <remarks>You need to specify an EMPTY, UINT64 or UINT8 value.</remarks>
    public FirewallValue Weight { get; set; }

    /// <summary>
    /// Specify the action for this filter.
    /// </summary>
    public FirewallActionType ActionType { get; set; }

    /// <summary>
    /// Specify the filter type GUID when not using a callout.
    /// </summary>
    public Guid FilterType { get; set; }

    /// <summary>
    /// Specify callout key GUID when using a callout.
    /// </summary>
    public Guid CalloutKey { get; set; }

    /// <summary>
    /// Specify provider key GUID.
    /// </summary>
    public Guid ProviderKey { get; set; }

    /// <summary>
    /// When the filter flag FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT is not set,
    /// the context data is stored in-place in the filter. 
    /// </summary>
    public ulong RawContext { get; internal set; }

    /// <summary>
    /// When the filter flag FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT is set,
    /// the context data is stored in a policy provider context.
    /// </summary>
    public Guid ProviderContextKey { get; internal set; }

    /// <summary>
    /// Provider data.
    /// </summary>
    public byte[] ProviderData { get; set; }
    #endregion

    #region Public Members
    /// <summary>
    /// Add a raw context value to the filter.
    /// </summary>
    /// <param name="raw_context">The raw context data.</param>
    /// <returns>The filter context value.</returns>
    public void SetContextValue(ulong raw_context)
    {
        Flags = Flags & ~FirewallFilterFlags.HasProviderContext;
        RawContext = raw_context;
    }

    /// <summary>
    /// Add a provider context GUID to the filter.
    /// </summary>
    /// <param name="provider_context_key">The key of the provider context.</param>
    /// <returns>The filter context value.</returns>
    public void SetContextValue(Guid provider_context_key)
    {
        Flags = Flags | FirewallFilterFlags.HasProviderContext;
        ProviderContextKey = provider_context_key;
    }

    /// <summary>
    /// Given an instance of a FirewallLayer, test if the conditions in the filter are valid, given the fields available in the layer.
    /// </summary>
    /// <param name="layer">The target firewall layer.</param>
    /// <exception cref="ArgumentException">The provided layer doesn't match the layer specified in LayerKey.</exception>
    /// <exception cref="InvalidOperationException">An incorrect argument was found in a condition.</exception>
    public void ValidateWithLayer(FirewallLayer layer)
    {
        if (layer.Key != LayerKey)
        {
            throw new ArgumentException($"The layer ({layer.Name}) does not match the layer defined in the filter.");
        }

        foreach (var condition in Conditions)
        {
            condition.ValidateWithLayer(layer);
        }
    }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    public FirewallFilterBuilder()
    {
        Name = string.Empty;
        Description = string.Empty;
        Weight = FirewallValue.Empty;
    }
    #endregion

    #region Internal Members
    internal FWPM_FILTER0 ToStruct(DisposableList list)
    {
        FWPM_FILTER0 ret = new();
        ret.filterKey = FilterKey;
        ret.layerKey = LayerKey;
        ret.subLayerKey = SubLayerKey;
        ret.displayData.name = Name;
        ret.displayData.description = Description;
        ret.flags = Flags;
        ret.weight = Weight.ToStruct(list);
        ret.action.type = ActionType;
        if (ActionType.HasFlag(FirewallActionType.Callout))
        {
            ret.action.action.calloutKey = CalloutKey;
        }
        else
        {
            ret.action.action.filterType = FilterType;
        }
        if (ProviderKey != Guid.Empty)
        {
            ret.providerKey = list.AddStructureRef(ProviderKey).DangerousGetHandle();
        }

        ret.context = new FWPM_FILTER0_UNION();
        if (Flags.HasFlag(FirewallFilterFlags.HasProviderContext))
        {
            ret.context.providerContextKey = ProviderContextKey;
        }
        else
        {
            ret.context.rawContext = RawContext;
        }

        if (Conditions.Count > 0)
        {
            ret.numFilterConditions = Conditions.Count;
            ret.filterCondition = list.AddList(Conditions.Select(c => c.ToStruct(list))).DangerousGetHandle();
        }

        if (ProviderData?.Length > 0)
        {
            FWP_BYTE_BLOB blob = new()
            {
                size = ProviderData.Length,
                data = list.AddBytes(ProviderData).DangerousGetHandle()
            };
            ret.providerData = blob;
        }

        return ret;
    }
    #endregion
}
