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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// A class to represent a firewall filter.
    /// </summary>
    public sealed class FirewallFilter : FirewallObject
    {
        internal FirewallFilter(FWPM_FILTER0 filter, FirewallEngine engine, Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd)
            : base(filter.filterKey, filter.displayData, new NamedGuidDictionary(), engine, get_sd)
        {
            ActionType = filter.action.type;
            if (ActionType.HasFlag(FirewallActionType.Callout))
            {
                CalloutKey = filter.action.action.calloutKey;
            }
            else
            {
                FilterType = filter.action.action.filterType;
            }
            LayerKey = filter.layerKey;
            LayerKeyName = NamedGuidDictionary.LayerGuids.Value.GetName(LayerKey);
            SubLayerKey = filter.subLayerKey;
            SubLayerKeyName = NamedGuidDictionary.SublayerGuids.Value.GetName(SubLayerKey);
            Flags = filter.flags;

            List<FirewallFilterCondition> conditions = new List<FirewallFilterCondition>();
            if (filter.numFilterConditions > 0)
            {
                var conds = new SafeHGlobalBuffer(filter.filterCondition, 1, false);
                conds.Initialize<FWPM_FILTER_CONDITION0>((uint)filter.numFilterConditions);
                conditions.AddRange(conds.ReadArray<FWPM_FILTER_CONDITION0>(0, filter.numFilterConditions).Select(c => new FirewallFilterCondition(c)));
            }
            Conditions = conditions.AsReadOnly();
            Weight = new FirewallValue(filter.weight, Guid.Empty);
            EffectiveWeight = new FirewallValue(filter.effectiveWeight, Guid.Empty);
            if (filter.providerKey != IntPtr.Zero)
            {
                ProviderKey = (Guid)Marshal.PtrToStructure(filter.providerKey, typeof(Guid));
            }
            ProviderData = filter.providerData.ToArray();
            FilterId = filter.filterId;
        }

        /// <summary>
        /// The filter action type.
        /// </summary>
        public FirewallActionType ActionType { get; }

        /// <summary>
        /// The layer the filter applies to.
        /// </summary>
        public Guid LayerKey { get; }

        /// <summary>
        /// The name of the layer if known.
        /// </summary>
        public string LayerKeyName { get; }

        /// <summary>
        /// The sub-layer the filter applies to.
        /// </summary>
        public Guid SubLayerKey { get; }

        /// <summary>
        /// The name of the sub-layer if known.
        /// </summary>
        public string SubLayerKeyName { get; }

        /// <summary>
        /// The flags for the filter.
        /// </summary>
        public FirewallFilterFlags Flags { get; }

        /// <summary>
        /// List of firewall conditions.
        /// </summary>
        public IReadOnlyList<FirewallFilterCondition> Conditions { get; }

        /// <summary>
        /// Original weight of the filter.
        /// </summary>
        public FirewallValue Weight { get; }

        /// <summary>
        /// Provider key.
        /// </summary>
        public Guid ProviderKey { get; }

        /// <summary>
        /// Provider data.
        /// </summary>
        public byte[] ProviderData { get; }

        /// <summary>
        /// Filter identifier.
        /// </summary>
        public ulong FilterId { get; }

        /// <summary>
        /// Effective weight of the filter.
        /// </summary>
        public FirewallValue EffectiveWeight { get; }

        /// <summary>
        /// Type of filter.
        /// </summary>
        public Guid FilterType { get; }

        /// <summary>
        /// Key for the callout.
        /// </summary>
        public Guid CalloutKey { get; }

        /// <summary>
        /// Is the filter a callout.
        /// </summary>
        public bool IsCallout => ActionType.HasFlag(FirewallActionType.Callout);

        /// <summary>
        /// Get a layer for this filter.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall layer.</returns>
        public NtResult<FirewallLayer> GetLayer(bool throw_on_error)
        {
            return _engine.GetLayer(LayerKey, throw_on_error);
        }

        /// <summary>
        /// Get a layer for this filter.
        /// </summary>
        /// <returns>The firewall layer.</returns>
        public FirewallLayer GetLayer()
        {
            return GetLayer(true).Result;
        }

        /// <summary>
        /// Get a sub-layer for this filter.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The firewall sub-layer.</returns>
        public NtResult<FirewallSubLayer> GetSubLayer(bool throw_on_error)
        {
            return _engine.GetSubLayer(SubLayerKey, throw_on_error);
        }

        /// <summary>
        /// Get a sub-layer for this filter.
        /// </summary>
        /// <returns>The firewall sub-layer.</returns>
        public FirewallSubLayer GetSubLayer()
        {
            return GetSubLayer(true).Result;
        }
    }
}
