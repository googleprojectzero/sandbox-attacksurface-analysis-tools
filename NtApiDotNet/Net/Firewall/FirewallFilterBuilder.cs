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
using System.Linq;

namespace NtApiDotNet.Net.Firewall
{
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
            FWPM_FILTER0 ret = new FWPM_FILTER0();
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
            if (Conditions.Count > 0)
            {
                ret.numFilterConditions = Conditions.Count;
                ret.filterCondition = list.AddList(Conditions.Select(c => c.ToStruct(list))).DangerousGetHandle();
            }

            return ret;
        }
        #endregion
    }
}
