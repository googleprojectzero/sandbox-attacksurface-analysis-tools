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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Options for enumerating a filter.
    /// </summary>
    public sealed class FirewallFilterEnumTemplate : FirewallConditionBuilder, IFirewallEnumTemplate
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
        /// Specify a token to check the user ID.
        /// </summary>
        public NtToken Token { get; set; }

        /// <summary>
        /// Specify a token to check the remote user ID.
        /// </summary>
        public NtToken RemoteToken { get; set; }

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
        /// <param name="layer_name">The well-known name of the layer.</param>
        public FirewallFilterEnumTemplate(string layer_name) 
            : this(NamedGuidDictionary.LayerGuids.Value.GuidFromName(layer_name))
        {
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

        private bool CheckUserId(NtToken token, FirewallFilter filter, Guid condition_guid)
        {
            if (token == null)
                return true;
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
            bool result = NtSecurity.AccessCheck(sd, token, FirewallFilterAccessRights.Match, 
                null, FirewallUtils.GetFilterGenericMapping()).IsSuccess;
            return condition.MatchType == FirewallMatchType.Equal ? result : !result;
        }

        private bool FilterFunc(FirewallFilter filter)
        {
            return CheckUserId(Token, filter, FirewallConditionGuids.FWPM_CONDITION_ALE_USER_ID) &&
                CheckUserId(Token, filter, FirewallConditionGuids.FWPM_CONDITION_ALE_REMOTE_USER_ID);
        }

        internal Func<FirewallFilter, bool> GetFilterFunc()
        {
            if (Token == null && RemoteToken == null)
                return _ => true;
            return FilterFunc;
        }

        SafeBuffer IFirewallEnumTemplate.ToTemplateBuffer(DisposableList list)
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

            if (Conditions.Count > 0)
            {
                template.numFilterConditions = Conditions.Count;
                template.filterCondition = list.AddList(Conditions.Select(c => c.ToStruct(list))).DangerousGetHandle();
            }

            return list.AddStructure(template);
        }
    }
}
