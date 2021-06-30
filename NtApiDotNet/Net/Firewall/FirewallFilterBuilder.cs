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
using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// A builder to create a new firewall filter.
    /// </summary>
    public sealed class FirewallFilterBuilder
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
        /// <remarks>If left as null then will use a default weight. Otherwise you need to specify either a UINT64 or UINT8.</remarks>
        public FirewallValue? Weight { get; set; }

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
        public Guid CalloutKey { get => FilterType; set => FilterType = value; }

        /// <summary>
        /// Specify list of firewall filter conditions.
        /// </summary>
        public List<FirewallFilterCondition> Conditions { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public FirewallFilterBuilder()
        {
            Name = string.Empty;
            Description = string.Empty;
            Conditions = new List<FirewallFilterCondition>();
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Add a condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="field_key">The field key for the condition.</param>
        /// <param name="value">The value for the condition.</param>
        public void AddCondition(FirewallMatchType match_type, Guid field_key, FirewallValue value)
        {
            Conditions.Add(new FirewallFilterCondition(match_type, field_key, value));
        }

        /// <summary>
        /// Add a condition range.
        /// </summary>
        /// <param name="field_key">The field key for the condition.</param>
        /// <param name="low">The low value for the range.</param>
        /// <param name="high">The high value from the range.</param>
        public void AddConditionRange(Guid field_key, FirewallValue low, FirewallValue high)
        {
            AddCondition(FirewallMatchType.Range, field_key, FirewallValue.FromRange(low, high));
        }

        /// <summary>
        /// Add an App ID condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="filename">The path to the file to use.</param>
        public void AddAppId(FirewallMatchType match_type, string filename)
        {
            AddAppIdRaw(match_type, FirewallUtils.GetAppIdFromFileName(filename));
        }

        /// <summary>
        /// Add an App ID condition using a raw path.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="appid">The path to the file already converted to absolute format.</param>
        public void AddAppIdRaw(FirewallMatchType match_type, string appid)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_APP_ID, 
                FirewallValue.FromBlobUnicodeString(appid));
        }

        /// <summary>
        /// Add a user ID security descriptor condition.
        /// </summary>
        /// <param name="security_descriptor">The security descriptor.</param>
        public void AddUserId(SecurityDescriptor security_descriptor)
        {
            AddCondition(FirewallMatchType.Equal, FirewallConditionGuids.FWPM_CONDITION_ALE_USER_ID,
                FirewallValue.FromSecurityDescriptor(security_descriptor));
        }

        /// <summary>
        /// Add a IP protocol type condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="protocol">The protocol type for the condition.</param>
        public void AddProtocolType(FirewallMatchType match_type, ProtocolType protocol)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_IP_PROTOCOL, FirewallValue.FromProtocolType(protocol));
        }

        /// <summary>
        /// Add a conditions flag condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="flags">The flags for the condition.</param>
        public void AddConditionFlags(FirewallMatchType match_type, FirewallConditionFlags flags)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_FLAGS, FirewallValue.FromConditionFlags(flags));
        }

        /// <summary>
        /// Add IP address range.
        /// </summary>
        /// <param name="remote">True to specify remote, false for local.</param>
        /// <param name="low_address">The low IP address.</param>
        /// <param name="high_address">The high IP address.</param>
        public void AddIpRange(bool remote, IPAddress low_address, IPAddress high_address)
        {
            AddConditionRange(remote ? FirewallConditionGuids.FWPM_CONDITION_IP_REMOTE_ADDRESS : FirewallConditionGuids.FWPM_CONDITION_IP_LOCAL_ADDRESS, 
                FirewallValue.FromIpAddress(low_address), FirewallValue.FromIpAddress(high_address));
        }

        /// <summary>
        /// Add port range.
        /// </summary>
        /// <param name="remote">True to specify remote, false for local.</param>
        /// <param name="low_port">The low port.</param>
        /// <param name="high_port">The high port.</param>
        public void AddPortRange(bool remote, int low_port, int high_port)
        {
            AddConditionRange(remote ? FirewallConditionGuids.FWPM_CONDITION_IP_REMOTE_PORT : FirewallConditionGuids.FWPM_CONDITION_IP_LOCAL_PORT, 
                FirewallValue.FromUInt16((ushort)low_port), FirewallValue.FromUInt16((ushort)high_port));
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
            ret.weight = (Weight ?? FirewallValue.Empty).ToStruct(list);
            ret.action.type = ActionType;
            ret.action.action.filterType = FilterType;
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
