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
using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Base class to implement common condition building operations.
    /// </summary>
    public class FirewallConditionBuilder
    {
        #region Public Properties
        /// <summary>
        /// Specify list of firewall filter conditions.
        /// </summary>
        public List<FirewallFilterCondition> Conditions { get; }
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
        /// Add an executable filename condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="filename">The path to the file to use.</param>
        public void AddFilename(FirewallMatchType match_type, string filename)
        {
            AddAppId(match_type, FirewallUtils.GetAppIdFromFileName(filename));
        }

        /// <summary>
        /// Add an App ID condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="appid">The path to the file already converted to absolute format.</param>
        public void AddAppId(FirewallMatchType match_type, string appid)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_APP_ID,
                FirewallValue.FromBlobUnicodeString(appid));
        }

        /// <summary>
        /// Add a user ID security descriptor condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="security_descriptor">The security descriptor.</param>
        public void AddUserId(FirewallMatchType match_type, SecurityDescriptor security_descriptor)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_USER_ID,
                FirewallValue.FromSecurityDescriptor(security_descriptor));
        }

        /// <summary>
        /// Add a remote user ID security descriptor condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="security_descriptor">The security descriptor.</param>
        public void AddRemoteUserId(FirewallMatchType match_type, SecurityDescriptor security_descriptor)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_REMOTE_USER_ID,
                FirewallValue.FromSecurityDescriptor(security_descriptor));
        }

        /// <summary>
        /// Add a remote machine ID security descriptor condition.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="security_descriptor">The security descriptor.</param>
        public void AddRemoteMachineId(FirewallMatchType match_type, SecurityDescriptor security_descriptor)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_REMOTE_MACHINE_ID,
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
        /// Add IP address.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="remote">True to specify remote, false for local.</param>
        /// <param name="address">The low IP address.</param>
        public void AddIpAddress(FirewallMatchType match_type, bool remote, IPAddress address)
        {
            AddCondition(match_type, remote ? FirewallConditionGuids.FWPM_CONDITION_IP_REMOTE_ADDRESS : FirewallConditionGuids.FWPM_CONDITION_IP_LOCAL_ADDRESS,
                FirewallValue.FromIpAddress(address));
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

        /// <summary>
        /// Add port.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="remote">True to specify remote, false for local.</param>
        /// <param name="port">The port.</param>
        public void AddPort(FirewallMatchType match_type, bool remote, int port)
        {
            AddCondition(match_type, remote ? FirewallConditionGuids.FWPM_CONDITION_IP_REMOTE_PORT : FirewallConditionGuids.FWPM_CONDITION_IP_LOCAL_PORT,
                FirewallValue.FromUInt16((ushort)port));
        }

        /// <summary>
        /// Add an IP endpoint.
        /// </summary>
        /// <param name="match_type">The match type for the condition.</param>
        /// <param name="remote">True to specify remote, false for local.</param>
        /// <param name="endpoint">The IP endpoint.</param>
        public void AddEndpoint(FirewallMatchType match_type, bool remote, IPEndPoint endpoint)
        {
            AddIpAddress(match_type, remote, endpoint.Address);
            AddPort(match_type, remote, endpoint.Port);
        }

        /// <summary>
        /// Add token information.
        /// </summary>
        /// <param name="match_type">The match type.</param>
        /// <param name="token">The token.</param>
        public void AddUserToken(FirewallMatchType match_type, NtToken token)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_USER_ID,
                FirewallValue.FromTokenInformation(token));
        }

        /// <summary>
        /// Add remote token information.
        /// </summary>
        /// <param name="match_type">The match type.</param>
        /// <param name="token">The token.</param>
        public void AddRemoteUserToken(FirewallMatchType match_type, NtToken token)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_REMOTE_USER_ID,
                FirewallValue.FromTokenInformation(token));
        }

        /// <summary>
        /// Add remote machine token information.
        /// </summary>
        /// <param name="match_type">The match type.</param>
        /// <param name="token">The token.</param>
        public void AddRemoteMachineToken(FirewallMatchType match_type, NtToken token)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_REMOTE_MACHINE_ID,
                FirewallValue.FromTokenInformation(token));
        }

        /// <summary>
        /// Add a package SID condition.
        /// </summary>
        /// <param name="match_type">The match type.</param>
        /// <param name="package_sid">The package SID.</param>
        public void AddPackageSid(FirewallMatchType match_type, Sid package_sid)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_ALE_PACKAGE_ID, FirewallValue.FromSid(package_sid));
        }

        /// <summary>
        /// Add a condition which excludes app containers.
        /// </summary>
        public void AddExcludeAppContainer()
        {
            AddPackageSid(FirewallMatchType.Equal, KnownSids.Null);
        }

        /// <summary>
        /// Add a condition which includes app containers.
        /// </summary>
        public void AddIncludeAppContainer()
        {
            AddPackageSid(FirewallMatchType.NotEqual, KnownSids.Null);
        }

        /// <summary>
        /// Adds details from a process, such as the process' App ID and package SID and token information.
        /// </summary>
        /// <param name="match_type">The match type.</param>
        /// <param name="process">The process.</param>
        public void AddProcess(FirewallMatchType match_type, NtProcess process)
        {
            AddFilename(match_type, process.Win32ImagePath);
            using (var token = NtToken.OpenProcessToken(process, TokenAccessRights.Query))
            {
                AddUserToken(match_type, token);
                if (token.AppContainer)
                {
                    AddPackageSid(match_type, token.AppContainerSid);
                }
                else
                {
                    AddPackageSid(match_type, KnownSids.Null);
                }
            }
        }

        /// <summary>
        /// Adds details from a process, such as the process' App ID and package SID and token information.
        /// </summary>
        /// <param name="match_type">The match type.</param>
        /// <param name="process_id">The PID of the process.</param>
        public void AddProcess(FirewallMatchType match_type, int process_id)
        {
            using (var process = NtProcess.Open(process_id, ProcessAccessRights.QueryLimitedInformation))
            {
                AddProcess(match_type, process);
            }
        }

        /// <summary>
        /// Add the RPC UUID.
        /// </summary>
        /// <param name="match_type">Match type.</param>
        /// <param name="uuid">The RPC UUID.</param>
        public void AddRpcUuid(FirewallMatchType match_type, Guid uuid)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_RPC_IF_UUID, FirewallValue.FromGuid(uuid));
        }

        /// <summary>
        /// Add a network event type.
        /// </summary>
        /// <param name="match_type">Match type.</param>
        /// <param name="type">Network event type.</param>
        public void AddNetEventType(FirewallMatchType match_type, FirewallNetEventType type)
        {
            AddCondition(match_type, FirewallConditionGuids.FWPM_CONDITION_NET_EVENT_TYPE, FirewallValue.FromUInt32((uint)type));
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public FirewallConditionBuilder()
        {
            Conditions = new List<FirewallFilterCondition>();
        }
        #endregion
    }
}
