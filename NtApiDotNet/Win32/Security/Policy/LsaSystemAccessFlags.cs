//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Flags for an account's system access.
    /// </summary>
    [Flags]
    public enum LsaSystemAccessFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("SECURITY_ACCESS_INTERACTIVE_LOGON")]
        InteractiveLogon = 0x00000001,
        [SDKName("SECURITY_ACCESS_NETWORK_LOGON")]
        NetworkLogon = 0x00000002,
        [SDKName("SECURITY_ACCESS_BATCH_LOGON")]
        BatchLogon = 0x00000004,
        [SDKName("SECURITY_ACCESS_SERVICE_LOGON")]
        ServiceLogon = 0x00000010,
        [SDKName("SECURITY_ACCESS_PROXY_LOGON")]
        ProxyLogon = 0x00000020,
        [SDKName("SECURITY_ACCESS_DENY_INTERACTIVE_LOGON")]
        DenyInteractiveLogon = 0x00000040,
        [SDKName("SECURITY_ACCESS_DENY_NETWORK_LOGON")]
        DenyNetworkLogon = 0x00000080,
        [SDKName("SECURITY_ACCESS_DENY_BATCH_LOGON")]
        DenyBatchLogon = 0x00000100,
        [SDKName("SECURITY_ACCESS_DENY_SERVICE_LOGON")]
        DenyServiceLogon = 0x00000200,
        [SDKName("SECURITY_ACCESS_REMOTE_INTERACTIVE_LOGON")]
        RemoteInteractiveLogon = 0x00000400,
        [SDKName("SECURITY_ACCESS_DENY_REMOTE_INTERACTIVE_LOGON")]
        DenyRemoteInteractiveLogon = 0x00000800,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
