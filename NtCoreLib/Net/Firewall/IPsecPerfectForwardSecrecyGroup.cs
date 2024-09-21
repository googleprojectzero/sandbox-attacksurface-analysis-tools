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

using NtApiDotNet.Utilities.Reflection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// IPsec perfect forward secrecy group.
    /// </summary>
    [SDKName("IPSEC_PFS_GROUP")]
    public enum IPsecPerfectForwardSecrecyGroup
    {
        [SDKName("IPSEC_PFS_NONE")]
        None,
        [SDKName("IPSEC_PFS_1")]
        PFS1,
        [SDKName("IPSEC_PFS_2")]
        PFS2,
        [SDKName("IPSEC_PFS_2048")]
        PFS2048,
        [SDKName("IPSEC_PFS_ECP_256")]
        ECP_256,
        [SDKName("IPSEC_PFS_ECP_384")]
        ECP_384,
        [SDKName("IPSEC_PFS_MM")]
        MainMode,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member