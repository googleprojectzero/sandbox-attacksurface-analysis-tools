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
    /// IPsec traffic type.
    /// </summary>
    [SDKName("IPSEC_TRAFFIC_TYPE")]
    public enum IPsecTrafficType
    {
        [SDKName("IPSEC_TRAFFIC_TYPE_TRANSPORT")]
        Transport,
        [SDKName("IPSEC_TRAFFIC_TYPE_TUNNEL")]
        Tunnel
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member