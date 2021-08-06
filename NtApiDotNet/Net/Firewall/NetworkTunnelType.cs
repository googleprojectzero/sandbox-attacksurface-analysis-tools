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
    /// Type of network tunnel.
    /// </summary>
    [SDKName("TUNNEL_TYPE")]
    public enum NetworkTunnelType : uint
    {
        [SDKName("TUNNEL_TYPE_NONE")]
        None = 0,
        [SDKName("TUNNEL_TYPE_OTHER")]
        Other = 1,
        [SDKName("TUNNEL_TYPE_DIRECT")]
        Direct = 2,
        [SDKName("TUNNEL_TYPE_6TO4")]
        SixToFour = 11,
        [SDKName("TUNNEL_TYPE_ISATAP")]
        ISATAP = 13,
        [SDKName("TUNNEL_TYPE_TEREDO")]
        TEREDO = 14,
        [SDKName("TUNNEL_TYPE_IPHTTPS")]
        IPHTTPS = 15
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member