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

using NtCoreLib.Utilities.Reflection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Address family when IP protocol is not specified.
/// </summary>
[SDKName("FWP_AF")]
public enum FirewallAddressFamily
{
    /// <summary>
    /// IPv4
    /// </summary>
    [SDKName("FWP_AF_INET")]
    Inet = 0,
    /// <summary>
    /// IPv6
    /// </summary>
    [SDKName("FWP_AF_INET6")]
    Inet6,
    /// <summary>
    /// Ethernet
    /// </summary>
    [SDKName("FWP_AF_ETHER")]
    Ether,
    /// <summary>
    /// None
    /// </summary>
    [SDKName("FWP_AF_NONE")]
    None
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member