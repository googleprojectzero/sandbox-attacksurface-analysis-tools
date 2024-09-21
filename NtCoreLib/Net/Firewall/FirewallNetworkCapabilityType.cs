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
/// AppContainer capability type.
/// </summary>
[SDKName("FWPM_APPC_NETWORK_CAPABILITY_TYPE")]
public enum FirewallNetworkCapabilityType
{
    [SDKName("FWPM_APPC_NETWORK_CAPABILITY_INTERNET_CLIENT")]
    InternetClient = 0,
    [SDKName("FWPM_APPC_NETWORK_CAPABILITY_INTERNET_CLIENT_SERVER")]
    InternetClientServer = (InternetClient + 1),
    [SDKName("FWPM_APPC_NETWORK_CAPABILITY_INTERNET_PRIVATE_NETWORK")]
    InternetPrivateNetwork = (InternetClientServer + 1)
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member