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

[SDKName("IKEEXT_DH_GROUP")]
public enum IkeExtDHGroup
{
    [SDKName("IKEEXT_DH_GROUP_NONE")]
    None = 0,
    [SDKName("IKEEXT_DH_GROUP_1")]
    Group1 = (None + 1),
    [SDKName("IKEEXT_DH_GROUP_2")]
    Group2 = (Group1 + 1),
    [SDKName("IKEEXT_DH_GROUP_14")]
    Group14 = (Group2 + 1),
    [SDKName("IKEEXT_DH_GROUP_2048")]
    Group2048 = Group14,
    [SDKName("IKEEXT_DH_ECP_256")]
    ECP256 = (Group2048 + 1),
    [SDKName("IKEEXT_DH_ECP_384")]
    ECP384 = (ECP256 + 1),
    [SDKName("IKEEXT_DH_GROUP_24")]
    Group24 = (ECP384 + 1),
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member