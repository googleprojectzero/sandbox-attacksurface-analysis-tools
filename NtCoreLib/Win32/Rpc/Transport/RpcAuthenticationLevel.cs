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

using NtCoreLib.Utilities.Reflection;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Authentication level for RPC transport.
/// </summary>
public enum RpcAuthenticationLevel : byte
{
    /// <summary>
    /// Default.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_DEFAULT")]
    Default = 0,
    /// <summary>
    /// None.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_NONE")]
    None = 1,
    /// <summary>
    /// Connect only.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_CONNECT")]
    Connect = 2,
    /// <summary>
    /// Call only.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_CALL")]
    Call = 3,
    /// <summary>
    /// Packet only.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_PKT")]
    Packet = 4,
    /// <summary>
    /// Packet integrity.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_PKT_INTEGRITY")]
    PacketIntegrity = 5,
    /// <summary>
    /// Packer privacy and integrity.
    /// </summary>
    [SDKName("RPC_C_AUTHN_LEVEL_PKT_PRIVACY")]
    PacketPrivacy = 6,
}
