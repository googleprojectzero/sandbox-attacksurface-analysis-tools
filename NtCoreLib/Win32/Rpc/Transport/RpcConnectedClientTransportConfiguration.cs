//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Base class for a connected client transport configuration.
/// </summary>
public class RpcConnectedClientTransportConfiguration : RpcClientTransportConfiguration
{
    /// <summary>
    /// Enable or disable bind time feature negotiation. If disabled then multiple security
    /// context are not permitted.
    /// </summary>
    public bool DisableBindTimeFeatureNegotiation { get; set; }

    /// <summary>
    /// Specified an existing association group ID for the new connection.
    /// </summary>
    public int? AssociationGroupId { get; set; }
}
