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

using NtCoreLib.Security.Authorization;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Class to configure the ALPC transport.
/// </summary>
public sealed class RpcAlpcClientTransportConfiguration : RpcClientTransportConfiguration
{
    /// <summary>
    /// Specify the required server SID when connecting.
    /// </summary>
    /// <remarks><see cref="ServerSecurityRequirements"/> will be used in preference to this if specified.</remarks>
    public Sid RequiredServerSid { get; set; }

    /// <summary>
    /// Specify the required server security requirements when connecting.
    /// </summary>
    public SecurityDescriptor ServerSecurityRequirements { get; set; }

    /// <summary>
    /// Specify the connection timeout.
    /// </summary>
    public NtWaitTimeout ConnectTimeout { get; set; }
}
