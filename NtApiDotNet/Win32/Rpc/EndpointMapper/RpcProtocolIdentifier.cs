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

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    /// <summary>
    /// RPC protocol identifiers.
    /// </summary>
    public enum RpcProtocolIdentifier
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        Tcp = 7,
        Udp = 8,
        Ip = 9,
        ConnectionlessProtocol = 0xA,
        ConnectionOrientatedProtocol = 0xB,
        Lrpc = 0xC,
        Uuid = 0xD,
        NetBIOS = 0x11,
        ContainerAddress = 0x22,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
