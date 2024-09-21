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

namespace NtApiDotNet.Net.Sockets
{
    /// <summary>
    /// Security protocol for a socket.
    /// </summary>
    internal enum SOCKET_SECURITY_PROTOCOL
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("SOCKET_SECURITY_PROTOCOL_DEFAULT")]
        Default,
        [SDKName("SOCKET_SECURITY_PROTOCOL_IPSEC")]
        IPsec,
        [SDKName("SOCKET_SECURITY_PROTOCOL_IPSEC2")]
        IPsec2,
        [SDKName("SOCKET_SECURITY_PROTOCOL_INVALID")]
        Invalid
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
