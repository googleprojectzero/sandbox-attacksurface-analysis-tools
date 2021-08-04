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
    [SDKName("IKEEXT_AUTHENTICATION_IMPERSONATION_TYPE")]
    public enum IkeExtAuthenticationImpersonationType
    {
        [SDKName("IKEEXT_IMPERSONATION_NONE")]
        None = 0,
        [SDKName("IKEEXT_IMPERSONATION_SOCKET_PRINCIPAL")]
        SocketPrincipal = (None + 1),
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member