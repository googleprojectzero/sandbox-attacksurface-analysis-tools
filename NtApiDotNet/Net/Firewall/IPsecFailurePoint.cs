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
    /// Type used for indicating where an IPsec failure occured.
    /// </summary>
    [SDKName("IPSEC_FAILURE_POINT")]
    public enum IPsecFailurePoint
    {
        /// <summary>
        /// No information available.
        /// </summary>
        [SDKName("IPSEC_FAILURE_NONE")]
        None,
        /// <summary>
        /// IPsec failure happened on local machine.
        /// </summary>
        [SDKName("IPSEC_FAILURE_ME")]
        Me,
        /// <summary>
        /// IPsec failure happened on remote machine.
        /// </summary>
        [SDKName("IPSEC_FAILURE_PEER")]
        Peer
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member