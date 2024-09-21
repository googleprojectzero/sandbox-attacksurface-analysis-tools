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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Direction of stream for firewall.
    /// </summary>
    public enum FirewallDirectionType : uint
    {
        /// <summary>
        /// Outbound flow.
        /// </summary>
        [SDKName("FWP_DIRECTION_OUTBOUND")]
        Outbound = 0,
        /// <summary>
        /// Inbound flow.
        /// </summary>
        [SDKName("FWP_DIRECTION_INBOUND")]
        Inbound = (Outbound + 1)
    }
}
