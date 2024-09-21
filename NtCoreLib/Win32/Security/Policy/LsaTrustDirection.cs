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

using NtApiDotNet.Utilities.Reflection;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Direction of trust for a trusted domain.
    /// </summary>
    public enum LsaTrustDirection
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("TRUST_DIRECTION_DISABLED")]
        Disabled = 0,
        [SDKName("TRUST_DIRECTION_INBOUND")]
        Inbound = 1,
        [SDKName("TRUST_DIRECTION_OUTBOUND")]
        Outbound = 2,
        [SDKName("TRUST_DIRECTION_BIDIRECTIONAL")]
        BiDirectional = Inbound | Outbound,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
