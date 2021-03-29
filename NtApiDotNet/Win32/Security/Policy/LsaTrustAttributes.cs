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
using System;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Trust attribute flags for a trusted domain.
    /// </summary>
    [Flags]
    public enum LsaTrustAttributes
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("TRUST_ATTRIBUTE_NON_TRANSITIVE")]
        NonTransitive = 0x00000001,
        [SDKName("TRUST_ATTRIBUTE_UPLEVEL_ONLY")]
        UplevelOnly = 0x00000002,
        [SDKName("TRUST_ATTRIBUTE_QUARANTINED_DOMAIN")]
        QuarantinedDomain = 0x00000004,
        [SDKName("TRUST_ATTRIBUTE_FOREST_TRANSITIVE")]
        ForestTransitive = 0x00000008,
        [SDKName("TRUST_ATTRIBUTE_CROSS_ORGANIZATION")]
        CrossOrganization = 0x00000010,
        [SDKName("TRUST_ATTRIBUTE_WITHIN_FOREST")]
        WithinForest = 0x00000020,
        [SDKName("TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL")]
        TreatAsExternal = 0x00000040,
        [SDKName("TRUST_ATTRIBUTE_TRUST_USES_RC4_ENCRYPTION")]
        TrustUsesRC4Encryption = 0x00000080,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
