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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Directory services name format.
    /// </summary>
    [SDKName("DS_NAME_FORMAT")]
    public enum DirectoryServiceNameFormat : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("DS_UNKNOWN_NAME")]
        Unknown = 0,
        [SDKName("DS_FQDN_1779_NAME")]
        FQDN1779 = 1,
        [SDKName("DS_NT4_ACCOUNT_NAME")]
        NT4Account = 2,
        [SDKName("DS_DISPLAY_NAME")]
        Display = 3,
        [SDKName("DS_UNIQUE_ID_NAME")]
        UniqueId = 6,
        [SDKName("DS_CANONICAL_NAME")]
        Canonical = 7,
        [SDKName("DS_USER_PRINCIPAL_NAME")]
        Principal = 8,
        [SDKName("DS_CANONICAL_NAME_EX")]
        CanonicalEx = 9,
        [SDKName("DS_SERVICE_PRINCIPAL_NAME")]
        ServicePrincipal = 10,
        [SDKName("DS_SID_OR_SID_HISTORY_NAME")]
        SidOrSidHistory = 11,
        [SDKName("DS_DNS_DOMAIN_NAME")]
        Domain = 12
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
