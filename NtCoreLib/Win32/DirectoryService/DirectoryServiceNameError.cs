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
    /// Directory services name error.
    /// </summary>
    [SDKName("DS_NAME_ERROR")]
    public enum DirectoryServiceNameError
    {
        [SDKName("DS_NAME_NO_ERROR")]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("DS_NAME_ERROR_RESOLVING")]
        Resolving = 1,
        [SDKName("DS_NAME_ERROR_NOT_FOUND")]
        NotFound = 2,
        [SDKName("DS_NAME_ERROR_NOT_UNIQUE")]
        NotUnique = 3,
        [SDKName("DS_NAME_ERROR_NO_MAPPING")]
        NoMapping = 4,
        [SDKName("DS_NAME_ERROR_DOMAIN_ONLY")]
        DomainOnly = 5,
        [SDKName("DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING")]
        NoSyntacticalMapping = 6,
        [SDKName("DS_NAME_ERROR_TRUST_REFERRAL")]
        TrustReferral = 7
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
