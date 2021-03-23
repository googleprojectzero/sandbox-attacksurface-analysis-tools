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

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Identifies the type of credentials.
    /// </summary>
    public enum CredentialType
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        Unknown = 0,
        [SDKName("CRED_TYPE_GENERIC")]
        Generic = 1,
        [SDKName("CRED_TYPE_DOMAIN_PASSWORD")]
        DomainPassword = 2,
        [SDKName("CRED_TYPE_DOMAIN_CERTIFICATE")]
        DomainCertificate = 3,
        [SDKName("CRED_TYPE_DOMAIN_VISIBLE_PASSWORD")]
        DomainVisiblePassword = 4,
        [SDKName("CRED_TYPE_GENERIC_CERTIFICATE")]
        GenericCertificate = 5,
        [SDKName("CRED_TYPE_DOMAIN_EXTENDED")]
        DomainExtended = 6,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
