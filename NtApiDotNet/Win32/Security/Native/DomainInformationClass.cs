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

namespace NtApiDotNet.Win32.Security.Native
{
    /// <summary>
    /// Information class for a SAM domain object.
    /// </summary>
    [SDKName("DOMAIN_INFORMATION_CLASS")]
    internal enum DomainInformationClass
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        DomainPasswordInformation = 1,
        DomainGeneralInformation,
        DomainLogoffInformation,
        DomainOemInformation,
        DomainNameInformation,
        DomainReplicationInformation,
        DomainServerRoleInformation,
        DomainModifiedInformation,
        DomainStateInformation,
        DomainUasInformation,
        DomainGeneralInformation2,
        DomainLockoutInformation,
        DomainModifiedInformation2
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
