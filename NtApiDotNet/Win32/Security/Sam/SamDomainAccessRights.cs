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

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Access rights for a SAM domain object.
    /// </summary>
    [Flags]
    public enum SamDomainAccessRights : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("DOMAIN_READ_PASSWORD_PARAMETERS")]
        ReadPasswordParameters = 0x0001,
        [SDKName("DOMAIN_WRITE_PASSWORD_PARAMS")]
        WritePasswordParams = 0x0002,
        [SDKName("DOMAIN_READ_OTHER_PARAMETERS")]
        ReadOtherParameters = 0x0004,
        [SDKName("DOMAIN_WRITE_OTHER_PARAMETERS")]
        WriteOtherParameters = 0x0008,
        [SDKName("DOMAIN_CREATE_USER")]
        CreateUser = 0x0010,
        [SDKName("DOMAIN_CREATE_GROUP")]
        CreateGroup = 0x0020,
        [SDKName("DOMAIN_CREATE_ALIAS")]
        CreateAlias = 0x0040,
        [SDKName("DOMAIN_GET_ALIAS_MEMBERSHIP")]
        GetAliasMembership = 0x0080,
        [SDKName("DOMAIN_LIST_ACCOUNTS")]
        ListAccounts = 0x0100,
        [SDKName("DOMAIN_LOOKUP")]
        Lookup = 0x0200,
        [SDKName("DOMAIN_ADMINISTER_SERVER")]
        AdministerServer = 0x0400,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
