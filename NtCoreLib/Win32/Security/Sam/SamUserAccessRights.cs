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
    /// Access rights for a SAM user object.
    /// </summary>
    [Flags]
    public enum SamUserAccessRights : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("USER_READ_GENERAL")]
        ReadGeneral = 0x00000001,
        [SDKName("USER_READ_PREFERENCES")]
        ReadPreferences = 0x00000002,
        [SDKName("USER_WRITE_PREFERENCES")]
        WritePreferences = 0x00000004,
        [SDKName("USER_READ_LOGON")]
        ReadLogon = 0x00000008,
        [SDKName("USER_READ_ACCOUNT")]
        ReadAccount = 0x00000010,
        [SDKName("USER_WRITE_ACCOUNT")]
        WriteAccount = 0x00000020,
        [SDKName("USER_CHANGE_PASSWORD")]
        ChangePassword = 0x00000040,
        [SDKName("USER_FORCE_PASSWORD_CHANGE")]
        ForcePasswordChange = 0x00000080,
        [SDKName("USER_LIST_GROUPS")]
        ListGroups = 0x00000100,
        [SDKName("USER_READ_GROUP_INFORMATION")]
        ReadGroupInformation = 0x00000200,
        [SDKName("USER_WRITE_GROUP_INFORMATION")]
        WriteGroupInformation = 0x00000400,
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
