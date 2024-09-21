//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.DirectoryService
{
#pragma warning disable 1591
    /// <summary>
    /// Access rights for Active Directory Services.
    /// </summary>
    [Flags]
    public enum DirectoryServiceAccessRights : uint
    {
        None = 0,
        [SDKName("ACTRL_DS_CREATE_CHILD")]
        CreateChild = 0x1,
        [SDKName("ACTRL_DS_DELETE_CHILD")]
        DeleteChild = 0x2,
        [SDKName("ACTRL_DS_LIST")]
        List = 0x4,
        [SDKName("ACTRL_DS_SELF")]
        Self = 0x8,
        [SDKName("ACTRL_DS_READ_PROP")]
        ReadProp = 0x10,
        [SDKName("ACTRL_DS_WRITE_PROP")]
        WriteProp = 0x20,
        [SDKName("ACTRL_DS_DELETE_TREE")]
        DeleteTree = 0x40,
        [SDKName("ACTRL_DS_LIST_OBJECT")]
        ListObject = 0x80,
        [SDKName("ACTRL_DS_CONTROL_ACCESS")]
        ControlAccess = 0x100,
        [SDKName("ACTRL_DS_ALL_ACCESS")]
        All = WriteOwner | WriteDac | ReadControl | Delete | ControlAccess | ListObject |
            DeleteTree | WriteProp | ReadProp | Self | List | CreateChild | DeleteChild,
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
    }
}
