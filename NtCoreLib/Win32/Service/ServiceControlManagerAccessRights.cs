//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Service;
#pragma warning disable 1591

/// <summary>
/// Access rights for the service control manager.
/// </summary>
[Flags]
public enum ServiceControlManagerAccessRights : uint
{
    [SDKName("SC_MANAGER_CONNECT")]
    Connect = 0x0001,
    [SDKName("SC_MANAGER_CREATE_SERVICE")]
    CreateService = 0x0002,
    [SDKName("SC_MANAGER_ENUMERATE_SERVICE")]
    EnumerateService = 0x0004,
    [SDKName("SC_MANAGER_LOCK")]
    Lock = 0x0008,
    [SDKName("SC_QUERY_LOCK_STATUS")]
    QueryLockStatus = 0x0010,
    [SDKName("SC_MANAGER_MODIFY_BOOT_CONFIG")]
    ModifyBootConfig = 0x0020,
    [SDKName("SC_MANAGER_ALL_ACCESS")]
    All = CreateService | Connect | EnumerateService
        | Lock | ModifyBootConfig | QueryLockStatus | ReadControl
        | Delete | WriteDac | WriteOwner,
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
    [SDKName("SYNCHRONIZE")]
    Synchronize = GenericAccessRights.Synchronize,
    [SDKName("MAXIMUM_ALLOWED")]
    MaximumAllowed = GenericAccessRights.MaximumAllowed,
    [SDKName("ACCESS_SYSTEM_SECURITY")]
    AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
}
