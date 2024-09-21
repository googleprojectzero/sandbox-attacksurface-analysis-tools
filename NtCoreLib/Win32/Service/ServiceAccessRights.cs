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
/// Access rights for Win32 services.
/// </summary>
[Flags]
public enum ServiceAccessRights : uint
{
    [SDKName("SERVICE_QUERY_CONFIG")]
    QueryConfig = 0x0001,
    [SDKName("SERVICE_CHANGE_CONFIG")]
    ChangeConfig = 0x0002,
    [SDKName("SERVICE_QUERY_STATUS")]
    QueryStatus = 0x0004,
    [SDKName("SERVICE_ENUMERATE_DEPENDENTS")]
    EnumerateDependents = 0x0008,
    [SDKName("SERVICE_START")]
    Start = 0x0010,
    [SDKName("SERVICE_STOP")]
    Stop = 0x0020,
    [SDKName("SERVICE_PAUSE_CONTINUE")]
    PauseContinue = 0x0040,
    [SDKName("SERVICE_INTERROGATE")]
    Interrogate = 0x0080,
    [SDKName("SERVICE_USER_DEFINED_CONTROL")]
    UserDefinedControl = 0x0100,
    [SDKName("SERVICE_SET_STATUS")]
    SetStatus = 0x8000,
    [SDKName("SERVICE_ALL_ACCESS")]
    All = ChangeConfig | EnumerateDependents | Interrogate | PauseContinue
        | QueryStatus | QueryConfig | Start | Stop | UserDefinedControl | ReadControl
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
