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

#nullable enable

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.TerminalServices;

/// <summary>
/// Access rights for a terminal server listener.
/// </summary>
[Flags]
public enum TerminalServerListenerAccessRights : uint
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("WTS_SECURITY_QUERY_INFORMATION")]
    QueryInformation = 0x00000001,
    [SDKName("WTS_SECURITY_SET_INFORMATION")]
    SetInformation   = 0x00000002,
    [SDKName("WTS_SECURITY_RESET")]
    Reset             =       0x00000004,
    [SDKName("WTS_SECURITY_VIRTUAL_CHANNELS")]
    VirtualChannels  =       0x00000008,
    [SDKName("WTS_SECURITY_REMOTE_CONTROL")]
    RemoteControl    =       0x00000010,
    [SDKName("WTS_SECURITY_LOGON")]
    SecurityLogon             =       0x00000020,
    [SDKName("WTS_SECURITY_LOGOFF")]
    SecurityLogoff            =       0x00000040,
    [SDKName("WTS_SECURITY_MESSAGE")]
    Message           =       0x00000080,
    [SDKName("WTS_SECURITY_CONNECT")]
    Connect =       0x00000100,
    [SDKName("WTS_SECURITY_DISCONNECT")]
    Disconnect =       0x00000200,
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
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
