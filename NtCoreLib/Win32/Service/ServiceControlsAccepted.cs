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
[Flags]
public enum ServiceControlsAccepted
{
    [SDKName("NONE")]
    None = 0,
    [SDKName("SERVICE_ACCEPT_STOP")]
    Stop = 1,
    [SDKName("SERVICE_ACCEPT_PAUSE_CONTINUE")]
    PauseContinue = 2,
    [SDKName("SERVICE_ACCEPT_SHUTDOWN")]
    Shutdown = 4,
    [SDKName("SERVICE_ACCEPT_PARAMCHANGE")]
    ParamChange = 8,
    [SDKName("SERVICE_ACCEPT_NETBINDCHANGE")]
    NetBindChange = 0x10,
    [SDKName("SERVICE_ACCEPT_HARDWAREPROFILECHANGE")]
    HardwareProfileChange = 0x20,
    [SDKName("SERVICE_ACCEPT_POWEREVENT")]
    PowerEvent = 0x40,
    [SDKName("SERVICE_ACCEPT_SESSIONCHANGE")]
    SessionChange = 0x80,
    [SDKName("SERVICE_ACCEPT_PRESHUTDOWN")]
    PreShutdown = 0x100,
    [SDKName("SERVICE_ACCEPT_TIMECHANGE")]
    Timechange = 0x200,
    [SDKName("SERVICE_ACCEPT_TRIGGEREVENT")]
    TriggerEvent = 0x400,
    [SDKName("SERVICE_ACCEPT_USER_LOGOFF")]
    UserLogoff = 0x800,
    [SDKName("SERVICE_ACCEPT_INTERNAL")]
    Internal = 0x1000,
    [SDKName("SERVICE_ACCEPT_LOWRESOURCES")]
    LowResources = 0x2000,
    [SDKName("SERVICE_ACCEPT_SYSTEMLOWRESOURCES")]
    SystemLowResources = 0x4000
}
