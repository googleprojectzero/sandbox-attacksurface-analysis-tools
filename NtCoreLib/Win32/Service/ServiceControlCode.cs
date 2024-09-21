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

namespace NtCoreLib.Win32.Service;
#pragma warning disable 1591
public enum ServiceControlCode
{
    [SDKName("SERVICE_CONTROL_STOP")]
    Stop = 0x00000001,
    [SDKName("SERVICE_CONTROL_PAUSE")]
    Pause = 0x00000002,
    [SDKName("SERVICE_CONTROL_CONTINUE")]
    Continue = 0x00000003,
    [SDKName("SERVICE_CONTROL_INTERROGATE")]
    Interrogate = 0x00000004,
    [SDKName("SERVICE_CONTROL_SHUTDOWN")]
    Shutdown = 0x00000005,
    [SDKName("SERVICE_CONTROL_PARAMCHANGE")]
    ParamChange = 0x00000006,
    [SDKName("SERVICE_CONTROL_NETBINDADD")]
    NetBindAdd = 0x00000007,
    [SDKName("SERVICE_CONTROL_NETBINDREMOVE")]
    NetBindRemove = 0x00000008,
    [SDKName("SERVICE_CONTROL_NETBINDENABLE")]
    NetBindEnable = 0x00000009,
    [SDKName("SERVICE_CONTROL_NETBINDDISABLE")]
    NetBindDisable = 0x0000000A,
    [SDKName("SERVICE_CONTROL_DEVICEEVENT")]
    DeviceEvent = 0x0000000B,
    [SDKName("SERVICE_CONTROL_HARDWAREPROFILECHANGE")]
    HardwareProfileChange = 0x0000000C,
    [SDKName("SERVICE_CONTROL_POWEREVENT")]
    PowerEvent = 0x0000000D,
    [SDKName("SERVICE_CONTROL_SESSIONCHANGE")]
    SessionChange = 0x0000000E,
    [SDKName("SERVICE_CONTROL_PRESHUTDOWN")]
    PreShutdown = 0x0000000F,
    [SDKName("SERVICE_CONTROL_TIMECHANGE")]
    TimeChange = 0x00000010,
    [SDKName("SERVICE_CONTROL_USER_LOGOFF")]
    UserLogoff = 0x00000011,
    [SDKName("SERVICE_CONTROL_TRIGGEREVENT")]
    TriggerEvent = 0x00000020,
    [SDKName("SERVICE_CONTROL_INTERNAL21")]
    Internal21 = 0x00000021,
    [SDKName("SERVICE_CONTROL_INTERNAL50")]
    Internal50 = 0x00000050,
    [SDKName("SERVICE_CONTROL_LOWRESOURCES")]
    LowResources = 0x00000060,
    [SDKName("SERVICE_CONTROL_SYSTEMLOWRESOURCES")]
    SystemLowResources = 0x00000061
}
