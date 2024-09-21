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
public enum ServiceType
{
    [SDKName("SERVICE_KERNEL_DRIVER")]
    KernelDriver = 0x00000001,
    [SDKName("SERVICE_FILE_SYSTEM_DRIVER")]
    FileSystemDriver = 0x00000002,
    [SDKName("SERVICE_ADAPTER")]
    Adapter = 0x00000004,
    [SDKName("SERVICE_RECOGNIZER_DRIVER")]
    RecognizerDriver = 0x00000008,
    [SDKName("SERVICE_DRIVER")]
    Driver = KernelDriver | FileSystemDriver | Adapter | RecognizerDriver,
    [SDKName("SERVICE_WIN32_OWN_PROCESS")]
    Win32OwnProcess = 0x00000010,
    [SDKName("SERVICE_WIN32_SHARE_PROCESS")]
    Win32ShareProcess = 0x00000020,
    [SDKName("SERVICE_WIN32")]
    Win32 = Win32OwnProcess | Win32ShareProcess,
    [SDKName("SERVICE_USER_SERVICE")]
    UserService = 0x00000040,
    [SDKName("SERVICE_USERSERVICE_INSTANCE")]
    UserServiceInstance = 0x00000080,
    [SDKName("SERVICE_INTERACTIVE_PROCESS")]
    InteractiveProcess = 0x00000100,
    [SDKName("SERVICE_PKG_SERVICE")]
    PkgService = 0x00000200
}
