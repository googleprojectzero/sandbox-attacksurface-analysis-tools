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
public enum ServiceControlManagerAction
{
    [SDKName("SC_ACTION_NONE")]
    None = 0,
    [SDKName("SC_ACTION_RESTART")]
    Restart = 1,
    [SDKName("SC_ACTION_REBOOT")]
    Reboot = 2,
    [SDKName("SC_ACTION_RUN_COMMAND")]
    RunCommand = 3
}
