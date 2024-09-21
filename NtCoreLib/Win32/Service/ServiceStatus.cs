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
public enum ServiceStatus
{
    [SDKName("SERVICE_STOPPED")]
    Stopped = 1,
    [SDKName("SERVICE_START_PENDING")]
    StartPending = 2,
    [SDKName("SERVICE_STOP_PENDING")]
    StopPending = 3,
    [SDKName("SERVICE_RUNNING")]
    Running = 4,
    [SDKName("SERVICE_CONTINUE_PENDING")]
    ContinuePending = 5,
    [SDKName("SERVICE_PAUSE_PENDING")]
    PausePending = 6,
    [SDKName("SERVICE_PAUSED")]
    Paused = 7,
}
