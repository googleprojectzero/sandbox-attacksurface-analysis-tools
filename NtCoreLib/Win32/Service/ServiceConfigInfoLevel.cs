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

#nullable enable

using NtCoreLib.Utilities.Reflection;

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Info level for QueryServiceConfig2 and ChangeServiceConfig2.
/// </summary>
public enum ServiceConfigInfoLevel
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [SDKName("SERVICE_CONFIG_DESCRIPTION")]
    Description = 1,
    [SDKName("SERVICE_CONFIG_FAILURE_ACTIONS")]
    FailureActions = 2,
    [SDKName("SERVICE_CONFIG_DELAYED_AUTO_START_INFO")]
    DelayedAutoStartInfo = 3,
    [SDKName("SERVICE_CONFIG_FAILURE_ACTIONS_FLAG")]
    FailureActionsFlag = 4,
    [SDKName("SERVICE_CONFIG_SERVICE_SID_INFO")]
    ServiceSidInfo = 5,
    [SDKName("SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO")]
    RequiredPrivilegesInfo = 6,
    [SDKName("SERVICE_CONFIG_PRESHUTDOWN_INFO")]
    PreShutdownInfo = 7,
    [SDKName("SERVICE_CONFIG_TRIGGER_INFO")]
    TriggerInfo = 8,
    [SDKName("SERVICE_CONFIG_PREFERRED_NODE")]
    PreferredNode = 9,
    Unknown10 = 10,
    ManagedAccount = 11,
    [SDKName("SERVICE_CONFIG_LAUNCH_PROTECTED")]
    LaunchProtected = 12,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
