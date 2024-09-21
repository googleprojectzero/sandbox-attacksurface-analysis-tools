//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Security.Authorization;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

/// <summary>
/// Flags for specifying auto-inherit behavior.
/// </summary>
[Flags]
public enum SecurityAutoInheritFlags
{
    None = 0,
    [SDKName("SEF_DACL_AUTO_INHERIT")]
    DaclAutoInherit = 0x1,
    [SDKName("SEF_SACL_AUTO_INHERIT")]
    SaclAutoInherit = 0x2,
    [SDKName("SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT")]
    DefaultDescriptorForObject = 0x4,
    [SDKName("SEF_AVOID_PRIVILEGE_CHECK")]
    AvoidPrivilegeCheck = 0x8,
    [SDKName("SEF_AVOID_OWNER_CHECK")]
    AvoidOwnerCheck = 0x10,
    [SDKName("SEF_DEFAULT_OWNER_FROM_PARENT")]
    DefaultOwnerFromParent = 0x20,
    [SDKName("SEF_DEFAULT_GROUP_FROM_PARENT")]
    DefaultGroupFromParent = 0x40,
    [SDKName("SEF_MACL_NO_WRITE_UP")]
    MaclNoWriteUp = 0x100,
    [SDKName("SEF_MACL_NO_READ_UP")]
    MaclNoReadUp = 0x200,
    [SDKName("SEF_MACL_NO_EXECUTE_UP")]
    MaclNoExecuteUp = 0x400,
    [SDKName("SEF_AI_USE_EXTRA_PARAMS")]
    AiUseExtraParams = 0x800,
    [SDKName("SEF_AVOID_OWNER_RESTRICTION")]
    AvoidOwnerRestriction = 0x1000,
    [SDKName("SEF_FORCE_USER_MODE")]
    ForceUserMode = 0x2000,
}

#pragma warning restore 1591

