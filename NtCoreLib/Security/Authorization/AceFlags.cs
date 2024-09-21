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
/// ACE Flags. Note that the value isn't completely the same as
/// the real flags.
/// </summary>
[Flags]
public enum AceFlags : uint
{
    None = 0,
    [SDKName("OBJECT_INHERIT_ACE")]
    ObjectInherit = 0x1,
    [SDKName("CONTAINER_INHERIT_ACE")]
    ContainerInherit = 0x2,
    [SDKName("NO_PROPAGATE_INHERIT_ACE")]
    NoPropagateInherit = 0x4,
    [SDKName("INHERIT_ONLY_ACE")]
    InheritOnly = 0x8,
    [SDKName("INHERITED_ACE")]
    Inherited = 0x10,
    // Used only for Allow ACEs.
    [SDKName("CRITICAL_ACE_FLAG")]
    Critical = 0x20,
    // Used only for Audit/Alarm ACEs.
    [SDKName("SUCCESSFUL_ACCESS_ACE_FLAG")]
    SuccessfulAccess = 0x40,
    [SDKName("FAILED_ACCESS_ACE_FLAG")]
    FailedAccess = 0x80,
    // Used only for AccessFilter ACE.
    [SDKName("TRUST_PROTECTED_FILTER_ACE_FLAG")]
    TrustProtected = 0x100,
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member