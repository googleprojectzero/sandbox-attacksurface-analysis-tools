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

/// <summary>
/// Security information class for security descriptors.
/// </summary>
[Flags]
public enum SecurityInformation : uint
{
    /// <summary>
    /// Owner SID
    /// </summary>
    [SDKName("OWNER_SECURITY_INFORMATION")]
    Owner = 1,
    /// <summary>
    /// Group SID
    /// </summary>
    [SDKName("GROUP_SECURITY_INFORMATION")]
    Group = 2,
    /// <summary>
    /// DACL
    /// </summary>
    [SDKName("DACL_SECURITY_INFORMATION")]
    Dacl = 4,
    /// <summary>
    /// SACL
    /// </summary>
    [SDKName("SACL_SECURITY_INFORMATION")]
    Sacl = 8,
    /// <summary>
    /// Mandatory label
    /// </summary>
    [SDKName("LABEL_SECURITY_INFORMATION")]
    Label = 0x10,
    /// <summary>
    /// Resource attribute
    /// </summary>
    [SDKName("ATTRIBUTE_SECURITY_INFORMATION")]
    Attribute = 0x20,
    /// <summary>
    /// Scope
    /// </summary>
    [SDKName("SCOPE_SECURITY_INFORMATION")]
    Scope = 0x40,
    /// <summary>
    /// Process trust label
    /// </summary>
    [SDKName("PROCESS_TRUST_LABEL_SECURITY_INFORMATION")]
    ProcessTrustLabel = 0x80,
    /// <summary>
    /// Access filter.
    /// </summary>
    [SDKName("ACCESS_FILTER_SECURITY_INFORMATION")]
    AccessFilter = 0x100,
    /// <summary>
    /// Backup all entries
    /// </summary>
    [SDKName("BACKUP_SECURITY_INFORMATION")]
    Backup = 0x10000,
    /// <summary>
    /// Protected DACL (for Win32 APIs)
    /// </summary>
    [SDKName("PROTECTED_DACL_SECURITY_INFORMATION")]
    ProtectedDacl = 0x80000000,
    /// <summary>
    /// Protected SACL (for Win32 APIs)
    /// </summary>
    [SDKName("PROTECTED_SACL_SECURITY_INFORMATION")]
    ProtectedSacl = 0x40000000,
    /// <summary>
    /// Unprotected DACL (for Win32 APIs)
    /// </summary>
    [SDKName("UNPROTECTED_DACL_SECURITY_INFORMATION")]
    UnprotectedDacl = 0x20000000,
    /// <summary>
    /// Unprotected SACL (for Win32 APIs)
    /// </summary>
    [SDKName("UNPROTECTED_SACL_SECURITY_INFORMATION")]
    UnprotectedSacl = 0x10000000,
    /// <summary>
    /// All basic information
    /// </summary>
    AllBasic = Dacl | Owner | Group | Label | ProcessTrustLabel,
    /// <summary>
    /// All information without SACL
    /// </summary>
    AllNoSacl = AllBasic | Attribute | Scope | AccessFilter,
    /// <summary>
    /// All information
    /// </summary>
    All = AllNoSacl | Sacl
}