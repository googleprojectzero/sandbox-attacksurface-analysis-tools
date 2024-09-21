//  Copyright 2023 Google LLC. All Rights Reserved.
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
//
//  Note this is relicensed from OleViewDotNet by the author.

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Assembly information flags.
/// </summary>
[Flags]
public enum ActivationContextDataAssemblyInformationFlags
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION_ROOT_ASSEMBLY")]
    RootAssembly = 0x00000001,
    [SDKName("ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION_POLICY_APPLIED")]
    PolicyApplied = 0x00000002,
    [SDKName("ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION_ASSEMBLY_POLICY_APPLIED")]
    AssemblyPolicyApplied = 0x00000004,
    [SDKName("ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION_ROOT_POLICY_APPLIED")]
    RootPolicyApplied = 0x00000008,
    [SDKName("ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION_PRIVATE_ASSEMBLY")]
    PrivateAssembly = 0x00000010,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
