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
/// Flags for DLL redirection entry.
/// </summary>
[Flags]
public enum ActivationContextDataDllRedirectionPathFlags
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME")]
    IncludesBaseName = 0x00000001,
    [SDKName("ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT")]
    OmitsAssemblyRoot = 0x00000002,
    [SDKName("ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_EXPAND")]
    Expand = 0x00000004,
    [SDKName("ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL")]
    RedirectedSystem32Dll = 0x00000008,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
