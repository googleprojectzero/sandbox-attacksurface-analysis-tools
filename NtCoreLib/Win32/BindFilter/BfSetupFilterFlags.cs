//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.BindFilter;

/// <summary>
/// Flags for the lower level BfSetupFilter function.
/// </summary>
/// <remarks>Flag names from https://github.com/Nukem9/BindFltAPI/blob/1398b9b95944384d43d38189f23799044684c522/bindfltapi.h</remarks>
[Flags]
public enum BfSetupFilterFlags
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("BINDFLT_FLAG_READ_ONLY_MAPPING")]
    ReadOnlyMapping = 0x00000001,
    [SDKName("BINDFLT_FLAG_MERGED_BIND_MAPPING")]
    MergedBindMapping = 0x00000002,
    [SDKName("BINDFLT_FLAG_USE_CURRENT_SILO_MAPPING")]
    UseCurrentSiloMapping = 0x00000004,
    [SDKName("BINDFLT_FLAG_REPARSE_ON_FILES")]
    ReparseOnFiles = 0x00000008,
    [SDKName("BINDFLT_FLAG_SKIP_SHARING_CHECK")]
    SkipSharingCheck = 0x00000010,
    [SDKName("BINDFLT_FLAG_CLOUD_FILES_ECPS")]
    CloudFilesEcps = 0x00000020,
    [SDKName("BINDFLT_FLAG_NO_MULTIPLE_TARGETS")]
    NoMultipleTargets = 0x00000040,
    [SDKName("BINDFLT_FLAG_IMMUTABLE_BACKING")]
    ImmutableBacking = 0x00000080,
    [SDKName("BINDFLT_FLAG_PREVENT_CASE_SENSITIVE_BINDING")]
    PreventCaseSensitiveBinding = 0x00000100,
    [SDKName("BINDFLT_FLAG_EMPTY_VIRT_ROOT")]
    EmptyVirtRoot = 0x00000200,
    [SDKName("BINDFLT_FLAG_NO_REPARSE_ON_ROOT")]
    NoReparseOnRoot = 0x10000000,
    [SDKName("BINDFLT_FLAG_BATCHED_REMOVE_MAPPINGS")]
    BatchedRemoveMappings = 0x20000000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
