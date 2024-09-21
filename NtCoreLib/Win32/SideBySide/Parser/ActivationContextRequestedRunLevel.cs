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

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Run level for the activation context.
/// </summary>
public enum ActivationContextRequestedRunLevel
{
    [SDKName("ACTCTX_RUN_LEVEL_UNSPECIFIED")]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    Unspecified,
    [SDKName("ACTCTX_RUN_LEVEL_AS_INVOKER")]
    AsInvoker,
    [SDKName("ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE")]
    HighestAvailable,
    [SDKName("ACTCTX_RUN_LEVEL_REQUIRE_ADMIN")]
    RequireAdmin,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
