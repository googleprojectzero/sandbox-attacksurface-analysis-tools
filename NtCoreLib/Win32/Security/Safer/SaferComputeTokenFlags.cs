//  Copyright 2018 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Security.Safer;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
/// <summary>
/// Flags for computing a token.
/// </summary>
[Flags]
public enum SaferComputeTokenFlags
{
    None = 0,
    [SDKName("SAFER_TOKEN_NULL_IF_EQUAL")]
    NullIfEqual = 1,
    [SDKName("SAFER_TOKEN_COMPARE_ONLY")]
    CompareOnly = 2,
    [SDKName("SAFER_TOKEN_MAKE_INERT")]
    MakeInert = 4,
    [SDKName("SAFER_TOKEN_NULL_IF_EQUAL")]
    WantFlags = 8,
}
#pragma warning restore 1591
