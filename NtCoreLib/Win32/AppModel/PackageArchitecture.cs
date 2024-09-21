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

namespace NtCoreLib.Win32.AppModel;

/// <summary>
/// APPX Package Architecture.
/// </summary>
public enum PackageArchitecture
{
    /// <summary>
    /// X86
    /// </summary>
    X86 = 0,
    /// <summary>
    /// ARM
    /// </summary>
    ARM = 5,
    /// <summary>
    /// X64
    /// </summary>
    X64 = 9,
    /// <summary>
    /// Neutral
    /// </summary>
    Neutral = 11,
    /// <summary>
    /// ARM64
    /// </summary>
    ARM64 = 12,
}
