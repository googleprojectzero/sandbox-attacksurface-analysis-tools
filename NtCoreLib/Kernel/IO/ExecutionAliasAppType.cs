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

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Application type for execution alias.
/// </summary>
public enum ExecutionAliasAppType
{
    /// <summary>
    /// Desktop bridge application.
    /// </summary>
    Desktop = 0,
    /// <summary>
    /// UWP type 1
    /// </summary>
    UWP1 = 1,
    /// <summary>
    /// UWP type 2
    /// </summary>
    UWP2 = 2,
    /// <summary>
    /// UWP type 3
    /// </summary>
    UWP3 = 3
}
