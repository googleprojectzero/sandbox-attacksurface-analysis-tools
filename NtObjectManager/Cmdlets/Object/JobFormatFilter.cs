//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using System;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="description">Flags for formatting a job.</para>
/// </summary>
[Flags]
public enum JobFormatFilter
{
    /// <summary>
    /// Basic information.
    /// </summary>
    BasicInfo = 1,
    /// <summary>
    /// Basic limits.
    /// </summary>
    BasicLimits = 2,
    /// <summary>
    /// List of processes.
    /// </summary>
    ProcessList = 4,
    /// <summary>
    /// UI Limits.
    /// </summary>
    UILimits = 8,
    /// <summary>
    /// Silo information.
    /// </summary>
    Silo = 0x10,
    /// <summary>
    /// Display all formats.
    /// </summary>
    All = BasicLimits | ProcessList | BasicInfo | UILimits | Silo
}