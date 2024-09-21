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

namespace NtCoreLib.Win32.Tracing;

/// <summary>
/// Level for trace event.
/// </summary>
public enum EventTraceLevel : byte
{
    /// <summary>
    /// Critical level.
    /// </summary>
    Critical = 1,
    /// <summary>
    /// Error level.
    /// </summary>
    Error = 2,
    /// <summary>
    /// Warning level.
    /// </summary>
    Warning = 3,
    /// <summary>
    /// Information level.
    /// </summary>
    Information = 4,
    /// <summary>
    /// Verbose level.
    /// </summary>
    Verbose = 5,
}
