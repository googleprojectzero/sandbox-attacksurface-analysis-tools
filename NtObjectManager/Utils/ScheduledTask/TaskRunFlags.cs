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

using System;

namespace NtObjectManager.Utils.ScheduledTask;

/// <summary>
/// Flags for running a task.
/// </summary>
[Flags]
public enum TaskRunFlags
{
    /// <summary>
    /// None
    /// </summary>
    None = 0,
    /// <summary>
    /// Run as user calling Run.
    /// </summary>
    AsSelf = 1,
    /// <summary>
    /// Ignore task constraints.
    /// </summary>
    IgnoreConstrains = 2,
    /// <summary>
    /// Use the session ID for the terminal session.
    /// </summary>
    UseSessionId = 4,
    /// <summary>
    /// Run using a SID.
    /// </summary>
    UserSid = 8,
}
