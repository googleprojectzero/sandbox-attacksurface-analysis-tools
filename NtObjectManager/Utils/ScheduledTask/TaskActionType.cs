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

namespace NtObjectManager.Utils.ScheduledTask;

/// <summary>
/// The type of action the task performs when run.
/// </summary>
public enum TaskActionType
{
    /// <summary>
    /// None or unknown.
    /// </summary>
    None,
    /// <summary>
    /// Execute a process.
    /// </summary>
    Execute,
    /// <summary>
    /// Load a COM object.
    /// </summary>
    ComObject,
    /// <summary>
    /// Send an email.
    /// </summary>
    SendEmail,
    /// <summary>
    /// Show a message.
    /// </summary>
    ShowMessage,
}
