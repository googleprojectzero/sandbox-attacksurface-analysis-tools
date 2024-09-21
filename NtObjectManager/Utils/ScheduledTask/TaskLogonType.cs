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
/// The type of logon used for the task.
/// </summary>
public enum TaskLogonType
{
    /// <summary>
    /// No logon type.
    /// </summary>
    None,
    /// <summary>
    /// Group activation.
    /// </summary>
    Group,
    /// <summary>
    /// User activation.
    /// </summary>
    User,
    /// <summary>
    /// Uses Services for User.
    /// </summary>
    S4U,
    /// <summary>
    /// Service account.
    /// </summary>
    ServiceAccount,
}
