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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Represents an action that the service control manager can perform.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct ServiceFailureAction
{
    /// <summary>
    /// The action to be performed.
    /// </summary>
    public ServiceControlManagerAction Action;

    /// <summary>
    /// The time to wait before performing the specified action, in milliseconds.
    /// </summary>
    public int Delay;

    /// <param name="action">The action to be performed.</param>
    /// <param name="delay">The time to wait before performing the specified action, in milliseconds.</param>
    public ServiceFailureAction(ServiceControlManagerAction action, int delay)
    {
        Action = action;
        Delay = delay;
    }
}
