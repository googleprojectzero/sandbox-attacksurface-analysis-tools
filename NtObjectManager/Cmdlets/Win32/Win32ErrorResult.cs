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

using NtCoreLib;
using NtCoreLib.Win32;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// The result of an WIN32 error code lookup.
/// </summary>
public sealed class Win32ErrorResult
{
    /// <summary>
    /// The numeric value of the error code.
    /// </summary>
    public int ErrorCode { get; }
    /// <summary>
    /// The name of the error code if known.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// Corresponding message text.
    /// </summary>
    public string Message { get; }

    internal Win32ErrorResult(Win32Error win32_error)
    {
        ErrorCode = (int)win32_error;
        Message = NtObjectUtils.GetNtStatusMessage(win32_error.MapDosErrorToStatus());
        Name = win32_error.ToString();
    }
}
