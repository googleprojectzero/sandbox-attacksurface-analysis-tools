//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Win32.Debugger.Interop;

namespace NtCoreLib.Win32.Debugger;

/// <summary>
/// Static methods for Win32 debug APIs.
/// </summary>
public static class Win32Debug
{
    /// <summary>
    /// Write debug string to output in ANSI mode.
    /// </summary>
    /// <param name="debug_str">The debug string to write.</param>
    public static void WriteDebugString(string debug_str) => NativeMethods.OutputDebugStringA(debug_str);

    /// <summary>
    /// Write debug string to output in unicode mode.
    /// </summary>
    /// <param name="debug_str">The debug string to write.</param>
    public static void WriteDebugStringUnicode(string debug_str) => NativeMethods.OutputDebugStringW(debug_str);

    /// <summary>
    /// Check if a debugger is present.
    /// </summary>
    /// <returns>True if a debugger is present.</returns>
    public static bool IsDebuggerPresent() => NativeMethods.IsDebuggerPresent();
}
