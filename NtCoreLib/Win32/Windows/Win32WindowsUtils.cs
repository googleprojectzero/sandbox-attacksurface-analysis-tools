//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Win32.Windows.Interop;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Windows;

/// <summary>
/// Utilities for the windowing system.
/// </summary>
public static class Win32WindowsUtils
{
    /// <summary>
    /// Send key down events.
    /// </summary>
    /// <param name="key_codes">The key codes to send.</param>
    public static void SendKeyDown(params VirtualKey[] key_codes)
    {
        INPUT[] inputs = key_codes.Select(k => new INPUT(k, false)).ToArray();
        Win32NativeMethods.SendInput(inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
    }

    /// <summary>
    /// Send key down events.
    /// </summary>
    /// <param name="key_codes">The key codes to send.</param>
    public static void SendKeyUp(params VirtualKey[] key_codes)
    {
        INPUT[] inputs = key_codes.Select(k => new INPUT(k, true)).ToArray();
        Win32NativeMethods.SendInput(inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
    }

    /// <summary>
    /// Send key down then up events.
    /// </summary>
    /// <param name="key_codes">The key codes to send.</param>
    /// <remarks>This will send all keys down first, then all up.</remarks>
    public static void SendKeys(params VirtualKey[] key_codes)
    {
        SendKeyDown(key_codes);
        SendKeyUp(key_codes);
    }

    /// <summary>
    /// This creates a Window Station using the User32 API.
    /// </summary>
    /// <param name="name">The name of the Window Station.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The Window Station.</returns>
    public static NtResult<NtWindowStation> CreateWindowStation(string name, bool throw_on_error)
    {
        return Win32NativeMethods.CreateWindowStation(name, 0,
            WindowStationAccessRights.MaximumAllowed, null).CreateWin32Result(throw_on_error, h => new NtWindowStation(h));
    }

    /// <summary>
    /// This creates a Window Station using the User32 API.
    /// </summary>
    /// <param name="name">The name of the Window Station.</param>
    /// <returns>The Window Station.</returns>
    public static NtWindowStation CreateWindowStation(string name)
    {
        return CreateWindowStation(name, true).Result;
    }
}
