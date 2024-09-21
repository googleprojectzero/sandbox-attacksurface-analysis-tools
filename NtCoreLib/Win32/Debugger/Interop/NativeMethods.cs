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

using NtCoreLib.Native.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.Debugger.Interop;

internal static class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    internal static extern void OutputDebugStringA(string lpOutputString);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    internal static extern void OutputDebugStringW(string lpOutputString);

    [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool EnumProcessModulesEx(
          SafeKernelObjectHandle hProcess,
          [Out] IntPtr[] lphModule,
          int cb,
          out int lpcbNeeded,
          EnumProcessModulesFilter dwFilterFlag
        );

    [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int GetModuleFileNameEx(
          SafeKernelObjectHandle hProcess,
          IntPtr hModule,
          StringBuilder lpFilename,
          int nSize
        );

    [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool GetModuleInformation(
      SafeKernelObjectHandle hProcess,
      IntPtr hModule,
      out MODULEINFO lpmodinfo,
      int cb
    );
}
