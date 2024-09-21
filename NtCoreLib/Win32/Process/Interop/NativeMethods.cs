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

#nullable enable

using NtCoreLib.Kernel.Interop;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Win32.SafeHandles;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Process.Interop;

internal static class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        int dwAttributeCount,
        int dwFlags,
        ref IntPtr lpSize
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        int dwFlags,
        IntPtr Attribute,
        IntPtr lpValue,
        IntPtr cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool DeleteProcThreadAttributeList(
        IntPtr lpAttributeList
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessAsUser(
      SafeKernelObjectHandle hToken,
      string lpApplicationName,
      string lpCommandLine,
      SECURITY_ATTRIBUTES lpProcessAttributes,
      SECURITY_ATTRIBUTES lpThreadAttributes,
      bool bInheritHandles,
      CreateProcessFlags dwCreationFlags,
      byte[] lpEnvironment,
      string lpCurrentDirectory,
      [In] STARTUPINFOEX lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessWithTokenW(
      SafeKernelObjectHandle hToken,
      CreateProcessLogonFlags dwLogonFlags,
      string lpApplicationName,
      string lpCommandLine,
      CreateProcessFlags dwCreationFlags,
      [In] byte[] lpEnvironment,
      string lpCurrentDirectory,
      in STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcess(
      string lpApplicationName,
      string lpCommandLine,
      [In] SECURITY_ATTRIBUTES lpProcessAttributes,
      [In] SECURITY_ATTRIBUTES lpThreadAttributes,
      bool bInheritHandles,
      CreateProcessFlags dwCreationFlags,
      [In] byte[] lpEnvironment,
      string lpCurrentDirectory,
      [In] STARTUPINFOEX lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessWithLogonW(
      string lpUsername,
      string lpDomain,
      string lpPassword,
      CreateProcessLogonFlags dwLogonFlags,
      string lpApplicationName,
      string lpCommandLine,
      CreateProcessFlags dwCreationFlags,
      [In] byte[] lpEnvironment,
      string lpCurrentDirectory,
      in STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool CreateProcessWithLogonW(
      string lpUsername,
      string lpDomain,
      SecureStringMarshalBuffer lpPassword,
      CreateProcessLogonFlags dwLogonFlags,
      string lpApplicationName,
      string lpCommandLine,
      CreateProcessFlags dwCreationFlags,
      [In] byte[] lpEnvironment,
      string lpCurrentDirectory,
      in STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeLocalAllocBuffer CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeKernelObjectHandle CreateRemoteThreadEx(
        SafeKernelObjectHandle hProcess,
        [In] SECURITY_ATTRIBUTES? lpThreadAttributes,
        IntPtr dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        CreateThreadFlags dwCreationFlags,
        SafeBuffer lpAttributeList,
        OptionalInt32? lpThreadId
    );
}