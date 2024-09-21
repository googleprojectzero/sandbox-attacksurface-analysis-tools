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

using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security.Authorization;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.TerminalServices.Interop;

internal static class NativeMethods
{
    [DllImport("wtsapi32.dll", SetLastError = true)]
    internal static extern bool WTSQueryUserToken(int SessionId, out SafeKernelObjectHandle phToken);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    internal static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool WTSFreeMemoryEx(
      WTS_TYPE_CLASS WTSTypeClass,
      IntPtr pMemory,
      int NumberOfEntries
    );

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool WTSEnumerateSessionsEx(
      SafeTerminalServerHandle hServer,
      ref int pLevel,
      int Filter,
      out IntPtr ppSessionInfo,
      out int pCount
    );

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool WTSQuerySessionInformation(
      SafeTerminalServerHandle hServer,
      int SessionId,
      WTS_INFO_CLASS WTSInfoClass,
      out IntPtr ppBuffer,
      out int pBytesReturned
    );

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool WTSEnumerateListeners(
          SafeTerminalServerHandle hServer,
          IntPtr pReserved,
          int Reserved,
          [Out] WTSLISTENERNAME[]? pListeners,
          ref int pCount
    );

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool WTSGetListenerSecurity(
        SafeTerminalServerHandle hServer,
        IntPtr pReserved,
        int Reserved,
        string pListenerName,
        SecurityInformation SecurityInformation,
        [Out] byte[]? pSecurityDescriptor, // PSECURITY_DESCRIPTOR 
        int nLength,
        out int lpnLengthNeeded
    );

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeTerminalServerHandle WTSOpenServerExW(string? pServerName);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern void WTSCloseServer(IntPtr hServer);
}
