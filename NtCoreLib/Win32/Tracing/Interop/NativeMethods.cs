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
using NtCoreLib.Security.Authorization;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Tracing.Interop;

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate void EventEnableCallback(
      ref Guid SourceId,
      int IsEnabled,
      byte Level,
      ulong MatchAnyKeyword,
      ulong MatchAllKeyword,
      ref EVENT_FILTER_DESCRIPTOR FilterData,
      IntPtr CallbackContext
    );

internal static class NativeMethods
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EventAccessQuery(
      ref Guid Guid,
      SafeBuffer Buffer,
      ref int BufferSize
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EventAccessControl(
      ref Guid Guid,
      EventSecurityOperation Operation,
      SafeSidBufferHandle Sid,
      AccessMask Rights,
      [MarshalAs(UnmanagedType.U1)] bool AllowOrDeny
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EventAccessRemove(
      ref Guid Guid
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EventRegister(
      ref Guid ProviderId,
      EventEnableCallback EnableCallback,
      IntPtr CallbackContext,
      out long RegHandle
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EventUnregister(
        long RegHandle
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EventWrite(
      long RegHandle,
      ref EVENT_DESCRIPTOR EventDescriptor,
      int UserDataCount,
      EVENT_DATA_DESCRIPTOR[] UserData
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EnumerateTraceGuidsEx(
        TRACE_QUERY_INFO_CLASS TraceQueryInfoClass,
        SafeBuffer InBuffer,
        int InBufferSize,
        SafeBuffer OutBuffer,
        int OutBufferSize,
        out int ReturnLength
    );

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error TdhEnumerateProviders(
            SafeBuffer pBuffer,
            ref int pBufferSize
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error StartTrace(
        out long SessionHandle,
        string SessionName,
        SafeBuffer Properties // EVENT_TRACE_PROPERTIES
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error ControlTrace(
      long TraceHandle,
      string InstanceName,
      SafeBuffer Properties, // EVENT_TRACE_PROPERTIES
      EventTraceControl ControlCode
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error EnableTraceEx2(
      long TraceHandle,
      ref Guid ProviderId,
      EventControlCode ControlCode,
      EventTraceLevel Level,
      ulong MatchAnyKeyword,
      ulong MatchAllKeyword,
      int Timeout,
      ENABLE_TRACE_PARAMETERS EnableParameters
    );
}
