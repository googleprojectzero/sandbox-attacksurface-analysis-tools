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

#nullable enable

using NtCoreLib.Kernel.Interop;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Service.Interop;

internal static class NativeMethods
{
    [DllImport("Advapi32.dll", SetLastError = true)]
    internal static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle OpenSCManager(string? lpMachineName, string? lpDatabaseName, ServiceControlManagerAccessRights dwDesiredAccess);

    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle OpenService(
          SafeServiceHandle hSCManager,
          string lpServiceName,
          ServiceAccessRights dwDesiredAccess
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    internal static extern bool DeleteService(
      SafeServiceHandle hService
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeServiceHandle CreateService(
      SafeServiceHandle hSCManager,
      string lpServiceName,
      string? lpDisplayName,
      ServiceAccessRights dwDesiredAccess,
      ServiceType dwServiceType,
      ServiceStartType dwStartType,
      ServiceErrorControl dwErrorControl,
      string? lpBinaryPathName,
      string? lpLoadOrderGroup,
      [Out] OptionalInt32? lpdwTagId,
      string? lpDependencies,
      string? lpServiceStartName,
      SecureStringMarshalBuffer? lpPassword
    );

    [DllImport("Advapi32.dll", SetLastError = true)]
    internal static extern bool QueryServiceObjectSecurity(
        SafeServiceHandle hService,
        SecurityInformation dwSecurityInformation,
        [Out] byte[] lpSecurityDescriptor,
        int cbBufSize,
        out int pcbBytesNeeded);

    [DllImport("Advapi32.dll", SetLastError = true)]
    internal static extern bool SetServiceObjectSecurity(
        SafeServiceHandle hService,
        SecurityInformation dwSecurityInformation,
        [In] byte[] lpSecurityDescriptor
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool QueryServiceConfig(
      SafeServiceHandle hService,
      SafeBuffer lpServiceConfig,
      int cbBufSize,
      out int pcbBytesNeeded
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool QueryServiceConfig2(
      SafeServiceHandle hService,
      ServiceConfigInfoLevel dwInfoLevel,
      SafeBuffer lpBuffer,
      int cbBufSize,
      out int pcbBytesNeeded
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool ChangeServiceConfig(
        SafeServiceHandle hService,
        ServiceType dwServiceType,
        ServiceStartType dwStartType,
        ServiceErrorControl dwErrorControl,
        string? lpBinaryPathName,
        string? lpLoadOrderGroup,
        [Out] OptionalInt32? lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        SecureStringMarshalBuffer? lpPassword,
        string? lpDisplayName
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool ChangeServiceConfig2(
        SafeServiceHandle hService,
        ServiceConfigInfoLevel dwInfoLevel,
        SafeBuffer lpInfo
    );

    [DllImport("Advapi32.dll", SetLastError = true)]
    internal static extern bool QueryServiceStatusEx(
      SafeServiceHandle hService,
      SC_STATUS_TYPE InfoLevel,
      SafeBuffer lpBuffer,
      int cbBufSize,
      out int pcbBytesNeeded
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool EnumServicesStatusEx(
          SafeServiceHandle hSCManager,
          SC_ENUM_TYPE InfoLevel,
          ServiceType dwServiceType,
          SERVICE_STATE dwServiceState,
          SafeHGlobalBuffer lpServices,
          int cbBufSize,
          out int pcbBytesNeeded,
          out int lpServicesReturned,
          ref int lpResumeHandle,
          string? pszGroupName
        );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool StartService(
      SafeServiceHandle hService,
      int dwNumServiceArgs,
      [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[]? lpServiceArgVectors
    );

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool ControlService(
      SafeServiceHandle hService,
      ServiceControlCode dwControl,
      out SERVICE_STATUS lpServiceStatus
    );
}