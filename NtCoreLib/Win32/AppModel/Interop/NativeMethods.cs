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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.AppModel.Interop;

internal static class NativeMethods
{
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus CreateAppContainerProfile(
        string pszAppContainerName,
        string pszDisplayName,
        string pszDescription,
        SidAndAttributes[]? pCapabilities,
        int dwCapabilityCount,
        out SafeSidBufferHandle ppSidAppContainerSid
    );

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus GetAppContainerRegistryLocation(
      KeyAccessRights desiredAccess,
      out SafeKernelObjectHandle phAppContainerKey
    );

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus DeleteAppContainerProfile(
        string pszAppContainerName
    );

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus GetAppContainerFolderPath(
      string pszAppContainerSid,
      out SafeCoTaskMemBuffer ppszPath
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error PackageIdFromFullName(
      string packageFullName,
      PackageFlags flags,
      ref int bufferLength,
      SafeBuffer buffer
    );

    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetStagedPackageOrigin(
      string packageFullName,
      out PackageOrigin origin
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetStagedPackagePathByFullName(
        string packageFullName,
        ref int pathLength,
        StringBuilder? path
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetPackagePathByFullName(
        string packageFullName,
        ref int pathLength,
        StringBuilder? path
    );

    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetPackageFullNameFromToken(
      SafeKernelObjectHandle token,
      ref int packageFullNameLength,
      StringBuilder? packageFullName
    );

    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error OpenPackageInfoByFullName(
        string packageFullName,
        int reserved,
        out IntPtr packageInfoReference
    );

    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error ClosePackageInfo(
      IntPtr packageInfoReference
    );

    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetPackageApplicationIds(
      IntPtr packageInfoReference,
      ref int bufferLength,
      [Out] SafeBuffer buffer,
      out int count
    );

    [DllImport("Firewallapi.dll", CharSet = CharSet.Unicode)]
    public static extern Win32Error NetworkIsolationEnumAppContainers(
        NETISO_FLAG Flags,
        out int pdwNumPublicAppCs,
        out IntPtr ppPublicAppCs
    );

    [DllImport("Firewallapi.dll", CharSet = CharSet.Unicode)]
    public static extern Win32Error NetworkIsolationFreeAppContainers(
        IntPtr pPublicAppCs
    );

    [DllImport("Firewallapi.dll", CharSet = CharSet.Unicode)]
    public static extern Win32Error NetworkIsolationGetAppContainerConfig(
        out int pdwNumPublicAppCs,
        out SafeProcessHeapBuffer appContainerSids  // PSID_AND_ATTRIBUTES
    );

    [DllImport("Firewallapi.dll", CharSet = CharSet.Unicode)]
    public static extern Win32Error NetworkIsolationSetAppContainerConfig(
        int dwNumPublicAppCs,
        [MarshalAs(UnmanagedType.LPArray)] SidAndAttributes[] appContainerSids
    );
}
