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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.AppModel
{
    internal enum NETISO_FLAG
    {
        NONE = 0,
        NETISO_FLAG_FORCE_COMPUTE_BINARIES,
    };

    [StructLayout(LayoutKind.Sequential)]
    internal struct INET_FIREWALL_AC_CAPABILITIES
    {
        public int count;
        public IntPtr capabilities; // SID_AND_ATTRIBUTES
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct INET_FIREWALL_AC_BINARIES
    {
        public int count;
        public IntPtr binaries; // LPWSTR*
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct INET_FIREWALL_APP_CONTAINER
    {
        public IntPtr appContainerSid;
        public IntPtr userSid;
        public string appContainerName;
        public string displayName;
        public string description;
        public INET_FIREWALL_AC_CAPABILITIES capabilities;
        public INET_FIREWALL_AC_BINARIES binaries;
        public string workingDirectory;
        public string packageFullName;
    }

    internal static class AppModelNativeMethods
    {
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
}
