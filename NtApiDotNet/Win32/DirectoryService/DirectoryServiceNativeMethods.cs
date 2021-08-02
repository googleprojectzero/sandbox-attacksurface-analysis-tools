//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.DirectoryService
{
    [StructLayout(LayoutKind.Sequential)]
    struct DS_NAME_RESULT_ITEMW
    {
        public DirectoryServiceNameError status;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pDomain;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DS_NAME_RESULTW
    {
        public int cItems;
        public IntPtr rItems; // PDS_NAME_RESULT_ITEMW 
    }

    /// <summary>
    /// Native methods for directory services.
    /// </summary>
    internal static class DirectoryServiceNativeMethods
    {
        [DllImport("Ntdsapi.dll", CharSet = CharSet.Unicode)]
        public static extern Win32Error DsBind(
            string DomainControllerName,
            string DnsDomainName,
            out SafeDirectoryServiceHandle phDS
        );

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Unicode)]
        public static extern Win32Error DsUnBind(
            ref IntPtr phDS
        );

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Unicode)]
        public static extern Win32Error DsCrackNames(
            SafeDirectoryServiceHandle hDS,
            DirectoryServiceNameFlags flags,
            DirectoryServiceNameFormat formatOffered,
            DirectoryServiceNameFormat formatDesired,
            int cNames,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)]
            string[] rpNames,
            out IntPtr ppResult // PDS_NAME_RESULTW *
        );

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Unicode)]
        public static extern void DsFreeNameResult(
            IntPtr pResult
        );
    }
}
