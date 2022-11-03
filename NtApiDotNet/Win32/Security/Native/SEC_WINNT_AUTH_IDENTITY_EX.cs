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
using System.Security;

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class SEC_WINNT_AUTH_IDENTITY_EX
    {
        public const int SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200;

        public int Version;
        public int Length;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        public SecureStringMarshalBuffer Password;
        public int PasswordLength;
        public SecWinNtAuthIdentityFlags Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string PackageList;
        public int PackageListLength;

        public SEC_WINNT_AUTH_IDENTITY_EX()
        {
        }

        public SEC_WINNT_AUTH_IDENTITY_EX(string user, string domain, SecureString password, string package_list, DisposableList list)
        {
            Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
            Length = Marshal.SizeOf(this);
            User = user;
            UserLength = user?.Length ?? 0;
            Domain = domain;
            DomainLength = domain?.Length ?? 0;
            if (password != null)
            {
                Password = list.AddResource(new SecureStringMarshalBuffer(password));
                PasswordLength = password.Length;
            }
            PackageList = package_list;
            PackageListLength = PackageList?.Length ?? 0;
            Flags = SecWinNtAuthIdentityFlags.Unicode;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SEC_WINNT_AUTH_IDENTITY_EX_OUT
    {
        public int Version;
        public int Length;
        public IntPtr User;
        public int UserLength;
        public IntPtr Domain;
        public int DomainLength;
        public IntPtr Password;
        public int PasswordLength;
        public SecWinNtAuthIdentityFlags Flags;
        public IntPtr PackageList;
        public int PackageListLength;
    }
}
