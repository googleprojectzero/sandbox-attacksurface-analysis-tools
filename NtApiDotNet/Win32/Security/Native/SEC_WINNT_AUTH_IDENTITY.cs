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

using System.Runtime.InteropServices;
using System.Security;

namespace NtApiDotNet.Win32.Security.Native
{
#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class SEC_WINNT_AUTH_IDENTITY
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        public SecureStringMarshalBuffer Password;
        public int PasswordLength;
        public SecWinNtAuthIdentityFlags Flags;

        public SEC_WINNT_AUTH_IDENTITY()
        {
        }

        public SEC_WINNT_AUTH_IDENTITY(string user, string domain, SecureString password, DisposableList list)
        {
            User = user;
            UserLength = user?.Length ?? 0;
            Domain = domain;
            DomainLength = domain?.Length ?? 0;
            if (password != null)
            {
                Password = list.AddResource(new SecureStringMarshalBuffer(password));
                PasswordLength = password.Length;
            }
            Flags = SecWinNtAuthIdentityFlags.Unicode;
        }
    }
}
