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

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_LOGON_SESSION_DATA
    {
        public int Size;
        public Luid LogonId;
        public UnicodeStringOut UserName;
        public UnicodeStringOut LogonDomain;
        public UnicodeStringOut AuthenticationPackage;
        public SecurityLogonType LogonType;
        public int Session;
        public IntPtr Sid;
        public LargeIntegerStruct LogonTime;
        public UnicodeStringOut LogonServer;
        public UnicodeStringOut DnsDomainName;
        public UnicodeStringOut Upn;
        public LsaLogonUserFlags UserFlags;
        public LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
        public UnicodeStringOut LogonScript;
        public UnicodeStringOut ProfilePath;
        public UnicodeStringOut HomeDirectory;
        public UnicodeStringOut HomeDirectoryDrive;
        public LargeIntegerStruct LogoffTime;
        public LargeIntegerStruct KickOffTime;
        public LargeIntegerStruct PasswordLastSet;
        public LargeIntegerStruct PasswordCanChange;
        public LargeIntegerStruct PasswordMustChange;
    }
}
