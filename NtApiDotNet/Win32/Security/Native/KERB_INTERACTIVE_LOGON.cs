﻿//  Copyright 2021 Google Inc. All Rights Reserved.
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
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct KERB_INTERACTIVE_LOGON
    {
        public KERB_LOGON_SUBMIT_TYPE MessageType;
        public UnicodeString LogonDomainName;
        public UnicodeString UserName;
        public UnicodeStringSecure Password;

        public KERB_INTERACTIVE_LOGON(string username, string domain, SecureString password, DisposableList list)
        {
            MessageType = KERB_LOGON_SUBMIT_TYPE.KerbInteractiveLogon;
            LogonDomainName = new UnicodeString(domain);
            UserName = new UnicodeString(username);
            var buf = list.AddResource(new SecureStringMarshalBuffer(password));
            Password = new UnicodeStringSecure(buf, password.Length);
        }
    }
}
