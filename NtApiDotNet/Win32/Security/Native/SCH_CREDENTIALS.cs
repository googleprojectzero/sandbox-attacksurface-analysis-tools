//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Authentication.Schannel;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SCH_CREDENTIALS
    {
        public const int SCH_CREDENTIALS_VERSION = 0x00000005;

        public int dwVersion;
        public int dwCredFormat;
        public int cCreds;
        public IntPtr paCred; // PCCERT_CONTEXT* 
        public IntPtr hRootStore; // HCERTSTORE
        public int cMappers;
        public IntPtr aphMappers; //  _HMAPPER

        public int dwSessionLifespan;
        public SchannelCredentialsFlags dwFlags;
        public int cTlsParameters;
        public IntPtr pTlsParameters; // PTLS_PARAMETERS 
    }
}
