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
    internal enum SCH_CRED_FORMAT
    {
        CERT = 0,
        CERT_HASH = 1,
        CERT_HASH_STORE = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SCHANNEL_CRED
    {
        public const int SCHANNEL_CRED_VERSION = 0x00000004;

        public int dwVersion;      // always SCHANNEL_CRED_VERSION
        public int cCreds;
        public IntPtr paCred; // PCCERT_CONTEXT* 
        public IntPtr hRootStore; // HCERTSTORE
        public int cMappers;
        public IntPtr aphMappers; //  _HMAPPER

        public int cSupportedAlgs;
        public IntPtr palgSupportedAlgs; // ALG_ID*

        public SchannelProtocolType grbitEnabledProtocols;
        public int dwMinimumCipherStrength;
        public int dwMaximumCipherStrength;
        public int dwSessionLifespan;
        public SchannelCredentialsFlags dwFlags;
        public SCH_CRED_FORMAT dwCredFormat;
    }
}
