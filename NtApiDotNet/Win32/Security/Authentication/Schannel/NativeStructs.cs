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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
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

        public int grbitEnabledProtocols;
        public int dwMinimumCipherStrength;
        public int dwMaximumCipherStrength;
        public int dwSessionLifespan;
        public SchannelCredentialsFlags dwFlags;
        public int dwCredFormat;
    }

    internal enum CREDSSP_SUBMIT_TYPE
    {
        CredsspPasswordCreds = 2,
        CredsspSchannelCreds = 4,
        CredsspCertificateCreds = 13,
        CredsspSubmitBufferBoth = 50,
        CredsspSubmitBufferBothOld = 51,
        CredsspCredEx = 100,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CREDSSP_CRED
    {
        public CREDSSP_SUBMIT_TYPE Type;
        public IntPtr pSchannelCred;
        public IntPtr pSpnegoCred;
    }

    internal enum CredSspExFlags
    {
        None = 0,
        Redirect = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CREDSSP_CRED_EX
    {
        public CREDSSP_SUBMIT_TYPE Type; // must be CredsspCredEx
        public int Version; // must be CREDSSP_CRED_EX_VERSION
        public CredSspExFlags Flags;
        public int Reserved;
        public CREDSSP_CRED Cred;
    }
}
