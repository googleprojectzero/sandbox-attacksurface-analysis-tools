//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// Guids for credential types.
    /// </summary>
    public static class SecWinNtPackedCredentialTypes
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_PASSWORD")]
        public static readonly Guid Password =
            new Guid(0x28bfc32f, 0x10f6, 0x4738, 0x98, 0xd1, 0x1a, 0xc0, 0x61, 0xdf, 0x71, 0x6a);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_CERT")]
        public static readonly Guid Certificate =
           new Guid(0x235f69ad, 0x73fb, 0x4dbc, 0x82, 0x3, 0x6, 0x29, 0xe7, 0x39, 0x33, 0x9b);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_CREDMAN_CERT")]
        public static readonly Guid CredManagerCertificate =
           new Guid(0x7cb72412, 0x1016, 0x491a, 0x8c, 0x87, 0x4d, 0x2a, 0xa1, 0xb7, 0xdd, 0x3a);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_NGC")]
        public static readonly Guid NextGenerationCredential =
           new Guid(0x10a47879, 0x5ebf, 0x4b85, 0xbd, 0x8d, 0xc2, 0x1b, 0xb4, 0xf4, 0x9c, 0x8a);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_FIDO")]
        public static readonly Guid FastIdentityOnline =
            new Guid(0x32e8f8d7, 0x7871, 0x4bcc, 0x83, 0xc5, 0x46, 0xf, 0x66, 0xc6, 0x13, 0x5c);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_KEYTAB")]
        public static readonly Guid KeyTab =
        new Guid(0xd587aae8, 0xf78f, 0x4455, 0xa1, 0x12, 0xc9, 0x34, 0xbe, 0xee, 0x7c, 0xe1);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA")]
        public static readonly Guid CspData =
           new Guid(0x68fd9879, 0x79c, 0x4dfe, 0x82, 0x81, 0x57, 0x8a, 0xad, 0xc1, 0xc1, 0x0);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS")]
        public static readonly Guid SmartcardContexts =
           new Guid(0xb86c4ff3, 0x49d7, 0x4dc4, 0xb5, 0x60, 0xb1, 0x16, 0x36, 0x85, 0xb2, 0x36);

        [SDKName("SEC_WINNT_AUTH_DATA_TYPE_DELEGATION_TOKEN")]
        public static readonly Guid DelegationToken =
            new Guid(0x12E52E0F, 0x6F9B, 0x4F83, 0x90, 0x20, 0x9D, 0xE4, 0x2B, 0x22, 0x62, 0x67);
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
