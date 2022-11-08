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

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Flags for packing and unpacking an authentication buffer.
    /// </summary>
    [Flags]
    public enum CredentialAuthenticationBufferFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Encrypts the credential so that it can only be decrypted by processes in the caller's logon session.
        /// </summary>
        [SDKName("CRED_PACK_PROTECTED_CREDENTIALS")]
        ProtectedCredentials = 0x1,
        /// <summary>
        /// Encrypts the credential in a WOW buffer.
        /// </summary>
        [SDKName("CRED_PACK_WOW_BUFFER")]
        WowBuffer = 0x2,
        /// <summary>
        /// Encrypts the credential in a CRED_GENERIC buffer.
        /// </summary>
        [SDKName("CRED_PACK_GENERIC_CREDENTIALS")]
        GenericCredentials = 0x4,
        /// <summary>
        /// Encrypts the credential of an online identity into a SEC_WINNT_AUTH_IDENTITY_EX2 structure.
        /// </summary>
        [SDKName("CRED_PACK_ID_PROVIDER_CREDENTIALS")]
        IdProviderCredentials = 0x8
    }
}
