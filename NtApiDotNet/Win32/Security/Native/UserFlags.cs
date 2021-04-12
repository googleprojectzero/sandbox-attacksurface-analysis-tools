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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Security.Native
{
    /// <summary>
    /// User flags.
    /// </summary>
    [Flags]
    internal enum UserFlags : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("UF_SCRIPT")]
        Script = 0x00000001,
        [SDKName("UF_ACCOUNTDISABLE")]
        AccountDisable = 0x00000002,
        [SDKName("UF_HOMEDIR_REQUIRED")]
        HomedirRequired = 0x00000008,
        [SDKName("UF_LOCKOUT")]
        Lockout = 0x00000010,
        [SDKName("UF_PASSWD_NOTREQD")]
        PasswordNotRequired = 0x00000020,
        [SDKName("UF_PASSWD_CANT_CHANGE")]
        PasswordCantChange = 0x00000040,
        [SDKName("UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED")]
        EncryptedTextPasswordAllowed = 0x00000080,
        [SDKName("UF_TEMP_DUPLICATE_ACCOUNT")]
        TempDuplicateAccount = 0x00000100,
        [SDKName("UF_NORMAL_ACCOUNT")]
        NormalAccount = 0x00000200,
        [SDKName("UF_INTERDOMAIN_TRUST_ACCOUNT")]
        InterDomainTrustAccount = 0x00000800,
        [SDKName("UF_WORKSTATION_TRUST_ACCOUNT")]
        WorkstationTrustAccount = 0x00001000,
        [SDKName("UF_SERVER_TRUST_ACCOUNT")]
        ServerTrustAccount = 0x00002000,
        [SDKName("UF_DONT_EXPIRE_PASSWD")]
        DontExpirePassword = 0x00010000,
        [SDKName("UF_MNS_LOGON_ACCOUNT")]
        MNSLogonAccount = 0x00020000,
        [SDKName("UF_SMARTCARD_REQUIRED")]
        SmartcardRequired = 0x00040000,
        [SDKName("UF_TRUSTED_FOR_DELEGATION")]
        TrustedForDelegation = 0x00080000,
        [SDKName("UF_NOT_DELEGATED")]
        NotDelegated = 0x00100000,
        [SDKName("UF_USE_DES_KEY_ONLY")]
        UseDesKeyOnly = 0x00200000,
        [SDKName("UF_DONT_REQUIRE_PREAUTH")]
        DontRequirePreAuth = 0x00400000,
        [SDKName("UF_PASSWORD_EXPIRED")]
        PasswordExpired = 0x00800000,
        [SDKName("UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION")]
        TrustedToAuthenticateForDelegation = 0x01000000,
        [SDKName("UF_NO_AUTH_DATA_REQUIRED")]
        NoAuthDataRequired = 0x02000000,
        [SDKName("UF_PARTIAL_SECRETS_ACCOUNT")]
        PartialSecretsAccount = 0x04000000,
        [SDKName("UF_USE_AES_KEYS")]
        UseAesKeys = 0x08000000
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
