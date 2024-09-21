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

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// User account control flags.
    /// </summary>
    [Flags]
    public enum UserAccountControlFlags : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("USER_ACCOUNT_DISABLED")]
        AccountDisabled = 0x00000001,
        [SDKName("USER_HOME_DIRECTORY_REQUIRED")]
        HomeDirectoryRequired = 0x00000002,
        [SDKName("USER_PASSWORD_NOT_REQUIRED")]
        PasswordNotRequired = 0x00000004,
        [SDKName("USER_TEMP_DUPLICATE_ACCOUNT")]
        TempDuplicateAccount = 0x00000008,
        [SDKName("USER_NORMAL_ACCOUNT")]
        NormalAccount = 0x00000010,
        [SDKName("USER_MNS_LOGON_ACCOUNT")]
        MNSLogonAccount = 0x00000020,
        [SDKName("USER_INTERDOMAIN_TRUST_ACCOUNT")]
        InterDomainTrustAccount = 0x00000040,
        [SDKName("USER_WORKSTATION_TRUST_ACCOUNT")]
        WorkstationTrustAccount = 0x00000080,
        [SDKName("USER_SERVER_TRUST_ACCOUNT")]
        ServerTrustAccount = 0x00000100,
        [SDKName("USER_DONT_EXPIRE_PASSWORD")]
        DontExpirePassword = 0x00000200,
        [SDKName("USER_ACCOUNT_AUTO_LOCKED")]
        AccountAutoLocked = 0x00000400,
        [SDKName("USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED")]
        EncryptedTextPasswordAllowed = 0x00000800,
        [SDKName("USER_SMARTCARD_REQUIRED")]
        SmartcardRequired = 0x00001000,
        [SDKName("USER_TRUSTED_FOR_DELEGATION")]
        TrustedForDelegation = 0x00002000,
        [SDKName("USER_NOT_DELEGATED")]
        NotDelegated = 0x00004000,
        [SDKName("USER_USE_DES_KEY_ONLY")]
        UseDesKeyOnly = 0x00008000,
        [SDKName("USER_DONT_REQUIRE_PREAUTH")]
        DontRequirePreauth = 0x00010000,
        [SDKName("USER_PASSWORD_EXPIRED")]
        PasswordExpired = 0x00020000,
        [SDKName("USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION")]
        TrustedToAuthenticateForDelegation = 0x00040000,
        [SDKName("USER_NO_AUTH_DATA_REQUIRED")]
        NoAuthDataRequired = 0x00080000,
        [SDKName("USER_PARTIAL_SECRETS_ACCOUNT")]
        PartialSecretsAccount = 0x00100000,
        [SDKName("USER_USE_AES_KEYS")]
        UseAesKeys = 0x00200000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
