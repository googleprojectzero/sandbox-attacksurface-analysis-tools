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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Security.Authentication.Logon;

/// <summary>
/// Flags for network logon.
/// </summary>
[Flags]
public enum NtlmNetworkLogonParameterControlFlags
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_CLEARTEXT_PASSWORD_ALLOWED    = 0x02,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_UPDATE_LOGON_STATISTICS       = 0x04,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_RETURN_USER_PARAMETERS        = 0x08,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_DONT_TRY_GUEST_ACCOUNT        = 0x10,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT    = 0x20,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_RETURN_PASSWORD_EXPIRY        = 0x40,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_USE_CLIENT_CHALLENGE          = 0x80,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_TRY_GUEST_ACCOUNT_ONLY        = 0x100,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_RETURN_PROFILE_PATH           = 0x200,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_TRY_SPECIFIED_DOMAIN_ONLY     = 0x400,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT = 0x800,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_DISABLE_PERSONAL_FALLBACK     = 0x00001000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_ALLOW_FORCE_GUEST             = 0x00002000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_CLEARTEXT_PASSWORD_SUPPLIED   = 0x00004000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_USE_DOMAIN_FOR_ROUTING_ONLY   = 0x00008000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_SUBAUTHENTICATION_DLL_EX      = 0x00100000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_ALLOW_MSVCHAPV2               = 0x00010000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_S4U2SELF                      = 0x00020000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_CHECK_LOGONHOURS_FOR_S4U      = 0x00040000,
    [SDKName("MSV1_0_CLEARTEXT_PASSWORD_ALLOWED")]
    MSV1_0_INTERNET_DOMAIN               = 0x00080000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
