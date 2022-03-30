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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Status code for the change password request.
    /// </summary>
    public enum KerberosChangePasswordStatus
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("KRB5_KPASSWD_SUCCESS")]
        Success = 0,
        [SDKName("KRB5_KPASSWD_MALFORMED")]
        Malformed = 1,
        [SDKName("KRB5_KPASSWD_HARDERROR")]
        HardError = 2,
        [SDKName("KRB5_KPASSWD_AUTHERROR")]
        AuthError = 3,
        [SDKName("KRB5_KPASSWD_SOFTERROR")]
        SoftError = 4,
        [SDKName("KRB5_KPASSWD_ACCESSDENIED")]
        AccessDenied = 5,
        [SDKName("KRB5_KPASSWD_BAD_VERSION")]
        BadVersion = 6,
        [SDKName("KRB5_KPASSWD_INITIAL_FLAG_NEEDED")]
        InitialFlagNeeded = 7
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
