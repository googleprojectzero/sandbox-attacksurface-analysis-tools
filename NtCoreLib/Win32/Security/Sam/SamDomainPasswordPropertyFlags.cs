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

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Flags for password properties.
    /// </summary>
    public enum SamDomainPasswordPropertyFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("DOMAIN_PASSWORD_COMPLEX")]
        Complex = 0x00000001,
        [SDKName("DOMAIN_PASSWORD_NO_ANON_CHANGE")]
        NoAnonChange = 0x00000002,
        [SDKName("DOMAIN_PASSWORD_NO_CLEAR_CHANGE")]
        NoClearChange = 0x00000004,
        [SDKName("DOMAIN_LOCKOUT_ADMINS")]
        LockoutAdmins = 0x00000008,
        [SDKName("DOMAIN_PASSWORD_STORE_CLEARTEXT")]
        StoreCleartext = 0x00000010,
        [SDKName("DOMAIN_REFUSE_PASSWORD_CHANGE")]
        RefusePasswordChange = 0x00000020,
        [SDKName("DOMAIN_NO_LM_OWF_CHANGE")]
        NoLMOWFChange = 0x00000040,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
