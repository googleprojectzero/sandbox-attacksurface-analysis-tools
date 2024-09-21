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

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Flags for a credential.
    /// </summary>
    [Flags]
    public enum CredentialFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("CRED_FLAGS_PASSWORD_FOR_CERT")]
        PasswordForCert = 0x0001,
        [SDKName("CRED_FLAGS_PROMPT_NOW")]
        PromptNow = 0x0002,
        [SDKName("CRED_FLAGS_USERNAME_TARGET")]
        UsernameTarget = 0x0004,
        [SDKName("CRED_FLAGS_OWF_CRED_BLOB")]
        OWFCredBlob = 0x0008,
        [SDKName("CRED_FLAGS_REQUIRE_CONFIRMATION")]
        RequireConfirmation = 0x0010,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
