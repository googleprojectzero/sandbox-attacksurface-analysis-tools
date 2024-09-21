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

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// Get the type of SEC_WINNT_AUTH_IDENTITY along with the character type.
    /// </summary>
    public enum SecWinNtAuthIdentityType
    {
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY structure with ANSI strings.
        /// </summary>
        Ansi,
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY structure with Unicode strings.
        /// </summary>
        Unicode,
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY_EX structure with ANSI strings.
        /// </summary>
        AnsiEx,
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY_EX structure with Unicode strings.
        /// </summary>
        UnicodeEx,
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY_EX2 structure with ANSI strings.
        /// </summary>
        AnsiEx2,
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY_EX2 structure with Unicode strings.
        /// </summary>
        UnicodeEx2,
    }
}
