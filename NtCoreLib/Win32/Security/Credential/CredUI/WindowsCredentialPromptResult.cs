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

using NtApiDotNet.Win32.Security.Authentication;
using NtApiDotNet.Win32.Security.Authentication.Logon;
using System;

namespace NtApiDotNet.Win32.Security.Credential.CredUI
{
    /// <summary>
    /// Result from the Windows credential prompt.
    /// </summary>
    public sealed class WindowsCredentialPromptResult
    {
        /// <summary>
        /// Chosen authentication credentials.
        /// </summary>
        public CredentialAuthenticationBuffer OutputAuthBuffer { get; }

        /// <summary>
        /// Indicates whether the save credentials check box was set.
        /// </summary>
        public bool Save { get; }

        /// <summary>
        /// The package ID for the output credentials.
        /// </summary>
        public uint PackageId { get; }

        /// <summary>
        /// The authentication package.
        /// </summary>
        public AuthenticationPackage Package => AuthenticationPackage.FromPackageId(PackageId);

        /// <summary>
        /// Get whether the request was cancelled.
        /// </summary>
        public bool Cancelled => OutputAuthBuffer == null;

        /// <summary>
        /// Convert the result to credentials which can be used to logon.
        /// </summary>
        /// <returns>The credentials buffer.</returns>
        public LsaLogonCredentialsBuffer ToLsaLogonCredentialBuffer()
        {
            if (Cancelled)
                throw new InvalidOperationException("The credentials request was cancelled.");
            return new LsaLogonCredentialsBuffer(OutputAuthBuffer.ToArray(), Package.Name);
        }

        internal WindowsCredentialPromptResult(CredentialAuthenticationBuffer creds,
            int save, uint package_id) : this(package_id)
        {
            OutputAuthBuffer = creds;
            Save = save != 0;
        }

        internal WindowsCredentialPromptResult(uint package_id)
        {
            PackageId = package_id;
        }
    }
}
