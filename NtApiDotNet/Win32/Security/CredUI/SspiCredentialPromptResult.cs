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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Authentication;
using System;

namespace NtApiDotNet.Win32.Security.CredUI
{
    /// <summary>
    /// Result from the credential prompt.
    /// </summary>
    public sealed class SspiCredentialPromptResult : IDisposable
    {
        /// <summary>
        /// Chosen authentication credentials.
        /// </summary>
        public AuthIdentityAuthenticationCredentials AuthIdentity { get; }

        /// <summary>
        /// Indicates whether the save credentials check box was set.
        /// </summary>
        public bool Save { get; }

        /// <summary>
        /// The SSPI package.
        /// </summary>
        public string Package { get; }

        /// <summary>
        /// Get whether the request was cancelled.
        /// </summary>
        public bool Cancelled => AuthIdentity == null;

        internal SspiCredentialPromptResult(SafeSecWinntAuthIdentityBuffer auth_id, 
            int save, string package) : this(package)
        {
            AuthIdentity = new AuthIdentityAuthenticationCredentials(auth_id);
            Save = save != 0;
        }

        internal SspiCredentialPromptResult(string package)
        {
            Package = package;
        }

        /// <summary>
        /// Create a SSPI credential handle from the credentials.
        /// </summary>
        /// <param name="cred_use_flag">The credential use flags.</param>
        /// <returns>The credential handle.</returns>
        public ICredentialHandle CreateHandle(SecPkgCredFlags cred_use_flag)
        {
            if (Cancelled)
                throw new InvalidOperationException("The operation was cancelled and there's no credentials.");
            return CredentialHandle.Create(Package, cred_use_flag, AuthIdentity);
        }

        /// <summary>
        /// Dispose the object.
        /// </summary>
        public void Dispose()
        {
            AuthIdentity?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
