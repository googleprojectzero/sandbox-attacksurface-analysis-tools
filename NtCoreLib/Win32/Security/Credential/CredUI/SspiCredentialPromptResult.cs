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
using NtApiDotNet.Win32.Security.Credential.AuthIdentity;
using System;

namespace NtApiDotNet.Win32.Security.Credential.CredUI
{
    /// <summary>
    /// Result from the SSPI credential prompt.
    /// </summary>
    public sealed class SspiCredentialPromptResult : IDisposable
    {
        /// <summary>
        /// Chosen authentication credentials.
        /// </summary>
        public SecWinNtAuthIdentity AuthIdentity { get; }

        /// <summary>
        /// Indicates whether the save credentials check box was set.
        /// </summary>
        public bool Save { get; }

        /// <summary>
        /// The SSPI package.
        /// </summary>
        public AuthenticationPackage AuthPackage { get; }

        /// <summary>
        /// Get whether the request was cancelled.
        /// </summary>
        public bool Cancelled => AuthIdentity == null;

        internal SspiCredentialPromptResult(SafeSecWinNtAuthIdentityBuffer auth_id,
            int save, AuthenticationPackage package) : this(package)
        {
            AuthIdentity = new SecWinNtAuthIdentity(auth_id);
            Save = save != 0;
        }

        internal SspiCredentialPromptResult(AuthenticationPackage package)
        {
            AuthPackage = package;
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
            return AuthPackage.CreateHandle(cred_use_flag, AuthIdentity.ToAuthenticationCredentials());
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
