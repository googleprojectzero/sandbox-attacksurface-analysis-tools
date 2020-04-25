//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a credential handle.
    /// </summary>
    public sealed class CredentialHandle : IDisposable
    {
        /// <summary>
        /// Name of the authentication package used.
        /// </summary>
        public string PackageName { get; }

        /// <summary>
        /// Expiry of the credentials.
        /// </summary>
        public long Expiry { get; }

        internal SecHandle CredHandle { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="principal">User principal.</param>
        /// <param name="package">The package name.</param>
        /// <param name="auth_id">Optional authentication ID for the user.</param>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <param name="auth_data">Optional authentication data.</param>
        public CredentialHandle(string principal, string package, Luid? auth_id,
            SecPkgCredFlags cred_use_flag, SafeBuffer auth_data)
        {
            if (package == null)
            {
                throw new ArgumentNullException(nameof(package));
            }

            OptionalLuid luid = null;
            if (auth_id.HasValue)
            {
                luid = new OptionalLuid() { luid = auth_id.Value };
            }
            SecHandle cred_handle = new SecHandle();
            LargeInteger expiry = new LargeInteger();
            SecurityNativeMethods.AcquireCredentialsHandle(principal, package, cred_use_flag,
                luid, auth_data ?? SafeHGlobalBuffer.Null,
                IntPtr.Zero, IntPtr.Zero, cred_handle, expiry)
                .CheckResult();
            CredHandle = cred_handle;
            PackageName = package;
            Expiry = expiry.QuadPart;
        }

        /// <summary>
        /// Create a new credential handle.
        /// </summary>
        /// <param name="principal">User principal.</param>
        /// <param name="package">The package name.</param>
        /// <param name="auth_id">Optional authentication ID for the user.</param>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <returns>The credential handle.</returns>
        public static CredentialHandle Create(string principal, string package, Luid? auth_id,
            SecPkgCredFlags cred_use_flag, AuthenticationCredentials credentials)
        {
            using (var list = new DisposableList())
            {
                var buffer = credentials?.ToBuffer(list, package);
                return new CredentialHandle(principal, package, auth_id, cred_use_flag, buffer);
            }
        }

        /// <summary>
        /// Create a new credential handle.
        /// </summary>
        /// <param name="package">The package name.</param>
        /// <param name="auth_id">Optional authentication ID for the user.</param>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <returns>The credential handle.</returns>
        public static CredentialHandle Create(string package, Luid? auth_id,
            SecPkgCredFlags cred_use_flag, AuthenticationCredentials credentials)
        {
            return Create(null, package, auth_id, cred_use_flag, credentials);
        }

        /// <summary>
        /// Create a new credential handle.
        /// </summary>
        /// <param name="package">The package name.</param>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <returns>The credential handle.</returns>
        public static CredentialHandle Create(string package,
            SecPkgCredFlags cred_use_flag, AuthenticationCredentials credentials)
        {
            return Create(null, package, null, cred_use_flag, credentials);
        }

        /// <summary>
        /// Create a new credential handle.
        /// </summary>
        /// <param name="package">The package name.</param>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <returns>The credential handle.</returns>
        public static CredentialHandle Create(string package,
            SecPkgCredFlags cred_use_flag)
        {
            return Create(package, cred_use_flag, null);
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            SecurityNativeMethods.FreeCredentialsHandle(CredHandle);
        }
    }
}
