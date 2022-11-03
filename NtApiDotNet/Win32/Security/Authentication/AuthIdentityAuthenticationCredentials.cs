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

using NtApiDotNet.Win32.Security.Credential;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Auth identity credentials, wraps a marshalled SEC_WINNT_AUTH_IDENTITY_OPAQUE.
    /// </summary>
    /// <remarks>This maintains a natively allocations buffer which should be freeds after user.</remarks>
    public sealed class AuthIdentityAuthenticationCredentials : AuthenticationCredentials, IDisposable
    {
        #region Private Members
        private readonly SecWinNtAuthIdentity _auth_id;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="auth_id">The auth identity to create from.</param>
        /// <param name="copy_credentials">If true then the auth identity is copied, if false then they'll be owned by this instance.</param>
        public AuthIdentityAuthenticationCredentials(SecWinNtAuthIdentity auth_id, bool copy_credentials = true) : base(false)
        {
            _auth_id = (copy_credentials ? auth_id?.Copy() : auth_id) ?? throw new ArgumentNullException(nameof(auth_id));
        }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create the credentials from a UserCredentials object.
        /// </summary>
        /// <param name="credentials">The user credentials.</param>
        /// <returns>The authentication credentials.</returns>
        public static AuthIdentityAuthenticationCredentials Create(UserCredentials credentials)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return Create(credentials.ToArray());
        }

        /// <summary>
        /// Create the credentials from a marshalled auth identity.
        /// </summary>
        /// <param name="marshaled_auth_identity">The marshalled auth identity.</param>
        /// <returns>The authentication credentials.</returns>
        public static AuthIdentityAuthenticationCredentials Create(byte[] marshaled_auth_identity)
        {
            return new AuthIdentityAuthenticationCredentials(SecWinNtAuthIdentity.Create(marshaled_auth_identity), false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert the authentication credentials to a marshalled byte array.
        /// </summary>
        /// <returns>The credentials as a byte array.</returns>
        public byte[] ToArray()
        {
            return _auth_id.ToArray();
        }

        /// <summary>
        /// Convert the authentication identity to user credentials.
        /// </summary>
        /// <returns>The user credentials.</returns>
        public UserCredentials ToUserCredentials()
        {
            var strs = _auth_id.ToEncodedStrings();
            return new UserCredentials(strs.UserName, strs.Domain, strs.PackedCredentials);
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the underlying auth identity.
        /// </summary>
        /// <remarks>This is owned by the authentication credentials, you shouldn't dispose it.</remarks>
        public SecWinNtAuthIdentity DangerousAuthIdentity => _auth_id;

        /// <summary>
        /// The user in the credentials.
        /// </summary>
        public string User => _auth_id.User;

        /// <summary>
        /// The domain in the credentials.
        /// </summary>
        public string Domain => _auth_id.Domain;
        #endregion

        #region Internal Members
        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            return _auth_id.Copy().DangerousBuffer;
        }
        #endregion

        #region IDisposable Implementation
        /// <summary>
        /// Dispose the object.
        /// </summary>
        public void Dispose()
        {
            _auth_id?.Dispose();
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
