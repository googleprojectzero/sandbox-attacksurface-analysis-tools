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

using NtApiDotNet.Utilities.Reflection;
using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Option flags for auth identity encryption/decryption.
    /// </summary>
    [Flags]
    public enum AuthIdentityEncryptionOptions
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_LOGON")]
        SameLogon = 0x1,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_PROCESS")]
        SameProcess = 0x2,
        [SDKName("SEC_WINNT_AUTH_IDENTITY_ENCRYPT_FOR_SYSTEM")]
        ForSystem = 0x4
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Auth identity credentials, wraps a marshalled SEC_WINNT_AUTH_IDENTITY_OPAQUE.
    /// </summary>
    /// <remarks>This maintains a natively allocations buffer which should be freeds after user.</remarks>
    public sealed class AuthIdentityAuthenticationCredentials : AuthenticationCredentials, IDisposable
    {
        #region Private Members
        private readonly SafeSecWinntAuthIdentityBuffer _auth_id;

        private static SafeSecWinntAuthIdentityBuffer UnmarshalAuthId(byte[] auth_id)
        {
            if (auth_id is null)
            {
                throw new ArgumentNullException(nameof(auth_id));
            }

            SecurityNativeMethods.SspiUnmarshalAuthIdentity(auth_id.Length,
                auth_id, out SafeSecWinntAuthIdentityBuffer ret).CheckResult();
            return ret;
        }

        private static byte[] MarshalAuthId(SafeSecWinntAuthIdentityBuffer auth_id)
        {
            if (auth_id is null || auth_id.IsInvalid)
            {
                throw new ArgumentNullException(nameof(auth_id));
            }

            using (var list = new DisposableList())
            {
                SecurityNativeMethods.SspiMarshalAuthIdentity(auth_id,
                    out int length, out SafeLocalAllocBuffer buffer).CheckResult();
                list.AddResource(buffer);
                buffer.Initialize((ulong)length);
                return BufferUtils.ReadBytes(buffer, 0, length);
            }
        }

        private SafeSecWinntAuthIdentityBuffer CopyAuthId()
        {
            SecurityNativeMethods.SspiCopyAuthIdentity(_auth_id, out SafeSecWinntAuthIdentityBuffer copy).CheckResult();
            return copy;
        }

        private void SetFlags(SecWinNtAuthIdentityFlags flags, bool set_flag)
        {
            if (set_flag)
                _auth_id.Flags |= flags;
            else
                _auth_id.Flags &= ~flags;
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
            return new AuthIdentityAuthenticationCredentials(UnmarshalAuthId(marshaled_auth_identity));
        }

        /// <summary>
        /// Create the credentials from packed credentials.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The domain name.</param>
        /// <param name="packed_credentials">The packed credentials. Can be a password or a packed credentials.</param>
        /// <returns>The authentication credentials.</returns>
        public static AuthIdentityAuthenticationCredentials Create(string username, string domain, string packed_credentials)
        {
            SecurityNativeMethods.SspiEncodeStringsAsAuthIdentity(username, domain, 
                packed_credentials, out SafeSecWinntAuthIdentityBuffer auth_id).CheckResult();
            return new AuthIdentityAuthenticationCredentials(auth_id);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Copy the credentials to a new buffer.
        /// </summary>
        /// <returns></returns>
        public AuthIdentityAuthenticationCredentials Copy()
        {
            return new AuthIdentityAuthenticationCredentials(CopyAuthId());
        }

        /// <summary>
        /// Create a copy of the auth identity which excludes a package.
        /// </summary>
        /// <param name="package">The SSPI package to exclude.</param>
        /// <returns>The copy with the excluded package.</returns>
        public AuthIdentityAuthenticationCredentials ExcludePackage(string package)
        {
            SecurityNativeMethods.SspiExcludePackage(_auth_id, package, out SafeSecWinntAuthIdentityBuffer ret).CheckResult();
            return new AuthIdentityAuthenticationCredentials(ret);
        }

        /// <summary>
        /// Convert the authentication credentials to a marshalled byte array.
        /// </summary>
        /// <returns>The credentials as a byte array.</returns>
        public byte[] ToArray()
        {
            return MarshalAuthId(_auth_id);
        }

        /// <summary>
        /// Convert the authentication identity to user credentials.
        /// </summary>
        /// <returns>The user credentials.</returns>
        public UserCredentials ToUserCredentials()
        {
            SecurityNativeMethods.SspiEncodeAuthIdentityAsStrings(_auth_id, out SafeLocalAllocBuffer username,
                out SafeLocalAllocBuffer domain, out SafeLocalAllocBuffer password).CheckResult();
            using (var list = new DisposableList(new[] { username, domain, password }))
            {
                return new UserCredentials(username.ReadNulTerminatedUnicodeStringUnsafe(),
                    domain.ReadNulTerminatedUnicodeStringUnsafe(),
                    password.ReadNulTerminatedUnicodeStringUnsafe());
            }
        }

        /// <summary>
        /// Convert the object to a string.
        /// </summary>
        /// <returns>The string.</returns>
        public override string ToString()
        {
            return _auth_id.AuthType.Name;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get whether the authidentity is encrypted.
        /// </summary>
        public bool IsEncrypted => SecurityNativeMethods.SspiIsAuthIdentityEncrypted(_auth_id);

        /// <summary>
        /// Specify to only allow for an identity token.
        /// </summary>
        public bool IdentityOnly
        {
            get => _auth_id.Flags.HasFlagSet(SecWinNtAuthIdentityFlags.IdentityOnly);
            set => SetFlags(SecWinNtAuthIdentityFlags.IdentityOnly, value);
        }
        #endregion

        #region Internal Members
        internal AuthIdentityAuthenticationCredentials(SafeSecWinntAuthIdentityBuffer auth_id) 
            : base(false)
        {
            SecurityNativeMethods.SspiValidateAuthIdentity(auth_id).CheckResult();
            _auth_id = auth_id;
        }

        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            return CopyAuthId();
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
