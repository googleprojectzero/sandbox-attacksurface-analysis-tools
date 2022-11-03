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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Credential;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Options when creating an authentication identity credential.
    /// </summary>
    [Flags]
    public enum AuthIdentityCreateOptions
    {
        /// <summary>
        /// No options.
        /// </summary>
        None = 0,
        /// <summary>
        /// Use an identity level impersonation token.
        /// </summary>
        IdentityOnly = 1,
        /// <summary>
        /// Specify the credentials are for an identity provider.
        /// </summary>
        IdProvider = 2,
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

        private static SafeSecWinntAuthIdentityBuffer CopyAuthId(SafeBuffer auth_id)
        {
            SecurityNativeMethods.SspiCopyAuthIdentity(auth_id, out SafeSecWinntAuthIdentityBuffer copy).CheckResult();
            return copy;
        }

        private SafeSecWinntAuthIdentityBuffer CopyAuthId()
        {
            return CopyAuthId(_auth_id);
        }

        private void SetFlags(SecWinNtAuthIdentityFlags flags, bool set_flag)
        {
            if (set_flag)
                _auth_id.Flags |= flags;
            else
                _auth_id.Flags &= ~flags;
        }

        private PackedCredential GetPackedCredential()
        {
            if (!HasPackedCredential)
                throw new NotSupportedException("Auth identity doesn't support packed credentials.");

            return _auth_id.PackedCredentials;
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

        /// <summary>
        /// Create the credentials from packed credentials.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The domain name.</param>
        /// <param name="packed_credentials">The packed credentials. Can be a password or a packed credentials.</param>
        /// <param name="encrypt">Specify to encrypt the credentials.</param>
        /// <returns>The authentication credentials.</returns>
        public static AuthIdentityAuthenticationCredentials Create(string username, string domain, string packed_credentials, bool encrypt)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException($"'{nameof(username)}' cannot be null or empty.", nameof(username));
            }

            if (!string.IsNullOrEmpty(domain))
            {
                username = $@"{domain}\{username}";
            }

            int length = 0;
            CredPackAuthenticationBufferFlags flags = CredPackAuthenticationBufferFlags.CRED_PACK_ID_PROVIDER_CREDENTIALS;
            if (encrypt)
                flags |= CredPackAuthenticationBufferFlags.CRED_PACK_PROTECTED_CREDENTIALS;

            var error = SecurityNativeMethods.CredPackAuthenticationBufferW(
                flags, username, packed_credentials, null, ref length).GetLastWin32Error();
            if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                error.ToNtException();
            byte[] credentials = new byte[length];
            error = SecurityNativeMethods.CredPackAuthenticationBufferW(
                flags, username, packed_credentials, credentials, ref length).GetLastWin32Error();
            error.ToNtException();
            return Create(credentials);
        }

        /// <summary>
        /// Create the credentials from packed credentials.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The domain name.</param>
        /// <param name="packed_credentials">The packed credentials.</param>
        /// <param name="encrypt_options">Options to encrypt the credentials.</param>
        /// <param name="package_list">The package list in the credentials.</param>
        /// <param name="options">Additional options for the created credentials.</param>
        /// <returns>The authentication credentials.</returns>
        public static AuthIdentityAuthenticationCredentials Create(string username, string domain, PackedCredential packed_credentials, 
            AuthIdentityEncryptionOptions encrypt_options = AuthIdentityEncryptionOptions.None, string package_list = null, 
            AuthIdentityCreateOptions options = AuthIdentityCreateOptions.None)
        {
            if (username is null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (packed_credentials is null)
            {
                throw new ArgumentNullException(nameof(packed_credentials));
            }

            bool encrypt = encrypt_options != AuthIdentityEncryptionOptions.None;

            SecWinNtAuthIdentityFlags flags = SecWinNtAuthIdentityFlags.Unicode | SecWinNtAuthIdentityFlags.IdentityMarshalled;
            if (encrypt)
                flags |= SecWinNtAuthIdentityFlags.Reserved;
            if (options.HasFlagSet(AuthIdentityCreateOptions.IdentityOnly))
                flags |= SecWinNtAuthIdentityFlags.IdentityOnly;
            if (options.HasFlagSet(AuthIdentityCreateOptions.IdProvider))
                flags |= SecWinNtAuthIdentityFlags.IdProvider;

            byte[] creds = packed_credentials.ToArray(encrypt);

            int header_size = Marshal.SizeOf<SEC_WINNT_AUTH_IDENTITY_EX2>();

            SEC_WINNT_AUTH_IDENTITY_EX2 auth_id = new SEC_WINNT_AUTH_IDENTITY_EX2
            {
                Version = SEC_WINNT_AUTH_IDENTITY_EX2.SEC_WINNT_AUTH_IDENTITY_VERSION_2,
                cbHeaderLength = (ushort)header_size,
                Flags = flags
            };

            var builder = auth_id.ToBuilder();
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.UserOffset), nameof(SEC_WINNT_AUTH_IDENTITY_EX2.UserLength), username);
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.DomainOffset), nameof(SEC_WINNT_AUTH_IDENTITY_EX2.DomainLength), domain);
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackageListOffset), nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackageListLength), package_list);
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackedCredentialsOffset), nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackedCredentialsLength), creds);

            using (var buffer = builder.ToBuffer())
            {
                var result = buffer.Result;
                result.cbStructureLength = buffer.Length;
                buffer.Result = result;

                if (encrypt)
                    SecurityNativeMethods.SspiEncryptAuthIdentityEx(encrypt_options, buffer).CheckResult();

                return new AuthIdentityAuthenticationCredentials(CopyAuthId(buffer));
            }
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
        /// Get whether the auth identity is encrypted.
        /// </summary>
        public bool IsEncrypted => SecurityNativeMethods.SspiIsAuthIdentityEncrypted(_auth_id);

        /// <summary>
        /// Get whether the credentials are for an ID provider.
        /// </summary>
        public bool IsIdProvider => _auth_id.Flags.HasFlagSet(SecWinNtAuthIdentityFlags.IdProvider);

        /// <summary>
        /// Specify to only allow for an identity token.
        /// </summary>
        public bool IdentityOnly
        {
            get => _auth_id.Flags.HasFlagSet(SecWinNtAuthIdentityFlags.IdentityOnly);
            set => SetFlags(SecWinNtAuthIdentityFlags.IdentityOnly, value);
        }

        /// <summary>
        /// Get whether the auth identity has a packed credential.
        /// </summary>
        public bool HasPackedCredential => _auth_id.AuthType == typeof(SEC_WINNT_AUTH_IDENTITY_EX2);

        /// <summary>
        /// The user in the credentials.
        /// </summary>
        public string User => _auth_id.User;

        /// <summary>
        /// The domain in the credentials.
        /// </summary>
        public string Domain => _auth_id.Domain;

        /// <summary>
        /// The password in the credentials.
        /// </summary>
        /// <remarks>If the auth identity supports packed credentials this might not return a valid value.</remarks>
        public string Password
        {
            get
            {
                if (IsEncrypted)
                    return null;
                if (!HasPackedCredential)
                    return _auth_id.Password;
                if (PackedCredential is PackedCredentialPassword cred)
                    return cred.Password;
                return null;
            }
        }

        /// <summary>
        /// The package list in the credentials.
        /// </summary>
        public string PackageList => _auth_id.PackageList;

        /// <summary>
        /// Get the packed credentials for the auth identity.
        /// </summary>
        /// <exception cref="NotSupportedException">Thrown if the auth identity doesn't support packed credentials.</exception>
        public PackedCredential PackedCredential => GetPackedCredential();
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
