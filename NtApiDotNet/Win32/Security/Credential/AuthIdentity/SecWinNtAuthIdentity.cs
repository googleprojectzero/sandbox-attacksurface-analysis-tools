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
using NtApiDotNet.Win32.Security.Authentication.Logon;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// Auth identity credentials buffer, wraps a marshalled SEC_WINNT_AUTH_IDENTITY_OPAQUE.
    /// </summary>
    public sealed class SecWinNtAuthIdentity : IDisposable
    {
        #region Private Members
        private readonly SafeSecWinNtAuthIdentityBuffer _auth_id;

        private class SecWinNtAuthIdentityAuthenticationCredentials : AuthenticationCredentials
        {
            private readonly byte[] _auth_id;

            public SecWinNtAuthIdentityAuthenticationCredentials(byte[] auth_id)
            {
                _auth_id = auth_id;
            }

            internal override SafeBuffer ToBuffer(DisposableList list, string package)
            {
                return SafeSecWinNtAuthIdentityBuffer.Unmarshal(_auth_id);
            }
        }

        private class SecWinNtAuthIdentityLsaLogonCredentials : ILsaLogonCredentials, ILsaLogonCredentialsSerializable
        {
            private readonly byte[] _auth_id;
            private readonly string _package;

            public SecWinNtAuthIdentityLsaLogonCredentials(string package, byte[] auth_id)
            {
                _package = package;
                _auth_id = auth_id;
            }

            string ILsaLogonCredentials.AuthenticationPackage => _package;

            byte[] ILsaLogonCredentialsSerializable.ToArray()
            {
                return _auth_id.CloneBytes();
            }

            SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
            {
                return _auth_id.ToBuffer();
            }
        }

        private void SetFlags(SecWinNtAuthIdentityFlags flags, bool set_flag)
        {
            if (set_flag)
                _auth_id.Flags |= flags;
            else
                _auth_id.Flags &= ~flags;
        }

        private SecWinNtAuthPackedCredential GetPackedCredential()
        {
            if (!HasPackedCredential)
                throw new NotSupportedException("Auth identity doesn't support packed credentials.");

            return _auth_id.PackedCredentials;
        }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create the credentials from a marshalled auth identity.
        /// </summary>
        /// <param name="marshaled_auth_identity">The marshalled auth identity.</param>
        /// <returns>The authentication credentials.</returns>
        public static SecWinNtAuthIdentity Create(byte[] marshaled_auth_identity)
        {
            return new SecWinNtAuthIdentity(SafeSecWinNtAuthIdentityBuffer.Unmarshal(marshaled_auth_identity));
        }

        /// <summary>
        /// Create the credentials from packed credentials.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The domain name.</param>
        /// <param name="packed_credentials">The packed credentials. Can be a password or a packed credentials.</param>
        /// <returns>The authentication credentials.</returns>
        public static SecWinNtAuthIdentity Create(string username, string domain, string packed_credentials)
        {
            SecurityNativeMethods.SspiEncodeStringsAsAuthIdentity(username, domain,
                packed_credentials, out SafeSecWinNtAuthIdentityBuffer auth_id).CheckResult();
            return new SecWinNtAuthIdentity(auth_id);
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
        public static SecWinNtAuthIdentity Create(string username, string domain, SecWinNtAuthPackedCredential packed_credentials,
            SecWinNtAuthIdentityEncryptionOptions encrypt_options = 0, string package_list = null,
            SecWinNtAuthIdentityCreateOptions options = SecWinNtAuthIdentityCreateOptions.None)
        {
            if (username is null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (packed_credentials is null)
            {
                throw new ArgumentNullException(nameof(packed_credentials));
            }

            bool encrypt = encrypt_options != 0;
            SecWinNtAuthIdentityFlags flags = SecWinNtAuthIdentityFlags.IdentityMarshalled | SecWinNtAuthIdentityFlags.Unicode;
            if (encrypt)
                flags |= SecWinNtAuthIdentityFlags.Reserved;
            if (options.HasFlagSet(SecWinNtAuthIdentityCreateOptions.IdentityOnly))
                flags |= SecWinNtAuthIdentityFlags.IdentityOnly;
            if (options.HasFlagSet(SecWinNtAuthIdentityCreateOptions.IdProvider))
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
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.UserOffset), 
                nameof(SEC_WINNT_AUTH_IDENTITY_EX2.UserLength), username);
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.DomainOffset), 
                nameof(SEC_WINNT_AUTH_IDENTITY_EX2.DomainLength), domain);
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackageListOffset), 
                nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackageListLength), package_list);
            builder.AddRelativeBuffer(nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackedCredentialsOffset), 
                nameof(SEC_WINNT_AUTH_IDENTITY_EX2.PackedCredentialsLength), creds);

            using (var buffer = builder.ToBuffer())
            {
                var result = buffer.Result;
                result.cbStructureLength = buffer.Length;
                buffer.Result = result;

                if (encrypt)
                    SecurityNativeMethods.SspiEncryptAuthIdentityEx(encrypt_options, buffer).CheckResult();

                return new SecWinNtAuthIdentity(SafeSecWinNtAuthIdentityBuffer.Copy(buffer));
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Copy the credentials to a new buffer.
        /// </summary>
        /// <returns></returns>
        public SecWinNtAuthIdentity Copy()
        {
            return new SecWinNtAuthIdentity(_auth_id.Copy());
        }

        /// <summary>
        /// Create a copy of the auth identity which excludes a package.
        /// </summary>
        /// <param name="package">The SSPI package to exclude.</param>
        /// <returns>The copy with the excluded package.</returns>
        public SecWinNtAuthIdentity ExcludePackage(string package)
        {
            SecurityNativeMethods.SspiExcludePackage(_auth_id, package, out SafeSecWinNtAuthIdentityBuffer ret).CheckResult();
            return new SecWinNtAuthIdentity(ret);
        }

        /// <summary>
        /// Convert the authentication credentials to a marshalled byte array.
        /// </summary>
        /// <returns>The credentials as a byte array.</returns>
        public byte[] ToArray()
        {
            return _auth_id.MarshalToArray();
        }

        /// <summary>
        /// Convert the authentication identity to encoded strings.
        /// </summary>
        /// <returns>The authentication identity as encoded strings.</returns>
        public SecWinNtAuthIdentityStrings ToEncodedStrings()
        {
            return new SecWinNtAuthIdentityStrings(_auth_id);
        }

        /// <summary>
        /// Convert to authentication credentials.
        /// </summary>
        /// <returns>The authentication credentials.</returns>
        public AuthenticationCredentials ToAuthenticationCredentials()
        {
            return new SecWinNtAuthIdentityAuthenticationCredentials(ToArray());
        }

        /// <summary>
        /// Convert to LSA logon credentials.
        /// </summary>
        /// <returns>The LSA logon credentials.</returns>
        public ILsaLogonCredentials ToLsaLogonCredentials(string package = AuthenticationPackage.NEGOSSP_NAME)
        {
            if (package is null)
            {
                throw new ArgumentNullException(nameof(package));
            }

            return new SecWinNtAuthIdentityLsaLogonCredentials(package, ToArray());
        }

        /// <summary>
        /// Decrypt the credentials if encrypted.
        /// </summary>
        /// <param name="encrypt_options">The decryption options.</param>
        public void Decrypt(SecWinNtAuthIdentityEncryptionOptions encrypt_options = 0)
        {
            if (!IsEncrypted)
                return;
            SecurityNativeMethods.SspiDecryptAuthIdentityEx(encrypt_options, _auth_id).CheckResult();
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
                if (PackedCredential is SecWinNtAuthPackedCredentialPassword cred)
                    return cred.Password;
                return null;
            }
        }

        /// <summary>
        /// The package list in the credentials.
        /// </summary>
        public string PackageList => _auth_id.PackageList;

        /// <summary>
        /// Get the type of authentication identity buffer.
        /// </summary>
        public SecWinNtAuthIdentityType AuthType
        {
            get
            {
                bool unicode = _auth_id.Flags.HasFlagSet(SecWinNtAuthIdentityFlags.Unicode);
                if (_auth_id.AuthType == typeof(SEC_WINNT_AUTH_IDENTITY_EX))
                {
                    return unicode ? SecWinNtAuthIdentityType.UnicodeEx : SecWinNtAuthIdentityType.AnsiEx;
                }
                if (_auth_id.AuthType == typeof(SEC_WINNT_AUTH_IDENTITY_EX2))
                {
                    return unicode ? SecWinNtAuthIdentityType.UnicodeEx2 : SecWinNtAuthIdentityType.AnsiEx2;
                }
                return unicode ? SecWinNtAuthIdentityType.Unicode : SecWinNtAuthIdentityType.Ansi;
            }
        }

        /// <summary>
        /// Get the packed credentials for the auth identity.
        /// </summary>
        /// <exception cref="NotSupportedException">Thrown if the auth identity doesn't support packed credentials.</exception>
        public SecWinNtAuthPackedCredential PackedCredential => GetPackedCredential();
        #endregion

        #region Internal Members
        internal SecWinNtAuthIdentity(SafeSecWinNtAuthIdentityBuffer auth_id)
        {
            SecurityNativeMethods.SspiValidateAuthIdentity(auth_id).CheckResult();
            _auth_id = auth_id;
        }

        internal SafeBufferGeneric DangerousBuffer => _auth_id;
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
