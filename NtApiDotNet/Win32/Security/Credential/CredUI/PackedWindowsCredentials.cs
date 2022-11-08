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
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Credential.CredUI
{
    /// <summary>
    /// Packed Windows credentials.
    /// </summary>
    public sealed class PackedWindowsCredentials
    {
        private readonly byte[] _credentials;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="credentials">The packed credentials.</param>
        internal PackedWindowsCredentials(byte[] credentials)
        {
            _credentials = credentials;
        }

        /// <summary>
        /// Create a packed credential from a byte array.
        /// </summary>
        /// <param name="credentials">The packed credentials.</param>
        /// <returns></returns>
        public static PackedWindowsCredentials Create(byte[] credentials)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return new PackedWindowsCredentials(credentials.CloneBytes());
        }

        /// <summary>
        /// Create a packed credential from user credentials.
        /// </summary>
        /// <param name="credentials">The packed credentials.</param>
        /// <param name="flags">Flags for the packing.</param>
        /// <returns>The packed credentials.</returns>
        public static PackedWindowsCredentials Create(UserCredentials credentials,
            PackedWindowsCredentialsFlags flags = PackedWindowsCredentialsFlags.None)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            string username = credentials.UserName;
            if (!string.IsNullOrEmpty(credentials.Domain))
            {
                username = $"{credentials.Domain}\\{username}";
            }

            int length = 0;
            using (var pwd = credentials.GetPassword())
            {
                SecurityNativeMethods.CredPackAuthenticationBuffer((int)flags,
                    username, pwd, null, ref length);
                var error = Win32Utils.GetLastWin32Error();
                if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                    error.ToNtException();
                byte[] buffer = new byte[length];
                SecurityNativeMethods.CredPackAuthenticationBuffer((int)flags,
                    username, pwd, buffer, ref length).ToNtException(true);
                return Create(buffer);
            }
        }

        /// <summary>
        /// Create a packed credential from user credentials.
        /// </summary>
        /// <param name="username">The user's name.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="flags">Flags for the packing.</param>
        /// <returns>The packed credentials.</returns>
        public static PackedWindowsCredentials Create(string username, string domain, string password, 
            PackedWindowsCredentialsFlags flags = PackedWindowsCredentialsFlags.None)
        {
            return Create(new UserCredentials(username, domain, password), flags);
        }

        /// <summary>
        /// Unpack the user credentials.
        /// </summary>
        /// <returns>The unpacked user credentials.</returns>
        public UserCredentials Unpack(PackedWindowsCredentialsFlags flags = PackedWindowsCredentialsFlags.None)
        {
            int user_length = 0;
            int domain_length = 0;
            int password_length = 0;

            SecurityNativeMethods.CredUnPackAuthenticationBuffer((int)flags, _credentials, _credentials.Length,
                null, ref user_length, null, ref domain_length, null, ref password_length);
            var error = Win32Utils.GetLastWin32Error();
            if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                error.ToNtException();
            StringBuilder username = new StringBuilder(user_length);
            StringBuilder domain = new StringBuilder(domain_length);
            StringBuilder password = new StringBuilder(password_length);

            SecurityNativeMethods.CredUnPackAuthenticationBuffer((int)flags, _credentials, _credentials.Length,
                username, ref user_length, domain, ref domain_length, password, ref password_length).ToNtException(true);
            string user = username.ToString().TrimEnd('\0');
            string dom = domain.ToString().TrimEnd('\0');

            if (string.IsNullOrEmpty(dom))
            {
                string[] parts = user.Split(new[] { '\\' }, 2);
                if (parts.Length == 2)
                {
                    dom = parts[0];
                    user = parts[1];
                }
            }

            return new UserCredentials(user, 
                dom, password.ToString().TrimEnd('\0'));
        }

        /// <summary>
        /// Convert credentials to an array.
        /// </summary>
        /// <returns></returns>
        public byte[] ToArray()
        {
            return _credentials.CloneBytes();
        }
    }
}
