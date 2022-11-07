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

using NtApiDotNet.Utilities.Security;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Client
{
    /// <summary>
    /// Authentication credentials representing an NT hash.
    /// </summary>
    public sealed class NtHashAuthenticationCredentials : AuthenticationCredentials, INtlmAuthenticationCredentials
    {
        #region Private Members
        private byte[] _nthash;
        private void SetNtHash(byte[] nthash)
        {
            if (nthash?.Length != 16)
                throw new ArgumentException("NT hash must be 16 bytes in length.", nameof(nthash));
            _nthash = nthash;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The user name.
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// The domain.
        /// </summary>
        public string Domain { get; set; }
        /// <summary>
        /// The password an NT hash.
        /// </summary>
        public byte[] NtHash { get => _nthash.CloneBytes(); set => SetNtHash(value); }
        #endregion

        #region Public Methods
        /// <summary>
        /// Calculate the NTOWFv2 hash for these credentials.
        /// </summary>
        /// <returns>The NTOWFv2 hash.</returns>
        public byte[] NtOWFv2()
        {
            var hmac = new HMACMD5(NtHash);
            return hmac.ComputeHash(Encoding.Unicode.GetBytes((UserName?.ToUpper() ?? string.Empty) + (Domain ?? string.Empty)));
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The user's domain name.</param>
        /// <param name="nthash">The user's NT hash.</param>
        public NtHashAuthenticationCredentials(byte[] nthash, string username = null, string domain = null) : base(true)
        {
            UserName = username;
            Domain = domain;
            NtHash = nthash;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="credentials">The user's credentials.</param>
        /// <remarks>Converts the user's password to the NT hash.</remarks>
        public NtHashAuthenticationCredentials(UserCredentials credentials) : base(true)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (credentials.Password is null)
            {
                throw new ArgumentNullException(nameof(credentials.Password));
            }

            UserName = credentials.UserName;
            Domain = credentials.Domain;
            NtHash = MD4.CalculateHash(credentials.GetPasswordBytes());
        }
        #endregion

        #region Internal Methods
        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
