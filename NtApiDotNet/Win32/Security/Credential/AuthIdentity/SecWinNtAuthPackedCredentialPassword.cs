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

using System.Text;

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// Class to represent a password packed credentials structure.
    /// </summary>
    public sealed class SecWinNtAuthPackedCredentialPassword : SecWinNtAuthPackedCredential
    {
        /// <summary>
        /// The user's password.
        /// </summary>
        public string Password => Encoding.Unicode.GetString(_credentials);

        /// <summary>
        /// The password as raw bytes.
        /// </summary>
        public byte[] PasswordBytes => _credentials.CloneBytes();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="password">The user's password.</param>
        public SecWinNtAuthPackedCredentialPassword(byte[] password)
            : base(SecWinNtPackedCredentialTypes.Password,
                  password ?? new byte[0])
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="password">The user's password.</param>
        public SecWinNtAuthPackedCredentialPassword(string password)
            : base(SecWinNtPackedCredentialTypes.Password,
                  Encoding.Unicode.GetBytes(password ?? string.Empty))
        {
        }
    }
}
