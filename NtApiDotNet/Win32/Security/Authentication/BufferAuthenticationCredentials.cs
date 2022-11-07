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

using NtApiDotNet.Win32.Security.Authentication.Logon;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent authentication credentials which is backed by a byte array.
    /// </summary>
    public sealed class BufferAuthenticationCredentials : AuthenticationCredentials
    {
        private readonly byte[] _buffer;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="buffer">The buffer for the credentials.</param>
        public BufferAuthenticationCredentials(byte[] buffer)
        {
            _buffer = buffer?.CloneBytes() ?? throw new ArgumentNullException(nameof(buffer));
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="credentials">The LSA logon credentials.</param>
        public BufferAuthenticationCredentials(ILsaLogonCredentialsSerializable credentials)
        {
            _buffer = credentials.ToArray() ?? throw new ArgumentNullException(nameof(credentials));
        }

        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            return _buffer.ToBuffer();
        }
    }
}
