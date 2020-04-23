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

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Raw authentication token.
    /// </summary>
    public class RawAuthenticationToken : AuthenticationToken
    {
        private readonly byte[] _data;

        /// <summary>
        /// Convert the authentication token to a byte array.
        /// </summary>
        /// <returns>The byte array.</returns>
        public override byte[] ToArray()
        {
            return (byte[])_data.Clone();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">The authentication token data.</param>
        public RawAuthenticationToken(byte[] data)
        {
            _data = (byte[])data.Clone();
        }
    }
}
