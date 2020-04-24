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

using NtApiDotNet.Utilities.Text;
using NtApiDotNet.Win32.Security.Authentication.Ntlm;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Base class to represent an authentication token.
    /// </summary>
    public class AuthenticationToken
    {
        private readonly byte[] _data;

        /// <summary>
        /// Convert the authentication token to a byte array.
        /// </summary>
        /// <returns>The byte array.</returns>
        public virtual byte[] ToArray()
        {
            return (byte[])_data.Clone();
        }

        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The token as a formatted string.</returns>
        public virtual string Format()
        {
            if (_data.Length == 0)
                return string.Empty;
            HexDumpBuilder builder = new HexDumpBuilder(true, true, true, false, 0);
            builder.Append(_data);
            builder.Complete();
            return builder.ToString();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">The authentication token data.</param>
        public AuthenticationToken(byte[] data)
        {
            _data = (byte[])data.Clone();
        }

        /// <summary>
        /// Parse a structured authentication token.
        /// </summary>
        /// <param name="token">The token to parse.</param>
        /// <returns>The parsed authentication token. If can't parse any other format returns
        /// RawAuthenticationToken.</returns>
        public static AuthenticationToken Parse(byte[] token)
        {
            if (NtlmAuthenticationToken.TryParse(token, out NtlmAuthenticationToken ntlm_token))
            {
                return ntlm_token;
            }
            return new AuthenticationToken(token);
        }
    }
}
