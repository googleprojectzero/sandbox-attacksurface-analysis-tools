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
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Authentication.Negotiate;
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
        /// <param name="package_name">Name of the authentication package.</param>
        /// <param name="token_count">The count of the tokens before this one.</param>
        /// <param name="token">The token to parse.</param>
        /// <param name="client">Parse operation from a client.</param>
        /// <returns>The parsed authentication token. If can't parse any other format returns
        /// a raw AuthenticationToken.</returns>
        internal static AuthenticationToken Parse(string package_name, int token_count, bool client, byte[] token)
        {
            if (AuthenticationPackage.CheckNtlm(package_name) 
                && NtlmAuthenticationToken.TryParse(token, token_count, client, out NtlmAuthenticationToken ntlm_token))
            {
                return ntlm_token;
            }

            if (AuthenticationPackage.CheckKerberos(package_name) 
                && KerberosAuthenticationToken.TryParse(token, token_count, client, out KerberosAuthenticationToken kerb_token))
            {
                return kerb_token;
            }

            if (AuthenticationPackage.CheckNegotiate(package_name) 
                && NegotiateAuthenticationToken.TryParse(token, token_count, 
                client, out NegotiateAuthenticationToken nego_token))
            {
                return nego_token;
            }

            if (ASN1AuthenticationToken.TryParse(token, token_count, 
                client, out ASN1AuthenticationToken asn1_token))
            {
                return asn1_token;
            }

            return new AuthenticationToken(token);
        }
    }
}
