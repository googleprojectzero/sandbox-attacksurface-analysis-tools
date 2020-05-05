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

using NtApiDotNet.Utilities.ASN1;
using System;
using System.IO;
using System.Runtime.Remoting.Messaging;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Authentication Token for Kerberos.
    /// </summary>
    public class KerberosAuthenticationToken : ASN1AuthenticationToken
    {
        #region Private Members
        private protected KerberosAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values)
        {
        }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Parse bytes into a kerberos token.
        /// </summary>
        /// <param name="data">The kerberos token in bytes.</param>
        /// <returns>The Kerberos token.</returns>
        public static KerberosAuthenticationToken Parse(byte[] data)
        {
            if (!TryParse(data, 0, false, out KerberosAuthenticationToken token))
            {
                throw new ArgumentException(nameof(data));
            }
            return token;
        }
        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an Kerberos authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Kerberos authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                if (!GSSAPIUtils.TryParse(data, out byte[] inner_token, out string oid))
                {
                    return false;
                }

                byte[] tok_id = new byte[] { inner_token[0], inner_token[1] };
                var values = DERParser.ParseData(inner_token, 2);

                switch (oid)
                {
                    case OIDValues.KERBEROS_OID:
                    case OIDValues.KERBEROS_USER_TO_USER_OID:
                        if (tok_id[0] == 1)
                        {
                            if (KerberosAPRequestAuthenticationToken.TryParse(data, values, out token))
                                return true;
                            break;
                        }
                        if (tok_id[0] == 2)
                        {
                            if (KerberosAPReplyAuthenticationToken.TryParse(data, values, out token))
                                return true;
                            break;
                        }
                        if (tok_id[0] == 3)
                        {
                            // Kerberos ERROR.
                            break;
                        }
                        if (tok_id[0] != 4)
                        {
                            break;
                        }
                        if (tok_id[1] == 0 )
                        {
                            if (KerberosTGTRequestAuthenticationToken.TryParse(data, values, out token))
                                return true;
                        }
                        if (tok_id[1] == 1)
                        {
                            if (KerberosTGTReplyAuthenticationToken.TryParse(data, values, out token))
                                return true;
                        }
                        break;
                    default:
                        return false;
                }

                // TODO: Need to select out the different types of authentication tokens.
                token = new KerberosAuthenticationToken(data, values);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
        #endregion
    }
}
