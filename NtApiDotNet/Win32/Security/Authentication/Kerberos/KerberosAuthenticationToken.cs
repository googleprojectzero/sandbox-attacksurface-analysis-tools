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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Authentication Token for Kerberos.
    /// </summary>
    public class KerberosAuthenticationToken : ASN1AuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// Protocol version.
        /// </summary>
        public int ProtocolVersion { get; }
        /// <summary>
        /// Message type.
        /// </summary>
        public KerberosMessageType MessageType { get; }
        #endregion

        #region Private Members
        private protected KerberosAuthenticationToken(byte[] data, DERValue[] values, KerberosMessageType message_type)
            : base(data, values)
        {
            ProtocolVersion = 5;
            MessageType = message_type;
        }

        private static bool GetInnerToken(byte[] tok_id, byte[] data, DERValue[] values, out KerberosAuthenticationToken token)
        {
            int id = tok_id[0] | (tok_id[1] << 8);
            switch (id)
            {
                case 1:
                    return KerberosAPRequestAuthenticationToken.TryParse(data, values, out token);
                case 2:
                    return KerberosAPReplyAuthenticationToken.TryParse(data, values, out token);
                case 3:
                    return KerberosErrorAuthenticationToken.TryParse(data, values, out token);
                case 4:
                    return KerberosTGTRequestAuthenticationToken.TryParse(data, values, out token);
                case 0x104:
                    return KerberosTGTReplyAuthenticationToken.TryParse(data, values, out token);
                case 5:
                    return KerberosKDCRequestAuthenticationToken.TryParse(data, values, out token);
                case 6:
                    return KerberosKDCReplyAuthenticationToken.TryParse(data, values, out token);
            }
            token = null;
            return false;
        }

        internal static bool TryParseWrapped(byte[] data, byte[] tok_id, string oid, DERValue[] values, out KerberosAuthenticationToken token)
        {
            // RFC1964
            switch (oid)
            {
                case OIDValues.KERBEROS:
                case OIDValues.KERBEROS_USER_TO_USER:
                case OIDValues.PKU2U:
                    return GetInnerToken(tok_id, data, values, out token);
            }
            token = null;
            return false;
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Remove any GSSAPI wrapper from the token.
        /// </summary>
        /// <returns>The unwrapped token, or the original token if already unwrapped.</returns>
        public KerberosAuthenticationToken Unwrap()
        {
            if (!GSSAPIUtils.TryParse(ToArray(), out byte[] inner_token, out string oid))
            {
                return this;
            }

            byte[] tok_id = new byte[] { inner_token[0], inner_token[1] };
            Buffer.BlockCopy(inner_token, 2, inner_token, 0, inner_token.Length - 2);
            Array.Resize(ref inner_token, inner_token.Length - 2);
            var values = DERParser.ParseData(inner_token, 0);
            if (!TryParseWrapped(inner_token, tok_id, oid, values, out KerberosAuthenticationToken token))
            {
                throw new ArgumentException("Invalid wrapped token.");
            }
            return token;
        }

        /// <summary>
        /// Add a GSSAPI wrapper to the token.
        /// </summary>
        /// <returns>The wrapped token, or the original token if already wrapped.</returns>
        public KerberosAuthenticationToken Wrap()
        {
            byte[] token = ToArray();
            if (GSSAPIUtils.TryParse(token, out byte[] _, out string _))
            {
                return this;
            }

            byte[] tok_id = new byte[2];
            string oid = OIDValues.KERBEROS;

            if (this is KerberosAPRequestAuthenticationToken)
            {
                tok_id[0] = 1;
            }
            else if (this is KerberosAPReplyAuthenticationToken)
            {
                tok_id[0] = 2;
            }
            else if (this is KerberosErrorAuthenticationToken)
            {
                tok_id[0] = 3;
            }
            else if (this is KerberosKDCRequestAuthenticationToken)
            {
                tok_id[0] = 5;
            }
            else if (this is KerberosKDCReplyAuthenticationToken)
            {
                tok_id[0] = 6;
            }
            else
            {
                oid = OIDValues.KERBEROS_USER_TO_USER;
                tok_id[0] = 4;
                if (this is KerberosTGTRequestAuthenticationToken)
                {
                    tok_id[1] = 0;
                }
                else if (this is KerberosTGTReplyAuthenticationToken)
                {
                    tok_id[1] = 1;
                }
                else
                {
                    throw new InvalidDataException("Unknown Kerberos token type.");
                }
            }

            return Parse(GSSAPIUtils.Wrap(oid, token, tok_id));
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

        #region Internal Methods
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
                    // If using DCE style then there's no GSS-API header, try manually parsing.
                    var values = DERParser.ParseData(data, 0);
                    if (KerberosAPRequestAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    if (KerberosAPReplyAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    if (KerberosErrorAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    if (KerberosTGTRequestAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    if (KerberosTGTReplyAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    if (KerberosKDCRequestAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    if (KerberosKDCReplyAuthenticationToken.TryParse(data, values, out token))
                        return true;
                    token = new KerberosAuthenticationToken(data, values, KerberosMessageType.UNKNOWN);
                    return true;
                }
                else
                {
                    // RFC1964
                    byte[] tok_id = new byte[] { inner_token[0], inner_token[1] };
                    var values = DERParser.ParseData(inner_token, 2);

                    if (!TryParseWrapped(data, tok_id, oid, values, out token))
                    {
                        token = new KerberosAuthenticationToken(data, values, KerberosMessageType.UNKNOWN);
                    }
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
        #endregion
    }
}
