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
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Authentication.Ntlm;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Negotiate
{
    /// <summary>
    /// SPNEGO Authentication Token.
    /// </summary>
    public abstract class NegotiateAuthenticationToken : ASN1AuthenticationToken
    {
        /// <summary>
        /// The negotiated authentication token.
        /// </summary>
        public AuthenticationToken Token { get; private set; }

        /// <summary>
        /// Optional message integrity code.
        /// </summary>
        public byte[] MessageIntegrityCode { get; }

        /// <summary>
        /// Decrypt the Authentication Token using a keyset.
        /// </summary>
        /// <param name="keyset">The set of keys to decrypt the </param>
        /// <returns>The decrypted token, or the same token if nothing could be decrypted.</returns>
        public override AuthenticationToken Decrypt(IEnumerable<AuthenticationKey> keyset)
        {
            if (Token == null)
                return this;
            var ret = (NegotiateAuthenticationToken)MemberwiseClone();
            ret.Token = Token.Decrypt(keyset);
            return ret;
        }

        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The token as a formatted string.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<SPNEGO {(this is NegotiateInitAuthenticationToken ? "Init" : "Response")}>");
            FormatData(builder);
            string token_format = Token?.Format();
            if (!string.IsNullOrWhiteSpace(token_format))
            {
                builder.AppendLine("<SPNEGO Token>");
                builder.AppendLine(token_format.TrimEnd());
                builder.AppendLine("</SPNEGO Token>");
            }
            return builder.ToString();
        }

        private protected abstract void FormatData(StringBuilder builder);

        private static AuthenticationToken ParseToken(byte[] data, int token_count, bool client)
        {
            if (NtlmAuthenticationToken.TryParse(data, token_count, client, out NtlmAuthenticationToken ntlm_token))
            {
                return ntlm_token;
            }

            if (KerberosAuthenticationToken.TryParse(data, token_count, client, out KerberosAuthenticationToken kerb_token))
            {
                return kerb_token;
            }

            return new AuthenticationToken(data);
        }

        private static IEnumerable<string> ParseMechList(DERValue[] values)
        {
            List<string> mech_list = new List<string>();
            if (values.CheckValueSequence())
            {
                foreach (var next in values[0].Children)
                {
                    if (!next.CheckPrimitive(UniversalTag.OBJECT_IDENTIFIER))
                    {
                        throw new InvalidDataException();
                    }
                    mech_list.Add(next.ReadObjID());
                }
            }
            return mech_list.AsReadOnly();
        }

        private static NegotiateContextFlags ConvertContextFlags(BitArray flags)
        {
            if (flags.Length > 32)
                throw new InvalidDataException();
            int ret = 0;
            for (int i = 0; i < flags.Length; ++i)
            {
                if (flags[i])
                    ret |= (1 << i);
            }
            return (NegotiateContextFlags)ret;
        }

        private static bool ParseInit(byte[] data, DERValue[] values, int token_count, bool client, out NegotiateAuthenticationToken token)
        {
            token = null;
            if (!values.CheckValueSequence())
            {
                return false;
            }

            IEnumerable<string> mech_list = null;
            NegotiateContextFlags flags = NegotiateContextFlags.None;
            AuthenticationToken auth_token = null;
            byte[] mic = null;

            foreach (var next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    return false;
                switch (next.Tag)
                {
                    case 0:
                        mech_list = ParseMechList(next.Children);
                        break;
                    case 1:
                        flags = ConvertContextFlags(next.ReadChildBitString());
                        break;
                    case 2:
                        auth_token = ParseToken(next.ReadChildOctetString(), token_count, client);
                        break;
                    case 3:
                        // If NegTokenInit2 then just ignore neg hints.
                        if (next.HasChildren() && next.Children[0].CheckSequence())
                            break;
                        mic = next.ReadChildOctetString();
                        break;
                    case 4:
                        // Used if NegTokenInit2.
                        mic = next.ReadChildOctetString();
                        break;
                    default:
                        return false;
                }
            }

            token = new NegotiateInitAuthenticationToken(data, mech_list, flags, auth_token, mic);
            return true;
        }

        private static bool ParseResp(byte[] data, DERValue[] values, int token_count, bool client, out NegotiateAuthenticationToken token)
        {
            token = null;
            if (!values.CheckValueSequence())
            {
                return false;
            }

            string mech = null;
            NegotiateAuthenticationState state = NegotiateAuthenticationState.Reject;
            AuthenticationToken auth_token = null;
            byte[] mic = null;

            foreach (var next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    return false;
                switch (next.Tag)
                {
                    case 0:
                        state = (NegotiateAuthenticationState)next.ReadChildEnumerated();
                        break;
                    case 1:
                        mech = next.ReadChildObjID();
                        break;
                    case 2:
                        auth_token = ParseToken(next.ReadChildOctetString(), token_count, client);
                        break;
                    case 3:
                        mic = next.ReadChildOctetString();
                        break;
                    default:
                        return false;
                }
            }

            token = new NegotiateResponseAuthenticationToken(data, mech, state, auth_token, mic);
            return true;
        }

        private protected NegotiateAuthenticationToken(byte[] data, AuthenticationToken token, byte[] mic) 
            : base(data)
        {
            Token = token;
            MessageIntegrityCode = mic;
        }

        #region Public Static Methods
        /// <summary>
        /// Parse bytes into a negotiate token.
        /// </summary>
        /// <param name="data">The negotiate token in bytes.</param>
        /// <returns>The Negotiate token.</returns>
        public static NegotiateAuthenticationToken Parse(byte[] data)
        {
            if (!TryParse(data, 0, false, out NegotiateAuthenticationToken token))
            {
                throw new ArgumentException(nameof(data));
            }
            return token;
        }
        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an Negotiate authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Negotiate authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out NegotiateAuthenticationToken token)
        {
            token = null;
            try
            {
                byte[] token_data;
                if (GSSAPIUtils.TryParse(data, out token_data, out string oid))
                {
                    if (oid != OIDValues.SPNEGO)
                    {
                        return false;
                    }
                }
                else
                {
                    token_data = data;
                }

                DERValue[] values = DERParser.ParseData(token_data, 0);
                if (values.Length != 1 || values[0].Type != DERTagType.ContextSpecific)
                {
                    return false;
                }

                if (values[0].CheckContext(0))
                {
                    return ParseInit(data, values[0].Children, token_count, client, out token);
                }
                else if (values[0].CheckContext(1))
                {
                    return ParseResp(data, values[0].Children, token_count, client, out token);
                }
                else
                {
                    return false;
                }
            }
            catch (EndOfStreamException)
            {
            }
            catch (InvalidDataException)
            {
            }
            return false;
        }
        #endregion
    }
}
