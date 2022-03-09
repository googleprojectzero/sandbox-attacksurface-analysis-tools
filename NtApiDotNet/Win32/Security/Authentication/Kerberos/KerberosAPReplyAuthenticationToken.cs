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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos AP Reply.
    /// </summary>
    public class KerberosAPReplyAuthenticationToken : KerberosAuthenticationToken
    {
        /// <summary>
        /// Encrypted mutual authentication data.
        /// </summary>
        public KerberosEncryptedData EncryptedPart { get; private set; }

        private protected KerberosAPReplyAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_AP_REP)
        {
            EncryptedPart = new KerberosEncryptedData();
        }

        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<KerberosV{ProtocolVersion} {MessageType}>");
            builder.AppendLine("<Encrypted Part>");
            builder.Append(EncryptedPart.Format());
            return builder.ToString();
        }

        /// <summary>
        /// Decrypt the Authentication Token using a keyset.
        /// </summary>
        /// <param name="keyset">The set of keys to decrypt the </param>
        /// <returns>The decrypted token, or the same token if nothing could be decrypted.</returns>
        public override AuthenticationToken Decrypt(IEnumerable<AuthenticationKey> keyset)
        {
            KerberosEncryptedData encrypted_part = null;
            KerberosKeySet tmp_keyset = new KerberosKeySet(keyset.OfType<KerberosAuthenticationKey>());
            if (EncryptedPart.Decrypt(tmp_keyset, string.Empty, new KerberosPrincipalName(), KerberosKeyUsage.ApRepEncryptedPart, out byte[] auth_decrypt))
            {
                if (!KerberosAPReplyEncryptedPart.Parse(EncryptedPart, auth_decrypt, out encrypted_part))
                {
                    encrypted_part = null;
                }
            }

            if (encrypted_part != null)
            {
                KerberosAPReplyAuthenticationToken ret = (KerberosAPReplyAuthenticationToken)MemberwiseClone();
                ret.EncryptedPart = encrypted_part;
                return ret;
            }
            return base.Decrypt(keyset);
        }

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an ASN1 authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Negotiate authentication token.</param>
        /// <param name="values">Parsed DER Values.</param>
        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                var ret = new KerberosAPReplyAuthenticationToken(data, values);

                if (values.Length != 1 || !values[0].CheckApplication(15) || !values[0].HasChildren())
                    return false;

                values = values[0].Children;
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    return false;

                foreach(var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            if (next.ReadChildInteger() != 5)
                                return false;
                            break;
                        case 1:
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_AP_REP)
                                return false;
                            break;
                        case 2:
                            if (!next.HasChildren())
                                return false;
                            ret.EncryptedPart = KerberosEncryptedData.Parse(next.Children[0], next.Data);
                            break;
                        default:
                            return false;
                    }
                }
                token = ret;
                return true;
            }
            catch (InvalidDataException)
            {
                return false;
            }
        }
        #endregion
    }
}
