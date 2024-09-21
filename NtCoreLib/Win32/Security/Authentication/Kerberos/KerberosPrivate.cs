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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a KRB-PRIV structure.
    /// </summary>
    public sealed class KerberosPrivate : KerberosAuthenticationToken
    {
        private KerberosPrivate(byte[] data, DERValue[] values)
           : base(data, values, KerberosMessageType.KRB_PRIV)
        {
        }

        /// <summary>
        /// The encrypted part.
        /// </summary>
        public KerberosEncryptedData EncryptedPart { get; private set; }

        /// <summary>
        /// Decrypt the Authentication Token using a keyset.
        /// </summary>
        /// <param name="keyset">The set of keys to decrypt the </param>
        /// <returns>The decrypted token, or the same token if nothing could be decrypted.</returns>
        public override AuthenticationToken Decrypt(IEnumerable<AuthenticationKey> keyset)
        {
            KerberosKeySet tmp_keys = new KerberosKeySet(keyset.OfType<KerberosAuthenticationKey>());

            if (EncryptedPart.Decrypt(tmp_keys, string.Empty, new KerberosPrincipalName(), KerberosKeyUsage.KrbPriv, out byte[] decrypted))
            {
                return Create(KerberosEncryptedData.Create(KerberosEncryptionType.NULL, decrypted));
            }

            return base.Decrypt(keyset);
        }

        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            return base.Format();
        }

        /// <summary>
        /// Create a new kerberos private token.
        /// </summary>
        /// <param name="encrypted_part">The encrypted data.</param>
        /// <returns>The new kerberos private token.</returns>
        public static KerberosPrivate Create(KerberosEncryptedData encrypted_part)
        {
            if (encrypted_part is null)
            {
                throw new ArgumentNullException(nameof(encrypted_part));
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication((int)KerberosMessageType.KRB_PRIV))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, 5);
                    seq.WriteContextSpecific(1, (int)KerberosMessageType.KRB_PRIV);
                    seq.WriteContextSpecific(3, encrypted_part);
                }
            }
            var ret = Parse(builder.ToArray());
            return ret;
        }

        /// <summary>
        /// Parse a DER encoding KRB-PRIV structure.
        /// </summary>
        /// <param name="data">The DER encoded data.</param>
        /// <returns>The parsed Kerberos private message.</returns>
        new public static KerberosPrivate Parse(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (!TryParse(data, values, out KerberosPrivate ret))
                throw new InvalidDataException("Invalid kerberos private data.");
            return ret;
        }

        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosPrivate token)
        {
            token = null;
            try
            {
                if (values == null)
                    values = DERParser.ParseData(data, 0);
                var ret = new KerberosPrivate(data, values);
                if (values.Length != 1 || !values[0].CheckMsg(KerberosMessageType.KRB_PRIV) || !values[0].HasChildren())
                    return false;

                values = values[0].Children;
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    return false;

                foreach (var next in values[0].Children)
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
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_PRIV)
                                return false;
                            break;
                        case 3:
                            if (!next.HasChildren())
                                return false;
                            ret.EncryptedPart = KerberosEncryptedData.Parse(next.Children[0], next.Data);
                            break;
                        default:
                            return false;
                    }
                }

                if (ret.EncryptedPart.EncryptionType == KerberosEncryptionType.NULL)
                {
                    if (KerberosPrivateEncryptedPart.TryParse(ret.EncryptedPart, ret.EncryptedPart.CipherText,
                        out KerberosPrivateEncryptedPart enc_part))
                    {
                        ret.EncryptedPart = enc_part;
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
    }
}
