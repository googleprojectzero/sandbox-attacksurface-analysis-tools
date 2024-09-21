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
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class representing a KRB-CRED structure.
    /// </summary>
    public class KerberosCredential : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// List of tickets in this credential.
        /// </summary>
        public IReadOnlyList<KerberosTicket> Tickets { get; private set; }
        /// <summary>
        /// Encrypted part contains sesssion keys etc.
        /// </summary>
        public KerberosEncryptedData EncryptedPart { get; private set; }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create a new kerberos credential token.
        /// </summary>
        /// <param name="tickets">The list of tickets.</param>
        /// <param name="encrypted_part">The encrypted data.</param>
        /// <returns>The new kerberos credential.</returns>
        public static KerberosCredential Create(IEnumerable<KerberosTicket> tickets, KerberosEncryptedData encrypted_part)
        {
            if (tickets is null)
            {
                throw new ArgumentNullException(nameof(tickets));
            }

            if (encrypted_part is null)
            {
                throw new ArgumentNullException(nameof(encrypted_part));
            }

            if (!tickets.Any())
                throw new ArgumentException("Must specify at least one ticket.");

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication((int)KerberosMessageType.KRB_CRED))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, 5);
                    seq.WriteContextSpecific(1, (int)KerberosMessageType.KRB_CRED);
                    seq.WriteContextSpecific(2, tickets);
                    seq.WriteContextSpecific(3, encrypted_part);
                }
            }
            var ret = Parse(builder.ToArray());
            if (encrypted_part is KerberosCredentialEncryptedPart)
                ret.EncryptedPart = encrypted_part;
            return ret;
        }

        /// <summary>
        /// Create a new kerberos credential token.
        /// </summary>
        /// <param name="ticket">The ticket.</param>
        /// <param name="ticket_info">The ticket info.</param>
        /// <returns>The new kerberos credential.</returns>
        public static KerberosCredential Create(KerberosTicket ticket, KerberosCredentialInfo ticket_info)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            if (ticket_info is null)
            {
                throw new ArgumentNullException(nameof(ticket_info));
            }

            var enc_part = KerberosCredentialEncryptedPart.Create(new[] { ticket_info });

            return Create(new[] { ticket }, enc_part);
        }

        /// <summary>
        /// Parse a DER encoding KRB-CRED structure.
        /// </summary>
        /// <param name="data">The DER encoded data.</param>
        /// <returns>The parsed Kerberos credentials.</returns>
        new public static KerberosCredential Parse(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (!TryParse(data, values, out KerberosCredential ret))
                throw new InvalidDataException("Invalid kerberos data.");
            return ret;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<KerberosV{ProtocolVersion} {MessageType}>");
            for (int i = 0; i < Tickets.Count; ++i)
            {
                builder.AppendLine($"<Ticket {i}>");
                builder.Append(Tickets[i].Format());
            }
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
            KerberosKeySet tmp_keys = new KerberosKeySet(keyset.OfType<KerberosAuthenticationKey>());

            if (EncryptedPart.Decrypt(tmp_keys, string.Empty, new KerberosPrincipalName(), KerberosKeyUsage.KrbCred, out byte[] decrypted))
            {
                return Create(Tickets, KerberosEncryptedData.Create(KerberosEncryptionType.NULL, decrypted));
            }

            return base.Decrypt(keyset);
        }

        /// <summary>
        /// Encrypt the kerberos credential.
        /// </summary>
        /// <param name="key">The key to encrypt with.</param>
        /// <param name="key_version">The key version.</param>
        /// <returns>The encrypted credential.</returns>
        public KerberosCredential Encrypt(KerberosAuthenticationKey key, int? key_version = null)
        {
            return Create(Tickets, EncryptedPart.Encrypt(key, KerberosKeyUsage.KrbCred, key_version));
        }

        /// <summary>
        /// Convert credential to an external ticket type.
        /// </summary>
        /// <returns>The external ticket.</returns>
        public KerberosExternalTicket ToExternalTicket()
        {
            return new KerberosExternalTicket(this);
        }
        #endregion

        #region Conversion Operators
        /// <summary>
        /// Explicit conversion to a KerberosExternalTicket.
        /// </summary>
        /// <param name="credential">The credential.</param>
        public static explicit operator KerberosExternalTicket (KerberosCredential credential) => credential.ToExternalTicket();
        #endregion

        #region Internal Members
        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosCredential token)
        {
            token = null;
            try
            {
                if (values == null)
                {
                    values = DERParser.ParseData(data, 0);
                }
                var ret = new KerberosCredential(data, values);
                if (values.Length != 1 || !values[0].CheckMsg(KerberosMessageType.KRB_CRED) || !values[0].HasChildren())
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
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_CRED)
                                return false;
                            break;
                        case 2:
                            if (!next.Children[0].CheckSequence())
                                return false;
                            List<KerberosTicket> tickets = new List<KerberosTicket>();
                            foreach (var child in next.Children[0].Children)
                            {
                                tickets.Add(KerberosTicket.Parse(child));
                            }
                            ret.Tickets = tickets.AsReadOnly();
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
                    if (KerberosCredentialEncryptedPart.TryParse(ret.EncryptedPart, ret.EncryptedPart.CipherText, 
                        ret.Tickets, new KerberosKeySet(), out KerberosCredentialEncryptedPart enc_part))
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
        #endregion

        #region Private Members
        private KerberosCredential(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_CRED)
        {
        }
        #endregion
    }
}
