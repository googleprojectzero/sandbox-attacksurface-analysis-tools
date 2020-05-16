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

        private KerberosCredential(byte[] data, DERValue[] values) 
            : base(data, values, KerberosMessageType.KRB_CRED)
        {
        }

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
            KerberosEncryptedData encdata = null;
            KerberosKeySet tmp_keys = new KerberosKeySet(keyset.OfType<KerberosAuthenticationKey>());
            List<KerberosTicket> dec_tickets = new List<KerberosTicket>();
            bool decrypted_ticket = false;
            foreach (var ticket in Tickets)
            {
                if (ticket.Decrypt(tmp_keys, KeyUsage.AsRepTgsRepTicket, out KerberosTicket dec_ticket))
                {
                    dec_tickets.Add(dec_ticket);
                    decrypted_ticket = true;
                }
                else
                {
                    dec_tickets.Add(ticket);
                }
            }

            if (EncryptedPart.Decrypt(tmp_keys, string.Empty, new KerberosPrincipalName(), KeyUsage.KrbCred, out byte[] decrypted))
            {
                // Needs session key from TGT request which we don't necessarily have.
            }

            if (decrypted_ticket || encdata != null)
            {
                KerberosCredential ret = (KerberosCredential)MemberwiseClone();
                ret.Tickets = dec_tickets.AsReadOnly();
                ret.EncryptedPart = encdata ?? ret.EncryptedPart;
                return ret;
            }
            return base.Decrypt(keyset);
        }

        /// <summary>
        /// Try and parse data into an ASN1 authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Negotiate authentication token.</param>
        /// <param name="values">Parsed DER Values.</param>
        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosCredential token)
        {
            token = null;
            try
            {
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
                                tickets.Add(KerberosTicket.Parse(child, next.Children[0].Data));
                            }
                            ret.Tickets = tickets.AsReadOnly();
                            break;
                        case 3:
                            if (!next.HasChildren())
                                return false;
                            ret.EncryptedPart = KerberosEncryptedData.Parse(next.Children[0]);
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
    }
}
