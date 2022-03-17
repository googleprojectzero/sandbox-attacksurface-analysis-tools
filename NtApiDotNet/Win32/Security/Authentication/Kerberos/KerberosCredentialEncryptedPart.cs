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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// The decrypted version of the Kerberos Credentials part.
    /// </summary>
    public sealed class KerberosCredentialEncryptedPart : KerberosEncryptedData
    {
        /// <summary>
        /// List of information for the tickets.
        /// </summary>
        public IReadOnlyList<KerberosCredentialInfo> TicketInfo { get; private set; }

        /// <summary>
        /// The credentials nonce.
        /// </summary>
        public int? Nonce { get; private set; }

        /// <summary>
        /// The ticket timestamp.
        /// </summary>
        public KerberosTime Timestamp { get; private set; }

        /// <summary>
        /// The ticket usecs.
        /// </summary>
        public int? USec { get; private set; }

        /// <summary>
        /// The ticket's sender address.
        /// </summary>
        public KerberosHostAddress SenderAddress { get; private set; }

        /// <summary>
        /// The ticket's recipient address.
        /// </summary>
        public KerberosHostAddress RecipientAddress { get; private set; }

        /// <summary>
        /// Create a new credentials encrypted part.
        /// </summary>
        /// <param name="ticket_info">The list of ticket information.</param>
        /// <param name="nonce">The credentials nonce.</param>
        /// <param name="timestamp">The credentials timestamp.</param>
        /// <param name="usec">The credentials usecs.</param>
        /// <param name="sender_address">The credentials sender address.</param>
        /// <param name="recipient_address">The credentials recipient address.</param>
        /// <returns>The credentials encrypted part.</returns>
        public static KerberosEncryptedData Create(IEnumerable<KerberosCredentialInfo> ticket_info,
            int? nonce = null, KerberosTime timestamp = null, int? usec = null,
            KerberosHostAddress sender_address = null, KerberosHostAddress recipient_address = null)
        {
            if (ticket_info is null)
            {
                throw new ArgumentNullException(nameof(ticket_info));
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication((int)KerberosMessageType.KRB_CRED_ENC_PART))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, ticket_info);
                    seq.WriteContextSpecific(1, nonce);
                    seq.WriteContextSpecific(2, timestamp);
                    seq.WriteContextSpecific(3, usec);
                    seq.WriteContextSpecific(4, sender_address);
                    seq.WriteContextSpecific(5, recipient_address);
                }
            }
            return Create(KerberosEncryptionType.NULL, builder.ToArray());
        }

        private KerberosCredentialEncryptedPart(byte[] data) :
            base(KerberosEncryptionType.NULL, null, data)
        {
        }

        private KerberosCredentialEncryptedPart(KerberosEncryptedData data) : 
            base(data.EncryptionType, data.KeyVersion, data.CipherText)
        {
        }

        internal override string Format()
        {
            StringBuilder builder = new StringBuilder();
            if (Nonce.HasValue)
            {
                builder.AppendLine($"Nonce           : {Nonce.Value}");
            }
            if (Timestamp != null)
            {
                builder.AppendLine($"Timestamp       : {Timestamp.ToDateTime(USec)}");
            }
            if (SenderAddress != null)
            {
                builder.AppendLine($"Sender Address  : {SenderAddress}");
            }
            if (RecipientAddress != null)
            {
                builder.AppendLine($"Recipient Address: {RecipientAddress}");
            }

            for (int i = 0; i < TicketInfo.Count; ++i)
            {
                builder.AppendLine($"<Ticket Info {i}>");
                builder.Append(TicketInfo[i].Format());
            }
            return builder.ToString();
        }

        internal static bool TryParse(KerberosEncryptedData orig_data, byte[] decrypted, IReadOnlyList<KerberosTicket> tickets, 
            KerberosKeySet keyset, out KerberosCredentialEncryptedPart token)
        {
            token = null;
            try
            {
                DERValue[] values = DERParser.ParseData(decrypted, 0);
                var ret = new KerberosCredentialEncryptedPart(orig_data);
                if (values.Length != 1 || !values[0].CheckMsg(KerberosMessageType.KRB_CRED_ENC_PART) || !values[0].HasChildren())
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
                            if (!next.HasChildren() || !next.Children[0].CheckSequence())
                                return false;
                            ret.TicketInfo = next.Children[0].Children.Select((v, i) => KerberosCredentialInfo.Parse(v, keyset, tickets[i])).ToList().AsReadOnly();
                            break;
                        case 1:
                            ret.Nonce = next.ReadChildInteger();
                            break;
                        case 2:
                            ret.Timestamp = next.ReadChildKerberosTime();
                            break;
                        case 3:
                            ret.USec = next.ReadChildInteger();
                            break;
                        case 4:
                            ret.SenderAddress = KerberosHostAddress.ParseChild(next);
                            break;
                        case 5:
                            ret.RecipientAddress = KerberosHostAddress.ParseChild(next);
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
