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

using NtApiDotNet.Utilities.ASN1.Builder;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class for a KDC-REP-ENC-PART builder.
    /// </summary>
    public abstract class KerberosKDCReplyEncryptedPartBuilder
    {
        /// <summary>
        /// The message type of the encrypted part.
        /// </summary>
        public KerberosMessageType MessageType { get; }

        /// <summary>
        /// The kerberos ticket's session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; set; }

        /// <summary>
        /// List of last request times.
        /// </summary>
        public IReadOnlyList<KerberosLastRequest> LastRequest { get; set; }

        /// <summary>
        /// The nonce value.
        /// </summary>
        public int Nonce { get; set; }

        /// <summary>
        /// Time for key expiration.
        /// </summary>
        public KerberosTime KeyExpirationTime { get; set; }

        /// <summary>
        /// The ticket flags.
        /// </summary>
        public KerberosTicketFlags TicketFlags { get; set; }

        /// <summary>
        /// The authentication time.
        /// </summary>
        public KerberosTime AuthTime { get; set; }

        /// <summary>
        /// The ticket start time.
        /// </summary>
        public KerberosTime StartTime { get; set; }

        /// <summary>
        /// The ticket end time.
        /// </summary>
        public KerberosTime EndTime { get; set; }

        /// <summary>
        /// The ticket renew time.
        /// </summary>
        public KerberosTime RenewTill { get; set; }

        /// <summary>
        /// The server realm.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// The server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; set; }

        /// <summary>
        /// The client addresses.
        /// </summary>
        public IReadOnlyList<KerberosHostAddress> ClientAddress { get; set; }

        /// <summary>
        /// Encypted pre-authentication data.
        /// </summary>
        public IReadOnlyList<KerberosPreAuthenticationData> EncryptedPreAuthentication { get; set; }

        /// <summary>
        /// Create the KDC encrypted part.
        /// </summary>
        /// <returns>The KDC encrypted part.</returns>
        public KerberosKDCReplyEncryptedPart Create()
        {
            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateMsg(MessageType))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, Key);
                    if (LastRequest != null && LastRequest.Count > 0)
                    {
                        seq.WriteContextSpecific(1, LastRequest);
                    }
                    seq.WriteContextSpecific(2, Nonce);
                    seq.WriteContextSpecific(3, KeyExpirationTime);
                    seq.WriteContextSpecific(4, b => b.WriteBitString(TicketFlags));
                    seq.WriteContextSpecific(5, AuthTime);
                    seq.WriteContextSpecific(6, StartTime);
                    seq.WriteContextSpecific(7, EndTime);
                    seq.WriteContextSpecific(8, RenewTill);
                    seq.WriteContextSpecific(9, Realm);
                    seq.WriteContextSpecific(10, ServerName);
                    if (ClientAddress != null && ClientAddress.Count > 0)
                    {
                        seq.WriteContextSpecific(11, ClientAddress);
                    }
                    if (EncryptedPreAuthentication != null && EncryptedPreAuthentication.Count > 0)
                    {
                        seq.WriteContextSpecific(12, EncryptedPreAuthentication);
                    }
                }
                return KerberosKDCReplyEncryptedPart.Parse(builder.ToArray());
            }
        }

        private protected KerberosKDCReplyEncryptedPartBuilder(KerberosMessageType type)
        {
            MessageType = type;
        }
    }
}
