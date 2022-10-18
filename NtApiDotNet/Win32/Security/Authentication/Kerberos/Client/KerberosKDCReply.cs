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

using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a KDC reply.
    /// </summary>
    public abstract class KerberosKDCReply
    {
        /// <summary>
        /// The service ticket.
        /// </summary>
        public KerberosTicket Ticket => ReplyToken.Ticket;

        /// <summary>
        /// The ticket's session key.
        /// </summary>
        public KerberosAuthenticationKey SessionKey => ReplyData.Key;

        /// <summary>
        /// The request token used for the reply.
        /// </summary>
        public KerberosKDCRequestAuthenticationToken RequestToken { get; }

        /// <summary>
        /// The reply token.
        /// </summary>
        public KerberosKDCReplyAuthenticationToken ReplyToken { get; }

        /// <summary>
        /// The decrypted reply data.
        /// </summary>
        public KerberosKDCReplyEncryptedPart ReplyData { get; }

        /// <summary>
        /// Convert the TGS reply to a KRB-CRED.
        /// </summary>
        /// <returns>The kerberos credentials.</returns>
        public KerberosCredential ToCredential()
        {
            List<KerberosCredentialInfo> cred_info = new List<KerberosCredentialInfo>();
            cred_info.Add(new KerberosCredentialInfo(ReplyData.Key, ReplyToken.ClientRealm, ReplyToken.ClientName,
                ReplyData.TicketFlags, ReplyData.AuthTime, ReplyData.StartTime, ReplyData.EndTime,
                ReplyData.RenewTill, ReplyData.Realm, ReplyData.ServerName, ReplyData.ClientAddress));
            return KerberosCredential.Create(new KerberosTicket[] { Ticket },
                KerberosCredentialEncryptedPart.Create(cred_info, ReplyData.Nonce, KerberosTime.Now, 0));
        }

        /// <summary>
        /// Convert the TGS reply to an external ticket.
        /// </summary>
        /// <returns>The kerberos external ticket.</returns>
        public KerberosExternalTicket ToExternalTicket()
        {
            return new KerberosExternalTicket(ToCredential());
        }

        private protected KerberosKDCReply(KerberosKDCRequestAuthenticationToken req_token, KerberosKDCReplyAuthenticationToken rep_token, KerberosKDCReplyEncryptedPart enc_part)
        {
            RequestToken = req_token;
            ReplyToken = rep_token;
            ReplyData = enc_part;
        }
    }
}
