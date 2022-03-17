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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent TGS-REP message.
    /// </summary>
    public sealed class KerberosTGSReply
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
        /// The reply token.
        /// </summary>
        public KerberosKDCReplyAuthenticationToken ReplyToken { get; }

        /// <summary>
        /// The decrypted reply data.
        /// </summary>
        public KerberosKDCReplyEncryptedPart ReplyData { get; }

        internal KerberosTGSReply(KerberosKDCReplyAuthenticationToken token, KerberosKDCReplyEncryptedPart enc_part)
        {
            ReplyToken = token;
            ReplyData = enc_part;
        }
    }
}
