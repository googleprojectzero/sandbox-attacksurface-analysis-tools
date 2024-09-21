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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class to build a KRB-CRED.
    /// </summary>
    public sealed class KerberosCredentialBuilder
    {
        #region Private Members
        private readonly List<KerberosTicket> _tickets;
        private readonly List<KerberosCredentialInfo> _ticket_info;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosCredentialBuilder()
        {
            _tickets = new List<KerberosTicket>();
            _ticket_info = new List<KerberosCredentialInfo>();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The list of tickets.
        /// </summary>
        public IReadOnlyCollection<KerberosTicket> Tickets => _tickets.AsReadOnly();

        /// <summary>
        /// The list of ticket info.
        /// </summary>
        public IReadOnlyCollection<KerberosCredentialInfo> TicketInfo => _ticket_info.AsReadOnly();

        /// <summary>
        /// The credentials nonce.
        /// </summary>
        public int? Nonce { get; set; }

        /// <summary>
        /// The ticket timestamp.
        /// </summary>
        public KerberosTime Timestamp { get; set; }

        /// <summary>
        /// The ticket usecs.
        /// </summary>
        public int? USec { get; set; }

        /// <summary>
        /// The ticket's sender address.
        /// </summary>
        public KerberosHostAddress SenderAddress { get; set; }

        /// <summary>
        /// The ticket's recipient address.
        /// </summary>
        public KerberosHostAddress RecipientAddress { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add a ticket and its information.
        /// </summary>
        /// <param name="ticket">The kerberos ticket.</param>
        /// <param name="ticket_info">The kerberos ticket info.</param>
        public void AddTicket(KerberosTicket ticket, KerberosCredentialInfo ticket_info)
        {
            _tickets.Add(ticket);
            _ticket_info.Add(ticket_info);
        }

        /// <summary>
        /// Add a decrypted ticket.
        /// </summary>
        /// <param name="ticket">The kerberos ticket.</param>
        /// <param name="key">The key to encrypt the ticket.</param>
        /// <param name="key_usage">The Kerberos key usage for the encryption.</param>
        /// <param name="key_version">Optional key version number.</param>
        public void AddTicket(KerberosTicketDecrypted ticket, KerberosAuthenticationKey key, 
            KerberosKeyUsage key_usage = KerberosKeyUsage.AsRepTgsRepTicket, int? key_version = null)
        {
            AddTicket(ticket.Encrypt(key, key_usage, key_version), ticket.ToCredentialInfo());
        }

        /// <summary>
        /// Create the KRB-CRED
        /// </summary>
        /// <returns>The kerberos credential.</returns>
        public KerberosCredential Create()
        {
            return KerberosCredential.Create(Tickets, KerberosCredentialEncryptedPart.Create(_ticket_info,
                Nonce, Timestamp, USec, SenderAddress, RecipientAddress));
        }
        #endregion

    }
}
