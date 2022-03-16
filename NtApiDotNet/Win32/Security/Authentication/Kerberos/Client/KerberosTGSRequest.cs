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

using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a TGS request.
    /// </summary>
    public sealed class KerberosTGSRequest
    {
        #region Public Properties
        /// <summary>
        /// The kerberos TGT for the the request.
        /// </summary>
        public KerberosTicket Ticket { get; set; }

        /// <summary>
        /// The kerberos session key for the TGT.
        /// </summary>
        public KerberosAuthenticationKey SessionKey { get; set; }

        /// <summary>
        /// The realm of the service.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Specify name of the service to request.
        /// </summary>
        public KerberosPrincipalName ServerName { get; set; }

        /// <summary>
        /// The name of the client principal.
        /// </summary>
        public KerberosPrincipalName ClientName { get; set; }

        /// <summary>
        /// The client's realm.
        /// </summary>
        public string ClientRealm { get; set; }

        /// <summary>
        /// Specify options for the new ticket.
        /// </summary>
        public KerberosKDCOptions KDCOptions { get; set; }

        /// <summary>
        /// Specify a list of encryption types.
        /// </summary>
        public List<KerberosEncryptionType> EncryptionTypes { get; }

        /// <summary>
        /// Specify the end time for the ticket.
        /// </summary>
        public KerberosTime TillTime { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket">The kerberos TGT for the the request.</param>
        /// <param name="session_key">The kerberos session key for the TGT.</param>
        /// <param name="client_name">The client name for the ticket.</param>
        /// <param name="client_realm">The client realm.</param>
        public KerberosTGSRequest(KerberosTicket ticket, KerberosAuthenticationKey session_key, KerberosPrincipalName client_name, string client_realm)
        {
            Ticket = ticket ?? throw new ArgumentNullException(nameof(ticket));
            if (Ticket.EncryptedData.EncryptionType == KerberosEncryptionType.NULL)
            {
                throw new ArgumentException("Ticket must be encrypted.", nameof(ticket));
            }
            SessionKey = session_key ?? throw new ArgumentNullException(nameof(session_key));
            ClientName = client_name ?? throw new ArgumentNullException(nameof(client_name));
            ClientRealm = client_realm ?? throw new ArgumentNullException(nameof(client_realm));
            Realm = ticket.Realm;
            TillTime = KerberosTime.MaximumTime;
            EncryptionTypes = new List<KerberosEncryptionType>();
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Create a request from a kerberos credential.
        /// </summary>
        /// <param name="credential">The kerberos TGT for the the request.</param>
        public KerberosTGSRequest CreateFromCredential(KerberosCredential credential)
        {
            if (credential is null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            if (credential.Tickets.Count != 1)
            {
                throw new ArgumentException("Credential must only have one ticket.", nameof(credential));
            }

            if (!(credential.EncryptedPart is KerberosCredentialEncryptedPart enc_part))
            {
                throw new ArgumentException("Credential must be decrypted.", nameof(credential));
            }

            if (enc_part.TicketInfo.Count != 1)
            {
                throw new ArgumentException("Credential must only have one ticket information.", nameof(enc_part.TicketInfo));
            }

            var ticket_info = enc_part.TicketInfo[0];

            return new KerberosTGSRequest(credential.Tickets[0], ticket_info.Key, ticket_info.ClientName, ticket_info.ClientRealm);
        }
        #endregion

        #region Internal Members
        private void Validate()
        {
            if (Ticket is null)
            {
                throw new ArgumentNullException(nameof(Ticket));
            }
            if (SessionKey is null)
            {
                throw new ArgumentNullException(nameof(SessionKey));
            }
            if (string.IsNullOrEmpty(Realm))
            {
                throw new ArgumentException($"{nameof(Realm)} must not be empty.");
            }
            if (ServerName is null)
            {
                throw new ArgumentNullException(nameof(ServerName));
            }
            if (TillTime is null)
            {
                throw new ArgumentNullException(nameof(TillTime));
            }
            if (string.IsNullOrEmpty(ClientRealm))
            {
                throw new ArgumentException($"{nameof(ClientRealm)} must not be empty.");
            }
            if (ClientName is null)
            {
                throw new ArgumentNullException(nameof(ClientName));
            }
        }

        internal KerberosTGSRequestBuilder ToBuilder()
        {
            Validate();

            List<KerberosEncryptionType> encryption_types;
            if (EncryptionTypes.Count > 0)
            {
                encryption_types = EncryptionTypes;
            }
            else
            {
                encryption_types = new List<KerberosEncryptionType>()
                {
                    KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96,
                    KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96,
                    KerberosEncryptionType.ARCFOUR_HMAC_MD5
                };
            }

            return new KerberosTGSRequestBuilder
            {
                ClientName = ClientName,
                EncryptionTypes = encryption_types,
                KDCOptions = KDCOptions,
                Realm = Realm,
                ServerName = ServerName,
                Nonce = KerberosBuilderUtils.GetRandomNonce()
            };
        }

        #endregion
    }
}
