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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a TGS request.
    /// </summary>
    public sealed class KerberosTGSRequest : KerberosKDCRequest
    {
        #region Public Properties
        /// <summary>
        /// The kerberos ticket for the request.
        /// </summary>
        public KerberosTicket Ticket { get; set; }

        /// <summary>
        /// The kerberos session key for the ticket.
        /// </summary>
        public KerberosAuthenticationKey SessionKey { get; set; }

        /// <summary>
        /// Specify name of the service to request.
        /// </summary>
        public KerberosPrincipalName ServerName { get; set; }

        /// <summary>
        /// The client's realm.
        /// </summary>
        public string ClientRealm { get; set; }

        /// <summary>
        /// Encrypted authorization data.
        /// </summary>
        public List<KerberosAuthorizationData> AuthorizationData { get; set; }

        /// <summary>
        /// List of additional tickets.
        /// </summary>
        public List<KerberosTicket> AdditionalTickets { get; set; }

        /// <summary>
        /// The PA-PAC-OPTIONS pre-authentication flags.
        /// </summary>
        public KerberosPreAuthenticationPACOptionsFlags PACOptionsFlags { get; set; }

        /// <summary>
        /// The name of the user for S4U.
        /// </summary>
        public KerberosPrincipalName S4UUserName { get; set; }

        /// <summary>
        /// The realm for S4U.
        /// </summary>
        public string S4URealm { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add authorization data to the request.
        /// </summary>
        /// <param name="auth_data">The authorization data to add.</param>
        public void AddAuthorizationData(KerberosAuthorizationData auth_data)
        {
            if (auth_data is null)
            {
                throw new ArgumentNullException(nameof(auth_data));
            }

            if (AuthorizationData == null)
                AuthorizationData = new List<KerberosAuthorizationData>();
            AuthorizationData.Add(auth_data);
        }

        /// <summary>
        /// Add an additional ticket to the request.
        /// </summary>
        /// <param name="ticket">The ticket to add.</param>
        public void AddAdditionalTicket(KerberosTicket ticket)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            if (AdditionalTickets == null)
                AdditionalTickets = new List<KerberosTicket>();
            AdditionalTickets.Add(ticket);
        }
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
        /// <param name="credential">The kerberos TGT for the request.</param>
        /// <param name="server_name">The server name for the request.</param>
        /// <param name="realm">The server realm for the request.</param>
        /// <returns>The new request object.</returns>
        public static KerberosTGSRequest Create(KerberosCredential credential, KerberosPrincipalName server_name, string realm)
        {

            if (server_name is null)
            {
                throw new ArgumentNullException(nameof(server_name));
            }

            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            var ret = Create(credential);
            ret.ServerName = server_name;
            ret.Realm = realm;
            return ret;
        }

        /// <summary>
        /// Create a request from a kerberos credential for renewal.
        /// </summary>
        /// <param name="credential">The kerberos credentials for the request.</param>
        /// <returns>The new request object.</returns>
        public static KerberosTGSRequest CreateForRenewal(KerberosCredential credential)
        {
            var ret = Create(credential);
            ret.ServerName = ret.Ticket.ServerName;
            ret.Realm = ret.Ticket.Realm;
            ret.Renew = true;
            return ret;
        }

        /// <summary>
        /// Create a request from a kerberos credential for S4U2Self.
        /// </summary>
        /// <param name="credential">The kerberos TGT for the request.</param>
        /// <param name="username">The name of the user for S4U.</param>
        /// <param name="realm">The realm for S4U.</param>
        public static KerberosTGSRequest CreateForS4U2Self(KerberosCredential credential, string username, string realm)
        {
            if (username is null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            var ret = Create(credential);
            ret.EncryptTicketInSessionKey = true;
            ret.AddAdditionalTicket(ret.Ticket);
            ret.ServerName = ret.ClientName;
            ret.Realm = ret.ClientRealm;
            ret.S4UUserName = new KerberosPrincipalName(KerberosNameType.ENTERPRISE_PRINCIPAL, username);
            ret.S4URealm = realm;
            return ret;
        }

        /// <summary>
        /// Create a request from a kerberos credential for S4U2Proxy.
        /// </summary>
        /// <param name="credential">The kerberos TGT for the request.</param>
        /// <param name="server_name">The server name for the request.</param>
        /// <param name="realm">The server realm for the request.</param>
        /// <param name="user_ticket">The user ticket for the caller's service for the user to delegate.</param>
        public static KerberosTGSRequest CreateForS4U2Proxy(KerberosCredential credential, KerberosPrincipalName server_name, string realm, KerberosTicket user_ticket)
        {
            if (user_ticket is null)
            {
                throw new ArgumentNullException(nameof(user_ticket));
            }

            var ret = Create(credential, server_name, realm);
            ret.ClientNameInAdditionalTicket = true;
            ret.PACOptionsFlags = KerberosPreAuthenticationPACOptionsFlags.ResourceBasedConstrainedDelegation;
            ret.AddAdditionalTicket(user_ticket);
            return ret;
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

        private KerberosEncryptedData GetAuthorizationData()
        {
            if (AuthorizationData == null || AuthorizationData.Count == 0)
                return null;
            DERBuilder builder = new DERBuilder();
            builder.WriteSequence(AuthorizationData);
            return KerberosEncryptedData.Create(KerberosEncryptionType.NULL, builder.ToArray());
        }

        internal override KerberosKDCRequestBuilder ToBuilder()
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
                Nonce = KerberosBuilderUtils.GetRandomNonce(),
                TillTime = TillTime,
                AdditionalTickets = AdditionalTickets?.ToList(),
                AuthorizationData = GetAuthorizationData(),
            };
        }

        #endregion

        #region Private Members
        void SetKDCOption(KerberosKDCOptions opt, bool value)
        {
            if (value)
            {
                KDCOptions |= opt;
            }
            else
            {
                KDCOptions &= ~opt;
            }
        }

        private static KerberosTGSRequest Create(KerberosCredential credential)
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
    }
}
