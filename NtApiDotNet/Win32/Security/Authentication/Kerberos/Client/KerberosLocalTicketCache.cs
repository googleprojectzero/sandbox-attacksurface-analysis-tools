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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a local ticket cache.
    /// </summary>
    public sealed class KerberosLocalTicketCache
    {
        #region Private Members
        private readonly ConcurrentDictionary<KerberosPrincipalName, KerberosExternalTicket> _cache;
        private readonly KerberosKDCClient _kdc_client;
        private readonly string _realm;
        private KerberosExternalTicket _tgt_ticket;

        private static KerberosPrincipalName ConvertSPN(string server_name)
        {
            if (server_name is null)
            {
                throw new ArgumentNullException(nameof(server_name));
            }

            return new KerberosPrincipalName(KerberosNameType.SRV_INST, server_name);
        }

        private KerberosExternalTicket GetTicketFromKDC(KerberosPrincipalName server_name, bool cache_only = false)
        {
            if (cache_only)
                throw new ArgumentException($"Ticket for {server_name} doesn't exist in the cache.");
            if (_kdc_client is null)
                throw new ArgumentNullException($"No KDC client to request the ticket for {server_name}");
            if (_realm is null)
                throw new ArgumentNullException($"No realm to request the ticket for {server_name}");
            if (_tgt_ticket is null)
                throw new ArgumentNullException($"No TGT ticket to request the ticket for {server_name}");

            KerberosTGSRequest request = KerberosTGSRequest.Create(_tgt_ticket.Credential, server_name, _realm);
            return _kdc_client.RequestServiceTicket(request).ToExternalTicket();
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="additional_tickets">Additional tickets to add to the cache.</param>
        public KerberosLocalTicketCache(IEnumerable<KerberosExternalTicket> additional_tickets)
        {
            if (additional_tickets is null)
            {
                throw new ArgumentNullException(nameof(additional_tickets));
            }

            _cache = new ConcurrentDictionary<KerberosPrincipalName, KerberosExternalTicket>();
            _realm = string.Empty;
            foreach (var ticket in additional_tickets)
            {
                _cache.TryAdd(ticket.ServiceName, ticket);
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="tgt_ticket">The TGT ticket to request as a KRB_CRED.</param>
        /// <param name="kdc_client">The KDC client.</param>
        /// <param name="realm">The realm for the client.</param>
        /// <param name="additional_tickets">Additional tickets to add to the cache.</param>
        public KerberosLocalTicketCache(KerberosCredential tgt_ticket, KerberosKDCClient kdc_client, string realm = null,
            IEnumerable<KerberosExternalTicket> additional_tickets = null) : this(new KerberosExternalTicket(tgt_ticket), kdc_client,
                realm, additional_tickets)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="tgt_ticket">The TGT ticket to request.</param>
        /// <param name="kdc_client">The KDC client.</param>
        /// <param name="realm">The realm for the client.</param>
        /// <param name="additional_tickets">Additional tickets to add to the cache.</param>
        public KerberosLocalTicketCache(KerberosExternalTicket tgt_ticket, KerberosKDCClient kdc_client, string realm = null,
            IEnumerable<KerberosExternalTicket> additional_tickets = null) : this(additional_tickets ?? Array.Empty<KerberosExternalTicket>())
        {
            _tgt_ticket = tgt_ticket ?? throw new ArgumentNullException(nameof(tgt_ticket));
            _kdc_client = kdc_client ?? throw new ArgumentNullException(nameof(kdc_client));
            _realm = string.IsNullOrEmpty(realm) ? _tgt_ticket.Ticket.Realm.ToUpper() : _realm.ToUpper();
        }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Populate a local cache using the system cache in LSA.
        /// </summary>
        /// <param name="logon_id">The logon ID for the cache to query.</param>
        /// <param name="create_client">True to create a KDC client based on the system's domain.</param>
        /// <returns>The local ticket cache.</returns>
        public static KerberosLocalTicketCache FromSystemCache(bool create_client = false, Luid logon_id = new Luid())
        {
            var tickets = KerberosTicketCache.QueryTicketCache(logon_id);
            if (create_client)
            {
                var tgt_ticket = tickets.FirstOrDefault(t => t.ServiceName.FullName.StartsWith("krbtgt/") && !t.SessionKey.IsZeroKey);
                if (tgt_ticket == null)
                    throw new ArgumentException("No cached TGT for the system with a valid session key.");
                Domain domain = logon_id.ToInt64() == 0 ? Domain.GetCurrentDomain() : Domain.GetComputerDomain();
                return new KerberosLocalTicketCache(tgt_ticket,
                    KerberosKDCClient.CreateTCPClient(domain.PdcRoleOwner.IPAddress), domain.Name, tickets);
            }
            return new KerberosLocalTicketCache(tickets);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get whether the cache contains a ticket.
        /// </summary>
        /// <param name="server_name">The server name.</param>
        /// <returns>True if the cache contains a ticket.</returns>
        public bool ContainsTicket(KerberosPrincipalName server_name)
        {
            return _cache.ContainsKey(server_name);
        }

        /// <summary>
        /// Get whether the cache contains a ticket.
        /// </summary>
        /// <param name="server_name">The server name.</param>
        /// <returns>True if the cache contains a ticket.</returns>
        public bool ContainsTicket(string server_name)
        {
            return ContainsTicket(ConvertSPN(server_name));
        }

        /// <summary>
        /// Create a client context for a server name.
        /// </summary>
        /// <param name="server_name">The server name.</param>
        /// <param name="request_attributes">The request attributes.</param>
        /// <param name="cache_only">If true then only the cache will be queried, a request won't be made to the KDC.</param>
        /// <returns>The client authentication context.</returns>
        public KerberosClientAuthenticationContext CreateClientContext(KerberosPrincipalName server_name, 
            InitializeContextReqFlags request_attributes, bool cache_only = false)
        {
            if (server_name is null)
            {
                throw new ArgumentNullException(nameof(server_name));
            }

            return new KerberosClientAuthenticationContext(GetTicket(server_name, cache_only), request_attributes);
        }

        /// <summary>
        /// Create a client context for a server name.
        /// </summary>
        /// <param name="server_name">The server name.</param>
        /// <param name="request_attributes">The request attributes.</param>
        /// <param name="cache_only">If true then only the cache will be queried, a request won't be made to the KDC.</param>
        /// <returns>The client authentication context.</returns>
        public KerberosClientAuthenticationContext CreateClientContext(string server_name, InitializeContextReqFlags request_attributes, bool cache_only = false)
        {
            return CreateClientContext(ConvertSPN(server_name), request_attributes, cache_only);
        }

        /// <summary>
        /// Get a ticket for a server name.
        /// </summary>
        /// <param name="server_name">The server name.</param>
        /// <param name="cache_only">True to only query the cache.</param>
        /// <returns>The ticket.</returns>
        public KerberosExternalTicket GetTicket(KerberosPrincipalName server_name, bool cache_only = false)
        {
            return _cache.GetOrAdd(server_name, _ => GetTicketFromKDC(server_name, cache_only));
        }

        /// <summary>
        /// Get a ticket for a server name.
        /// </summary>
        /// <param name="server_name">The server name.</param>
        /// <param name="cache_only">True to only query the cache.</param>
        /// <returns>The ticket.</returns>
        public KerberosExternalTicket GetTicket(string server_name, bool cache_only = false)
        {
            return GetTicket(ConvertSPN(server_name), cache_only);
        }

        /// <summary>
        /// Add an existing ticket to the cache.
        /// </summary>
        /// <param name="ticket">The ticket to add.</param>
        public void AddTicket(KerberosExternalTicket ticket)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }
            if (!_cache.TryAdd(ticket.ServiceName, ticket))
            {
                throw new ArgumentException($"Ticket already exists with this service name {ticket.ServiceName}");
            }
        }

        /// <summary>
        /// Add an existing ticket to the cache.
        /// </summary>
        /// <param name="credential">The ticket to add as a KRB_CRED.</param>
        public void AddTicket(KerberosCredential credential)
        {
            if (credential is null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            AddTicket(new KerberosExternalTicket(credential));
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get the list of cached tickets.
        /// </summary>
        public IEnumerable<KerberosExternalTicket> Tickets => _cache.Values.ToArray();
        #endregion
    }
}
