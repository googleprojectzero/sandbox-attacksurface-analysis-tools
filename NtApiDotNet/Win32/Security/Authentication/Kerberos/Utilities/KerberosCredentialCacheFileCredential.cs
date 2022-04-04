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
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    /// <summary>
    /// Class to represent a kerbero cache file credential.
    /// </summary>
    public sealed class KerberosCredentialCacheFileCredential
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="client">The ticket client principal.</param>
        /// <param name="server">The ticket server principal.</param>
        /// <param name="key">The ticket session key.</param>
        /// <param name="auth_time">The ticket authentication time.</param>
        /// <param name="start_time">The ticket start time.</param>
        /// <param name="end_time">The ticket end time.</param>
        /// <param name="renew_till">The ticket renew time.</param>
        /// <param name="is_session_key">Whether the ticket is encrypted with a session key.</param>
        /// <param name="ticket_flags">Ticket flags.</param>
        /// <param name="addresses">List of host addresses.</param>
        /// <param name="auth_data">Authentication data.</param>
        /// <param name="ticket">The kerberos ticket.</param>
        /// <param name="second_ticket">The secondary ticket, used when encrypted using a session key.</param>
        public KerberosCredentialCacheFileCredential(KerberosCredentialCacheFilePrincipal client, KerberosCredentialCacheFilePrincipal server, 
            KerberosAuthenticationKey key, KerberosTime auth_time, 
            KerberosTime start_time, KerberosTime end_time, KerberosTime renew_till, 
            bool is_session_key, KerberosTicketFlags ticket_flags, IEnumerable<KerberosHostAddress> addresses,
            IEnumerable<KerberosAuthorizationData> auth_data, KerberosTicket ticket, KerberosTicket second_ticket)
        {
            Client = client ?? throw new System.ArgumentNullException(nameof(client));
            Server = server ?? throw new System.ArgumentNullException(nameof(server));
            Key = key ?? throw new System.ArgumentNullException(nameof(key));
            AuthTime = auth_time;
            StartTime = start_time;
            EndTime = end_time;
            RenewTill = renew_till;
            IsSessionKey = is_session_key;
            TicketFlags = ticket_flags;
            Addresses = addresses?.ToList().AsReadOnly();
            AuthData = auth_data?.ToList().AsReadOnly();
            Ticket = ticket ?? throw new System.ArgumentNullException(nameof(ticket));
            SecondTicket = second_ticket;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket">The external ticket.</param>
        public KerberosCredentialCacheFileCredential(KerberosExternalTicket ticket) 
            : this(new KerberosCredentialCacheFilePrincipal(ticket.ClientName, ticket.TargetDomainName),
                    new KerberosCredentialCacheFilePrincipal(ticket.ServiceName, ticket.DomainName),
                    ticket.SessionKey, null, ticket.StartTime.ToKerbTime(), ticket.EndTime.ToKerbTime(), 
                    ticket.RenewUntil.ToKerbTime(), false, ticket.TicketFlags, null, null, ticket.Ticket, null)
        {
        }

        /// <summary>
        /// The ticket client principal.
        /// </summary>
        public KerberosCredentialCacheFilePrincipal Client { get; }
        /// <summary>
        /// The ticket server principal.
        /// </summary>
        public KerberosCredentialCacheFilePrincipal Server { get; }
        /// <summary>
        /// The ticket session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; }
        /// <summary>
        /// The ticket authentication time.
        /// </summary>
        public KerberosTime AuthTime { get; }
        /// <summary>
        /// The ticket start time.
        /// </summary>
        public KerberosTime StartTime { get; }
        /// <summary>
        /// The ticket end time.
        /// </summary>
        public KerberosTime EndTime { get; }
        /// <summary>
        /// The ticket renew time.
        /// </summary>
        public KerberosTime RenewTill { get; }
        /// <summary>
        /// Whether the ticket is encrypted with a session key.
        /// </summary>
        public bool IsSessionKey { get; }
        /// <summary>
        /// Ticket flags.
        /// </summary>
        public KerberosTicketFlags TicketFlags { get; }
        /// <summary>
        /// List of host addresses.
        /// </summary>
        public IReadOnlyList<KerberosHostAddress> Addresses { get; }
        /// <summary>
        /// Authentication data.
        /// </summary>
        public IReadOnlyList<KerberosAuthorizationData> AuthData { get; }
        /// <summary>
        /// The kerberos ticket.
        /// </summary>
        public KerberosTicket Ticket { get; }
        /// <summary>
        /// The secondary ticket, used when encrypted using a session key.
        /// </summary>
        public KerberosTicket SecondTicket { get; }

        /// <summary>
        /// Convert the cached entry to a KRB-CRED.
        /// </summary>
        /// <returns>The KRB-CRED structure.</returns>
        public KerberosCredential ToCredential()
        {
            var cred_info = new KerberosCredentialInfo(Key, Client.Realm,
                Client.Name, TicketFlags, AuthTime, StartTime, EndTime, RenewTill, Server.Realm, Server.Name, Addresses);
            var enc_part = KerberosCredentialEncryptedPart.Create(new[] { cred_info });
            return KerberosCredential.Create(new[] { Ticket }, enc_part);
        }

        /// <summary>
        /// Convert the cached entry to an external ticket.
        /// </summary>
        /// <returns>The external ticket.</returns>
        public KerberosExternalTicket ToTicket()
        {
            return new KerberosExternalTicket(ToCredential());
        }

        internal void Write(BinaryWriter writer)
        {
            writer.WritePrincipal(Client);
            writer.WritePrincipal(Server);
            writer.WriteKeyBlock(Key);
            writer.WriteUnixTime(AuthTime);
            writer.WriteUnixTime(StartTime);
            writer.WriteUnixTime(EndTime);
            writer.WriteUnixTime(RenewTill);
            writer.Write((byte)(IsSessionKey ? 1 : 0));
            writer.WriteUInt32BE(((uint)TicketFlags).RotateBits());
            writer.WriteAddresses(Addresses);
            writer.WriteAuthData(AuthData);
            writer.WriteTicket(Ticket);
            writer.WriteTicket(SecondTicket);
        }
    }
}
