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
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Builder for a Kerberos ticket.
    /// </summary>
    public sealed class KerberosTicketBuilder
    {
        #region Constructor
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ticket_version">Kerberos ticket version.</param>
        /// <param name="realm">The server realm.</param>
        /// <param name="server_name">The server name.</param>
        /// <param name="flags">The server flags.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="auth_time">The authentication time.</param>
        /// <param name="start_time">The start time.</param>
        /// <param name="end_time">The end time.</param>
        /// <param name="renew_till">The renew time.</param>
        /// <param name="key">The session key.</param>
        /// <param name="transited_type">The transited type.</param>
        /// <param name="host_addresses">List of host addresses.</param>
        /// <param name="authorization_data">List of authorization data.</param>
        public KerberosTicketBuilder(int ticket_version, string realm, KerberosPrincipalName server_name, KerberosTicketFlags flags, string client_realm, 
            KerberosPrincipalName client_name, KerberosTime auth_time, KerberosTime start_time, KerberosTime end_time, KerberosTime renew_till, 
            KerberosAuthenticationKey key, KerberosTransitedEncoding transited_type, 
            IEnumerable<KerberosHostAddress> host_addresses, IEnumerable<KerberosAuthorizationData> authorization_data)
        {
            TicketVersion = ticket_version;
            Realm = realm ?? throw new ArgumentNullException(nameof(realm));
            ServerName = server_name ?? throw new ArgumentNullException(nameof(server_name));
            Flags = flags;
            ClientRealm = client_realm ?? throw new ArgumentNullException(nameof(client_realm));
            ClientName = client_name ?? throw new ArgumentNullException(nameof(client_name));
            AuthTime = auth_time ?? throw new ArgumentNullException(nameof(auth_time));
            StartTime = start_time;
            EndTime = end_time ?? throw new ArgumentNullException(nameof(end_time));
            RenewTill = renew_till;
            Key = key ?? throw new ArgumentNullException(nameof(key));
            TransitedType = transited_type ?? throw new ArgumentNullException(nameof(transited_type));
            HostAddresses = host_addresses?.ToList();
            AuthorizationData = authorization_data?.Select(a => a.ToBuilder()).ToList();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosTicketBuilder()
        {
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Version number for the ticket.
        /// </summary>
        public int TicketVersion { get; set; }
        /// <summary>
        /// Realm.
        /// </summary>
        public string Realm { get; set; }
        /// <summary>
        /// Server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; set; }
        /// <summary>
        /// Ticket flags.
        /// </summary>
        public KerberosTicketFlags Flags { get; set; }
        /// <summary>
        /// Client Realm.
        /// </summary>
        public string ClientRealm { get; set; }
        /// <summary>
        /// Client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; set; }
        /// <summary>
        /// Authentication time,
        /// </summary>
        public KerberosTime AuthTime { get; set; }
        /// <summary>
        /// Start time.
        /// </summary>
        public KerberosTime StartTime { get; set; }
        /// <summary>
        /// End time.
        /// </summary>
        public KerberosTime EndTime { get; set; }
        /// <summary>
        /// Renew till time.
        /// </summary>
        public KerberosTime RenewTill { get; set; }
        /// <summary>
        /// The kerberos session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; set; }
        /// <summary>
        /// The ticket transited type information.
        /// </summary>
        public KerberosTransitedEncoding TransitedType { get; set; }
        /// <summary>
        /// List of host addresses for ticket.
        /// </summary>
        public List<KerberosHostAddress> HostAddresses { get; set; }
        /// <summary>
        /// List of authorization data.
        /// </summary>
        public List<KerberosAuthorizationDataBuilder> AuthorizationData { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Find a list of builders for a specific AD type.
        /// </summary>
        /// <param name="data_type">The AD type.</param>
        /// <returns>The list of builders. And empty list if not found.</returns>
        public IEnumerable<KerberosAuthorizationDataBuilder> FindAuthorizationDataBuilder(KerberosAuthorizationDataType data_type)
        {
            return AuthorizationData.FindAuthorizationDataBuilder(data_type);
        }

        /// <summary>
        /// Find the first builder for a specific AD type.
        /// </summary>
        /// <param name="data_type">The AD type.</param>
        /// <returns>The first builder. Returns null if not found.</returns>
        public KerberosAuthorizationDataBuilder FindFirstAuthorizationDataBuilder(KerberosAuthorizationDataType data_type)
        {
            return FindAuthorizationDataBuilder(data_type).FirstOrDefault();
        }

        /// <summary>
        /// Find a list of builders for a specific .NET type.
        /// </summary>
        /// <returns>The list of builders. And empty list if not found.</returns>
        /// <typeparam name="T">The type of builder to find.</typeparam>
        public IEnumerable<T> FindAuthorizationDataBuilder<T>() where T : KerberosAuthorizationDataBuilder
        {
            return AuthorizationData.FindAuthorizationDataBuilder<T>();
        }

        /// <summary>
        /// Find the first builder for a specific .NET type.
        /// </summary>
        /// <returns>The first builder. Returns null if not found.</returns>
        /// <typeparam name="T">The type of builder to find.</typeparam>
        public T FindFirstAuthorizationDataBuilder<T>() where T : KerberosAuthorizationDataBuilder
        {
            return FindAuthorizationDataBuilder<T>().FirstOrDefault();
        }

        /// <summary>
        /// Get the current builder for the PAC.
        /// </summary>
        /// <returns>The PAC builder.</returns>
        public KerberosAuthorizationDataPACBuilder FindPACBuilder()
        {
            return (KerberosAuthorizationDataPACBuilder)FindAuthorizationDataBuilder(KerberosAuthorizationDataType.AD_WIN2K_PAC).First();
        }

        /// <summary>
        /// Compute the KDC ticket signature for the ticket and add to the PAC.
        /// </summary>
        /// <param name="key">The krbtgt KDC key for the signature.</param>
        /// <remarks>You should call the PAC's <see cref="KerberosAuthorizationDataPACBuilder.ComputeSignatures(KerberosAuthenticationKey, KerberosAuthenticationKey)"/> method after creating the ticket signature to finish resigning.</remarks>
        public void ComputeTicketSignature(KerberosAuthenticationKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var pac = FindPACBuilder();
            try
            {
                pac.EncodeForTicketSignature = true;
                var signature = new KerberosAuthorizationDataPACSignatureBuilder(KerberosAuthorizationDataPACEntryType.TicketChecksum);
                signature.UpdateSignature(key, EncodeEncTicketPart());
                int index = pac.Entries.FindIndex(m => m.PACType == KerberosAuthorizationDataPACEntryType.TicketChecksum);
                if (index >= 0)
                    pac.Entries[index] = signature;
                else
                    pac.Entries.Add(signature);
            }
            finally
            {
                pac.EncodeForTicketSignature = false;
            }
        }

        /// <summary>
        /// Create the decrypted ticket.
        /// </summary>
        /// <returns></returns>
        public KerberosTicketDecrypted Create()
        {
            byte[] encoded = EncodeEncTicketPart();
            KerberosTicket outerTicket = KerberosTicket.Create(Realm, ServerName, 
                    KerberosEncryptedData.Create(KerberosEncryptionType.NULL, encoded));
            bool result = KerberosTicketDecrypted.Parse(outerTicket, encoded, 
                new KerberosKeySet(), out KerberosTicketDecrypted ticket);
            System.Diagnostics.Debug.Assert(result);

            return ticket;
        }
        #endregion

        #region Private Members
        private byte[] EncodeEncTicketPart()
        {
            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication(3))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, b => b.WriteBitString(Flags));
                    seq.WriteContextSpecific(1, Key);
                    seq.WriteContextSpecific(2, ClientRealm);
                    seq.WriteContextSpecific(3, ClientName);
                    seq.WriteContextSpecific(4, TransitedType);
                    seq.WriteContextSpecific(5, AuthTime);
                    seq.WriteContextSpecific(6, StartTime);
                    seq.WriteContextSpecific(7, EndTime);
                    seq.WriteContextSpecific(8, RenewTill);
                    seq.WriteContextSpecific(9, HostAddresses);
                    seq.WriteContextSpecific(10, AuthorizationData?.Select(o => o.Create()));
                }
            }

            return builder.ToArray();
        }
        #endregion
    }
}
