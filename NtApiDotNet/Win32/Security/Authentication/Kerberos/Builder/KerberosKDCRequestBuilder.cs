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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class to build a KDC-REQ object.
    /// </summary>
    public abstract class KerberosKDCRequestBuilder
    {
        /// <summary>
        /// Message type.
        /// </summary>
        public KerberosMessageType MessageType { get; }
        /// <summary>
        /// List of pre-authentication data.
        /// </summary>
        public List<KerberosPreAuthenticationData> PreAuthenticationData { get; set; }
        /// <summary>
        /// The KDC options flags.
        /// </summary>
        public KerberosKDCOptions KDCOptions { get; set; }
        /// <summary>
        /// The client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; set; }
        /// <summary>
        /// The server and/or client's realm.
        /// </summary>
        public string Realm { get; set; }
        /// <summary>
        /// The server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; set; }
        /// <summary>
        /// The from valid time.
        /// </summary>
        public KerberosTime FromTime { get; set; }
        /// <summary>
        /// The time valid time.
        /// </summary>
        public KerberosTime TillTime { get; set; }
        /// <summary>
        /// The renew till time.
        /// </summary>
        public KerberosTime RenewTill { get; set; }
        /// <summary>
        /// The nonce.
        /// </summary>
        public int Nonce { get; set; }
        /// <summary>
        /// List of supported encryption types.
        /// </summary>
        public List<KerberosEncryptionType> EncryptionTypes { get; set; }
        /// <summary>
        /// List of host addresses.
        /// </summary>
        public List<KerberosHostAddress> Addresses { get; set; }
        /// <summary>
        /// Encrypted authorization data.
        /// </summary>
        public KerberosEncryptedData AuthorizationData { get; set; }
        /// <summary>
        /// List of additional tickets.
        /// </summary>
        public List<KerberosTicket> AdditionalTickets { get; set; }

        /// <summary>
        /// Add some pre-authentication data.
        /// </summary>
        /// <param name="data">The data to add.</param>
        public void AddPreAuthenticationData(KerberosPreAuthenticationData data)
        {
            if (PreAuthenticationData == null)
                PreAuthenticationData = new List<KerberosPreAuthenticationData>();
            PreAuthenticationData.Add(data);
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

        /// <summary>
        /// Add a PA-FOR-USER structure and generate checksum.
        /// </summary>
        /// <param name="username">The user's principal name.</param>
        /// <param name="userrealm">The user's realm.</param>
        /// <param name="key">The key to generate the checksum.</param>
        public void AddPreAuthenticationDataForUser(KerberosPrincipalName username, 
            string userrealm, KerberosAuthenticationKey key)
        {
            if (username is null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (userrealm is null)
            {
                throw new ArgumentNullException(nameof(userrealm));
            }

            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm, Encoding.UTF8);
            writer.Write((int)username.NameType);
            foreach (var part in username.Names)
            {
                writer.Write(part.ToCharArray());
            }
            writer.Write(userrealm.ToCharArray());
            writer.Write("Kerberos".ToCharArray());

            KerberosChecksumEngine chk_engine = KerberosChecksumEngine.Get(KerberosChecksumType.HMAC_MD5);

            KerberosChecksum checksum = new KerberosChecksum(KerberosChecksumType.HMAC_MD5,
                chk_engine.ComputeHash(key.Key, stm.ToArray(), KerberosKeyUsage.KerbNonKerbChksumSalt));

            AddPreAuthenticationData(new KerberosPreAuthenticationDataForUser(username, userrealm, checksum, "Kerberos"));
        }


        /// <summary>
        /// Create the KDC-REQ authentication token.
        /// </summary>
        /// <returns>The created token.</returns>
        public KerberosKDCRequestAuthenticationToken Create()
        {
            return KerberosKDCRequestAuthenticationToken.Create(MessageType, Realm, TillTime, Nonce,
                EncryptionTypes, KDCOptions, PreAuthenticationData, ClientName, ServerName, FromTime,
                RenewTill, Addresses, AuthorizationData, AdditionalTickets);
        }

        /// <summary>
        /// Encode the body of the request. Commonly used for checksuming.
        /// </summary>
        /// <returns>The encoded body.</returns>
        public byte[] EncodeBody()
        {
            DERBuilder builder = new DERBuilder();
            KerberosKDCRequestAuthenticationToken.EncodeBody(builder, Realm, TillTime, Nonce,
                EncryptionTypes, KDCOptions, ClientName, ServerName,
                FromTime, RenewTill, Addresses, AuthorizationData, AdditionalTickets);
            return builder.ToArray();
        }

        private protected KerberosKDCRequestBuilder(KerberosMessageType type)
        {
            MessageType = type;
        }
    }
}
