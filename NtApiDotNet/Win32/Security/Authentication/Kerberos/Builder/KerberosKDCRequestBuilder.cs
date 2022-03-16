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
        public IReadOnlyList<KerberosEncryptionType> EncryptionTypes { get; set; }
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
        /// Create the KDC-REQ authentication token.
        /// </summary>
        /// <returns>The created token.</returns>
        public KerberosKDCRequestAuthenticationToken Create()
        {
            return KerberosKDCRequestAuthenticationToken.Create(MessageType, Realm, TillTime, Nonce,
                EncryptionTypes, KDCOptions, PreAuthenticationData, ClientName, ServerName, FromTime,
                RenewTill, Addresses, AuthorizationData, AdditionalTickets);
        }

        private protected KerberosKDCRequestBuilder(KerberosMessageType type)
        {
            MessageType = type;
        }

        internal byte[] EncodeBody()
        {
            DERBuilder builder = new DERBuilder();
            KerberosKDCRequestAuthenticationToken.EncodeBody(builder, Realm, TillTime, Nonce,
                EncryptionTypes, KDCOptions, ClientName, ServerName,
                null, null, null, null, null);
            return builder.ToArray();
        }
    }
}
