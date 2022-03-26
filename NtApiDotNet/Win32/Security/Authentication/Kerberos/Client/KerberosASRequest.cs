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
    /// Class to represent an AS request.
    /// </summary>
    public sealed class KerberosASRequest : KerberosKDCRequest
    {
        /// <summary>
        /// The key for the principal.
        /// </summary>
        public KerberosAuthenticationKey Key { get; set; }

        /// <summary>
        /// Specify to include the PAC in the ticket.
        /// </summary>
        public bool? IncludePac { get; set; }

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key">The kerberos key for the user.</param>
        /// <param name="client_name">The client name for the ticket.</param>
        /// <param name="realm">The client and server realm realm.</param>
        public KerberosASRequest(KerberosAuthenticationKey key, KerberosPrincipalName client_name, string realm)
        {
            Key = key;
            ClientName = client_name ?? throw new ArgumentNullException(nameof(client_name));
            Realm = realm ?? throw new ArgumentNullException(nameof(realm));
            TillTime = KerberosTime.MaximumTime;
            EncryptionTypes = new List<KerberosEncryptionType>();
        }
        #endregion

        private void Validate()
        {
            if (Key is null)
            {
                throw new ArgumentNullException(nameof(Key));
            }
            if (string.IsNullOrEmpty(Realm))
            {
                throw new ArgumentException($"{nameof(Realm)} must not be empty.");
            }
            if (TillTime is null)
            {
                throw new ArgumentNullException(nameof(TillTime));
            }
            if (ClientName is null)
            {
                throw new ArgumentNullException(nameof(ClientName));
            }
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

            var ret = new KerberosASRequestBuilder
            {
                ClientName = ClientName,
                EncryptionTypes = encryption_types,
                KDCOptions = KDCOptions,
                Realm = Realm,
                ServerName = new KerberosPrincipalName(KerberosNameType.SRV_INST, $"krbtgt/{Realm.ToUpper()}"),
                Nonce = KerberosBuilderUtils.GetRandomNonce(),
                TillTime = TillTime
            };
            ret.AddPreAuthenticationData(KerberosPreAuthenticationDataEncTimestamp.Create(KerberosTime.Now, Key));
            if (IncludePac.HasValue)
            {
                ret.AddPreAuthenticationData(new KerberosPreAuthenticationDataPACRequest(IncludePac.Value));
            }
            return ret;
        }
    }
}
