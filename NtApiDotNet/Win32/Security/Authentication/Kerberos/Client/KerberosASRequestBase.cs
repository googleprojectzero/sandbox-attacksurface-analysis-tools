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
    /// Base class for an AS request.
    /// </summary>
    public abstract class KerberosASRequestBase : KerberosKDCRequest
    {
        #region Public Properties
        /// <summary>
        /// Specify to include the PAC in the ticket.
        /// </summary>
        public bool? IncludePac { get; set; }

        /// <summary>
        /// Specify additional pre-authentication data to send in the request.
        /// </summary>
        public List<KerberosPreAuthenticationData> AdditionalPreAuthenticationData { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert the request to a builder.
        /// </summary>
        /// <returns>The builder.</returns>
        public override KerberosKDCRequestBuilder ToBuilder()
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
                ServerName = ServerName ?? new KerberosPrincipalName(KerberosNameType.SRV_INST, $"krbtgt/{Realm.ToUpper()}"),
                Nonce = KerberosBuilderUtils.GetRandomNonce(),
                TillTime = TillTime
            };

            if (IncludePac.HasValue)
            {
                ret.AddPreAuthenticationData(new KerberosPreAuthenticationDataPACRequest(IncludePac.Value));
            }

            foreach (var pa_data in AdditionalPreAuthenticationData)
            {
                ret.AddPreAuthenticationData(pa_data);
            }
            return ret;
        }
        #endregion

        #region Private Members
        private void Validate()
        {
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
        #endregion

        #region Protected Members
        /// <summary>
        /// Constructor.
        /// </summary>
        protected KerberosASRequestBase()
        {
            TillTime = KerberosTime.MaximumTime;
            EncryptionTypes = new List<KerberosEncryptionType>();
            AdditionalPreAuthenticationData = new List<KerberosPreAuthenticationData>();
        }
        #endregion
    }
}
