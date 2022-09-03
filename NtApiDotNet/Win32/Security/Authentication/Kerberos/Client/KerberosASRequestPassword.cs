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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a AS request with a password.
    /// </summary>
    public sealed class KerberosASRequestPassword : KerberosASRequestBase
    {
        #region Public Properties
        /// <summary>
        /// The user's password.
        /// </summary>
        public string Password { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="password">The password for the user.</param>
        /// <param name="client_name">The client name for the ticket.</param>
        /// <param name="realm">The client and server realm realm.</param>
        public KerberosASRequestPassword(string password, KerberosPrincipalName client_name, string realm)
        {
            Password = password ?? throw new ArgumentNullException(nameof(password));
            ClientName = client_name ?? throw new ArgumentNullException(nameof(client_name));
            Realm = realm ?? throw new ArgumentNullException(nameof(realm));
        }
        #endregion

        #region Internal Members
        internal KerberosAuthenticationKey DeriveKey(KerberosEncryptionType enc_type, IEnumerable<KerberosPreAuthenticationData> pre_auth_data)
        {
            switch (enc_type)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                    return KerberosAuthenticationKey.DeriveKey(KerberosEncryptionType.ARCFOUR_HMAC_MD5, Password, 0, null, null, 0);
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.NULL:
                    break;
                default:
                    throw new ArgumentException($"Unsupported encryption type for key derivation {enc_type}", nameof(enc_type));
            }

            var etype_info2 = pre_auth_data?.OfType<KerberosPreAuthenticationDataEncryptionTypeInfo2>().FirstOrDefault();
            if (etype_info2 == null || etype_info2.Entries.Count == 0)
                throw new ArgumentException("No PA-ETYPE-INFO2 available.", nameof(pre_auth_data));
            var etype_entry = etype_info2.Entries.FirstOrDefault(e => enc_type == KerberosEncryptionType.NULL || e.EncryptionType == enc_type);
            if (etype_entry == null || etype_entry.Salt == null)
                throw new ArgumentException("No salt available for key.", nameof(pre_auth_data));
            return KerberosAuthenticationKey.DeriveKey(etype_entry.EncryptionType, Password, 4096, 
                KerberosNameType.PRINCIPAL, "UNKNOWN", etype_entry.Salt, 0);
        }
        #endregion
    }
}
