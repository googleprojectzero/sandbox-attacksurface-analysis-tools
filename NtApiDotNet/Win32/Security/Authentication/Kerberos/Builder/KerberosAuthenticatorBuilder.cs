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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Builder class for a Kerberos Authenticator.
    /// </summary>
    public sealed class KerberosAuthenticatorBuilder
    {
        /// <summary>
        /// Client realm.
        /// </summary>
        public string ClientRealm { get; set; }
        /// <summary>
        /// Client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; set; }
        /// <summary>
        /// Checksum value.
        /// </summary>
        public KerberosChecksum Checksum { get; set; }
        /// <summary>
        /// Client uS.
        /// </summary>
        public int ClientUSec { get; set; }
        /// <summary>
        /// Client time.
        /// </summary>
        public KerberosTime ClientTime { get; set; }
        /// <summary>
        /// Subkey.
        /// </summary>
        public KerberosAuthenticationKey SubKey { get; set; }
        /// <summary>
        /// Sequence number.
        /// </summary>
        public int? SequenceNumber { get; set; }
        /// <summary>
        /// Authorization data.
        /// </summary>
        public List<KerberosAuthorizationDataBuilder> AuthorizationData { get; set; }

        /// <summary>
        /// Add an authorization data entry.
        /// </summary>
        /// <param name="ad">The authorization data entry.</param>
        /// <remarks>Will create a List object as needed for AuthorizationData.</remarks>
        public void AddAuthorizationData(KerberosAuthorizationData ad)
        {
            AddAuthorizationData(ad?.ToBuilder());
        }

        /// <summary>
        /// Add an authorization data entry.
        /// </summary>
        /// <param name="ad">The authorization data entry.</param>
        /// <remarks>Will create a List object as needed for AuthorizationData.</remarks>
        public void AddAuthorizationData(KerberosAuthorizationDataBuilder ad)
        {
            if (ad is null)
            {
                throw new ArgumentNullException(nameof(ad));
            }

            if (AuthorizationData == null)
                AuthorizationData = new List<KerberosAuthorizationDataBuilder>();
            AuthorizationData.Add(ad);
        }

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
        /// Create the authenticator.
        /// </summary>
        /// <returns></returns>
        public KerberosAuthenticator Create()
        {
            return KerberosAuthenticator.Create(ClientRealm, ClientName, ClientTime,
                ClientUSec, Checksum, SubKey, SequenceNumber, AuthorizationData?.Select(d => d.Create()));
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosAuthenticatorBuilder()
        {
        }
    }
}
