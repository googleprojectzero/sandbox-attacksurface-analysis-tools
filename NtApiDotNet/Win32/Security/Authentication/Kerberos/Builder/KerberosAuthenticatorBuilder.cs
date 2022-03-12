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
        public DateTime ClientTime { get; set; }
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
        public List<KerberosAuthorizationData> AuthorizationData { get; set; }

        /// <summary>
        /// Add an authorization data entry.
        /// </summary>
        /// <param name="ad">The authorization data entry.</param>
        /// <remarks>Will create a List object as needed for AuthorizationData.</remarks>
        public void AddAuthorizationData(KerberosAuthorizationData ad)
        {
            if (AuthorizationData == null)
                AuthorizationData = new List<KerberosAuthorizationData>();
            AuthorizationData.Add(ad);
        }

        /// <summary>
        /// Create the authenticator.
        /// </summary>
        /// <returns></returns>
        public KerberosAuthenticator Create()
        {
            return KerberosAuthenticator.Create(ClientRealm, ClientName, ClientTime, 
                ClientUSec, Checksum, SubKey, SequenceNumber, AuthorizationData);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosAuthenticatorBuilder()
        {
        }
    }
}
