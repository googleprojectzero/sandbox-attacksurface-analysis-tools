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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class to build a KDC-REP token.
    /// </summary>
    public abstract class KerberosKDCReplyBuilder
    {
        #region Public Properties
        /// <summary>
        /// Message type.
        /// </summary>
        public KerberosMessageType MessageType { get; }
        /// <summary>
        /// List of pre-authentication data.
        /// </summary>
        public List<KerberosPreAuthenticationData> PreAuthenticationData { get; set; }
        /// <summary>
        /// The client's realm.
        /// </summary>
        public string ClientRealm { get; set; }
        /// <summary>
        /// The client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; set; }
        /// <summary>
        /// The Keberos ticket.
        /// </summary>
        public KerberosTicket Ticket { get; set; }
        /// <summary>
        /// Encrypted data.
        /// </summary>
        public KerberosEncryptedData EncryptedData { get; set; }
        #endregion

        #region Public Methods
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
        public KerberosKDCReplyAuthenticationToken Create()
        {
            return KerberosKDCReplyAuthenticationToken.Create(MessageType, PreAuthenticationData, ClientRealm,
                ClientName, Ticket, EncryptedData);
        }
        #endregion

        #region Private Members
        private protected KerberosKDCReplyBuilder(KerberosMessageType message_type)
        {
            System.Diagnostics.Debug.Assert(message_type == KerberosMessageType.KRB_TGS_REP || message_type == KerberosMessageType.KRB_AS_REP);
            MessageType = message_type;
        }
        #endregion
    }
}
