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
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Base class for a KDC request.
    /// </summary>
    public abstract class KerberosKDCRequest
    {
        #region Public Properties
        /// <summary>
        /// The realm of the service.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// The name of the client principal.
        /// </summary>
        public KerberosPrincipalName ClientName { get; set; }

        /// <summary>
        /// Specify options for the new ticket.
        /// </summary>
        public KerberosKDCOptions KDCOptions { get; set; }

        /// <summary>
        /// Specify a list of encryption types.
        /// </summary>
        public List<KerberosEncryptionType> EncryptionTypes { get; set; }

        /// <summary>
        /// Specify the end time for the ticket.
        /// </summary>
        public KerberosTime TillTime { get; set; }

        /// <summary>
        /// Get or set the forwardable ticket option.
        /// </summary>
        public bool Forwardable
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.Forwardable);
            set => SetKDCOption(KerberosKDCOptions.Forwardable, value);
        }

        /// <summary>
        /// Get or set the forwarded ticket option.
        /// </summary>
        public bool Forwarded
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.Forwarded);
            set => SetKDCOption(KerberosKDCOptions.Forwarded, value);
        }

        /// <summary>
        /// Get or set the renew ticket option.
        /// </summary>
        public bool Renew
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.Renew);
            set => SetKDCOption(KerberosKDCOptions.Renew, value);
        }

        /// <summary>
        /// Get or set the renewable ticket option.
        /// </summary>
        public bool Renewable
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.Renewable);
            set => SetKDCOption(KerberosKDCOptions.Renewable, value);
        }

        /// <summary>
        /// Get or set the renewableok ticket option.
        /// </summary>
        public bool RenewableOK
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.RenewableOk);
            set => SetKDCOption(KerberosKDCOptions.RenewableOk, value);
        }

        /// <summary>
        /// Get or set the ENC-TKT-IN-SKEY ticket option.
        /// </summary>
        public bool EncryptTicketInSessionKey
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.EncTicketInSessionKey);
            set => SetKDCOption(KerberosKDCOptions.EncTicketInSessionKey, value);
        }

        /// <summary>
        /// Get or set the CNAME-IN-ADDL-TKT ticket option. Better known as constrained delegation.
        /// </summary>
        public bool ClientNameInAdditionalTicket
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.ClientNameInAdditionalTicket);
            set => SetKDCOption(KerberosKDCOptions.ClientNameInAdditionalTicket, value);
        }

        /// <summary>
        /// Get or set the canonicalize ticket option.
        /// </summary>
        public bool Canonicalize
        {
            get => KDCOptions.HasFlagSet(KerberosKDCOptions.Canonicalize);
            set => SetKDCOption(KerberosKDCOptions.Canonicalize, value);
        }

        #endregion

        #region Private Members
        void SetKDCOption(KerberosKDCOptions opt, bool value)
        {
            if (value)
            {
                KDCOptions |= opt;
            }
            else
            {
                KDCOptions &= ~opt;
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert the request to a builder.
        /// </summary>
        /// <returns>The builder.</returns>
        public abstract KerberosKDCRequestBuilder ToBuilder();
        #endregion
    }
}
