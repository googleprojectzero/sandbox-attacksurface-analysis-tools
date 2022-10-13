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
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP
{
    /// <summary>
    /// Class to represent a TSSmartCardCreds structure.
    /// </summary>
    public sealed class TSSmartCardCredentials : TSCredentials
    {
        /// <summary>
        /// The smart card PIN.
        /// </summary>
        public string Pin { get; }

        /// <summary>
        /// The key spec.
        /// </summary>
        public int KeySpec { get; }

        /// <summary>
        /// The name of the card.
        /// </summary>
        public string CardName { get; }

        /// <summary>
        /// The reader name.
        /// </summary>
        public string ReaderName { get; }

        /// <summary>
        /// The container name.
        /// </summary>
        public string ContainerName { get; }

        /// <summary>
        /// The CSP name.
        /// </summary>
        public string CspName { get; }

        /// <summary>
        /// The user hint.
        /// </summary>
        public string UserHint { get; }

        /// <summary>
        /// The domain hint.
        /// </summary>
        public string DomainHint { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="pin">The smart card PIN.</param>
        /// <param name="keyspec">The key spec.</param>
        /// <param name="card_name">The name of the card.</param>
        /// <param name="reader_name">The reader name.</param>
        /// <param name="container_name">The container name.</param>
        /// <param name="csp_name">The CSP name.</param>
        /// <param name="user_hint">The user hint.</param>
        /// <param name="domain_hint">The domain hint.</param>
        public TSSmartCardCredentials(string pin, int keyspec, string card_name = null, 
            string reader_name = null, string container_name = null, string csp_name = null, string user_hint = null, string domain_hint = null) 
            : base(TSCredentialsType.SmartCard)
        {
            Pin = pin ?? throw new ArgumentNullException(nameof(pin));
            KeySpec = keyspec;
            CardName = card_name;
            ReaderName = reader_name;
            ContainerName = container_name;
            CspName = csp_name;
            UserHint = user_hint;
            DomainHint = domain_hint;
        }

        private static byte[] GetOctetString(string value)
        {
            if (value == null)
                return null;
            return Encoding.Unicode.GetBytes(value);
        }

        private void WriteCspData(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, KeySpec);
                seq.WriteContextSpecific(1, GetOctetString(CardName));
                seq.WriteContextSpecific(2, GetOctetString(ReaderName));
                seq.WriteContextSpecific(3, GetOctetString(ContainerName));
                seq.WriteContextSpecific(4, GetOctetString(CspName));
            }
        }

        private protected override byte[] GetCredentials()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, Encoding.Unicode.GetBytes(Pin));
                using (var cspdata = seq.CreateContextSpecific(1))
                {
                    WriteCspData(cspdata);
                }
                seq.WriteContextSpecific(2, GetOctetString(UserHint));
                seq.WriteContextSpecific(3, GetOctetString(DomainHint));
            }
            return builder.ToArray();
        }
    }
}
