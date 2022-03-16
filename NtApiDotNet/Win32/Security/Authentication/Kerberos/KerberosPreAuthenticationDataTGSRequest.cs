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

using NtApiDotNet.Utilities.ASN1;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a PA-TGS-REQ pre-authentication data structure.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataTGSRequest : KerberosPreAuthenticationData
    {
        /// <summary>
        /// AP Request Options.
        /// </summary>
        public KerberosAPRequestOptions Options { get; }

        /// <summary>
        /// The Kerberos Ticket.
        /// </summary>
        public KerberosTicket Ticket { get; }

        /// <summary>
        /// Authenticator data.
        /// </summary>
        public KerberosEncryptedData Authenticator { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="options">The AP-REQ options.</param>
        /// <param name="ticket">The ticket for the AP-REQ</param>
        /// <param name="authenticator">The authentication for the AP-REQ.</param>
        public KerberosPreAuthenticationDataTGSRequest(KerberosAPRequestOptions options, KerberosTicket ticket, KerberosEncryptedData authenticator) 
            : base(KerberosPreAuthenticationType.PA_TGS_REQ)
        {
            Options = options;
            Ticket = ticket;
            Authenticator = authenticator;
        }

        internal static KerberosPreAuthenticationDataTGSRequest Parse(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (!KerberosAPRequestAuthenticationToken.TryParse(data, values, out KerberosAuthenticationToken token))
            {
                throw new InvalidDataException();
            }
            KerberosAPRequestAuthenticationToken ap_req = (KerberosAPRequestAuthenticationToken)token;
            return new KerberosPreAuthenticationDataTGSRequest(ap_req.Options, ap_req.Ticket, ap_req.Authenticator);
        }

        private protected override byte[] GetData()
        {
            return KerberosAPRequestAuthenticationToken.Create(Ticket, Authenticator, Options, 
                raw_token: true, tgs_req: true).ToArray();
        }
    }
}
