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
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a AS request with a certificate.
    /// </summary>
    public sealed class KerberosAsRequestCertificate : KerberosASRequestBase
    {
        /// <summary>
        /// The certificate for the PKINIT request.
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="certificate">The certificate for the PKINIT request.</param>
        /// <param name="client_name">The client name for the ticket.</param>
        /// <param name="realm">The client and server realm realm.</param>
        public KerberosAsRequestCertificate(X509Certificate2 certificate, KerberosPrincipalName client_name, string realm)
        {
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            if (!Certificate.HasPrivateKey)
                throw new ArgumentException("Certificate must have a corresponding private key.");
            ClientName = client_name ?? throw new ArgumentNullException(nameof(client_name));
            Realm = realm ?? throw new ArgumentNullException(nameof(realm));
        }
    }
}
