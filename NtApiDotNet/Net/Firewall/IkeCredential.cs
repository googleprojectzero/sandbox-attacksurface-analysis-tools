//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent an IKE credential.
    /// </summary>
    public class IkeCredential
    {
        /// <summary>
        /// Authentication method type.
        /// </summary>
        public IkeExtAuthenticationMethodType AuthenticationMethodType { get; }

        /// <summary>
        /// Impersonation type.
        /// </summary>
        public IkeExtAuthenticationImpersonationType ImpersonationType { get; }

        private protected IkeCredential(IKEEXT_CREDENTIAL1 creds)
        {
            AuthenticationMethodType = creds.authenticationMethodType;
            ImpersonationType = creds.impersonationType;
        }

        internal static IkeCredential Create(IKEEXT_CREDENTIAL1 creds)
        {
            if (creds.cred != IntPtr.Zero)
            {
                switch (creds.authenticationMethodType)
                {
                    case IkeExtAuthenticationMethodType.PreSharedKey:
                        return new IkePreSharedKeyCredential(creds);
                    case IkeExtAuthenticationMethodType.Certificate:
                    case IkeExtAuthenticationMethodType.Ssl:
                        return new IkeCertificateCredential(creds);
                    case IkeExtAuthenticationMethodType.NtlmV2:
                    case IkeExtAuthenticationMethodType.Kerberos:
                        return new IkeNameCredential(creds);
                    default:
                        System.Diagnostics.Trace.WriteLine($"Unknown cred type {creds.authenticationMethodType}");
                        break;
                }
            }
            return new IkeCredential(creds);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The pair as a string.</returns>
        public override string ToString()
        {
            return AuthenticationMethodType.ToString();
        }
    }
}
