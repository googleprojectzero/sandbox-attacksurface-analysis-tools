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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    /// <summary>
    /// Base class for a KDC server which tokenizes the request and reponse.
    /// </summary>
    public abstract class KerberosKDCServerToken : KerberosKDCServer
    {
        private static AuthenticationToken GetGenericError()
        {
            return KerberosErrorAuthenticationToken.Create(KerberosTime.Now, 0, KerberosErrorType.GENERIC, "UNKNOWN",
                    new KerberosPrincipalName(KerberosNameType.SRV_INST, "UNKNOWN"),
                    KerberosTime.Now);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="listener">The network listener.</param>
        protected KerberosKDCServerToken(IKerberosKDCServerListener listener) : base(listener)
        {
        }

        /// <summary>
        /// Handle a request.
        /// </summary>
        /// <param name="request">The request to handle.</param>
        /// <returns>The reply.</returns>
        protected sealed override byte[] HandleRequest(byte[] request)
        {
            AuthenticationToken ret = null;
            if (KerberosKDCRequestAuthenticationToken.TryParse(request, out KerberosKDCRequestAuthenticationToken token))
                ret = HandleRequest(token);
            return (ret ?? GetGenericError()).ToArray();
        }

        /// <summary>
        /// Handle a tokenized request.
        /// </summary>
        /// <param name="request">The request token.</param>
        /// <returns>The response token.</returns>
        protected abstract AuthenticationToken HandleRequest(KerberosKDCRequestAuthenticationToken request);
    }
}
