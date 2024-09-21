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

using NtApiDotNet.Win32.Security.Authentication.Kerberos.Client;
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    internal sealed class KerberosManagedAuthenticationPackage : AuthenticationPackage
    {
        private class KerberosManagedCredentialHandle : ICredentialHandle
        {
            private readonly SecPkgCredFlags _cred_use_flag;
            private readonly AuthenticationCredentials _credentials;

            public KerberosManagedCredentialHandle(SecPkgCredFlags cred_use_flag,
                AuthenticationCredentials credentials)
            {
                _cred_use_flag = cred_use_flag;
                _credentials = credentials;
            }

            public string PackageName => KERBEROS_NAME;

            public IClientAuthenticationContext CreateClient(InitializeContextReqFlags req_attributes,
                string target, SecurityChannelBinding channel_binding, SecDataRep data_rep, bool initialize, bool owns_credentials = false)
            {
                if (!_cred_use_flag.HasFlagSet(SecPkgCredFlags.Outbound))
                    throw new ArgumentException("Credential handle not configured for outbound authentication.");

                KerberosClientAuthenticationContextConfig config = new KerberosClientAuthenticationContextConfig();
                config.ChannelBinding = channel_binding;

                return new KerberosClientAuthenticationContext(_credentials, target, req_attributes, config, initialize);
            }

            public IServerAuthenticationContext CreateServer(AcceptContextReqFlags req_attributes = AcceptContextReqFlags.None, SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native, bool owns_credentials = false)
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            {
            }
        }

        internal KerberosManagedAuthenticationPackage()
            : base(KERBEROS_NAME, SecPkgCapabilityFlag.Integrity | SecPkgCapabilityFlag.Privacy | SecPkgCapabilityFlag.Connection | 
                  SecPkgCapabilityFlag.Negotiable | SecPkgCapabilityFlag.MutualAuth | SecPkgCapabilityFlag.Delegation,
                  0, 16, 48000, "Kerberos Security Package (NtApiDotNet)", true)
        {
        }

        private protected override ICredentialHandle CreateManagedHandle(SecPkgCredFlags cred_use_flag,
            AuthenticationCredentials credentials)
        {
            return new KerberosManagedCredentialHandle(cred_use_flag, credentials);
        }
    }
}
