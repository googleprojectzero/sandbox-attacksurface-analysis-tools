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

using NtApiDotNet.Win32.Security.Authentication.Ntlm.Client;
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
    internal sealed class NtlmManagedAuthenticationPackage : AuthenticationPackage
    {
        private class NtlmManagedCredentialHandle : ICredentialHandle
        {
            private readonly SecPkgCredFlags _cred_use_flag;
            private readonly AuthenticationCredentials _credentials;

            public NtlmManagedCredentialHandle(SecPkgCredFlags cred_use_flag,
                AuthenticationCredentials credentials)
            {
                _cred_use_flag = cred_use_flag;
                _credentials = credentials;
            }

            public string PackageName => NTLM_NAME;

            public IClientAuthenticationContext CreateClient(InitializeContextReqFlags req_attributes,
                string target, SecurityChannelBinding channel_binding, SecDataRep data_rep, bool initialize, bool owns_credentials)
            {
                if (!_cred_use_flag.HasFlagSet(SecPkgCredFlags.Outbound))
                    throw new ArgumentException("Credential handle not configured for outbound authentication.");

                NtlmClientAuthenticationContextConfig config = new NtlmClientAuthenticationContextConfig
                {
                    ChannelBinding = channel_binding
                };

                return new NtlmClientAuthenticationContext(_credentials, req_attributes, target, config, initialize);
            }

            public IServerAuthenticationContext CreateServer(AcceptContextReqFlags req_attributes = AcceptContextReqFlags.None, SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native, bool owns_credentials = false)
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            {
            }
        }

        internal NtlmManagedAuthenticationPackage() 
            : base(NTLM_NAME, SecPkgCapabilityFlag.Integrity | SecPkgCapabilityFlag.Privacy | SecPkgCapabilityFlag.Connection | SecPkgCapabilityFlag.Negotiable, 
                  0, 10, 2888, "NTLM Security Package (NtApiDotNet)", true)
        {
        }

        private protected override ICredentialHandle CreateManagedHandle(SecPkgCredFlags cred_use_flag, 
            AuthenticationCredentials credentials)
        {
            return new NtlmManagedCredentialHandle(cred_use_flag, credentials);
        }
    }
}
