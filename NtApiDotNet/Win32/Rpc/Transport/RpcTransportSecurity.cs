//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Authentication;
using System;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Class to represent the RPC transport security.
    /// </summary>
    public struct RpcTransportSecurity
    {
        /// <summary>
        /// Security quality of service.
        /// </summary>
        public SecurityQualityOfService SecurityQualityOfService { get; set; }

        /// <summary>
        /// Authentication level.
        /// </summary>
        public RpcAuthenticationLevel AuthenticationLevel { get; set; }

        /// <summary>
        /// Authentication type.
        /// </summary>
        public RpcAuthenticationType AuthenticationType { get; set; }

        /// <summary>
        /// Authentication credentials.
        /// </summary>
        public AuthenticationCredentials Credentials { get; set; }

        /// <summary>
        /// The SPN for the authentication.
        /// </summary>
        public string ServicePrincipalName { get; set; }

        /// <summary>
        /// Authentication capabilities.
        /// </summary>
        public RpcAuthenticationCapabilities AuthenticationCapabilities { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="security_quality_of_service">Security quality of service.</param>
        public RpcTransportSecurity(SecurityQualityOfService security_quality_of_service)
        {
            SecurityQualityOfService = security_quality_of_service;
            AuthenticationLevel = RpcAuthenticationLevel.None;
            AuthenticationType = RpcAuthenticationType.None;
            AuthenticationCapabilities = RpcAuthenticationCapabilities.None;
            Credentials = null;
            ServicePrincipalName = null;
        }

        private string GetAuthPackageName()
        {
            switch (AuthenticationType)
            {
                case RpcAuthenticationType.Negotiate:
                    return "Negotiate";
                case RpcAuthenticationType.Kerberos:
                    return "Kerberos";
                case RpcAuthenticationType.WinNT:
                    return "NTLM";
                case RpcAuthenticationType.None:
                    throw new ArgumentException("Must specify an authentication type to authenticate an RPC connection.");
                default:
                    throw new ArgumentException($"Unknown authentication type: {AuthenticationType}");
            }
        }

        private InitializeContextReqFlags GetContextRequestFlags()
        {
            InitializeContextReqFlags flags = InitializeContextReqFlags.Connection | InitializeContextReqFlags.UseDCEStyle;
            if (SecurityQualityOfService != null)
            {
                switch (SecurityQualityOfService.ImpersonationLevel)
                {
                    case SecurityImpersonationLevel.Identification:
                        flags |= InitializeContextReqFlags.Identify;
                        break;
                }
            }

            switch (AuthenticationLevel)
            {
                case RpcAuthenticationLevel.PacketIntegrity:
                    flags |= InitializeContextReqFlags.Integrity | InitializeContextReqFlags.ReplayDetect | InitializeContextReqFlags.SequenceDetect;
                    break;
                case RpcAuthenticationLevel.PacketPrivacy:
                    flags |= InitializeContextReqFlags.Confidentiality | InitializeContextReqFlags.Integrity | InitializeContextReqFlags.ReplayDetect | InitializeContextReqFlags.SequenceDetect;
                    break;
            }

            if (AuthenticationCapabilities.HasFlagSet(RpcAuthenticationCapabilities.Delegation))
            {
                flags |= InitializeContextReqFlags.Delegate;
            }
            if (AuthenticationCapabilities.HasFlagSet(RpcAuthenticationCapabilities.MutualAuthentication))
            {
                flags |= InitializeContextReqFlags.MutualAuth;
            }
            if (AuthenticationCapabilities.HasFlagSet(RpcAuthenticationCapabilities.NullSession))
            {
                flags |= InitializeContextReqFlags.NullSession;
            }

            return flags;
        }

        internal ClientAuthenticationContext CreateClientContext()
        {
            switch (AuthenticationLevel)
            {
                case RpcAuthenticationLevel.None:
                    return null;
                case RpcAuthenticationLevel.Connect:
                case RpcAuthenticationLevel.PacketIntegrity:
                    break;
                default:
                    throw new ArgumentException($"Unsupported authentication level {AuthenticationLevel}");
            }

            using (var creds = CredentialHandle.Create(GetAuthPackageName(),
                    SecPkgCredFlags.Outbound, Credentials))
            {
                return new ClientAuthenticationContext(creds, GetContextRequestFlags(),
                    ServicePrincipalName, SecDataRep.Native);
            }
        }
    }
}
