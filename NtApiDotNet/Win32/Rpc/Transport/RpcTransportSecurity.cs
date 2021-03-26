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
        private readonly Func<RpcTransportSecurity, IClientAuthenticationContext> _auth_factory;
        private RpcAuthenticationType _auth_type;

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
        public RpcAuthenticationType AuthenticationType
        {
            get => _auth_type;
            set => _auth_type = value == RpcAuthenticationType.Default ? RpcAuthenticationType.WinNT : value;
        }

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
        /// <param name="auth_factory">Factory to create a non-standard authentication context.</param>
        /// <remarks>You can use this version to create a mechanism to pass existing tokens such as pass-the-hash or sending arbitrary Kerberos tickets.</remarks>
        public RpcTransportSecurity(Func<RpcTransportSecurity, IClientAuthenticationContext> auth_factory) : this()
        {
            _auth_factory = auth_factory;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="security_quality_of_service">Security quality of service.</param>
        public RpcTransportSecurity(SecurityQualityOfService security_quality_of_service) : this()
        {
            SecurityQualityOfService = security_quality_of_service;
        }

        private string GetAuthPackageName()
        {
            switch (_auth_type)
            {
                case RpcAuthenticationType.Negotiate:
                    return AuthenticationPackage.NEGOSSP_NAME;
                case RpcAuthenticationType.Kerberos:
                    return AuthenticationPackage.KERBEROS_NAME;
                case RpcAuthenticationType.WinNT:
                    return AuthenticationPackage.NTLM_NAME;
                case RpcAuthenticationType.None:
                    throw new ArgumentException("Must specify an authentication type to authenticate an RPC connection.");
                default:
                    throw new ArgumentException($"Unknown authentication type: {_auth_type}");
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
                    case SecurityImpersonationLevel.Delegation:
                        flags |= InitializeContextReqFlags.Delegate | InitializeContextReqFlags.MutualAuth;
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

        internal IClientAuthenticationContext CreateClientContext()
        {
            if (_auth_factory != null)
                return _auth_factory(this);

            switch (AuthenticationLevel)
            {
                case RpcAuthenticationLevel.None:
                    return null;
                case RpcAuthenticationLevel.Connect:
                case RpcAuthenticationLevel.PacketIntegrity:
                case RpcAuthenticationLevel.PacketPrivacy:
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
