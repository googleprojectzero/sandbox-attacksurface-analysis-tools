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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Authentication;
using System;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Class to represent the RPC transport security.
    /// </summary>
    public struct RpcTransportSecurity
    {
        #region Private Members
        private readonly Func<RpcTransportSecurity, IClientAuthenticationContext> _auth_factory;
        private RpcAuthenticationType _auth_type;

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
            if (AuthenticationCapabilities.HasFlagSet(RpcAuthenticationCapabilities.Delegation))
            {
                flags |= InitializeContextReqFlags.Delegate | InitializeContextReqFlags.MutualAuth;
            }

            return flags;
        }

        #endregion

        #region Public Properties
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
        #endregion

        #region Constructors
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
        #endregion

        #region Static Members
        /// <summary>
        /// Query the service principal name for the server.
        /// </summary>
        /// <param name="string_binding">The binding string for the server.</param>
        /// <param name="authn_svc">The authentication service to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The service principal name.</returns>
        public static NtResult<string> QueryServicePrincipalName(string string_binding, RpcAuthenticationType authn_svc, bool throw_on_error)
        {
            using (var binding = SafeRpcBindingHandle.Create(string_binding, false))
            {
                if (!binding.IsSuccess)
                {
                    return binding.Cast<string>();
                }

                return Win32NativeMethods.RpcMgmtInqServerPrincName(binding.Result, authn_svc,
                    out SafeRpcStringHandle spn).CreateWin32Result(throw_on_error, () => {
                        using (spn)
                        {
                            return spn.ToString();
                        }
                    }
                    );
            }
        }

        /// <summary>
        /// Query the service principal name for the server.
        /// </summary>
        /// <param name="string_binding">The binding string for the server.</param>
        /// <param name="authn_svc">The authentication service to query.</param>
        /// <returns>The service principal name.</returns>
        public static string QueryServicePrincipalName(string string_binding, RpcAuthenticationType authn_svc)
        {
            return QueryServicePrincipalName(string_binding, authn_svc, true).Result;
        }
        #endregion

        #region Internal Members
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

            return new ClientAuthenticationContext(CredentialHandle.Create(GetAuthPackageName(),
                SecPkgCredFlags.Outbound, Credentials), GetContextRequestFlags(),
                    ServicePrincipalName, SecDataRep.Native) { OwnsCredentials = true };
        }
        #endregion
    }
}
