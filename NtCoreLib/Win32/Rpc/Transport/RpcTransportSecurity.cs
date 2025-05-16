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

using NtCoreLib.Security.Token;
using NtCoreLib.Win32.Security.Authentication;
using System;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Class to represent the RPC transport security.
/// </summary>
public struct RpcTransportSecurity
{
    #region Private Members
    private readonly Func<RpcTransportSecurity, IClientAuthenticationContext> _auth_factory;
    private RpcAuthenticationType _auth_type;

    private readonly AuthenticationPackage GetAuthPackage()
    {
        if (_auth_type == RpcAuthenticationType.None)
            throw new ArgumentException("Must specify an authentication type to authenticate an RPC connection.");

        switch (_auth_type)
        {
            case RpcAuthenticationType.WinNT:
            case RpcAuthenticationType.Kerberos:
            case RpcAuthenticationType.Negotiate:
                break;
            default:
                throw new ArgumentException($"Unknown authentication type: {_auth_type}");
        }

        var rpc_id = (int)_auth_type;
        var package = AuthenticationPackage.Get().FirstOrDefault(p => p.RpcId == rpc_id);
        return package ?? throw new ArgumentException($"Unsupported authentication type: {_auth_type}");
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Get the context request flags for this RPC transport security.
    /// </summary>
    /// <returns>The context request flags.</returns>
    public readonly InitializeContextReqFlags GetContextRequestFlags()
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
    /// <param name="auth_factory">Factory to create a non-standard authentication context, based on an existing one.</param>
    /// <remarks>You can use this version to add functionality to the existing security context.</remarks>
    public RpcTransportSecurity(Func<IClientAuthenticationContext, IClientAuthenticationContext> auth_factory) : this()
    {
        _auth_factory = r => auth_factory(r.CreateClientContext(false));
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

    #region Internal Members
    internal readonly IClientAuthenticationContext CreateClientContext(bool call_auth_factory = true)
    {
        if (call_auth_factory && _auth_factory != null)
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

        return GetAuthPackage().CreateClient(Credentials, GetContextRequestFlags(), ServicePrincipalName);
    }
    #endregion
}
