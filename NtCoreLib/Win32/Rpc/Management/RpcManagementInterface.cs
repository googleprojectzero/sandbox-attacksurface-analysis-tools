//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Transport;
using System.Collections.Generic;

#nullable enable

namespace NtCoreLib.Win32.Rpc.Management;

/// <summary>
/// Class to access RPC management interface.
/// </summary>
public sealed class RpcManagementInterface
{
    #region Private Members
    private readonly IRpcManagementInterface _mgmt;
    private readonly RpcStringBinding _string_binding;
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="string_binding">The string binding to query.</param>
    /// <param name="force_managed">Force using the managed client.</param>
    /// <param name="transport_security">Transport security for the managed client.</param>
    /// <param name="config">Configuration for the managed client.</param>
    public RpcManagementInterface(RpcStringBinding string_binding, bool force_managed = false, RpcTransportSecurity transport_security = default, RpcClientTransportConfiguration? config = null)
    {
        _string_binding = string_binding;
        if (!NtObjectUtils.IsWindows || force_managed)
            _mgmt = new RpcManagementInterfaceClientManaged(transport_security, config);
        else
            _mgmt = new RpcManagementInterfaceClientNative();
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Query for interfaces for a RPC binding. 
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of interfaces on the RPC binding.</returns>
    public NtResult<IEnumerable<RpcSyntaxIdentifier>> QueryInterfaces(bool throw_on_error)
    {
        return _mgmt.rpc_mgmt_inq_if_ids(_string_binding, throw_on_error).Cast<IEnumerable<RpcSyntaxIdentifier>>();
    }

    /// <summary>
    /// Query for interfaces for a RPC binding. 
    /// </summary>
    /// <returns>The list of endpoints on the RPC binding.</returns>
    public IEnumerable<RpcSyntaxIdentifier> QueryInterfaces()
    {
        return QueryInterfaces(true).Result;
    }

    /// <summary>
    /// Query the service principal name for the server.
    /// </summary>
    /// <param name="authn_svc">The authentication service to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service principal name.</returns>
    public NtResult<string> QueryServicePrincipalName(RpcAuthenticationType authn_svc, bool throw_on_error)
    {
        return _mgmt.rpc_mgmt_inq_princ_name(_string_binding, authn_svc, throw_on_error);
    }

    /// <summary>
    /// Query the service principal name for the server.
    /// </summary>
    /// <param name="authn_svc">The authentication service to query.</param>
    /// <returns>The service principal name.</returns>
    public string QueryServicePrincipalName(RpcAuthenticationType authn_svc)
    {
        return QueryServicePrincipalName(authn_svc, true).Result;
    }
    #endregion

    #region Static Methods
    /// <summary>
    /// Query for interfaces for a RPC binding. 
    /// </summary>
    /// <param name="string_binding">The RPC binding to query, e.g. ncalrpc:[PORT]</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of interfaces on the RPC binding.</returns>
    public static NtResult<IEnumerable<RpcSyntaxIdentifier>> QueryInterfaces(RpcStringBinding string_binding, bool throw_on_error)
    {
        return new RpcManagementInterface(string_binding).QueryInterfaces(throw_on_error);
    }

    /// <summary>
    /// Query for interfaces for a RPC binding. 
    /// </summary>
    /// <param name="string_binding">The RPC binding to query.</param>
    /// <returns>The list of endpoints on the RPC binding.</returns>
    public static IEnumerable<RpcSyntaxIdentifier> QueryInterfaces(RpcStringBinding string_binding)
    {
        return QueryInterfaces(string_binding, true).Result;
    }

    /// <summary>
    /// Query the service principal name for the server.
    /// </summary>
    /// <param name="string_binding">The binding string for the server.</param>
    /// <param name="authn_svc">The authentication service to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service principal name.</returns>
    public static NtResult<string> QueryServicePrincipalName(RpcStringBinding string_binding, RpcAuthenticationType authn_svc, bool throw_on_error)
    {
        return new RpcManagementInterface(string_binding).QueryServicePrincipalName(authn_svc, throw_on_error);
    }

    /// <summary>
    /// Query the service principal name for the server.
    /// </summary>
    /// <param name="string_binding">The binding string for the server.</param>
    /// <param name="authn_svc">The authentication service to query.</param>
    /// <returns>The service principal name.</returns>
    public static string QueryServicePrincipalName(RpcStringBinding string_binding, RpcAuthenticationType authn_svc)
    {
        return QueryServicePrincipalName(string_binding, authn_svc, true).Result;
    }
    #endregion
}