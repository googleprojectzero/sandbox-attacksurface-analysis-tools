//  Copyright 2018 Google Inc. All Rights Reserved.
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
using NtCoreLib.Win32.Rpc.Client;
using NtCoreLib.Win32.Rpc.Management;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

/// <summary>
/// Static class to access information from the RPC mapper.
/// </summary>
public static class RpcEndpointMapper
{
    #region Private Members
    private static readonly IRpcEndpointMapper _ep_mapper_native = new RpcEndpointMapperNative();
    private static readonly IRpcEndpointMapper _ep_mapper_managed = new RpcEndpointMapperManaged();

    private static IRpcEndpointMapper GetMapper(bool force_managed = false)
    {
        if (UseManagedClient || !NtObjectUtils.IsWindows || force_managed)
            return _ep_mapper_managed;
        return _ep_mapper_native;
    }

    private static RpcEndpoint CreateEndpoint(RpcStringBinding binding, RpcSyntaxIdentifier if_id)
    {
        var endpoints = GetMapper().LookupEndpoint(binding, RpcEndpointInquiryFlag.Interface,
            if_id, RpcEndPointVersionOption.Exact, null, false).ToArray();
        RpcEndpoint ret = endpoints.Where(ep => ep.Binding == binding).FirstOrDefault();
        return ret ?? new RpcEndpoint(if_id, binding);
    }

    private const string RPC_CONTROL_PATH = @"\RPC Control\";

    #endregion

    #region Static Properties
    /// <summary>
    /// Set whether to use the managed client or native client.
    /// </summary>
    /// <remarks>On non-Windows systems this value is ignored and the managed client always used.</remarks>
    public static bool UseManagedClient { get; set; }
    #endregion

    #region Static Methods
    /// <summary>
    /// Query all endpoints registered on the local system.
    /// </summary>
    /// <returns>List of endpoints.</returns>
    public static IEnumerable<RpcEndpoint> QueryAllEndpoints()
    {
        return GetMapper().LookupEndpoint(null, RpcEndpointInquiryFlag.All, null, RpcEndPointVersionOption.All, null);
    }

    /// <summary>
    /// Query all endpoints registered based on a binding string.
    /// </summary>
    /// <param name="search_binding">The binding string for the server to search on. If null or empty will search localhost.</param>
    /// <returns>List of endpoints.</returns>
    public static IEnumerable<RpcEndpoint> QueryAllEndpoints(RpcStringBinding search_binding)
    {
        return GetMapper().LookupEndpoint(search_binding, RpcEndpointInquiryFlag.All, null, RpcEndPointVersionOption.All, null);
    }

    /// <summary>
    /// Query for endpoints registered on the local system for an RPC endpoint.
    /// </summary>
    /// <param name="search_binding">The binding string for the server to search on. If null or empty will search localhost.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The list of registered RPC endpoints.</returns>
    public static IEnumerable<RpcEndpoint> QueryEndpointsForInterface(RpcStringBinding search_binding, RpcSyntaxIdentifier interface_id)
    {
        return GetMapper().LookupEndpoint(search_binding, RpcEndpointInquiryFlag.Interface, interface_id,
            RpcEndPointVersionOption.Exact, null);
    }

    /// <summary>
    /// Query for endpoints registered on the local system for an RPC endpoint ignoring the version.
    /// </summary>
    /// <param name="search_binding">The binding string for the server to search on. If null or empty will search localhost.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The list of registered RPC endpoints.</returns>
    public static IEnumerable<RpcEndpoint> QueryEndpointsForInterface(RpcStringBinding search_binding, Guid interface_id)
    {
        return GetMapper().LookupEndpoint(search_binding, RpcEndpointInquiryFlag.Interface,
            new RpcSyntaxIdentifier(interface_id), RpcEndPointVersionOption.All, null);
    }

    /// <summary>
    /// Query for endpoints registered on the local system for an RPC endpoint via ALPC.
    /// </summary>
    /// <param name="interface_id">Interface to lookup.</param>
    /// <returns>The list of registered RPC endpoints.</returns>
    public static IEnumerable<RpcEndpoint> QueryAlpcEndpoints(RpcSyntaxIdentifier interface_id)
    {
        return GetMapper().LookupEndpoint(null, RpcEndpointInquiryFlag.Interface, interface_id,
            RpcEndPointVersionOption.Exact, null).Where(e => e.ProtocolSequence.Equals(RpcProtocolSequence.LRPC, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Query for endpoints registered on the local system for an RPC endpoint via ALPC.
    /// </summary>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <param name="interface_version">Interface version lookup.</param>
    /// <returns>The list of registered RPC endpoints.</returns>
    public static IEnumerable<RpcEndpoint> QueryAlpcEndpoints(Guid interface_id, RpcVersion interface_version)
    {
        return QueryAlpcEndpoints(new RpcSyntaxIdentifier(interface_id, interface_version));
    }

    /// <summary>
    /// Query for endpoints for a RPC binding. 
    /// </summary>
    /// <param name="alpc_port">The ALPC port to query. Can be a full path as long as it contains \RPC Control\ somewhere.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of endpoints on the RPC binding.</returns>
    public static NtResult<IEnumerable<RpcEndpoint>> QueryEndpointsForAlpcPort(string alpc_port, bool throw_on_error)
    {
        int index = alpc_port.IndexOf(@"\RPC Control\", StringComparison.OrdinalIgnoreCase);
        if (index >= 0)
        {
            alpc_port = alpc_port.Substring(0, index) + RPC_CONTROL_PATH + alpc_port.Substring(index + RPC_CONTROL_PATH.Length);
        }

        RpcStringBinding binding = new RpcStringBinding(RpcProtocolSequence.LRPC, null, alpc_port);
        return QueryEndpointsForBinding(binding, throw_on_error);
    }

    /// <summary>
    /// Query for endpoints for a RPC binding. 
    /// </summary>
    /// <param name="alpc_port">The ALPC port to query. Can be a full path as long as it contains \RPC Control\ somewhere.</param>
    /// <returns>The list of endpoints on the RPC binding.</returns>
    public static IEnumerable<RpcEndpoint> QueryEndpointsForAlpcPort(string alpc_port)
    {
        return QueryEndpointsForAlpcPort(alpc_port, true).Result;
    }

    /// <summary>
    /// Query for endpoints for a RPC binding. 
    /// </summary>
    /// <param name="string_binding">The RPC binding to query, e.g. ncalrpc:[PORT]</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of endpoints on the RPC binding.</returns>
    public static NtResult<IEnumerable<RpcEndpoint>> QueryEndpointsForBinding(RpcStringBinding string_binding, bool throw_on_error)
    {
        return new RpcManagementInterface(string_binding, UseManagedClient).QueryInterfaces(throw_on_error)
            .Map(r => r.Select(m => CreateEndpoint(string_binding, m)).ToArray())
                .Cast<IEnumerable<RpcEndpoint>>();
    }

    /// <summary>
    /// Query for endpoints for a RPC binding. 
    /// </summary>
    /// <param name="string_binding">The RPC binding to query, e.g. ncalrpc:[PORT]</param>
    /// <returns>The list of endpoints on the RPC binding.</returns>
    public static IEnumerable<RpcEndpoint> QueryEndpointsForBinding(RpcStringBinding string_binding)
    {
        return QueryEndpointsForBinding(string_binding, true).Result;
    }

    /// <summary>
    /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence to lookup.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The mapped endpoint.</returns>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    public static RpcEndpoint MapServerToEndpoint(string protocol_seq, RpcSyntaxIdentifier interface_id)
    {
        return MapServerToEndpoint(protocol_seq, null, interface_id);
    }

    /// <summary>
    /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence to lookup.</param>
    /// <param name="network_address">The network address for the lookup.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The mapped endpoint.</returns>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    public static RpcEndpoint MapServerToEndpoint(string protocol_seq, string network_address, RpcSyntaxIdentifier interface_id)
    {
        RpcStringBinding binding = MapServerToBindingString(protocol_seq, network_address, interface_id);
        if (binding == null)
        {
            return null;
        }

        return new RpcEndpoint(interface_id, binding, registered: true);
    }

    /// <summary>
    /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
    /// </summary>
    /// <param name="string_binding">The string binding to map.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The mapped endpoint.</returns>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    public static RpcEndpoint MapBindingStringToEndpoint(string string_binding, RpcSyntaxIdentifier interface_id)
    {
        return MapBindingStringToEndpoint(RpcStringBinding.Parse(string_binding), interface_id);
    }

    /// <summary>
    /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
    /// </summary>
    /// <param name="string_binding">The string binding to map.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The mapped endpoint.</returns>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    public static RpcEndpoint MapBindingStringToEndpoint(RpcStringBinding string_binding, RpcSyntaxIdentifier interface_id)
    {
        var binding = MapBindingToBindingString(string_binding, interface_id);
        if (binding == null)
        {
            return null;
        }

        return new RpcEndpoint(interface_id, binding, registered: true);
    }

    /// <summary>
    /// Resolve the local binding string for this service from the local Endpoint Mapper and return the ALPC port path.
    /// </summary>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The mapped endpoint.</returns>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    public static RpcEndpoint MapServerToAlpcEndpoint(RpcSyntaxIdentifier interface_id)
    {
        return MapServerToEndpoint(RpcProtocolSequence.LRPC, interface_id);
    }

    /// <summary>
    /// Resolve the local binding string for this service from the local Endpoint Mapper and return the ALPC port path.
    /// </summary>
    /// <param name="server_interface">The server interface.</param>
    /// <returns>The mapped endpoint.</returns>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    public static RpcEndpoint MapServerToAlpcEndpoint(RpcServerInterface server_interface)
    {
        return MapServerToAlpcEndpoint(server_interface.InterfaceId);
    }

    /// <summary>
    /// Finds ALPC endpoints which allows for the server binding. This brute forces all ALPC ports to try and find
    /// something which will accept the bind.
    /// </summary>
    /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>A list of RPC endpoints which can bind the interface.</returns>
    /// <exception cref="NtException">Throws on error.</exception>
    public static IEnumerable<RpcEndpoint> FindAlpcEndpointForInterface(RpcSyntaxIdentifier interface_id)
    {
        using var dir = NtDirectory.Open(@"\RPC Control");
        var nt_type = NtType.GetTypeByType<NtAlpc>().Name;

        foreach (var port in dir.Query().Where(e => e.NtTypeName == nt_type))
        {
            bool success = false;
            try
            {
                using var server = new RpcClient(interface_id);
                server.Connect(port.Name);
                success = true;
            }
            catch
            {
            }
            if (success)
            {
                yield return new RpcEndpoint(interface_id, new RpcStringBinding(RpcProtocolSequence.LRPC, endpoint: port.Name), registered: false);
            }
        }
    }

    /// <summary>
    /// Finds ALPC endpoints which allows for the server binding. This brute forces all ALPC ports to try and find
    /// something which will accept the bind.
    /// </summary>
    /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <param name="interface_version">Interface version to lookup.</param>
    /// <returns>A list of RPC endpoints which can bind the interface.</returns>
    /// <exception cref="NtException">Throws on error.</exception>
    public static IEnumerable<RpcEndpoint> FindAlpcEndpointForInterface(Guid interface_id, RpcVersion interface_version)
    {
        return FindAlpcEndpointForInterface(new RpcSyntaxIdentifier(interface_id, interface_version));
    }

    /// <summary>
    /// Finds ALPC endpoints which allows for the server binding. This brute forces all ALPC ports to try and find
    /// something which will accept the bind.
    /// </summary>
    /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
    /// <param name="server">Server interface to lookup.</param>
    /// <returns>A list of RPC endpoints which can bind the interface.</returns>
    /// <exception cref="NtException">Throws on error.</exception>
    public static IEnumerable<RpcEndpoint> FindAlpcEndpointForInterface(RpcServerInterface server)
    {
        return FindAlpcEndpointForInterface(server.InterfaceId);
    }

    /// <summary>
    /// Finds an ALPC endpoint which allows for the server binding. This brute forces all ALPC ports to try and find
    /// something which will accept the bind.
    /// </summary>
    /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <returns>The first RPC endpoints which can bind the interface. Throws exception if nothing found.</returns>
    /// <exception cref="NtException">Throws on error.</exception>
    public static RpcEndpoint FindFirstAlpcEndpointForInterface(RpcSyntaxIdentifier interface_id)
    {
        return FindAlpcEndpointForInterface(interface_id).First();
    }

    /// <summary>
    /// Finds an ALPC endpoint which allows for the server binding. This brute forces all ALPC ports to try and find
    /// something which will accept the bind.
    /// </summary>
    /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
    /// <param name="server">The server interface to lookup.</param>
    /// <returns>The first RPC endpoints which can bind the interface. Throws exception if nothing found.</returns>
    /// <exception cref="NtException">Throws on error.</exception>
    public static RpcEndpoint FindFirstAlpcEndpointForInterface(RpcServerInterface server)
    {
        return FindFirstAlpcEndpointForInterface(server.InterfaceId);
    }

    /// <summary>
    /// Resolve the binding string for this service from the Endpoint Mapper.
    /// </summary>
    /// <param name="string_binding">The binding string to map.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
    public static RpcStringBinding MapBindingToBindingString(RpcStringBinding string_binding, RpcSyntaxIdentifier interface_id)
    {
        return GetMapper().MapEndpoint(string_binding, interface_id);
    }

    /// <summary>
    /// Resolve the binding string for this service from the the Endpoint Mapper.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence to lookup.</param>
    /// <param name="network_address">The network address to lookup the endpoint.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
    public static RpcStringBinding MapServerToBindingString(string protocol_seq, string network_address, RpcSyntaxIdentifier interface_id)
    {
        RpcStringBinding string_binding = new(protocol_seq, network_addr: network_address);
        return GetMapper().MapEndpoint(string_binding, interface_id);
    }

    /// <summary>
    /// Resolve the binding string for this service from the local Endpoint Mapper.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence to lookup.</param>
    /// <param name="interface_id">Interface UUID to lookup.</param>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
    public static RpcStringBinding MapServerToBindingString(string protocol_seq, RpcSyntaxIdentifier interface_id)
    {
        return MapServerToBindingString(protocol_seq, null, interface_id);
    }

    /// <summary>
    /// Low level query for a list of endpoints.
    /// </summary>
    /// <param name="search_binding">The search binding.</param>
    /// <param name="inquiry_flag">What endpoints to lookup.</param>
    /// <param name="if_id_search">The interface to lookup.</param>
    /// <param name="version">The version options.</param>
    /// <param name="uuid_search">What object UUID to lookup.</param>
    /// <param name="force_managed">True to force using a managed implementation. Doesn't do anything except on Windows.</param>
    /// <returns>The list of endpoints.</returns>
    public static IEnumerable<RpcEndpoint> LookupEndpoint(RpcStringBinding search_binding, 
        RpcEndpointInquiryFlag inquiry_flag, RpcSyntaxIdentifier? if_id_search,
        RpcEndPointVersionOption version, Guid? uuid_search, bool force_managed = false)
    {
        return GetMapper(force_managed).LookupEndpoint(search_binding, inquiry_flag, 
            if_id_search, version, uuid_search, true);
    }

    /// <summary>
    /// Low level method to resolve the binding string for this service from the Endpoint Mapper.
    /// </summary>
    /// <param name="search_binding">The search binding string to map.</param>
    /// <param name="if_id_search">Interface UUID to lookup.</param>
    /// <param name="force_managed">True to force using a managed implementation. Doesn't do anything except on Windows.</param>
    /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
    /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
    public static RpcStringBinding MapEndpoint(RpcStringBinding search_binding, RpcSyntaxIdentifier if_id_search, bool force_managed)
    {
        return GetMapper(force_managed).MapEndpoint(search_binding, if_id_search);
    }
    #endregion
}
