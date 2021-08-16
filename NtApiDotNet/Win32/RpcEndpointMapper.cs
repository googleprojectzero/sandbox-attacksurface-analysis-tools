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

using NtApiDotNet.Ndr;
using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
    internal enum RpcEndPointVersionOption
    {
        All = 1,
        Compatible = 2,
        Exact = 3,
        MajorOnly = 4,
        Upto = 5
    }

    internal enum RpcEndpointInquiryFlag
    {
        All = 0,
        Interface = 1,
        Object = 2,
        Both = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class UUID
    {
        public Guid Uuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class RPC_IF_ID
    {
        public Guid Uuid;
        public ushort VersMajor;
        public ushort VersMinor;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("IfId")]
    internal class RPC_IF_ID_VECTOR
    {
        public int Count;
        public IntPtr IfId; // RPC_IF_ID*
    };

    /// <summary>
    /// Static class to access information from the RPC mapper.
    /// </summary>
    public static class RpcEndpointMapper
    {
        #region Private Members
        private static IEnumerable<RpcEndpoint> QueryEndpoints(string search_binding, RpcEndpointInquiryFlag inquiry_flag, RPC_IF_ID if_id_search, RpcEndPointVersionOption version, UUID uuid_search, bool throw_on_error = true)
        {
            using (SafeRpcBindingHandle search_handle = string.IsNullOrEmpty(search_binding) ? SafeRpcBindingHandle.Null : SafeRpcBindingHandle.Create(search_binding))
            {
                int status = Win32NativeMethods.RpcMgmtEpEltInqBegin(search_handle,
                    inquiry_flag,
                    if_id_search, version, uuid_search, out SafeRpcInquiryHandle inquiry);
                if (status != 0)
                {
                    if (throw_on_error)
                        throw new SafeWin32Exception(status);
                    yield break;
                }

                using (inquiry)
                {
                    while (true)
                    {
                        RPC_IF_ID if_id = new RPC_IF_ID();
                        UUID uuid = new UUID();
                        status = Win32NativeMethods.RpcMgmtEpEltInqNext(inquiry, if_id, out SafeRpcBindingHandle binding, uuid, out SafeRpcStringHandle annotation);
                        if (status != 0)
                        {
                            if (status != 1772 && throw_on_error)
                            {
                                throw new SafeWin32Exception(status);
                            }
                            break;
                        }
                        try
                        {
                            yield return new RpcEndpoint(if_id, uuid, annotation, binding, true);
                        }
                        finally
                        {
                            binding.Dispose();
                            annotation.Dispose();
                        }
                    }
                }
            }
        }

        private static RpcEndpoint CreateEndpoint(SafeRpcBindingHandle binding_handle, RPC_IF_ID if_id)
        {
            var endpoints = QueryEndpoints(binding_handle.ToString(), RpcEndpointInquiryFlag.Interface,
                if_id, RpcEndPointVersionOption.Exact, null, false).ToArray();
            RpcEndpoint ret = endpoints.Where(ep => ep.BindingString.Equals(binding_handle.ToString(), StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
            return ret ?? new RpcEndpoint(if_id, new UUID(), null, binding_handle, false);
        }

        private const string RPC_CONTROL_PATH = @"\RPC Control\";

        private static IEnumerable<RpcEndpoint> QueryEndpointsForBinding(SafeRpcBindingHandle binding_handle)
        {
            using (binding_handle)
            {
                int status = Win32NativeMethods.RpcMgmtInqIfIds(binding_handle, out SafeRpcIfIdVectorHandle if_id_vector);
                // If the RPC server doesn't exist return an empty list.
                if (status == 1722)
                {
                    return new RpcEndpoint[0];
                }
                if (status != 0)
                {
                    throw new SafeWin32Exception(status);
                }

                using (if_id_vector)
                {
                    return if_id_vector.GetIfIds().Select(if_id => CreateEndpoint(binding_handle, if_id)).ToArray();
                }
            }
        }

        private static string MapBindingToBindingString(NtResult<SafeRpcBindingHandle> binding, Guid interface_id, Version interface_version)
        {
            if (!binding.IsSuccess)
                return string.Empty;

            RPC_SERVER_INTERFACE ifspec = new RPC_SERVER_INTERFACE();
            ifspec.Length = Marshal.SizeOf(ifspec);
            ifspec.InterfaceId.SyntaxGUID = interface_id;
            ifspec.InterfaceId.SyntaxVersion = interface_version.ToRpcVersion();

            var result = Win32NativeMethods.RpcEpResolveBinding(binding.Result, ref ifspec);
            if (result != Win32Error.SUCCESS)
            {
                return string.Empty;
            }

            return binding.Result.ToString();
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Query all endpoints registered on the local system.
        /// </summary>
        /// <returns>List of endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints()
        {
            return QueryEndpoints(null, RpcEndpointInquiryFlag.All, null, RpcEndPointVersionOption.All, null);
        }

        /// <summary>
        /// Query all endpoints registered based on a binding string.
        /// </summary>
        /// <param name="search_binding">The binding string for the server to search on. If null or empty will search localhost.</param>
        /// <returns>List of endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(string search_binding)
        {
            return QueryEndpoints(search_binding, RpcEndpointInquiryFlag.All, null, RpcEndPointVersionOption.All, null);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint.
        /// </summary>
        /// <param name="search_binding">The binding string for the server to search on. If null or empty will search localhost.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(string search_binding, Guid interface_id, Version interface_version)
        {
            RPC_IF_ID if_id = new RPC_IF_ID()
            {
                Uuid = interface_id,
                VersMajor = (ushort)interface_version.Major,
                VersMinor = (ushort)interface_version.Minor
            };
            return QueryEndpoints(search_binding, RpcEndpointInquiryFlag.Interface, if_id, RpcEndPointVersionOption.Exact, null);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(Guid interface_id, Version interface_version)
        {
            return QueryEndpoints(null, interface_id, interface_version);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint ignoring the version.
        /// </summary>
        /// <param name="search_binding">The binding string for the server to search on. If null or empty will search localhost.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(string search_binding, Guid interface_id)
        {
            RPC_IF_ID if_id = new RPC_IF_ID()
            {
                Uuid = interface_id
            };
            return QueryEndpoints(search_binding, RpcEndpointInquiryFlag.Interface, if_id, RpcEndPointVersionOption.All, null);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint ignoring the version.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(Guid interface_id)
        {
            return QueryEndpoints(null, interface_id);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint.
        /// </summary>
        /// <param name="server_interface">The server interface.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(NdrRpcServerInterface server_interface)
        {
            return QueryEndpoints(server_interface.InterfaceId, server_interface.InterfaceVersion);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint via ALPC.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryAlpcEndpoints(Guid interface_id, Version interface_version)
        {
            RPC_IF_ID if_id = new RPC_IF_ID()
            {
                Uuid = interface_id,
                VersMajor = (ushort)interface_version.Major,
                VersMinor = (ushort)interface_version.Minor
            };
            return QueryEndpoints(null, RpcEndpointInquiryFlag.Interface, if_id, 
                RpcEndPointVersionOption.Exact, null).Where(e => e.ProtocolSequence.Equals("ncalrpc", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint via ALPC.
        /// </summary>
        /// <param name="server_interface">The server interface.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryAlpcEndpoints(NdrRpcServerInterface server_interface)
        {
            return QueryAlpcEndpoints(server_interface.InterfaceId, server_interface.InterfaceVersion);
        }

        /// <summary>
        /// Query for endpoints for a RPC binding. 
        /// </summary>
        /// <param name="alpc_port">The ALPC port to query. Can be a full path as long as it contains \RPC Control\ somewhere.</param>
        /// <returns>The list of endpoints on the RPC binding.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpointsForAlpcPort(string alpc_port)
        {
            int index = alpc_port.IndexOf(@"\RPC Control\", StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                alpc_port = alpc_port.Substring(0, index) + RPC_CONTROL_PATH + alpc_port.Substring(index + RPC_CONTROL_PATH.Length);
            }
            return QueryEndpointsForBinding(SafeRpcBindingHandle.Create(null, "ncalrpc", null, alpc_port, null));
        }

        /// <summary>
        /// Query for endpoints for a RPC binding. 
        /// </summary>
        /// <param name="string_binding">The RPC binding to query, e.g. ncalrpc:[PORT]</param>
        /// <returns>The list of endpoints on the RPC binding.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpointsForBinding(string string_binding)
        {
            return QueryEndpointsForBinding(SafeRpcBindingHandle.Create(string_binding));
        }

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence to lookup.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The mapped endpoint.</returns>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        public static RpcEndpoint MapServerToEndpoint(string protocol_seq, Guid interface_id, Version interface_version)
        {
            return MapServerToEndpoint(protocol_seq, null, interface_id, interface_version);
        }

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence to lookup.</param>
        /// <param name="network_address">The network address for the lookup.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The mapped endpoint.</returns>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        public static RpcEndpoint MapServerToEndpoint(string protocol_seq, string network_address, Guid interface_id, Version interface_version)
        {
            string binding = MapServerToBindingString(protocol_seq, network_address, interface_id, interface_version);
            if (string.IsNullOrEmpty(binding))
            {
                return null;
            }

            return new RpcEndpoint(interface_id, interface_version, binding, true);
        }

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper and return the endpoint.
        /// </summary>
        /// <param name="string_binding">The string binding to map.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The mapped endpoint.</returns>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        public static RpcEndpoint MapBindingStringToEndpoint(string string_binding, Guid interface_id, Version interface_version)
        {
            string binding = MapBindingToBindingString(string_binding, interface_id, interface_version);
            if (string.IsNullOrEmpty(binding))
            {
                return null;
            }

            return new RpcEndpoint(interface_id, interface_version, binding, true);
        }

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper and return the ALPC port path.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The mapped endpoint.</returns>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        public static RpcEndpoint MapServerToAlpcEndpoint(Guid interface_id, Version interface_version)
        {
            return MapServerToEndpoint("ncalrpc", interface_id, interface_version);
        }

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper and return the ALPC port path.
        /// </summary>
        /// <param name="server_interface">The server interface.</param>
        /// <returns>The mapped endpoint.</returns>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        public static RpcEndpoint MapServerToAlpcEndpoint(NdrRpcServerInterface server_interface)
        {
            return MapServerToAlpcEndpoint(server_interface.InterfaceId, server_interface.InterfaceVersion);
        }

        /// <summary>
        /// Finds ALPC endpoints which allows for the server binding. This brute forces all ALPC ports to try and find
        /// something which will accept the bind.
        /// </summary>
        /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>A list of RPC endpoints which can bind the interface.</returns>
        /// <exception cref="NtException">Throws on error.</exception>
        public static IEnumerable<RpcEndpoint> FindAlpcEndpointForInterface(Guid interface_id, Version interface_version)
        {
            using (var dir = NtDirectory.Open(@"\RPC Control"))
            {
                var nt_type = NtType.GetTypeByType<NtAlpc>().Name;

                foreach (var port in dir.Query().Where(e => e.NtTypeName == nt_type))
                {
                    bool success = false;
                    try
                    {
                        using (var server = new RpcClient(interface_id, interface_version))
                        {
                            server.Connect(port.Name);
                            success = true;
                        }
                    }
                    catch
                    {
                    }
                    if (success)
                    {
                        yield return new RpcEndpoint(interface_id, interface_version, 
                            SafeRpcBindingHandle.Compose(null, "ncalrpc", null, port.Name, null), false);
                    }
                }
            }
        }

        /// <summary>
        /// Finds an ALPC endpoint which allows for the server binding. This brute forces all ALPC ports to try and find
        /// something which will accept the bind.
        /// </summary>
        /// <remarks>This could hang if the ALPC port is owned by a suspended process.</remarks>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The first RPC endpoints which can bind the interface. Throws exception if nothing found.</returns>
        /// <exception cref="NtException">Throws on error.</exception>
        public static RpcEndpoint FindFirstAlpcEndpointForInterface(Guid interface_id, Version interface_version)
        {
            return FindAlpcEndpointForInterface(interface_id, interface_version).First();
        }

        /// <summary>
        /// Resolve the binding string for this service from the Endpoint Mapper.
        /// </summary>
        /// <param name="string_binding">The binding string to map.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public static string MapBindingToBindingString(string string_binding, Guid interface_id, Version interface_version)
        {
            using (var binding = SafeRpcBindingHandle.Create(string_binding, false))
            {
                return MapBindingToBindingString(binding, interface_id, interface_version);
            }
        }

        /// <summary>
        /// Resolve the binding string for this service from the the Endpoint Mapper.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence to lookup.</param>
        /// <param name="network_address">The network address to lookup the endpoint.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public static string MapServerToBindingString(string protocol_seq, string network_address, Guid interface_id, Version interface_version)
        { 
            using (var binding = SafeRpcBindingHandle.Create(null, protocol_seq, network_address, null, null, false))
            {
                if (!binding.IsSuccess)
                    return string.Empty;

                RPC_SERVER_INTERFACE ifspec = new RPC_SERVER_INTERFACE();
                ifspec.Length = Marshal.SizeOf(ifspec);
                ifspec.InterfaceId.SyntaxGUID = interface_id;
                ifspec.InterfaceId.SyntaxVersion = interface_version.ToRpcVersion();

                var result = Win32NativeMethods.RpcEpResolveBinding(binding.Result, ref ifspec);
                if (result != Win32Error.SUCCESS)
                {
                    return string.Empty;
                }

                return binding.Result.ToString();
            }
        }

        /// <summary>
        /// Resolve the binding string for this service from the local Endpoint Mapper.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence to lookup.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public static string MapServerToBindingString(string protocol_seq, Guid interface_id, Version interface_version)
        {
            return MapServerToBindingString(protocol_seq, null, interface_id, interface_version);
        }

        #endregion
    }
}
