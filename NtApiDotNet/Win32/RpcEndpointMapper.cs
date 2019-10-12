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

using Microsoft.Win32.SafeHandles;
using NtApiDotNet.Ndr;
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

    internal class CrackedBindingString
    {
        public string ObjUuid { get; }
        public string Protseq { get; }
        public string NetworkAddr { get; }
        public string Endpoint { get; }
        public string NetworkOptions { get; }

        public CrackedBindingString(string string_binding)
        {
            SafeRpcStringHandle objuuid = null;
            SafeRpcStringHandle protseq = null;
            SafeRpcStringHandle endpoint = null;
            SafeRpcStringHandle networkaddr = null;
            SafeRpcStringHandle networkoptions = null;

            try
            {
                int status = Win32NativeMethods.RpcStringBindingParse(string_binding, 
                    out objuuid, out protseq, out networkaddr, out endpoint, out networkoptions);
                if (status == 0)
                {
                    ObjUuid = objuuid.ToString();
                    Protseq = protseq.ToString();
                    Endpoint = endpoint.ToString();
                    NetworkAddr = networkaddr.ToString();
                    NetworkOptions = networkoptions.ToString();
                }
                else
                {
                    ObjUuid = string.Empty;
                    Protseq = string.Empty;
                    Endpoint = string.Empty;
                    NetworkAddr = string.Empty;
                    NetworkOptions = string.Empty;
                }
            }
            finally
            {
                objuuid?.Dispose();
                protseq?.Dispose();
                endpoint?.Dispose();
                networkaddr?.Dispose();
                networkoptions?.Dispose();
            }
        }
    }

    internal sealed class SafeRpcBindingHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private CrackedBindingString _cracked_binding;

        private CrackedBindingString GetCrackedBinding()
        {
            if (IsClosed)
            {
                throw new ObjectDisposedException("CrackedBindingString");
            }
            if (_cracked_binding == null)
            {
                _cracked_binding = new CrackedBindingString(ToString());
            }
            return _cracked_binding;
        }

        public SafeRpcBindingHandle() : base(true)
        {
        }

        public SafeRpcBindingHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.RpcBindingFree(ref handle) == 0;
        }

        public string ObjUuid => GetCrackedBinding().ObjUuid;
        public string Protseq => GetCrackedBinding().Protseq;
        public string NetworkAddr => GetCrackedBinding().NetworkAddr;
        public string Endpoint => GetCrackedBinding().Endpoint;
        public string NetworkOptions => GetCrackedBinding().NetworkOptions;

        public static SafeRpcBindingHandle Create(string string_binding)
        {
            int status = Win32NativeMethods.RpcBindingFromStringBinding(string_binding, out SafeRpcBindingHandle binding);
            if (status != 0)
            {
                throw new SafeWin32Exception(status);
            }
            binding._cracked_binding = new CrackedBindingString(string_binding);
            return binding;
        }

        public static SafeRpcBindingHandle Create(string objuuid, string protseq, string networkaddr, string endpoint, string options)
        {
            int status = Win32NativeMethods.RpcStringBindingCompose(objuuid, protseq,
                networkaddr, endpoint, options, out SafeRpcStringHandle binding);
            if (status != 0)
            {
                throw new SafeWin32Exception(status);
            }
            using (binding)
            {
                return Create(binding.ToString());
            }
        }

        public static string Compose(string objuuid, string protseq, string networkaddr, string endpoint, string options)
        {
            using (var binding = Create(objuuid, protseq, networkaddr, endpoint, options))
            {
                return binding.ToString();
            }
        }

        public override string ToString()
        {
            if (!IsInvalid && !IsClosed)
            {
                if (Win32NativeMethods.RpcBindingToStringBinding(handle, out SafeRpcStringHandle str) == 0)
                {
                    using (str)
                    {
                        return str.ToString();
                    }
                }
            }
            return string.Empty;
        }

        public static SafeRpcBindingHandle Null => new SafeRpcBindingHandle(IntPtr.Zero, false);
    }

    internal sealed class SafeRpcStringHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeRpcStringHandle() : base(true)
        {
        }

        public SafeRpcStringHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.RpcStringFree(ref handle) == 0;
        }

        public override string ToString()
        {
            if (!IsInvalid && !IsClosed)
            {
                return Marshal.PtrToStringUni(handle);
            }
            return string.Empty;
        }
    }

    internal sealed class SafeRpcInquiryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeRpcInquiryHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.RpcMgmtEpEltInqDone(ref handle) == 0;
        }
    }

    internal sealed class SafeRpcIfIdVectorHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeRpcIfIdVectorHandle() : base(true)
        {
        }

        public SafeRpcIfIdVectorHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.RpcIfIdVectorFree(ref handle) == 0;
        }

        public RPC_IF_ID[] GetIfIds()
        {
            if (IsClosed)
            {
                throw new ObjectDisposedException("vector");
            }

            var vector_buffer = new SafeStructureInOutBuffer<RPC_IF_ID_VECTOR>(handle, int.MaxValue, false);
            var vector = vector_buffer.Result;
            IntPtr[] ptrs = new IntPtr[vector.Count];
            vector_buffer.Data.ReadArray(0, ptrs, 0, vector.Count);
            return ptrs.Select(p => (RPC_IF_ID)Marshal.PtrToStructure(p, typeof(RPC_IF_ID))).ToArray();
        }
    }

    /// <summary>
    /// Static class to access information from the RPC mapper.
    /// </summary>
    public static class RpcEndpointMapper
    {
        private static IEnumerable<RpcEndpoint> QueryEndpoints(SafeRpcBindingHandle search_binding, RpcEndpointInquiryFlag inquiry_flag, RPC_IF_ID if_id_search, RpcEndPointVersionOption version, UUID uuid_search, bool throw_on_error = true)
        {
            int status = Win32NativeMethods.RpcMgmtEpEltInqBegin(search_binding, 
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

        /// <summary>
        /// Query all endpoints registered on the local system.
        /// </summary>
        /// <returns>List of endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints()
        {
            return QueryEndpoints(SafeRpcBindingHandle.Null, RpcEndpointInquiryFlag.All, null, RpcEndPointVersionOption.All, null);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(Guid interface_id, Version interface_version)
        {
            RPC_IF_ID if_id = new RPC_IF_ID()
            {
                Uuid = interface_id,
                VersMajor = (ushort)interface_version.Major,
                VersMinor = (ushort)interface_version.Minor
            };
            return QueryEndpoints(SafeRpcBindingHandle.Null, RpcEndpointInquiryFlag.Interface, if_id, RpcEndPointVersionOption.Exact, null);
        }

        /// <summary>
        /// Query for endpoints registered on the local system for an RPC endpoint ignoring the version.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <returns>The list of registered RPC endpoints.</returns>
        public static IEnumerable<RpcEndpoint> QueryEndpoints(Guid interface_id)
        {
            RPC_IF_ID if_id = new RPC_IF_ID()
            {
                Uuid = interface_id
            };
            return QueryEndpoints(SafeRpcBindingHandle.Null, RpcEndpointInquiryFlag.Interface, if_id, RpcEndPointVersionOption.All, null);
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
            return QueryEndpoints(SafeRpcBindingHandle.Null, RpcEndpointInquiryFlag.Interface, if_id, 
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

        private static RpcEndpoint CreateEndpoint(SafeRpcBindingHandle binding_handle, RPC_IF_ID if_id)
        {
            var endpoints = QueryEndpoints(binding_handle, RpcEndpointInquiryFlag.Interface, 
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
            string binding = MapServerToBindingString(protocol_seq, interface_id, interface_version);
            if (binding == null)
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
        /// Resolve the binding string for this service from the local Endpoint Mapper.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence to lookup.</param>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public static string MapServerToBindingString(string protocol_seq, Guid interface_id, Version interface_version)
        {
            int result = Win32NativeMethods.RpcBindingFromStringBinding($"{protocol_seq}:", out SafeRpcBindingHandle binding);
            if (result != 0)
            {
                return string.Empty;
            }
            using (binding)
            {
                RPC_SERVER_INTERFACE ifspec = new RPC_SERVER_INTERFACE();
                ifspec.Length = Marshal.SizeOf(ifspec);
                ifspec.InterfaceId.SyntaxGUID = interface_id;
                ifspec.InterfaceId.SyntaxVersion = interface_version.ToRpcVersion();

                result = Win32NativeMethods.RpcEpResolveBinding(binding, ref ifspec);
                if (result != 0)
                {
                    return string.Empty;
                }

                return binding.ToString();
            }
        }
    }
}
