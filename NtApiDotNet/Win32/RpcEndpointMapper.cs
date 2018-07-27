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

        public static SafeRpcBindingHandle Create(string string_binding)
        {
            int status = Win32NativeMethods.RpcBindingFromStringBinding(string_binding, out SafeRpcBindingHandle binding);
            if (status != 0)
            {
                throw new SafeWin32Exception(status);
            }
            return binding;
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

    /// <summary>
    /// Class to represent an RPC endpoint.
    /// </summary>
    public class RpcEndpoint
    {
        /// <summary>
        /// The interface ID of the endpoint.
        /// </summary>
        public Guid InterfaceId { get; }
        /// <summary>
        /// The interface version.
        /// </summary>
        public Version InterfaceVersion { get; }
        /// <summary>
        /// The object UUID.
        /// </summary>
        public Guid ObjectUuid { get; }
        /// <summary>
        /// Optional annotation.
        /// </summary>
        public string Annotation { get; }
        /// <summary>
        /// RPC binding string.
        /// </summary>
        public string BindingString { get; }
        /// <summary>
        /// Endpoint protocol sequence.
        /// </summary>
        public string Protseq { get; }
        /// <summary>
        /// Endpoint network address.
        /// </summary>
        public string NetworkAddr { get; }
        /// <summary>
        /// Endpoint name.
        /// </summary>
        public string Endpoint { get; }
        /// <summary>
        /// Endpoint network options.
        /// </summary>
        public string NetworkOptions { get; }
        /// <summary>
        /// The endpoint path.
        /// </summary>
        public string EndpointPath { get; }

        internal RpcEndpoint(RPC_IF_ID if_id, UUID uuid, SafeRpcStringHandle annotation, SafeRpcBindingHandle binding)
        {
            InterfaceId = if_id.Uuid;
            InterfaceVersion = new Version(if_id.VersMajor, if_id.VersMinor);
            ObjectUuid = uuid.Uuid;
            Annotation = annotation.ToString();
            BindingString = binding.ToString();
            var cracked = new CrackedBindingString(BindingString);
            Protseq = cracked.Protseq;
            NetworkAddr = cracked.NetworkAddr;
            Endpoint = cracked.Endpoint;
            NetworkOptions = cracked.NetworkOptions;
            if (Protseq.Equals("ncalrpc", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Endpoint))
            {
                EndpointPath = $@"\RPC Control\{Endpoint}";
            }
            else if (Protseq.Equals("ncacn_np", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Endpoint))
            {
                EndpointPath = $@"\??{Endpoint}";
            }
            else
            {
                EndpointPath = string.Empty;
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>String form of the object.</returns>
        public override string ToString()
        {
            return $"[{InterfaceId}, {InterfaceVersion}] {BindingString}";
        }
    }

    /// <summary>
    /// Static class to access information from the RPC mapper.
    /// </summary>
    public static class RpcEndpointMapper
    {
        private static IEnumerable<RpcEndpoint> QueryEndpoints(SafeRpcBindingHandle search_binding, RpcEndpointInquiryFlag inquiry_flag, RPC_IF_ID if_id_search, RpcEndPointVersionOption version, UUID uuid_search)
        {
            using (search_binding)
            {
                int status = Win32NativeMethods.RpcMgmtEpEltInqBegin(search_binding, 
                    inquiry_flag,
                    if_id_search, version, uuid_search, out SafeRpcInquiryHandle inquiry);
                if (status != 0)
                {
                    throw new SafeWin32Exception(status);
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
                            if (status == 1772)
                            {
                                break;
                            }
                            throw new SafeWin32Exception(status);
                        }
                        try
                        {
                            yield return new RpcEndpoint(if_id, uuid, annotation, binding);
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
                RpcEndPointVersionOption.Exact, null).Where(e => e.Protseq.Equals("ncalrpc", StringComparison.OrdinalIgnoreCase));
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
        /// Resolve the local binding string for this service from the local Endpoint Mapper.
        /// </summary>
        /// <param name="interface_id">Interface UUID to lookup.</param>
        /// <param name="interface_version">Interface version lookup.</param>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public static string MapServerToBindingString(Guid interface_id, Version interface_version)
        {
            int result = Win32NativeMethods.RpcBindingFromStringBinding("ncalrpc:", out SafeRpcBindingHandle binding);
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

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper.
        /// </summary>
        /// <param name="server_interface">The server interface.</param>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public static string MapServerToBindingString(NdrRpcServerInterface server_interface)
        {
            return MapServerToBindingString(server_interface.InterfaceId, server_interface.InterfaceVersion);
        }
    }
}
