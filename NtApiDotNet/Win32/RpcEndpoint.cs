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

using Microsoft.Win32;
using NtApiDotNet.Win32.Rpc;
using NtApiDotNet.Win32.Rpc.Transport;
using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Concurrent;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class to represent an RPC endpoint.
    /// </summary>
    public sealed class RpcEndpoint
    {
        #region Private Members
        private readonly Lazy<RpcServerProcessInformation> _server_process_info;
        private static ConcurrentDictionary<Guid, bool> _com_interface_check = new ConcurrentDictionary<Guid, bool>();

        private RpcServerProcessInformation GetServerProcessInformation()
        {
            using (var transport = RpcClientTransportFactory.ConnectEndpoint(this, new RpcTransportSecurity() { AuthenticationLevel = RpcAuthenticationLevel.None }))
            {
                return transport.ServerProcess;
            }
        }

        private static bool GetIsComInterface(Guid interface_id)
        {
            using (var key = Registry.ClassesRoot.OpenSubKey($@"Interface\{interface_id:B}"))
            {
                return key != null;
            }
        }

        private RpcEndpoint(Guid interface_id, Version interface_version, string annotation, RpcStringBinding cracked, string binding, bool registered) 
            : this(interface_id, interface_version, cracked.ProtocolSequence, cracked.NetworkAddress, cracked.Endpoint, cracked.NetworkOptions,
                  cracked.ObjUuid.GetValueOrDefault(), binding, annotation, registered)
        {
        }

        private RpcEndpoint(Guid interface_id, Version interface_version, string annotation, string binding, bool registered) 
            : this(interface_id, interface_version, annotation, RpcStringBinding.Parse(binding), binding, registered)
        {
        }

        #endregion

        #region Public Properties
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
        public string ProtocolSequence { get; }
        /// <summary>
        /// Endpoint network address.
        /// </summary>
        public string NetworkAddress { get; }
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
        /// <summary>
        /// Indicates this endpoint is registered with the endpoint mapper.
        /// </summary>
        public bool Registered { get; }
        /// <summary>
        /// Indicates this endpoint is a COM interface.
        /// </summary>
        public bool IsComInterface => _com_interface_check.GetOrAdd(InterfaceId, GetIsComInterface);
        #endregion

        #region Internal Members
        internal RpcEndpoint(Guid interface_id, Version interface_version, string string_binding, bool registered)
            : this(interface_id, interface_version, null, string_binding, registered)
        {
        }

        internal RpcEndpoint(RPC_IF_ID if_id, UUID uuid, SafeRpcStringHandle annotation, SafeRpcBindingHandle binding, bool registered)
            : this(if_id.Uuid, new Version(if_id.VersMajor, if_id.VersMinor), annotation?.ToString(), binding.ToString(), registered)
        {
            if (ObjectUuid == Guid.Empty)
                ObjectUuid = uuid.Uuid;
        }
        #endregion
        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="interface_id">The RPC interface ID.</param>
        /// <param name="interface_version">The RPC interface version.</param>
        /// <param name="protseq">The RPC protocol sequence.</param>
        /// <param name="network_addr">The RPC network address.</param>
        /// <param name="endpoint">The RPC endpoint.</param>
        /// <param name="network_options">The RPC network options.</param>
        /// <param name="object_uuid">The RPC object UUID.</param>
        /// <param name="binding">The RPC string binding.</param>
        /// <param name="annotation">The RPC annotation.</param>
        /// <param name="registered">Whether the RPC interface is registered.</param>
        /// <exception cref="ArgumentException">Thrown if invalid paramters passed.</exception>
        public RpcEndpoint(Guid interface_id, Version interface_version, string protseq, string network_addr = null, 
            string endpoint = null, string network_options = null, Guid object_uuid = default, string binding = null, 
            string annotation = null, bool registered = false)
        {
            if (string.IsNullOrWhiteSpace(protseq))
            {
                throw new ArgumentException($"'{nameof(protseq)}' cannot be null or whitespace.", nameof(protseq));
            }

            InterfaceId = interface_id;
            InterfaceVersion = interface_version;
            ObjectUuid = object_uuid;
            Annotation = annotation ?? string.Empty;
            BindingString = binding ?? string.Empty;

            ProtocolSequence = protseq;
            NetworkAddress = network_addr;
            Endpoint = endpoint;
            NetworkOptions = network_options;
            if (ProtocolSequence.Equals("ncalrpc", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Endpoint))
            {
                if (Endpoint.Contains(@"\"))
                {
                    EndpointPath = Endpoint;
                }
                else
                {
                    EndpointPath = $@"\RPC Control\{Endpoint}";
                }
            }
            else if (ProtocolSequence.Equals("ncacn_np", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Endpoint))
            {
                EndpointPath = string.IsNullOrEmpty(NetworkAddress) ? $@"\??{Endpoint}" : $@"\??\UNC\{NetworkAddress}{Endpoint}";
            }
            else
            {
                EndpointPath = string.Empty;
            }
            Registered = registered;
            _server_process_info = new Lazy<RpcServerProcessInformation>(GetServerProcessInformation);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>String form of the object.</returns>
        public override string ToString()
        {
            return $"[{InterfaceId}, {InterfaceVersion}] {BindingString}";
        }

        /// <summary>
        /// Get information about the server process.
        /// </summary>
        /// <returns></returns>
        public RpcServerProcessInformation GetServerProcess()
        {
            return _server_process_info.Value;
        }
        #endregion
    }
}
