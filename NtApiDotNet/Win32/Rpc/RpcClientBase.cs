//  Copyright 2019 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Win32.Rpc.Transport;
using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Base class for a RPC client.
    /// </summary>
    public abstract class RpcClientBase : IDisposable
    {
        #region Private Members
        private IRpcClientTransport _transport;

        private RpcEndpoint LookupEndpoint(string protocol_seq, string network_address)
        {
            var endpoint = RpcEndpointMapper.MapServerToEndpoint(protocol_seq, network_address, InterfaceId, InterfaceVersion);
            if (endpoint == null || string.IsNullOrEmpty(endpoint.Endpoint))
            {
                throw new ArgumentException($"Can't find endpoint for {InterfaceId} {InterfaceVersion} with protocol sequence {protocol_seq}");
            }
            return endpoint;
        }

        private RpcEndpoint LookupEndpoint(string string_binding)
        {
            var endpoint = RpcEndpointMapper.MapBindingStringToEndpoint(string_binding, InterfaceId, InterfaceVersion);
            if (endpoint == null || string.IsNullOrEmpty(endpoint.Endpoint))
            {
                throw new ArgumentException($"Can't find endpoint for {InterfaceId} {InterfaceVersion} for binding string {string_binding}");
            }
            return endpoint;
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="interface_id">The interface ID.</param>
        /// <param name="interface_version">Version of the interface.</param>
        protected RpcClientBase(Guid interface_id, Version interface_version)
        {
            InterfaceId = interface_id;
            InterfaceVersion = interface_version;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="interface_id">The interface ID as a string.</param>
        /// <param name="major">Major version of the interface.</param>
        /// <param name="minor">Minor version of the interface.</param>
        protected RpcClientBase(string interface_id, int major, int minor)
            : this(new Guid(interface_id), new Version(major, minor))
        {
        }

        #endregion

        #region Protected Methods

        /// <summary>
        /// Send and receive an RPC message.
        /// </summary>
        /// <param name="proc_num">The procedure number.</param>
        /// <param name="data_representation">The NDR data representation.</param>
        /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
        /// <param name="handles">List of handles marshaled into the buffer.</param>
        /// <returns>Unmarshal NDR buffer for the result.</returns>
        protected RpcClientResponse SendReceive(int proc_num, NdrDataRepresentation data_representation, 
            byte[] ndr_buffer, IReadOnlyCollection<NtObject> handles)
        {
            if (!Connected)
            {
                throw new InvalidOperationException("RPC client is not connected.");
            }

            RpcUtils.DumpBuffer(false, "NDR Send Data", ndr_buffer);
            var resp = _transport.SendReceive(proc_num, ObjectUuid, data_representation, ndr_buffer, handles);
            RpcUtils.DumpBuffer(false, "NDR Receive Data", resp.NdrBuffer);
            return resp;
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get whether the client is connected or not.
        /// </summary>
        public bool Connected => _transport?.Connected ?? false;

        /// <summary>
        /// Get the endpoint that we connected to.
        /// </summary>
        public string Endpoint => _transport?.Endpoint ?? string.Empty;

        /// <summary>
        /// Get the protocol sequence that we connected to.
        /// </summary>
        public string ProtocolSequence => _transport?.ProtocolSequence ?? string.Empty;

        /// <summary>
        /// Get or set the current Object UUID used for calls.
        /// </summary>
        public Guid ObjectUuid { get; set; }

        /// <summary>
        /// The RPC interface ID.
        /// </summary>
        public Guid InterfaceId { get; }

        /// <summary>
        /// The RPC interface version.
        /// </summary>
        public Version InterfaceVersion { get; }

        #endregion

        #region Public Methods

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="endpoint">The endpoint for RPC server.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public void Connect(RpcEndpoint endpoint, RpcTransportSecurity transport_security)
        {
            if (Connected)
            {
                throw new InvalidOperationException("RPC client is already connected.");
            }

            if (endpoint == null)
            {
                throw new ArgumentNullException("Must specify an endpoint", nameof(endpoint));
            }

            try
            {
                _transport = RpcClientTransportFactory.ConnectEndpoint(endpoint, transport_security);
                _transport.Bind(InterfaceId, InterfaceVersion, NdrNativeUtils.DCE_TransferSyntax, new Version(2, 0));
                ObjectUuid = endpoint.ObjectUuid;
            }
            catch
            {
                // Disconnect transport on any exception.
                _transport?.Disconnect();
                _transport = null;
                throw;
            }
        }

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="endpoint">The endpoint for RPC server.</param>
        /// <param name="security_quality_of_service">The security quality of service for the connection.</param>
        [Obsolete("Use Connect specifying RpcTransportSecurity.")]
        public void Connect(RpcEndpoint endpoint, SecurityQualityOfService security_quality_of_service)
        {
            Connect(endpoint, new RpcTransportSecurity(security_quality_of_service));
        }

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence for the transport.</param>
        /// <param name="endpoint">The endpoint for the protocol sequence.</param>
        /// <param name="network_address">The network address for the protocol sequence.</param>
        /// <param name="security_quality_of_service">The security quality of service for the connection.</param>
        [Obsolete("Use Connect specifying RpcTransportSecurity.")]
        public void Connect(string protocol_seq, string endpoint, string network_address, SecurityQualityOfService security_quality_of_service)
        {
            Connect(protocol_seq, endpoint, network_address, new RpcTransportSecurity(security_quality_of_service));
        }

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence for the transport.</param>
        /// <param name="endpoint">The endpoint for the protocol sequence.</param>
        /// <param name="network_address">The network address for the protocol sequence.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public void Connect(string protocol_seq, string endpoint, string network_address, RpcTransportSecurity transport_security)
        {
            if (Connected)
            {
                throw new InvalidOperationException("RPC client is already connected.");
            }

            if (string.IsNullOrEmpty(protocol_seq))
            {
                throw new ArgumentException("Must specify a protocol sequence", nameof(protocol_seq));
            }

            Connect(string.IsNullOrEmpty(endpoint) ? LookupEndpoint(protocol_seq, network_address) :
                new RpcEndpoint(InterfaceId, InterfaceVersion,
                    SafeRpcBindingHandle.Compose(null, protocol_seq,
                    string.IsNullOrEmpty(network_address) ? null : network_address, endpoint, null), true),
                    transport_security);
        }

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence for the transport.</param>
        /// <param name="endpoint">The endpoint for the protocol sequence.</param>
        /// <param name="security_quality_of_service">The security quality of service for the connection.</param>
        [Obsolete("Use Connect specifying RpcTransportSecurity.")]
        public void Connect(string protocol_seq, string endpoint, SecurityQualityOfService security_quality_of_service)
        {
            Connect(protocol_seq, endpoint, null, security_quality_of_service);
        }

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="protocol_seq">The protocol sequence for the transport.</param>
        /// <param name="endpoint">The endpoint for the protocol sequence.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public void Connect(string protocol_seq, string endpoint, RpcTransportSecurity transport_security)
        {
            Connect(protocol_seq, endpoint, null, transport_security);
        }

        /// <summary>
        /// Connect the client to an ALPC RPC port.
        /// </summary>
        /// <param name="alpc_path">The path to the ALPC RPC port.</param>
        /// <param name="security_quality_of_service">The security quality of service for the port.</param>
        public void Connect(string alpc_path, SecurityQualityOfService security_quality_of_service)
        {
            if (Connected)
            {
                throw new InvalidOperationException("RPC client is already connected.");
            }

            Connect("ncalrpc", alpc_path, new RpcTransportSecurity(security_quality_of_service));
        }

        /// <summary>
        /// Connect the client to a RPC endpoint.
        /// </summary>
        /// <param name="string_binding">The binding string for the RPC server.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public void Connect(string string_binding, RpcTransportSecurity transport_security)
        {
            var endpoint = new RpcEndpoint(InterfaceId, InterfaceVersion, string_binding, false);
            if (string.IsNullOrEmpty(endpoint.ProtocolSequence))
            {
                throw new ArgumentException("Binding string must contain a protocol sequence.");
            }

            if (string.IsNullOrEmpty(endpoint.Endpoint))
            {
                endpoint = LookupEndpoint(string_binding);
            }

            Connect(endpoint, transport_security);
        }

        /// <summary>
        /// Connect the client to an ALPC RPC port.
        /// </summary>
        /// <param name="alpc_path">The path to the ALPC RPC port. If an empty string the endpoint will be looked up in the endpoint mapper.</param>
        public void Connect(string alpc_path)
        {
            Connect(alpc_path, null);
        }

        /// <summary>
        /// Connect the client to an ALPC RPC port.
        /// </summary>
        /// <remarks>The ALPC endpoint will be looked up in the endpoint mapper.</remarks>
        public void Connect()
        {
            Connect(null);
        }

        /// <summary>
        /// Dispose of the client.
        /// </summary>
        public virtual void Dispose()
        {
            _transport?.Dispose();
        }

        /// <summary>
        /// Disconnect the client.
        /// </summary>
        public void Disconnect()
        {
            _transport?.Disconnect();
        }

        #endregion
    }
}
