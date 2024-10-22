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

using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Security.Token;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Transport;
using System;

namespace NtCoreLib.Win32.Rpc.Client;

/// <summary>
/// Base class for a RPC client.
/// </summary>
public abstract class RpcClientBase : IDisposable
{
    #region Private Members
    private IRpcClientTransport _transport;

    private RpcStringBinding LookupEndpoint(RpcStringBinding binding)
    {
        var ret = RpcEndpointMapper.MapBindingToBindingString(binding, InterfaceId);
        if (ret == null || string.IsNullOrEmpty(ret.Endpoint))
        {
            throw new ArgumentException($"Can't find endpoint for {InterfaceId} with protocol sequence {binding.ProtocolSequence}");
        }
        return ret;
    }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="interface_id">The interface ID.</param>
    protected RpcClientBase(RpcSyntaxIdentifier interface_id)
    {
        InterfaceId = interface_id;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="interface_id">The interface ID.</param>
    /// <param name="interface_version">Version of the interface.</param>
    protected RpcClientBase(Guid interface_id, RpcVersion interface_version) 
        : this(new RpcSyntaxIdentifier(interface_id, interface_version))
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="interface_id">The interface ID as a string.</param>
    /// <param name="major">Major version of the interface.</param>
    /// <param name="minor">Minor version of the interface.</param>
    protected RpcClientBase(string interface_id, ushort major, ushort minor)
        : this(new Guid(interface_id), new RpcVersion(major, minor))
    {
    }

    #endregion

    #region Protected Methods
    /// <summary>
    /// Send and receive an RPC message.
    /// </summary>
    /// <param name="proc_num">The procedure number.</param>
    /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
    /// <returns>Unmarshal NDR buffer for the result.</returns>
    protected INdrUnmarshalBuffer SendReceiveTransport(int proc_num, INdrMarshalBuffer ndr_buffer)
    {
        if (!Connected)
        {
            throw new InvalidOperationException("RPC client is not connected.");
        }

        RpcTransportUtils.DumpBuffer(_transport.TraceFlags, RpcTransportTraceFlags.ClientNdr, "NDR Send Data", ndr_buffer.ToArray());
        var resp = _transport.SendReceive(proc_num, ObjectUuid, ndr_buffer);
        RpcTransportUtils.DumpBuffer(_transport.TraceFlags, RpcTransportTraceFlags.ClientNdr, "NDR Receive Data", resp.ToArray());
        return resp;
    }

    /// <summary>
    /// Method to call to check if the transport supports synchronous pipes.
    /// </summary>
    protected void CheckSynchronousPipeSupport()
    {
        if (_transport?.SupportsSynchronousPipes ?? false)
            return;
        throw new RpcTransportException("RPC transport doesn't support synchronous pipes.");
    }

    /// <summary>
    /// Method to call to check if the transport supports asynchronous pipes.
    /// </summary>
    protected void CheckAsynchronousPipeSupport()
    {
        throw new RpcTransportException("RPC transport doesn't support asynchronous pipes.");
    }

    /// <summary>
    /// Create a NDR marshal buffer for the negotiated transfer syntax.
    /// </summary>
    /// <returns>The NDR marshal buffer.</returns>
    /// <exception cref="RpcTransportException">Thrown if not connected.</exception>
    protected INdrMarshalBuffer CreateMarshalBuffer()
    {
        return _transport?.CreateMarshalBuffer() ?? throw new RpcTransportException("Client not connected.");
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
    public Guid? ObjectUuid { get; set; }

    /// <summary>
    /// The RPC interface ID.
    /// </summary>
    public RpcSyntaxIdentifier InterfaceId { get; }

    /// <summary>
    /// Get the client transport object.
    /// </summary>
    public IRpcClientTransport Transport => _transport;

    /// <summary>
    /// Specify the default flags to trace on the connected transport.
    /// </summary>
    public RpcTransportTraceFlags DefaultTraceFlags { get; set; }
    #endregion

    #region Public Methods
    /// <summary>
    /// Connect the client to a RPC endpoint.
    /// </summary>
    /// <param name="endpoint">The endpoint for RPC server.</param>
    /// <param name="transport_security">Security for the transport.</param>
    /// <param name="config">The transport configuration for the connection.</param>
    public void Connect(RpcEndpoint endpoint, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config = null)
    {
        Connect(endpoint.Binding, transport_security, config);
    }

    /// <summary>
    /// Connect the client to a RPC endpoint.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence for the transport.</param>
    /// <param name="endpoint">The endpoint for the protocol sequence.</param>
    /// <param name="transport_security">Security for the transport.</param>
    /// <param name="network_address">The network address for the protocol sequence.</param>
    /// <param name="config">The transport configuration for the connection.</param>
    public void Connect(string protocol_seq, string endpoint, string network_address,
        RpcTransportSecurity transport_security, RpcClientTransportConfiguration config = null)
    {
        Connect(new RpcStringBinding(protocol_seq, endpoint: endpoint, network_addr: network_address), transport_security, config);
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

        Connect(RpcProtocolSequence.LRPC, alpc_path, null, new(security_quality_of_service), null);
    }

    /// <summary>
    /// Connect the client to a RPC endpoint.
    /// </summary>
    /// <param name="binding">The binding string for the RPC server.</param>
    /// <param name="transport_security">Security for the transport.</param>
    /// <param name="config">The transport security for the connection.</param>
    public void Connect(RpcStringBinding binding, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config = null)
    {
        if (binding is null)
        {
            throw new ArgumentNullException(nameof(binding));
        }

        if (Connected)
        {
            throw new InvalidOperationException("RPC client is already connected.");
        }

        if (string.IsNullOrEmpty(binding.Endpoint))
        {
            binding = LookupEndpoint(binding);
        }

        try
        {
            _transport = RpcClientTransportFactory.ConnectEndpoint(binding, transport_security, config);
            _transport.TraceFlags = DefaultTraceFlags;
            _transport.Bind(InterfaceId);
            ObjectUuid = binding.ObjUuid;
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
