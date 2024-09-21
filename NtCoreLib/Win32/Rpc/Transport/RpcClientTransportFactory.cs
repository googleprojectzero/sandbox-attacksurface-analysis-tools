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

using NtCoreLib.Net.Sockets.HyperV;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Factory for RPC client transports.
/// </summary>
public static class RpcClientTransportFactory
{
    private static Dictionary<string, IRpcClientTransportFactory> CreateFactories()
    {
        var ret = new Dictionary<string, IRpcClientTransportFactory>(StringComparer.OrdinalIgnoreCase);
        if (NtObjectUtils.IsWindows)
        {
            ret.Add(RpcProtocolSequence.LRPC, new AlpcRpcClientTransportFactory());
            ret.Add(RpcProtocolSequence.Container, new HyperVRpcClientTransportFactory());
        }
        ret.Add(RpcProtocolSequence.NamedPipe, new NamedPipeRpcClientTransportFactory());
        ret.Add(RpcProtocolSequence.Tcp, new TcpRpcClientTransportFactory());
        return ret;
    }

    private static readonly Dictionary<string, IRpcClientTransportFactory> _factories = CreateFactories();

    private class AlpcRpcClientTransportFactory : IRpcClientTransportFactory
    {
        public IRpcClientTransport Connect(RpcStringBinding binding, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config)
        {
            return new RpcAlpcClientTransport(binding, 
                transport_security.SecurityQualityOfService, config as RpcAlpcClientTransportConfiguration);
        }
    }

    private class NamedPipeRpcClientTransportFactory : IRpcClientTransportFactory
    {
        public IRpcClientTransport Connect(RpcStringBinding endpoint, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config)
        {
            return new RpcNamedPipeClientTransport(endpoint, transport_security, config as RpcNamedPipeClientTransportConfiguration);
        }
    }

    private class TcpRpcClientTransportFactory : IRpcClientTransportFactory
    {
        public IRpcClientTransport Connect(RpcStringBinding endpoint, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config)
        {
            string hostname = string.IsNullOrEmpty(endpoint.NetworkAddress) ? "127.0.0.1" : endpoint.NetworkAddress;
            int port = int.Parse(endpoint.Endpoint);
            return new RpcTcpClientTransport(hostname, port, transport_security, config as RpcConnectedClientTransportConfiguration);
        }
    }

    private class HyperVRpcClientTransportFactory : IRpcClientTransportFactory
    {
        private static HyperVEndPoint GetEndpoint(RpcStringBinding binding)
        {
            return new HyperVEndPoint(Guid.Parse(binding.Endpoint), RpcHyperVClientTransport.ResolveVmId(binding.NetworkAddress));
        }

        public IRpcClientTransport Connect(RpcStringBinding binding, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config)
        {
            return new RpcHyperVClientTransport(GetEndpoint(binding), transport_security, config as RpcConnectedClientTransportConfiguration);
        }
    }

    /// <summary>
    /// Add or replace a new transport factory.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence to add or replace.</param>
    /// <param name="factory">The transport factory.</param>
    public static void AddOrReplaceFactory(string protocol_seq, IRpcClientTransportFactory factory)
    {
        _factories[protocol_seq] = factory;
    }

    /// <summary>
    /// Add a new transport factory.
    /// </summary>
    /// <param name="protocol_seq">The protocol sequence to add.</param>
    /// <param name="factory">The transport factory.</param>
    public static void AddFactory(string protocol_seq, IRpcClientTransportFactory factory)
    {
        _factories.Add(protocol_seq, factory);
    }

    /// <summary>
    /// Connect a client transport from an endpoint.
    /// </summary>
    /// <param name="binding">The RPC binding to connect to.</param>
    /// <param name="transport_security">The security for the transport.</param>
    /// <param name="config">The transport configuration for the connection.</param>
    /// <returns>The connected client transport.</returns>
    /// <exception cref="ArgumentException">Thrown if protocol sequence unsupported.</exception>
    /// <exception cref="Exception">Other exceptions depending on the connection.</exception>
    public static IRpcClientTransport ConnectEndpoint(RpcStringBinding binding, RpcTransportSecurity transport_security, RpcClientTransportConfiguration config)
    {
        if (!_factories.ContainsKey(binding.ProtocolSequence))
        {
            throw new ArgumentException($"Unsupported protocol sequence {binding.ProtocolSequence}", nameof(binding));
        }

        return _factories[binding.ProtocolSequence].Connect(binding, transport_security, config);
    }
}
