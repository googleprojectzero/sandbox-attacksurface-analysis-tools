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

using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Interface to implement an RPC client transport factory.
    /// </summary>
    public interface IRpcClientTransportFactory
    {
        /// <summary>
        /// Connect a new RPC client transport.
        /// </summary>
        /// <param name="endpoint">The RPC endpoint.</param>
        /// <param name="security_quality_of_service">The security quality of service for the connection.</param>
        /// <returns>The connected transport.</returns>
        IRpcClientTransport Connect(RpcEndpoint endpoint, SecurityQualityOfService security_quality_of_service);
    }

    /// <summary>
    /// Factory for RPC client transports.
    /// </summary>
    public static class RpcClientTransportFactory
    {
        private static Dictionary<string, IRpcClientTransportFactory> _factories = 
            new Dictionary<string, IRpcClientTransportFactory>(StringComparer.OrdinalIgnoreCase) { { "ncalrpc", new AlpcRpcClientTransportFactory() } };

        private class AlpcRpcClientTransportFactory : IRpcClientTransportFactory
        {
            public IRpcClientTransport Connect(RpcEndpoint endpoint, SecurityQualityOfService security_quality_of_service)
            {
                return new RpcAlpcClientTransport(endpoint.EndpointPath, security_quality_of_service);
            }
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
        /// <param name="endpoint">The RPC endpoint.</param>
        /// <param name="security_quality_of_service">The security quality of service for the connection.</param>
        /// <returns>The  connected client transport.</returns>
        /// <exception cref="ArgumentException">Thrown if protocol sequence unsupported.</exception>
        /// <exception cref="Exception">Other exceptions depending on the connection.</exception>
        public static IRpcClientTransport ConnectEndpoint(RpcEndpoint endpoint, SecurityQualityOfService security_quality_of_service)
        {
            if (!_factories.ContainsKey(endpoint.ProtocolSequence))
            {
                throw new ArgumentException($"Unsupported protocol sequence {endpoint.ProtocolSequence}", nameof(endpoint));
            }

            return _factories[endpoint.ProtocolSequence].Connect(endpoint, security_quality_of_service);
        }
    }
}
