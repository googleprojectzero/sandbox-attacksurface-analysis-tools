//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Base class for a low-level client RPC transport configuration.
    /// </summary>
    public class RpcClientTransportConfiguration
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        protected RpcClientTransportConfiguration()
        {
        }

        /// <summary>
        /// Create a transport configuration for a specified protocol sequence.
        /// </summary>
        /// <param name="protocol_sequence">The protocol sequence.</param>
        /// <returns>The transport configuration. Returns a default object if no specific configuration supported.</returns>
        public static RpcClientTransportConfiguration Create(string protocol_sequence)
        {
            if (string.IsNullOrWhiteSpace(protocol_sequence))
            {
                throw new ArgumentException($"'{nameof(protocol_sequence)}' cannot be null or whitespace.", nameof(protocol_sequence));
            }

            switch (protocol_sequence.ToLower())
            {
                case RpcProtocolSequence.NamedPipe:
                    return new RpcNamedPipeClientTransportConfiguration();
                case RpcProtocolSequence.LRPC:
                    return new RpcAlpcClientTransportConfiguration();
            }
            return new RpcClientTransportConfiguration();
        }
    }
}
