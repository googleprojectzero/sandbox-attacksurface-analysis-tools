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
using NtApiDotNet.Win32.RpcClient;
using System;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Generic RPC ALPC client.
    /// </summary>
    public sealed class RpcAlpcClient : RpcAlpcClientBase
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="interface_id">The interface ID.</param>
        /// <param name="interface_version">Version of the interface.</param>
        public RpcAlpcClient(Guid interface_id, Version interface_version) 
            : base(interface_id, interface_version)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="server">The RPC server to bind to.</param>
        public RpcAlpcClient(RpcServer server)
            : base(server.InterfaceId, server.InterfaceVersion)
        {
        }

        /// <summary>
        /// Send and receive an RPC message.
        /// </summary>
        /// <param name="proc_num">The procedure number.</param>
        /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
        /// <returns>Unmarshal NDR buffer for the result.</returns>
        public NdrUnmarshalBuffer SendReceive(int proc_num, NdrMarshalBuffer ndr_buffer)
        {
            var response = SendReceive(proc_num, ndr_buffer.ToArray(), ndr_buffer.Handles);
            return new NdrUnmarshalBuffer(response.NdrBuffer, response.Handles);
        }
    }
}
