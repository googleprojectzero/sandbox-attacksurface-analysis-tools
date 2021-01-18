//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Net.Sockets;
using System.Net.Sockets;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    class RpcHyperVClientTransport : RpcStreamSocketClientTransport
    {
        #region Private Members
        private const ushort MaxXmitFrag = 5840;
        private const ushort MaxRecvFrag = 5840;

        private static Socket CreateSocket(HyperVEndPoint endpoint)
        {
            Socket socket = new Socket(HyperVEndPoint.AF_HYPERV, 
                SocketType.Stream, HyperVEndPoint.HV_PROTOCOL_RAW);
            socket.Connect(endpoint);
            return socket;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="endpoint">The HyperV socket endpoint to connect to.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public RpcHyperVClientTransport(HyperVEndPoint endpoint, RpcTransportSecurity transport_security)
            : base(CreateSocket(endpoint), MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation(), transport_security)
        {
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public override string ProtocolSequence => "ncacn_hvsocket";
        #endregion
    }
}
