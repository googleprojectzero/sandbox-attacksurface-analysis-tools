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
using System.Net.Sockets;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// RPC client transport over TCP/IP;
    /// </summary>
    public sealed class RpcTcpClientTransport : RpcStreamSocketClientTransport
    {
        #region Private Members
        private const ushort MaxXmitFrag = 5840;
        private const ushort MaxRecvFrag = 5840;

        private static Socket CreateSocket(string hostname, int port)
        {
            Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            socket.DualMode = true;
            // Enable no delay.
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.Debug, 1);
            socket.Connect(hostname, port);
            return socket;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="hostname">The hostname to connect to.</param>
        /// <param name="port">The TCP port to connect to.</param>
        public RpcTcpClientTransport(string hostname, int port) 
            : base(CreateSocket(hostname, port), MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation())
        {
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public override string ProtocolSequence => "ncacn_ip_tcp";
        #endregion
    }
}
