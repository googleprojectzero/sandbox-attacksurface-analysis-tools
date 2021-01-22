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
using NtApiDotNet.Win32.Net;
using System;
using System.Net;
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

        /// <summary>
        /// Get the server process information.
        /// </summary>
        /// <returns>The server process information.</returns>
        private RpcServerProcessInformation GetServerProcess()
        {
            if (!Connected)
                throw new InvalidOperationException("TCP/IP transport is not connected.");
            IPEndPoint endpoint = (IPEndPoint)_socket.RemoteEndPoint;
            IPAddress address = endpoint.Address;

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            if (!IPAddress.IsLoopback(address))
            {
                throw new ArgumentException("Can't get server process on a remote system.");
            }

            var listener_info = Win32NetworkUtils.GetListenerForTcpPort(address.AddressFamily, endpoint.Port);
            if (listener_info == null)
                throw new ArgumentException("Can't find local listener for port.");
            return new RpcServerProcessInformation(listener_info.ProcessId, 0);
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="hostname">The hostname to connect to.</param>
        /// <param name="port">The TCP port to connect to.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public RpcTcpClientTransport(string hostname, int port, RpcTransportSecurity transport_security) 
            : base(CreateSocket(hostname, port), MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation(), transport_security)
        {
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public override string ProtocolSequence => "ncacn_ip_tcp";

        /// <summary>
        /// Get information about the local server process, if known.
        /// </summary>
        public override RpcServerProcessInformation ServerProcess => GetServerProcess();
        #endregion
    }
}
